#include "stream_tcp.h"

#include <algorithm>
#include <cstring>
#include <list>
#include <map>

namespace ethprobe {

namespace {

/* Sequence comparison that tolerates wraparound (RFC 1982 style) */
inline bool seq_leq(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b) <= 0; }
inline bool seq_lt(uint32_t a, uint32_t b)  { return static_cast<int32_t>(a - b) < 0; }

struct Direction {
    bool     initialized = false;
    uint32_t next_seq    = 0;
    /* out-of-order segments keyed by start seq (non-overlapping, first-seen wins) */
    std::map<uint32_t, std::vector<uint8_t>> ooo;
    size_t   ooo_bytes   = 0;
    bool     gap_pending = false;
    uint64_t gap_since_ms = 0;
    bool     fin_seen    = false;
};

struct Flow {
    Direction dir[2];
    uint64_t last_seen_ms = 0;
    bool     rst_seen = false;
};

} /* namespace */

struct TcpReassembly::Impl {
    Config cfg;
    std::map<FlowKey, Flow> flows;
    std::list<FlowKey> lru;  /* front = least recently used */
    std::map<FlowKey, std::list<FlowKey>::iterator> lru_pos;
    size_t mem_used = 0;

    void touch(const FlowKey& k) {
        auto it = lru_pos.find(k);
        if (it != lru_pos.end()) lru.erase(it->second);
        lru.push_back(k);
        lru_pos[k] = std::prev(lru.end());
    }

    void erase_flow(const FlowKey& k) {
        auto it = flows.find(k);
        if (it != flows.end()) {
            mem_used -= it->second.dir[0].ooo_bytes + it->second.dir[1].ooo_bytes;
            flows.erase(it);
        }
        auto lp = lru_pos.find(k);
        if (lp != lru_pos.end()) {
            lru.erase(lp->second);
            lru_pos.erase(lp);
        }
    }
};

TcpReassembly::TcpReassembly() : TcpReassembly(Config{}) {}

TcpReassembly::TcpReassembly(const Config& cfg) : m_(std::make_unique<Impl>()) {
    m_->cfg = cfg;
}

TcpReassembly::~TcpReassembly() = default;

TcpReassembly::DeliverResult TcpReassembly::add_segment(const ParsedPacket& pp,
                                                        uint64_t now_ms) {
    DeliverResult r;
    if (!pp.is_tcp) return r;

    /* Normalize flow key */
    FlowKey key;
    const bool forward =
        std::lexicographical_compare(pp.src_ip, pp.src_ip + 16, pp.dst_ip, pp.dst_ip + 16) ||
        (std::equal(pp.src_ip, pp.src_ip + 16, pp.dst_ip) && pp.src_port <= pp.dst_port);
    if (forward) {
        std::copy(pp.src_ip, pp.src_ip + 16, key.a_ip.begin());
        std::copy(pp.dst_ip, pp.dst_ip + 16, key.b_ip.begin());
        key.a_port = pp.src_port;
        key.b_port = pp.dst_port;
    } else {
        std::copy(pp.src_ip, pp.src_ip + 16, key.b_ip.begin());
        std::copy(pp.dst_ip, pp.dst_ip + 16, key.a_ip.begin());
        key.b_port = pp.src_port;
        key.a_port = pp.dst_port;
    }
    r.flow = key;
    r.dir  = forward ? 0 : 1;

    /* Capacity: evict LRU flows until a new one fits */
    if (m_->flows.find(key) == m_->flows.end()) {
        while (m_->flows.size() >= m_->cfg.max_flows &&
               !m_->lru.empty() && !(m_->lru.front() == key)) {
            m_->erase_flow(m_->lru.front());
            r.evicted = true;
        }
    }

    Flow& fl = m_->flows[key];
    fl.last_seen_ms = now_ms;
    m_->touch(key);
    Direction& d = fl.dir[r.dir];

    /* RST: terminate flow after flagging */
    if (pp.tcp_flags & TCP_RST) {
        fl.rst_seen = true;
        r.closed = true;
        m_->erase_flow(key);
        return r;
    }

    /* Sequence init: SYN consumes one sequence number */
    uint32_t seq = pp.tcp_seq;
    if (!d.initialized) {
        d.initialized = true;
        d.next_seq    = seq + ((pp.tcp_flags & TCP_SYN) ? 1u : 0u);
    }

    const uint8_t* data     = pp.payload;
    size_t         data_len = pp.payload_len;

    /* FIN consumes one sequence number after payload */
    const bool fin = (pp.tcp_flags & TCP_FIN) != 0;

    if (data_len > 0) {
        const uint32_t seg_begin = seq;
        const uint32_t seg_end   = seq + static_cast<uint32_t>(data_len);

        if (seq_leq(seg_end, d.next_seq)) {
            /* fully retransmitted: nothing to deliver */
        } else if (seq_lt(seg_begin, d.next_seq)) {
            /* leading overlap: trim */
            const size_t trim = d.next_seq - seg_begin;
            data     += trim;
            data_len -= trim;
            seq       = d.next_seq;
            r.has_data = true;
            r.data.insert(r.data.end(), data, data + data_len);
            d.next_seq += static_cast<uint32_t>(data_len);
        } else if (seq == d.next_seq) {
            r.has_data = true;
            r.data.insert(r.data.end(), data, data + data_len);
            d.next_seq += static_cast<uint32_t>(data_len);
        } else {
            /* future segment: buffer out-of-order (first-seen wins on overlap) */
            if (d.ooo_bytes + data_len <= m_->cfg.max_stream_bytes &&
                m_->mem_used + data_len <= m_->cfg.max_mem_bytes) {
                auto it = d.ooo.lower_bound(seg_begin);
                bool dominated = false;
                if (it != d.ooo.end() && it->first == seg_begin &&
                    seq_leq(seg_end, it->first + it->second.size())) {
                    dominated = true;  /* duplicate start, no new tail bytes */
                }
                if (it != d.ooo.begin()) {
                    auto prev = std::prev(it);
                    if (seq_leq(seg_end, prev->first + prev->second.size())) dominated = true;
                }
                if (!dominated) {
                    /* drop any later segments fully covered by the new one */
                    while (it != d.ooo.end() &&
                           seq_leq(it->first + it->second.size(), seg_end)) {
                        d.ooo_bytes -= it->second.size();
                        m_->mem_used -= it->second.size();
                        it = d.ooo.erase(it);
                    }
                    d.ooo.emplace(seg_begin, std::vector<uint8_t>(data, data + data_len));
                    d.ooo_bytes  += data_len;
                    m_->mem_used += data_len;
                    if (!d.gap_pending) {
                        d.gap_pending  = true;
                        d.gap_since_ms = now_ms;
                    }
                }
            } else {
                r.evicted = true;  /* stream/global cap hit: segment dropped */
            }
        }

        /* Drain contiguous out-of-order segments; skip gap after timeout */
        if (!d.ooo.empty()) {
            if (d.gap_pending && now_ms - d.gap_since_ms >= m_->cfg.gap_timeout_ms &&
                seq_lt(d.next_seq, d.ooo.begin()->first)) {
                d.next_seq   = d.ooo.begin()->first;  /* skip the gap */
                d.gap_pending = false;
            }
            auto it = d.ooo.begin();
            while (it != d.ooo.end() && seq_leq(it->first, d.next_seq)) {
                const auto& seg = it->second;
                if (seq_lt(d.next_seq, it->first + seg.size())) {
                    const size_t skip = d.next_seq - it->first;
                    r.has_data = true;
                    r.data.insert(r.data.end(), seg.begin() + skip, seg.end());
                    d.next_seq = it->first + static_cast<uint32_t>(seg.size());
                }
                d.ooo_bytes  -= seg.size();
                m_->mem_used -= seg.size();
                it = d.ooo.erase(it);
            }
            if (d.ooo.empty()) d.gap_pending = false;
        }
    }

    /* FIN handling */
    if (fin && !d.fin_seen) {
        d.fin_seen = true;
        ++d.next_seq;  /* FIN occupies one sequence number */
    }
    if (fl.dir[0].fin_seen && fl.dir[1].fin_seen) {
        r.closed = true;
        m_->erase_flow(key);
    }
    return r;
}

size_t TcpReassembly::expire(uint64_t now_ms) {
    size_t dropped = 0;
    for (auto it = m_->flows.begin(); it != m_->flows.end();) {
        if (now_ms - it->second.last_seen_ms >= m_->cfg.idle_timeout_ms) {
            const FlowKey k = it->first;
            ++it;
            m_->erase_flow(k);
            ++dropped;
        } else {
            ++it;
        }
    }
    return dropped;
}

size_t TcpReassembly::active_flows()  const { return m_->flows.size(); }
size_t TcpReassembly::buffered_bytes() const { return m_->mem_used; }

} /* namespace ethprobe */
