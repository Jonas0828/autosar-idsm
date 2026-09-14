#include "ip_defrag.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <list>
#include <map>
#include <set>

namespace ethprobe {

namespace {

constexpr uint32_t MAX_DATAGRAM_LEN = 65535;

struct FragKey {
    std::array<uint8_t, 16> src{};
    std::array<uint8_t, 16> dst{};
    uint32_t id    = 0;
    uint8_t  proto = 0;
    bool     is_v6 = false;

    bool operator<(const FragKey& o) const {
        return std::tie(src, dst, id, proto, is_v6) <
               std::tie(o.src, o.dst, o.id, o.proto, o.is_v6);
    }
    bool operator==(const FragKey& o) const {
        return src == o.src && dst == o.dst && id == o.id &&
               proto == o.proto && is_v6 == o.is_v6;
    }
};

struct Datagram {
    std::vector<uint8_t> buf;                 /* sized as fragments arrive */
    std::set<std::pair<uint32_t, uint32_t>> covered;  /* merged [begin,end) */
    uint32_t total_len  = 0;                  /* valid when have_last */
    bool     have_last  = false;
    uint64_t last_seen_ms = 0;
    size_t   accounted  = 0;                  /* bytes charged to memory pool */
};

} /* namespace */

struct IpDefrag::Impl {
    Config cfg;
    std::map<FragKey, Datagram> table;
    /* LRU order: front = least recently touched */
    std::list<FragKey> lru;
    std::map<FragKey, std::list<FragKey>::iterator> lru_pos;
    size_t mem_used = 0;

    void touch(const FragKey& k) {
        auto it = lru_pos.find(k);
        if (it != lru_pos.end()) lru.erase(it->second);
        lru.push_back(k);
        lru_pos[k] = std::prev(lru.end());
    }

    bool evict_one() {
        if (lru.empty()) return false;
        const FragKey victim = lru.front();
        lru.pop_front();
        lru_pos.erase(victim);
        auto it = table.find(victim);
        if (it != table.end()) {
            mem_used -= it->second.accounted;
            table.erase(it);
        }
        return true;
    }
};

IpDefrag::IpDefrag() : IpDefrag(Config{}) {}

IpDefrag::IpDefrag(const Config& cfg) : m_(std::make_unique<Impl>()) {
    m_->cfg = cfg;
}

IpDefrag::~IpDefrag() = default;

IpDefrag::Result IpDefrag::add_fragment(const ParsedPacket& pp,
                                        const uint8_t* frag_payload, size_t frag_len,
                                        uint64_t now_ms) {
    Result r;
    if (frag_payload == nullptr || frag_len == 0) return r;
    if (pp.frag_offset >= MAX_DATAGRAM_LEN) return r;
    const uint32_t off  = pp.frag_offset;
    uint32_t       flen = static_cast<uint32_t>(frag_len);
    if (off + flen > MAX_DATAGRAM_LEN) flen = MAX_DATAGRAM_LEN - off;

    FragKey key;
    std::copy(std::begin(pp.src_ip), std::end(pp.src_ip), key.src.begin());
    std::copy(std::begin(pp.dst_ip), std::end(pp.dst_ip), key.dst.begin());
    key.id    = pp.frag_id;
    key.proto = pp.l4_proto;
    key.is_v6 = pp.is_ipv6;

    /* Capacity: make room before inserting a new entry */
    bool new_entry = m_->table.find(key) == m_->table.end();
    if (new_entry) {
        while (m_->table.size() >= m_->cfg.max_datagrams && m_->evict_one()) r.evicted = true;
    }

    Datagram& dg = m_->table[key];  /* creates empty entry when new */
    dg.last_seen_ms = now_ms;
    m_->touch(key);

    /* Grow buffer to cover this fragment. Evict LRU entries until it fits,
       but never the entry we are feeding (lru.front() == key means we are
       the only candidate left). */
    const size_t need = off + flen;
    if (dg.buf.size() < need) {
        const size_t grow = need - dg.buf.size();
        while (m_->mem_used + grow > m_->cfg.max_mem_bytes &&
               !m_->lru.empty() && !(m_->lru.front() == key)) {
            m_->evict_one();
            r.evicted = true;
        }
        if (m_->mem_used + grow > m_->cfg.max_mem_bytes) {
            /* Still cannot fit: drop the (fresh) entry and skip this fragment */
            if (dg.accounted == 0) {
                m_->table.erase(key);
                auto lp = m_->lru_pos.find(key);
                if (lp != m_->lru_pos.end()) {
                    m_->lru.erase(lp->second);
                    m_->lru_pos.erase(lp);
                }
            }
            return r;
        }
        dg.buf.resize(need);
        m_->mem_used += grow;
        dg.accounted += grow;
    }

    /* First-seen wins: only copy ranges not yet covered */
    uint32_t begin = off, end = off + flen;
    auto& cov = dg.covered;
    auto it = cov.lower_bound({begin, 0});
    if (it != cov.begin()) {
        auto prev = std::prev(it);
        if (prev->second >= begin) it = prev;
    }
    uint32_t cursor = begin;
    while (it != cov.end() && it->first < end) {
        if (cursor < it->first) {
            std::memcpy(dg.buf.data() + cursor, frag_payload + (cursor - off), it->first - cursor);
        }
        cursor = std::max(cursor, it->second);
        ++it;
    }
    if (cursor < end) {
        std::memcpy(dg.buf.data() + cursor, frag_payload + (cursor - off), end - cursor);
    }

    /* Merge [begin,end) into the covered interval set */
    uint32_t mb = begin, me = end;
    it = cov.lower_bound({begin, 0});
    if (it != cov.begin()) {
        auto prev = std::prev(it);
        if (prev->second >= begin) { mb = std::min(mb, prev->first); me = std::max(me, prev->second); it = cov.erase(prev); }
    }
    while (it != cov.end() && it->first <= me) {
        me = std::max(me, it->second);
        it = cov.erase(it);
    }
    cov.insert(it, {mb, me});

    if (!pp.frag_more) {
        dg.have_last = true;
        dg.total_len = end;
    }

    /* Complete? single covered range [0,total) */
    if (dg.have_last && cov.size() == 1 && cov.begin()->first == 0 &&
        cov.begin()->second >= dg.total_len) {
        r.complete  = true;
        r.datagram.assign(dg.buf.begin(), dg.buf.begin() + dg.total_len);
        m_->mem_used -= dg.accounted;
        m_->table.erase(key);
        auto lp = m_->lru_pos.find(key);
        if (lp != m_->lru_pos.end()) {
            m_->lru.erase(lp->second);
            m_->lru_pos.erase(lp);
        }
    }
    return r;
}

size_t IpDefrag::expire(uint64_t now_ms) {
    size_t dropped = 0;
    for (auto it = m_->table.begin(); it != m_->table.end();) {
        if (now_ms - it->second.last_seen_ms >= m_->cfg.timeout_ms) {
            m_->mem_used -= it->second.accounted;
            auto lp = m_->lru_pos.find(it->first);
            if (lp != m_->lru_pos.end()) {
                m_->lru.erase(lp->second);
                m_->lru_pos.erase(lp);
            }
            it = m_->table.erase(it);
            ++dropped;
        } else {
            ++it;
        }
    }
    return dropped;
}

size_t IpDefrag::active_datagrams() const { return m_->table.size(); }
size_t IpDefrag::buffered_bytes()  const { return m_->mem_used; }

} /* namespace ethprobe */
