/*
 * pipeline.cpp — the eth_probe detection pipeline (see pipeline.h).
 *
 * Feed path per frame:
 *   parse_packet
 *     → ARP:    ArpSpoofDetector
 *     → IP:     RateFloodDetector (every packet)
 *               cross-border check (outbound to non-domestic dst)
 *               fragment? → IpDefrag (complete datagrams re-enter below)
 *               TCP:      flag anomaly + port scan (packet level)
 *                         header-only rules (packet level)
 *                         TcpReassembly → per-direction app handling:
 *                           DoIP (13400) / TLS (443) / HTTP (80,8080)
 *                           + stream rule matching with tail retention
 *               UDP:      DoIP / SOME-IP(+SD) / DNS + full packet rules
 *               ICMP:     full packet rules
 *
 * Everything runs on the capture thread; alerts go out through cb_.
 */
#include "pipeline.h"

#include "proto_dns.h"
#include "proto_doip.h"
#include "proto_http.h"
#include "proto_tls.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <vector>

namespace ethprobe {

namespace {

/* aux codes for DT_REASSEMBLY */
constexpr uint32_t REASS_ALERT_DEFRAG_EVICT = 1;
constexpr uint32_t REASS_ALERT_STREAM_EVICT = 2;

/* Build a ParsedPacket for a reassembled datagram: L3 from the fragment
   that completed it, L4 re-parsed from the reassembled bytes. */
ParsedPacket reassembled_packet(const ParsedPacket& frag,
                                std::vector<uint8_t>& datagram) {
    ParsedPacket rp{};
    rp.src_mac  = frag.src_mac;
    rp.dst_mac  = frag.dst_mac;
    rp.is_ipv4  = frag.is_ipv4;
    rp.is_ipv6  = frag.is_ipv6;
    std::memcpy(rp.src_ip, frag.src_ip, 16);
    std::memcpy(rp.dst_ip, frag.dst_ip, 16);
    rp.l4_proto = frag.l4_proto;
    rp.l4_data  = datagram.data();
    rp.l4_len   = datagram.size();
    parse_l4_only(frag.l4_proto, datagram.data(), datagram.size(), rp);
    return rp;
}

} /* namespace */

struct ProbePipeline::Impl {
    explicit Impl(AlertCallback cb) : cb_(std::move(cb)) {}

    Config       cfg;
    AlertCallback cb_;

    RuleEngine        rules_;
    GeoIp             geoip_;
    SomeipSdTracker   sd_;
    PortScanDetector  port_scan_;
    RateFloodDetector rate_flood_;
    ArpSpoofDetector  arp_;
    IpDefrag          defrag_;
    TcpReassembly     tcp_;

    /* Per-flow per-direction app-layer state (reassembly-side) */
    struct DirState {
        std::vector<uint8_t> rule_tail;  /* last max_pattern_len-1 bytes matched */
        std::vector<uint8_t> acc;        /* app parser accumulation buffer */
        bool http_checked = false;       /* protocol sniff done on this dir */
        bool http_bad     = false;       /* non-HTTP on an HTTP port (alerted) */
        bool tls_done     = false;       /* ClientHello already processed */
    };
    struct FlowState { DirState dir[2]; };
    std::map<FlowKey, FlowState> flows_;

    /* Cross-border alert cooldown: (src_ip, dst_ip) → last alert ms */
    std::map<std::array<uint8_t, 32>, uint64_t> xborder_last_;

    void emit(const ProbeAlert& a) { cb_(a); }

    void feed_frame(const uint8_t* data, size_t len, uint64_t now_ms) {
        ParsedPacket pp;
        if (!parse_packet(data, len, pp)) return;

        if (pp.is_arp) {
            if (auto a = arp_.feed(pp, now_ms)) emit(*a);
            return;
        }
        if (!pp.is_ipv4 && !pp.is_ipv6) return;

        if (auto a = rate_flood_.feed(pp, now_ms)) emit(*a);
        check_cross_border(pp, now_ms);

        if (pp.is_fragment) {
            handle_fragment(pp, now_ms);
            return;
        }
        handle_l4(pp, now_ms);
    }

    /* Reassembled datagrams re-enter here with is_fragment cleared. */
    void handle_l4(const ParsedPacket& pp, uint64_t now_ms) {
        if (pp.is_tcp) {
            handle_tcp(pp, now_ms);
        } else if (pp.is_udp) {
            handle_udp(pp, now_ms);
        } else if (pp.l4_proto == IP_PROTO_ICMP ||
                   pp.l4_proto == IP_PROTO_ICMPV6) {
            match_rules_packet(pp, /*header_only=*/false);
        }
    }

    void handle_fragment(const ParsedPacket& pp, uint64_t now_ms) {
        if (pp.l4_data == nullptr || pp.l4_len == 0) return;
        auto res = defrag_.add_fragment(pp, pp.l4_data, pp.l4_len, now_ms);
        if (res.evicted) {
            emit(make_alert(DT_REASSEMBLY, pp, REASS_ALERT_DEFRAG_EVICT));
        }
        if (!res.complete) return;
        ParsedPacket rp = reassembled_packet(pp, res.datagram);
        handle_l4(rp, now_ms);
    }

    /* ---- cross-border (detector 8) ---- */

    void check_cross_border(const ParsedPacket& pp, uint64_t now_ms) {
        if (!cfg.cross_border_enabled || !geoip_.loaded()) return;
        const bool v6 = pp.is_ipv6;
        /* multicast / broadcast / link-local destinations are local by
           definition — never cross-border (mDNS 224.0.0.251, LLMNR, SSDP,
           IPv6 ff02::/16, IPv4 broadcast 255.255.255.255 ...) */
        if (!v6) {
            if ((pp.dst_ip[0] & 0xF0) == 0xE0) return;       /* 224.0.0.0/4 */
            if (pp.dst_ip[0] == 169 && pp.dst_ip[1] == 254) return;
            if (pp.dst_ip[0] == 255) return;                  /* broadcast */
        } else {
            if (pp.dst_ip[0] == 0xFF) return;                 /* ff00::/8 */
            if (pp.dst_ip[0] == 0xFE && (pp.dst_ip[1] & 0xC0) == 0x80) return;
        }
        /* outbound only: src inside the vehicle, dst outside */
        if (geoip_.classify(pp.src_ip, v6) != GeoIp::Verdict::HOME) return;
        if (geoip_.classify(pp.dst_ip, v6) != GeoIp::Verdict::FOREIGN) return;

        std::array<uint8_t, 32> key{};
        std::memcpy(key.data(), pp.src_ip, 16);
        std::memcpy(key.data() + 16, pp.dst_ip, 16);
        auto it = xborder_last_.find(key);
        if (it != xborder_last_.end() &&
            now_ms - it->second < cfg.cross_border_cooldown_ms) return;
        xborder_last_[key] = now_ms;
        emit(make_alert(DT_CROSS_BORDER, pp, 0));
    }

    /* ---- TCP ---- */

    void handle_tcp(const ParsedPacket& pp, uint64_t now_ms) {
        if (auto a = check_flag_anomaly(pp)) emit(*a);
        if ((pp.tcp_flags & TCP_SYN) && !(pp.tcp_flags & TCP_RST)) {
            if (auto a = port_scan_.feed(pp, now_ms)) emit(*a);
        }
        /* Pure-header rules match at packet level; payload-bearing rules
           are evaluated on the reassembled stream to catch cross-packet
           signatures. */
        match_rules_packet(pp, /*header_only=*/true);

        auto res = tcp_.add_segment(pp, now_ms);
        if (res.evicted) {
            emit(make_alert(DT_REASSEMBLY, pp, REASS_ALERT_STREAM_EVICT));
        }
        if (res.has_data && !res.data.empty()) {
            handle_stream_data(pp, res, now_ms);
        }
        if (res.closed) flows_.erase(res.flow);
    }

    void handle_stream_data(const ParsedPacket& pp,
                            const TcpReassembly::DeliverResult& res,
                            uint64_t now_ms) {
        (void)now_ms;
        FlowState& fs = flows_[res.flow];
        DirState&  ds = fs.dir[res.dir];

        /* Rule matching on retained tail + new bytes (cross-chunk hits) */
        std::vector<uint8_t> window = ds.rule_tail;
        window.insert(window.end(), res.data.begin(), res.data.end());
        MatchBuffers bufs{};
        bufs.raw     = window.data();
        bufs.raw_len = window.size();
        for (const Rule* r : rules_.match(pp, bufs)) {
            emit(make_alert(DT_RULE_HIT, pp, r->sid));
        }
        const size_t keep = rules_.max_pattern_len() > 0
                                ? rules_.max_pattern_len() - 1 : 0;
        if (window.size() > keep) {
            ds.rule_tail.assign(window.end() - static_cast<ptrdiff_t>(keep),
                                window.end());
        } else {
            ds.rule_tail = std::move(window);
        }

        /* App-layer protocols by port */
        const uint16_t port = (res.dir == 0) ? res.flow.b_port : res.flow.a_port;
        if (port == DOIP_PORT) {
            feed_doip_stream(pp, ds, res.data);
        } else if (port == cfg.tls_port) {
            feed_tls_stream(pp, ds, res.data);
        } else if (port == cfg.http_port || port == cfg.http_alt_port) {
            feed_http_stream(pp, ds, res.data);
        }
        if (ds.acc.size() > cfg.stream_acc_cap) {
            ds.acc.erase(ds.acc.begin(),
                         ds.acc.end() - static_cast<ptrdiff_t>(cfg.stream_acc_cap));
        }
    }

    /* DoIP over TCP: header carries its own length → frame messages from
       the accumulated stream. */
    void feed_doip_stream(const ParsedPacket& pp, DirState& ds,
                          const std::vector<uint8_t>& data) {
        ds.acc.insert(ds.acc.end(), data.begin(), data.end());
        size_t off = 0;
        while (ds.acc.size() - off >= 8) {
            const uint8_t* m = ds.acc.data() + off;
            const uint32_t pay_len = static_cast<uint32_t>(m[4]) << 24 |
                                     static_cast<uint32_t>(m[5]) << 16 |
                                     static_cast<uint32_t>(m[6]) << 8  | m[7];
            if (pay_len > 16 * 1024 * 1024) {  /* implausible → resync impossible */
                emit(make_alert(DT_DOIP, pp, DOIP_ERR_LENGTH));
                off = ds.acc.size();
                break;
            }
            if (ds.acc.size() - off < 8 + pay_len) break;  /* wait for more */
            inspect_doip_message(pp, m, 8 + pay_len);
            off += 8 + pay_len;
        }
        ds.acc.erase(ds.acc.begin(), ds.acc.begin() + static_cast<ptrdiff_t>(off));
    }

    void inspect_doip_message(const ParsedPacket& pp,
                              const uint8_t* data, size_t len) {
        const DoipInfo    info = parse_doip(data, len);
        const DoipVerdict v    = inspect_doip(info);
        if (v.alert) emit(make_alert(DT_DOIP, pp, v.aux));
    }

    void feed_tls_stream(const ParsedPacket& pp, DirState& ds,
                         const std::vector<uint8_t>& data) {
        if (ds.tls_done) return;
        ds.acc.insert(ds.acc.end(), data.begin(), data.end());
        if (!looks_like_tls(ds.acc.data(), ds.acc.size())) {
            ds.tls_done = true;  /* not TLS on the TLS port — nothing to do */
            return;
        }
        const TlsClientHello ch = parse_tls_client_hello(ds.acc.data(), ds.acc.size());
        if (ch.error == TLS_ERR_TRUNCATED) return;  /* wait for more bytes */
        ds.tls_done = true;
        if (!ch.valid) {
            emit(make_alert(DT_TLS, pp, TLS_ALERT_MALFORMED));
            return;
        }
        const bool v6 = pp.is_ipv6;
        const bool internal =
            geoip_.classify(pp.src_ip, v6) == GeoIp::Verdict::HOME &&
            geoip_.classify(pp.dst_ip, v6) == GeoIp::Verdict::HOME;
        if (internal) {
            /* TLS on the vehicle net where plain SOME/IP/DoIP is expected */
            emit(make_alert(DT_TLS, pp, TLS_ALERT_SEEN_ON_VEHICLE_NET));
        }
        if (ch.client_version < 0x0303) {  /* < TLS 1.2 */
            emit(make_alert(DT_TLS, pp, TLS_ALERT_VERSION_LT_1_2));
        }
    }

    void feed_http_stream(const ParsedPacket& pp, DirState& ds,
                          const std::vector<uint8_t>& data) {
        if (ds.http_bad) return;
        ds.acc.insert(ds.acc.end(), data.begin(), data.end());

        if (!ds.http_checked) {
            ds.http_checked = true;
            if (!looks_like_http(ds.acc.data(), ds.acc.size())) {
                ds.http_bad = true;
                /* non-HTTP traffic on an HTTP port = protocol anomaly */
                emit(make_alert(DT_HTTP, pp, HTTP_ALERT_MALFORMED));
                return;
            }
        }

        /* Parse pipelined messages; sticky buffers feed the rule engine */
        size_t off = 0;
        while (off < ds.acc.size()) {
            const uint8_t* m   = ds.acc.data() + off;
            const size_t   rem = ds.acc.size() - off;
            if (rem > HTTP_MAX_HEADER) {
                emit(make_alert(DT_HTTP, pp, HTTP_ALERT_MALFORMED));
                off = ds.acc.size();
                break;
            }
            const HttpMessage msg = parse_http(m, rem);
            if (msg.error == HTTP_INCOMPLETE) break;  /* wait for more */
            if (msg.error != HTTP_OK) {
                emit(make_alert(DT_HTTP, pp,
                                msg.error == HTTP_ERR_URI_TOO_LONG
                                    ? HTTP_ALERT_URI_TOO_LONG
                                    : HTTP_ALERT_MALFORMED));
                off = ds.acc.size();
                break;
            }
            /* RAW-content rules already matched on the stream window above;
               here only the sticky buffers are live (no duplicate alerts). */
            MatchBuffers bufs{};
            bufs.http_header = msg.header_block;
            bufs.http_header_len = msg.header_block_len;
            if (msg.is_request) {
                bufs.http_method     = reinterpret_cast<const uint8_t*>(msg.method.data());
                bufs.http_method_len = msg.method.size();
                bufs.http_uri        = reinterpret_cast<const uint8_t*>(msg.uri.data());
                bufs.http_uri_len    = msg.uri.size();
            }
            for (const Rule* r : rules_.match(pp, bufs)) {
                emit(make_alert(DT_RULE_HIT, pp, r->sid));
            }
            off += msg.consumed;
        }
        ds.acc.erase(ds.acc.begin(), ds.acc.begin() + static_cast<ptrdiff_t>(off));
    }

    /* ---- UDP ---- */

    void handle_udp(const ParsedPacket& pp, uint64_t now_ms) {
        if (pp.payload == nullptr) return;

        const bool is_dns = pp.src_port == DNS_PORT || pp.dst_port == DNS_PORT;
        if (pp.src_port == DOIP_PORT || pp.dst_port == DOIP_PORT) {
            inspect_doip_message(pp, pp.payload, pp.payload_len);
        }
        if (pp.src_port == cfg.someip_port || pp.dst_port == cfg.someip_port) {
            handle_someip(pp, now_ms);
        }
        if (is_dns) {
            handle_dns(pp);  /* does its own rule match (raw + dns_query) */
        } else {
            match_rules_packet(pp, /*header_only=*/false);
        }
    }

    void handle_someip(const ParsedPacket& pp, uint64_t now_ms) {
        const SomeipInfo info = parse_someip(pp.payload, pp.payload_len);
        if (!info.valid) {
            emit(make_alert(DT_SOMEIP, pp,
                            static_cast<uint32_t>(info.error)));
            return;
        }
        if (info.is_sd()) {
            for (const uint32_t aux : sd_.inspect(info, pp.src_ip, now_ms)) {
                emit(make_alert(DT_SOMEIP, pp, aux));
            }
        }
    }

    void handle_dns(const ParsedPacket& pp) {
        const DnsInfo info = parse_dns(pp.payload, pp.payload_len);
        if (info.error == DNS_ERR_QNAME) {
            emit(make_alert(DT_DNS, pp, DNS_ALERT_QNAME_ILLEGAL));
        } else if (info.error != DNS_OK && info.error != DNS_ERR_TRUNCATED) {
            emit(make_alert(DT_DNS, pp, static_cast<uint32_t>(info.error)));
        }
        if (info.valid && dns_qtype_suspicious(info.qtype)) {
            emit(make_alert(DT_DNS, pp,
                            DNS_ALERT_SUSPICIOUS_QTYPE | info.qtype));
        }
        if (info.valid && !info.qname.empty()) {
            MatchBuffers bufs{};
            bufs.raw           = pp.payload;
            bufs.raw_len       = pp.payload_len;
            bufs.dns_query     = reinterpret_cast<const uint8_t*>(info.qname.data());
            bufs.dns_query_len = info.qname.size();
            for (const Rule* r : rules_.match(pp, bufs)) {
                emit(make_alert(DT_RULE_HIT, pp, r->sid));
            }
        }
    }

    /* Packet-level rule match. header_only=true restricts to rules without
       payload options (used for TCP, whose payload rules run on the stream). */
    void match_rules_packet(const ParsedPacket& pp, bool header_only) {
        if (rules_.rule_count() == 0) return;
        MatchBuffers bufs{};
        bufs.raw     = pp.payload;
        bufs.raw_len = pp.payload_len;
        for (const Rule* r : rules_.match(pp, bufs)) {
            if (header_only &&
                (!r->contents.empty() || !r->pcre_patterns.empty())) continue;
            emit(make_alert(DT_RULE_HIT, pp, r->sid));
        }
    }

    void tick(uint64_t now_ms) {
        if (defrag_.expire(now_ms) > 0) { /* silent: normal timeout */ }
        tcp_.expire(now_ms);
    }
};

/* ---- public wrapper ---- */

ProbePipeline::ProbePipeline(AlertCallback cb)
    : m_(std::make_unique<Impl>(std::move(cb))) {}
ProbePipeline::~ProbePipeline() = default;

RuleEngine&        ProbePipeline::rules()      { return m_->rules_; }
GeoIp&             ProbePipeline::geoip()      { return m_->geoip_; }
SomeipSdTracker&   ProbePipeline::sd_tracker() { return m_->sd_; }
PortScanDetector&  ProbePipeline::port_scan()  { return m_->port_scan_; }
RateFloodDetector& ProbePipeline::rate_flood() { return m_->rate_flood_; }
ArpSpoofDetector&  ProbePipeline::arp_spoof()  { return m_->arp_; }
IpDefrag&          ProbePipeline::defrag()     { return m_->defrag_; }
TcpReassembly&     ProbePipeline::tcp()        { return m_->tcp_; }
ProbePipeline::Config& ProbePipeline::config() { return m_->cfg; }

void ProbePipeline::feed_frame(const uint8_t* data, size_t len, uint64_t now_ms) {
    m_->feed_frame(data, len, now_ms);
}
void ProbePipeline::tick(uint64_t now_ms) { m_->tick(now_ms); }

} /* namespace ethprobe */
