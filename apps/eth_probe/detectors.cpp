#include "detectors.h"

#include <cstring>

namespace ethprobe {

namespace {

std::array<uint8_t, 16> key16(const uint8_t ip[16]) {
    std::array<uint8_t, 16> k{};
    std::memcpy(k.data(), ip, 16);
    return k;
}

} /* namespace */

/* ---- flag anomaly (stateless) ---- */

std::optional<ProbeAlert> check_flag_anomaly(const ParsedPacket& pp) {
    if (!pp.is_tcp) return std::nullopt;
    const uint8_t f = pp.tcp_flags;
    uint32_t aux = 0;
    if (f == 0) {
        aux = FLAG_ANOMALY_NULL;
    } else if ((f & (TCP_FIN | TCP_PSH | TCP_URG)) == (TCP_FIN | TCP_PSH | TCP_URG)) {
        aux = FLAG_ANOMALY_XMAS;
    } else if ((f & TCP_SYN) && (f & TCP_FIN)) {
        aux = FLAG_ANOMALY_SYN_FIN;
    } else {
        return std::nullopt;
    }
    return make_alert(DT_FLAG_ANOMALY, pp, aux);
}

/* ---- port scan ---- */

PortScanDetector::PortScanDetector() : PortScanDetector(Config{}) {}
PortScanDetector::PortScanDetector(const Config& cfg) : cfg_(cfg) {}

std::optional<ProbeAlert> PortScanDetector::feed(const ParsedPacket& pp,
                                                 uint64_t now_ms) {
    if (!pp.is_tcp) return std::nullopt;
    SrcState& st = sources_[key16(pp.src_ip)];

    /* expire events outside the window */
    while (!st.events.empty() && now_ms - st.events.front().first >= cfg_.window_ms) {
        const uint16_t port = st.events.front().second;
        auto it = st.port_counts.find(port);
        if (it != st.port_counts.end() && --it->second == 0) st.port_counts.erase(it);
        st.events.pop_front();
    }
    if (st.port_counts.size() < cfg_.unique_threshold) st.alerted = false;

    /* record this SYN */
    st.events.emplace_back(now_ms, pp.dst_port);
    ++st.port_counts[pp.dst_port];

    if (st.port_counts.size() >= cfg_.unique_threshold && !st.alerted) {
        st.alerted = true;
        return make_alert(DT_PORT_SCAN, pp,
                          static_cast<uint32_t>(st.port_counts.size()));
    }
    return std::nullopt;
}

/* ---- rate flood ---- */

RateFloodDetector::RateFloodDetector() : RateFloodDetector(Config{}) {}
RateFloodDetector::RateFloodDetector(const Config& cfg) : cfg_(cfg) {}

std::optional<ProbeAlert> RateFloodDetector::feed(const ParsedPacket& pp,
                                                  uint64_t now_ms) {
    SrcState& st = sources_[key16(pp.src_ip)];
    if (!st.active || now_ms - st.window_start >= cfg_.window_ms) {
        st.active       = true;
        st.window_start = now_ms;
        st.count        = 0;
        st.alerted      = false;
    }
    ++st.count;
    if (st.count >= cfg_.pps_threshold && !st.alerted) {
        st.alerted = true;
        auto a = make_alert(DT_RATE_FLOOD, pp, st.count);
        a.count = st.count;  /* pre-aggregated occurrences */
        return a;
    }
    return std::nullopt;
}

/* ---- ARP spoofing ---- */

ArpSpoofDetector::ArpSpoofDetector() : ArpSpoofDetector(Config{}) {}
ArpSpoofDetector::ArpSpoofDetector(const Config& cfg) : cfg_(cfg) {}

std::optional<ProbeAlert> ArpSpoofDetector::feed(const ParsedPacket& pp,
                                                 uint64_t now_ms) {
    if (!pp.is_arp) return std::nullopt;
    const bool is_request = pp.arp_opcode == 1;
    const bool is_reply   = pp.arp_opcode == 2;
    if (!is_request && !is_reply) return std::nullopt;

    /* sender protocol address is in the first 4 bytes of src_ip */
    std::array<uint8_t, 4> spa = {pp.src_ip[0], pp.src_ip[1], pp.src_ip[2], pp.src_ip[3]};
    const uint8_t zero4[4] = {};
    if (std::memcmp(spa.data(), zero4, 4) == 0) return std::nullopt;  /* probe request */

    /* binding conflict: a different MAC answers for a known IP */
    auto [it, inserted] = bindings_.emplace(spa, pp.src_mac);
    if (!inserted && it->second != pp.src_mac) {
        const MacAddress old = it->second;
        it->second = pp.src_mac;  /* track the new claimant */
        (void)old;
        return make_alert(DT_ARP, pp, ARP_ALERT_BINDING_CHANGE);
    }

    /* gratuitous ARP: reply to broadcast, or request where sender == target */
    const uint8_t zero6[6] = {};
    const bool gratuitous =
        (is_reply && std::memcmp(pp.dst_mac.b, zero6, 6) == 0) ||
        (is_request && std::memcmp(pp.src_ip, pp.dst_ip, 4) == 0);
    if (gratuitous) {
        std::array<uint8_t, 6> mac_key{};
        std::memcpy(mac_key.data(), pp.src_mac.b, 6);
        StormState& st = gratuitous_[mac_key];
        if (!st.active || now_ms - st.window_start >= cfg_.window_ms) {
            st.active       = true;
            st.window_start = now_ms;
            st.count        = 0;
            st.alerted      = false;
        }
        ++st.count;
        if (st.count >= cfg_.gratuitous_threshold && !st.alerted) {
            st.alerted = true;
            return make_alert(DT_ARP, pp, ARP_ALERT_GRATUITOUS_STORM);
        }
    }
    return std::nullopt;
}

} /* namespace ethprobe */
