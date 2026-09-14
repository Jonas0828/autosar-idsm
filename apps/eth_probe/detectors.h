#pragma once
/*
 * detectors.h — packet-level anomaly detectors (stateless or sliding
 * window): port scan, rate flood, TCP flag anomalies, ARP spoofing.
 * Each feed() returns an alert when its condition triggers.
 */
#include "alert.h"
#include "packet.h"

#include <array>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>

namespace ethprobe {

/* aux codes for DT_FLAG_ANOMALY */
inline constexpr uint32_t FLAG_ANOMALY_NULL     = 1;  /* flags == 0 */
inline constexpr uint32_t FLAG_ANOMALY_XMAS     = 2;  /* FIN+PSH+URG */
inline constexpr uint32_t FLAG_ANOMALY_SYN_FIN  = 3;  /* SYN+FIN */

/* Stateless TCP flag anomaly check. Caller feeds only TCP packets. */
std::optional<ProbeAlert> check_flag_anomaly(const ParsedPacket& pp);

/* ---- port scan: unique dst ports per source within a sliding window ---- */

class PortScanDetector {
public:
    struct Config {
        uint32_t window_ms        = 10000;
        size_t   unique_threshold = 20;
    };

    PortScanDetector();
    explicit PortScanDetector(const Config& cfg);

    void set_config(const Config& cfg) { cfg_ = cfg; }

    /* Feed TCP packets with SYN set (and RST cleared). Returns an alert
       (aux = unique port count) once per window crossing. */
    std::optional<ProbeAlert> feed(const ParsedPacket& pp, uint64_t now_ms);

private:
    struct SrcState {
        std::deque<std::pair<uint64_t, uint16_t>> events;  /* (ts, port) */
        std::map<uint16_t, uint32_t> port_counts;
        bool alerted = false;
    };
    Config cfg_;
    std::map<std::array<uint8_t, 16>, SrcState> sources_;
};

/* ---- rate flood: packets per source per tumbling window ---- */

class RateFloodDetector {
public:
    struct Config {
        uint32_t window_ms     = 1000;
        uint32_t pps_threshold = 1000;
    };

    RateFloodDetector();
    explicit RateFloodDetector(const Config& cfg);

    void set_config(const Config& cfg) { cfg_ = cfg; }

    /* Feed every IP packet. On threshold crossing returns an alert with
       aux = observed rate and count pre-aggregated; the source is then
       muted for one window. */
    std::optional<ProbeAlert> feed(const ParsedPacket& pp, uint64_t now_ms);

private:
    struct SrcState {
        bool     active       = false;
        uint64_t window_start = 0;
        uint32_t count        = 0;
        bool     alerted      = false;
    };
    Config cfg_;
    std::map<std::array<uint8_t, 16>, SrcState> sources_;
};

/* ---- ARP spoofing: IP↔MAC binding tracking ---- */

/* aux codes for DT_ARP */
inline constexpr uint32_t ARP_ALERT_BINDING_CHANGE = 1;  /* known IP answered by new MAC */
inline constexpr uint32_t ARP_ALERT_GRATUITOUS_STORM = 2;  /* gratuitous ARP flood */

class ArpSpoofDetector {
public:
    struct Config {
        uint32_t window_ms          = 10000;
        uint32_t gratuitous_threshold = 50;
    };

    ArpSpoofDetector();
    explicit ArpSpoofDetector(const Config& cfg);

    /* Feed ARP packets (pp.is_arp). Alerts on binding conflicts and
       gratuitous-ARP storms. */
    std::optional<ProbeAlert> feed(const ParsedPacket& pp, uint64_t now_ms);

private:
    std::map<std::array<uint8_t, 4>, MacAddress> bindings_;
    struct StormState {
        bool     active       = false;
        uint64_t window_start = 0;
        uint32_t count        = 0;
        bool     alerted      = false;
    };
    Config cfg_;
    std::map<std::array<uint8_t, 6>, StormState> gratuitous_;
};

} /* namespace ethprobe */
