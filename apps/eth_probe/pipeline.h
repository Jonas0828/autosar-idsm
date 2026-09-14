#pragma once
/*
 * pipeline.h — the eth_probe detection pipeline.
 *
 * Wires together: packet parse → ARP/packet-level detectors → IP defrag →
 * cross-border check → TCP reassembly → app parsers (DoIP/SOME-IP/TLS/
 * HTTP/DNS) → rule engine (packet + stream paths). Alerts are emitted
 * through a single callback; the caller (main.cpp) turns them into
 * IdsM_ReportSecurityEvent() calls.
 *
 * Not thread-safe: driven entirely from the capture thread.
 */
#include "alert.h"
#include "detectors.h"
#include "geoip.h"
#include "ip_defrag.h"
#include "proto_someip.h"
#include "rules.h"
#include "stream_tcp.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

namespace ethprobe {

class ProbePipeline {
public:
    struct Config {
        uint16_t someip_port            = SOMEIP_DEFAULT_PORT;
        bool     cross_border_enabled   = true;
        uint32_t cross_border_cooldown_ms = 60000;  /* per 5-tuple alert muting */
        uint16_t http_port              = 80;
        uint16_t http_alt_port          = 8080;
        uint16_t tls_port               = 443;
        size_t   stream_acc_cap         = 64 * 1024; /* per-direction app buffer cap */
    };

    using AlertCallback = std::function<void(const ProbeAlert&)>;

    explicit ProbePipeline(AlertCallback cb);
    ~ProbePipeline();

    ProbePipeline(const ProbePipeline&) = delete;
    ProbePipeline& operator=(const ProbePipeline&) = delete;

    /* component access for startup configuration */
    RuleEngine&       rules();
    GeoIp&            geoip();
    SomeipSdTracker&  sd_tracker();
    PortScanDetector& port_scan();
    RateFloodDetector& rate_flood();
    ArpSpoofDetector& arp_spoof();
    IpDefrag&         defrag();
    TcpReassembly&    tcp();
    Config&           config();

    /* Feed one raw Ethernet frame. */
    void feed_frame(const uint8_t* data, size_t len, uint64_t now_ms);

    /* Periodic housekeeping (defrag/stream expiry). Call ~1/s. */
    void tick(uint64_t now_ms);

private:
    struct Impl;
    std::unique_ptr<Impl> m_;
};

} /* namespace ethprobe */
