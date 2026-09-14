#pragma once
/*
 * stream_tcp.h — lightweight TCP stream reassembly.
 *
 * Tracks flows by normalized 4-tuple and delivers newly in-order payload
 * bytes per direction. Semantics:
 *   - retransmits/overlaps: first-seen wins (leading overlap trimmed)
 *   - out-of-order segments buffered per direction (capped); a gap is
 *     skipped once it has persisted past `gap_timeout_ms` when the next
 *     segment arrives
 *   - FIN closes a direction after flush; RST closes the flow immediately
 *   - hard resource caps: `max_flows` concurrent flows (LRU eviction) and
 *     `max_mem_bytes` total out-of-order buffering; evictions are reported
 *     so the probe can raise a resource alert (detector_type 7)
 *
 * Thread safety: NOT thread-safe; runs on the capture thread.
 */
#include "packet.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace ethprobe {

/* Normalized flow identity: endpoint A < endpoint B (by ip, then port) */
struct FlowKey {
    std::array<uint8_t, 16> a_ip{};
    std::array<uint8_t, 16> b_ip{};
    uint16_t a_port = 0;
    uint16_t b_port = 0;

    bool operator<(const FlowKey& o) const {
        return std::tie(a_ip, a_port, b_ip, b_port) <
               std::tie(o.a_ip, o.a_port, o.b_ip, o.b_port);
    }
    bool operator==(const FlowKey& o) const {
        return a_ip == o.a_ip && a_port == o.a_port &&
               b_ip == o.b_ip && b_port == o.b_port;
    }
};

class TcpReassembly {
public:
    struct Config {
        size_t   max_flows        = 1024;
        size_t   max_stream_bytes = 64 * 1024;      /* out-of-order bytes per direction */
        size_t   max_mem_bytes    = 4 * 1024 * 1024; /* global out-of-order pool */
        uint32_t gap_timeout_ms   = 5000;
        uint32_t idle_timeout_ms  = 120000;
    };

    struct DeliverResult {
        bool has_data = false;
        std::vector<uint8_t> data;  /* newly in-order bytes (may contain a gap skip) */
        uint8_t dir     = 0;        /* 0 = A→B (FlowKey order), 1 = B→A */
        FlowKey flow{};
        bool closed   = false;      /* flow terminated (FIN both ways or RST) */
        bool evicted  = false;      /* capacity eviction happened on this call */
    };

    TcpReassembly();  /* default Config */
    explicit TcpReassembly(const Config& cfg);
    ~TcpReassembly();

    TcpReassembly(const TcpReassembly&) = delete;
    TcpReassembly& operator=(const TcpReassembly&) = delete;

    /* Feed one TCP packet (pp.is_tcp must be true). */
    DeliverResult add_segment(const ParsedPacket& pp, uint64_t now_ms);

    /* Drop flows idle past idle_timeout_ms; returns number dropped. */
    size_t expire(uint64_t now_ms);

    size_t active_flows() const;
    size_t buffered_bytes() const;

private:
    struct Impl;
    std::unique_ptr<Impl> m_;
};

} /* namespace ethprobe */
