#pragma once
/*
 * ip_defrag.h — lightweight IPv4/IPv6 fragment reassembly.
 *
 * Buffers fragments keyed by (src, dst, identification, protocol, v6) until
 * the datagram is complete, then returns the reassembled IP payload (L4
 * header + data). Semantics:
 *   - overlapping bytes: first-seen wins
 *   - entries expire after `timeout_ms` without progress
 *   - hard resource caps: at most `max_datagrams` concurrent datagrams and
 *     `max_mem_bytes` total buffered bytes; on pressure the least-recently
 *     touched entry is evicted (counted for a resource alert)
 *
 * Thread safety: NOT thread-safe; the probe runs it on the capture thread.
 */
#include "packet.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace ethprobe {

class IpDefrag {
public:
    struct Config {
        size_t   max_datagrams = 256;
        size_t   max_mem_bytes = 2 * 1024 * 1024;
        uint32_t timeout_ms    = 10000;
    };

    struct Result {
        bool complete = false;         /* datagram finished */
        bool evicted  = false;         /* an entry was evicted for capacity */
        std::vector<uint8_t> datagram; /* reassembled IP payload (L4 onward) */
    };

    IpDefrag();  /* default Config */
    explicit IpDefrag(const Config& cfg);
    ~IpDefrag();

    IpDefrag(const IpDefrag&) = delete;
    IpDefrag& operator=(const IpDefrag&) = delete;

    /*
     * Feed one fragment. `pp` must describe a fragment (pp.is_fragment).
     * `frag_payload`/`frag_len` is this fragment's IP-payload slice starting
     * at pp.frag_offset (i.e. L4 header included when offset==0).
     */
    Result add_fragment(const ParsedPacket& pp,
                        const uint8_t* frag_payload, size_t frag_len,
                        uint64_t now_ms);

    /* Drop expired entries; returns number dropped. Call periodically. */
    size_t expire(uint64_t now_ms);

    size_t active_datagrams() const;
    size_t buffered_bytes() const;

private:
    struct Impl;
    std::unique_ptr<Impl> m_;  /* pImpl: keeps STL containers out of the header */
};

} /* namespace ethprobe */
