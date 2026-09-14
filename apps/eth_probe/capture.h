#pragma once
/*
 * capture.h — frame sources for eth_probe.
 *
 * Two sources, one callback shape:
 *   LiveCapture — AF_PACKET socket on a Linux interface (requires root)
 *   replay_pcap — offline classic-pcap file reader (no libpcap dependency)
 *
 * now_ms delivered to the callback is milliseconds from a monotonic clock
 * (live) or synthesized from pcap record timestamps relative to the first
 * frame (replay).
 */
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

namespace ethprobe {

using FrameCallback = std::function<void(const uint8_t* data, size_t len,
                                         uint64_t now_ms)>;

class LiveCapture {
public:
    LiveCapture() = default;
    ~LiveCapture();

    LiveCapture(const LiveCapture&) = delete;
    LiveCapture& operator=(const LiveCapture&) = delete;

    /* Open an AF_PACKET socket bound to `ifname` (all protocols). */
    bool open(const std::string& ifname, std::string& err);

    /* Blocking receive loop; returns when stop() is called or on error.
       Polls with a 500ms timeout so stop() stays responsive. */
    bool run(const FrameCallback& cb, std::string& err);

    void stop();  /* thread- and signal-handler-safe */

private:
    int fd_ = -1;
    std::atomic<bool> stop_{false};
};

/*
 * Read a classic pcap file (micro- or nano-second magic, Ethernet link
 * type) and deliver every record through cb. No timing replay — frames are
 * delivered as fast as they are read.
 */
bool replay_pcap(const std::string& path, const FrameCallback& cb,
                 std::string& err);

} /* namespace ethprobe */
