#pragma once
/*
 * capture.h -- frame sources for can_probe.
 *
 * Two sources, one callback shape:
 *   LiveCanCapture -- CAN_RAW socket on a SocketCAN interface (can0...,
 *                     requires root); CAN-FD frames enabled via
 *                     CAN_RAW_FD_FRAMES so both record layouts arrive
 *   replay_pcap    -- offline classic-pcap reader restricted to
 *                     LINKTYPE_CAN_SOCKETCAN (no libpcap dependency)
 *
 * now_ms delivered to the callback is milliseconds from a monotonic
 * clock (live) or synthesized from pcap record timestamps relative to
 * the first frame (replay).
 */
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

namespace canprobe {

using FrameCallback = std::function<void(const uint8_t* data, size_t len,
                                         uint64_t now_ms)>;

class LiveCanCapture {
public:
    LiveCanCapture() = default;
    ~LiveCanCapture();

    LiveCanCapture(const LiveCanCapture&) = delete;
    LiveCanCapture& operator=(const LiveCanCapture&) = delete;

    /* Open a CAN_RAW socket bound to `ifname` (e.g. "can0"). */
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
 * Read a classic pcap file (micro- or nano-second magic, link type
 * LINKTYPE_CAN_SOCKETCAN) and deliver every record through cb. No
 * timing replay -- frames are delivered as fast as they are read.
 */
bool replay_pcap(const std::string& path, const FrameCallback& cb,
                 std::string& err);

} /* namespace canprobe */