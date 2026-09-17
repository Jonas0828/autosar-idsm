#pragma once
/*
 * capture.h -- event sources for host_probe.
 *
 * Three sources, one callback shape:
 *   NetlinkProcCapture -- PF_NETLINK + PROC_CONNECTOR (CN_PROC) exec
 *                         events in real time (needs root; requires
 *                         the kernel UAPI headers linux/connector.h +
 *                         linux/cn_proc.h, otherwise open() fails and
 *                         the caller falls back to the poller)
 *   ProcScanCapture    -- /proc polling: the pid diff synthesizes exec
 *                         events, plus aggregate snapshots (zombie
 *                         count, top CPU / RSS process), kernel-module
 *                         diff and monitored-file scans. Works on any
 *                         /proc system, including Android, without
 *                         special kernel config.
 *   replay_events      -- offline replay of the text event log used by
 *                         --events (no timing replay)
 *
 * now_ms delivered to the callback is milliseconds from a monotonic
 * clock (live) or the event timestamp (replay).
 */
#include "event.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace hostprobe {

using EventCallback = std::function<void(const HostEvent&)>;

class NetlinkProcCapture {
public:
    NetlinkProcCapture() = default;
    ~NetlinkProcCapture();

    NetlinkProcCapture(const NetlinkProcCapture&) = delete;
    NetlinkProcCapture& operator=(const NetlinkProcCapture&) = delete;

    /* Subscribe to PROC_EVENT_EXEC. */
    bool open(std::string& err);

    /* Blocking receive loop; returns when stop() is called or on error.
       Polls with a 500ms timeout so stop() stays responsive. */
    bool run(const EventCallback& cb, std::string& err);

    void stop();  /* thread- and signal-handler-safe */

private:
    int fd_ = -1;
    std::atomic<bool> stop_{false};
};

class ProcScanCapture {
public:
    ProcScanCapture();
    ~ProcScanCapture();

    ProcScanCapture(const ProcScanCapture&) = delete;
    ProcScanCapture& operator=(const ProcScanCapture&) = delete;

    bool open(uint32_t scan_ms, std::string& err);

    /* When a NetlinkProcCapture feeds exec events, the poller must not
       re-report them from its pid diff. Default: on. */
    void set_emit_execs(bool on) { emit_execs_ = on; }

    /* Monitor a file for the integrity detectors (one FILE_SCAN event
       per scan pass). */
    void add_scan_file(const std::string& path);

    /* Blocking scan loop; returns when stop() is called or on error. */
    bool run(const EventCallback& cb, std::string& err);

    void stop();

private:
    struct Impl;
    std::unique_ptr<Impl> m_;
    uint32_t scan_ms_  = 1000;
    bool     emit_execs_ = true;
};

/*
 * Read a text event log (one parse_host_event() line per record) and
 * deliver every event through cb as fast as they are read. Malformed
 * lines are counted into err as a warning; only an unreadable file
 * fails the replay.
 */
bool replay_events(const std::string& path, const EventCallback& cb,
                   std::string& err);

} /* namespace hostprobe */
