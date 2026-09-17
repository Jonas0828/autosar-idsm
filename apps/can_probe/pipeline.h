#pragma once
/*
 * pipeline.h -- the can_probe detection pipeline.
 *
 * Wires: frame parse -> error-burst / DLC / remote-frame checks ->
 * unknown-ID + cycle-time (whitelist-driven) -> per-ID and bus-wide
 * floods -> diagnostics path (diag flood / UDS SecurityAccess / service
 * scan). Alerts are emitted through a single callback; the caller
 * (main.cpp) turns them into IdsM_ReportSecurityEvent() calls.
 *
 * Not thread-safe: driven entirely from the capture thread.
 */
#include "alert.h"
#include "detectors.h"
#include "frame.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace canprobe {

class CanProbePipeline {
public:
    struct Config {
        IdFloodDetector::Config      id_flood;
        BusFloodDetector::Config     bus_flood;
        ErrorBurstDetector::Config   err_burst;
        DiagFloodDetector::Config    diag_flood;
        UdsSecAccessDetector::Config sec_access;
        UdsSvcScanDetector::Config   svc_scan;
        CycleAnomalyDetector::Config cycle;
    };

    using AlertCallback = std::function<void(const CanAlert&)>;

    explicit CanProbePipeline(AlertCallback cb);
    ~CanProbePipeline();

    CanProbePipeline(const CanProbePipeline&) = delete;
    CanProbePipeline& operator=(const CanProbePipeline&) = delete;

    /* component access for startup configuration */
    UnknownIdDetector&     unknown_id();
    CycleAnomalyDetector&  cycle();
    IdFloodDetector&       id_flood();
    BusFloodDetector&      bus_flood();
    ErrorBurstDetector&    err_burst();
    DiagFloodDetector&     diag_flood();
    UdsSecAccessDetector&  sec_access();
    UdsSvcScanDetector&    svc_scan();
    Config&                config();

    /*
     * Whitelist file, one entry per line:
     *     hex_id [min_interval_ms]
     * Lines starting with '#' and blank lines are ignored. Loading
     * enables unknown-ID detection; entries with a min interval also
     * enable cycle-time anomaly detection for that ID. Returns false if
     * the file cannot be opened; *bad (if given) receives the skipped
     * line count.
     */
    bool load_ids(const std::string& path, std::string& err, size_t* bad = nullptr);

    /* Feed one raw SocketCAN record (16 or 72 bytes). */
    void feed_raw(const uint8_t* data, size_t len, uint64_t now_ms);

    /* Feed one already-parsed frame. */
    void feed_frame(const CanFrame& f, uint64_t now_ms);

private:
    struct Impl;
    std::unique_ptr<Impl> m_;
};

} /* namespace canprobe */