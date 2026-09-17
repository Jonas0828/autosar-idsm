#pragma once
/*
 * detectors.h -- CAN anomaly detectors (GB 44495-2024 / R155 IDS
 * coverage): unknown-ID injection, flooding (per-ID / bus-wide /
 * diagnostic), error bursts, DLC anomalies, unexpected remote frames,
 * UDS SecurityAccess brute force, diagnostic service scanning, and
 * periodic-message cycle-time violations.
 *
 * All detectors are single-threaded: the capture thread feeds frames in
 * timestamp order and calls tick() periodically. Each feed() returns an
 * alert only when its condition triggers (alert-once semantics inside a
 * window, per-key muting afterwards), so downstream aggregation windows
 * stay meaningful.
 */
#include "alert.h"
#include "frame.h"

#include <cstdint>
#include <map>
#include <optional>
#include <set>

namespace canprobe {

/* aux codes for DT_DLC_ANOMALY */
inline constexpr uint32_t DLC_ANOMALY_CLASSIC_GT8 = 1;  /* classic DLC > 8 */
inline constexpr uint32_t DLC_ANOMALY_FD_LEN      = 2;  /* CAN-FD len > 64 */

/* aux codes for DT_UDS_SEC_ACCESS */
inline constexpr uint32_t SEC_ACCESS_SEED_FLOOD = 1;  /* requestSeed repetitions */
inline constexpr uint32_t SEC_ACCESS_KEY_GUESS  = 2;  /* sendKey attempts */

/* ---- stateless checks ---- */

/* Classic DLC > 8 or CAN-FD len > 64. Caller feeds data frames only. */
std::optional<CanAlert> check_dlc_anomaly(const CanFrame& f);

/* Any RTR frame on a modern vehicle bus is anomalous (RTR is deprecated
   in CANopen/CAN-FD era automotive networks). */
std::optional<CanAlert> check_remote_frame(const CanFrame& f);

/* ---- unknown-ID whitelist ---- */

/* Enabled once the first known ID is added; frames whose ID is not in
   the set alert once per frame (aux = 0). The pipeline excludes the
   standardized diagnostics range (0x7DF/0x7E0-0x7EF) before calling. */
class UnknownIdDetector {
public:
    UnknownIdDetector() = default;

    bool enabled() const { return !known_.empty(); }
    void add_known(uint32_t can_id) { known_.insert(can_id); }
    void clear() { known_.clear(); }
    size_t known_count() const { return known_.size(); }

    std::optional<CanAlert> feed(const CanFrame& f, uint64_t now_ms);

private:
    std::set<uint32_t> known_;
};

/* ---- cycle-time anomaly: same ID reappearing faster than its minimum
       inter-arrival time (masquerade / duplicated periodic message) ---- */

class CycleAnomalyDetector {
public:
    struct Config {
        uint32_t cooldown_ms = 60000;  /* per-ID alert muting */
    };

    void set_config(const Config& cfg) { cfg_ = cfg; }

    /* Track min_interval_ms for an ID (from the whitelist file). IDs
       without an entry are not checked. */
    void add_min_interval(uint32_t can_id, uint32_t min_interval_ms);

    std::optional<CanAlert> feed(const CanFrame& f, uint64_t now_ms);

private:
    struct IdState {
        uint32_t min_ms     = 0;
        bool     seen        = false;
        uint64_t last_ms     = 0;
        uint64_t muted_until = 0;
    };
    Config cfg_;
    std::map<uint32_t, IdState> ids_;
};

/* ---- per-ID flood: frames of one ID per tumbling window ---- */

class IdFloodDetector {
public:
    struct Config {
        uint32_t window_ms     = 1000;
        uint32_t fps_threshold = 100;
    };

    IdFloodDetector();
    explicit IdFloodDetector(const Config& cfg);

    void set_config(const Config& cfg) { cfg_ = cfg; }

    /* Feed data frames (error frames excluded by the pipeline). Alerts
       once per window crossing with aux = observed fps. */
    std::optional<CanAlert> feed(const CanFrame& f, uint64_t now_ms);

private:
    struct IdState {
        uint64_t window_start = 0;
        uint32_t count        = 0;
        bool     alerted      = false;
    };
    Config cfg_;
    std::map<uint32_t, IdState> ids_;
};

/* ---- bus-wide flood: all frames in one tumbling window ---- */

class BusFloodDetector {
public:
    struct Config {
        uint32_t window_ms     = 1000;
        uint32_t fps_threshold = 1000;
    };

    BusFloodDetector();
    explicit BusFloodDetector(const Config& cfg);

    void set_config(const Config& cfg) { cfg_ = cfg; }

    std::optional<CanAlert> feed(const CanFrame& f, uint64_t now_ms);

private:
    struct State {
        uint64_t window_start = 0;
        uint32_t count        = 0;
        bool     alerted      = false;
    };
    Config cfg_;
    State state_;
};

/* ---- error frame burst (bus-off attack / heavy fault injection) ---- */

class ErrorBurstDetector {
public:
    struct Config {
        uint32_t window_ms = 1000;
        uint32_t err_threshold = 20;
    };

    ErrorBurstDetector();
    explicit ErrorBurstDetector(const Config& cfg);

    void set_config(const Config& cfg) { cfg_ = cfg; }

    /* Feed error frames only (pipeline filters). Alerts once per window
       with aux = error count in that window. */
    std::optional<CanAlert> feed(const CanFrame& f, uint64_t now_ms);

private:
    struct State {
        uint64_t window_start = 0;
        uint32_t count        = 0;
        bool     alerted      = false;
    };
    Config cfg_;
    State state_;
};

/* ---- diagnostic request flood (per tester ID) ---- */

class DiagFloodDetector {
public:
    struct Config {
        uint32_t window_ms     = 1000;
        uint32_t fps_threshold = 50;
    };

    DiagFloodDetector();
    explicit DiagFloodDetector(const Config& cfg);

    void set_config(const Config& cfg) { cfg_ = cfg; }

    /* Feed diagnostic request frames only. aux = observed fps. */
    std::optional<CanAlert> feed(const CanFrame& f, uint64_t now_ms);

private:
    struct TesterState {
        uint64_t window_start = 0;
        uint32_t count        = 0;
        bool     alerted      = false;
    };
    Config cfg_;
    std::map<uint32_t, TesterState> testers_;
};

/* ---- UDS SecurityAccess brute force (SID 0x27) ----
 *
 * Per tester ID within a window: repeated requestSeed (odd sub-function)
 * or sendKey (even sub-function) attempts indicate seed/key harvesting
 * or key guessing. */
class UdsSecAccessDetector {
public:
    struct Config {
        uint32_t window_ms      = 60000;
        uint32_t seed_threshold = 5;
        uint32_t key_threshold  = 5;
    };

    UdsSecAccessDetector();
    explicit UdsSecAccessDetector(const Config& cfg);

    void set_config(const Config& cfg) { cfg_ = cfg; }

    /* Feed diagnostic request frames carrying UDS (data[0] = SID). */
    std::optional<CanAlert> feed(const CanFrame& f, uint64_t now_ms);

private:
    struct TesterState {
        uint64_t window_start = 0;
        uint32_t seeds        = 0;
        uint32_t keys         = 0;
        bool     seed_alerted = false;
        bool     key_alerted  = false;
    };
    Config cfg_;
    std::map<uint32_t, TesterState> testers_;
};

/* ---- diagnostic service scan: many distinct SIDs from one tester ---- */

class UdsSvcScanDetector {
public:
    struct Config {
        uint32_t window_ms    = 10000;
        uint32_t svc_threshold = 8;
    };

    UdsSvcScanDetector();
    explicit UdsSvcScanDetector(const Config& cfg);

    void set_config(const Config& cfg) { cfg_ = cfg; }

    /* Feed diagnostic request frames. Alerts once per window with
       aux = distinct SID count. */
    std::optional<CanAlert> feed(const CanFrame& f, uint64_t now_ms);

private:
    struct TesterState {
        uint64_t          window_start = 0;
        std::set<uint8_t> sids;
        bool              alerted = false;
    };
    Config cfg_;
    std::map<uint32_t, TesterState> testers_;
};

} /* namespace canprobe */