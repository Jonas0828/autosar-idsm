#include "detectors.h"

namespace canprobe {

namespace {

/* UDS SecurityAccess (ISO 14229): odd sub-function = requestSeed,
   even = sendKey; bit 7 = suppressPosRspMsgIndication */
constexpr uint8_t UDS_SID_SECURITY_ACCESS = 0x27;

} /* namespace */

/* ---- stateless checks ---- */

std::optional<CanAlert> check_dlc_anomaly(const CanFrame& f) {
    if (f.err || f.rtr) return std::nullopt;
    if (!f.fd && f.dlc > 8)
        return make_alert(DT_DLC_ANOMALY, f, DLC_ANOMALY_CLASSIC_GT8);
    if (f.fd && f.dlc > 64)
        return make_alert(DT_DLC_ANOMALY, f, DLC_ANOMALY_FD_LEN);
    return std::nullopt;
}

std::optional<CanAlert> check_remote_frame(const CanFrame& f) {
    if (!f.rtr || f.err) return std::nullopt;
    return make_alert(DT_REMOTE_FRAME, f, 0);
}

/* ---- UnknownIdDetector ---- */

std::optional<CanAlert> UnknownIdDetector::feed(const CanFrame& f, uint64_t) {
    if (known_.find(f.can_id) == known_.end())
        return make_alert(DT_UNKNOWN_ID, f, 0);
    return std::nullopt;
}

/* ---- CycleAnomalyDetector ---- */

void CycleAnomalyDetector::add_min_interval(uint32_t can_id, uint32_t min_interval_ms) {
    ids_[can_id].min_ms = min_interval_ms;
}

std::optional<CanAlert> CycleAnomalyDetector::feed(const CanFrame& f, uint64_t now_ms) {
    auto it = ids_.find(f.can_id);
    if (it == ids_.end()) return std::nullopt;

    IdState& st = it->second;
    std::optional<CanAlert> alert;
    if (st.seen && now_ms >= st.last_ms) {
        const uint64_t interval = now_ms - st.last_ms;
        if (interval < st.min_ms && now_ms >= st.muted_until) {
            alert = make_alert(DT_CYCLE_ANOMALY, f, static_cast<uint32_t>(interval));
            alert->count = 1;
            st.muted_until = now_ms + cfg_.cooldown_ms;
        }
    }
    st.seen     = true;
    st.last_ms  = now_ms;
    return alert;
}

/* ---- IdFloodDetector ---- */

IdFloodDetector::IdFloodDetector() = default;
IdFloodDetector::IdFloodDetector(const Config& cfg) : cfg_(cfg) {}

std::optional<CanAlert> IdFloodDetector::feed(const CanFrame& f, uint64_t now_ms) {
    if (f.err) return std::nullopt;
    IdState& st = ids_[f.can_id];
    if (st.window_start == 0) st.window_start = now_ms;
    if (now_ms - st.window_start >= cfg_.window_ms) {
        st.window_start = now_ms;
        st.count        = 0;
        st.alerted      = false;
    }
    ++st.count;
    if (st.count >= cfg_.fps_threshold && !st.alerted) {
        st.alerted = true;
        CanAlert a = make_alert(DT_ID_FLOOD, f, st.count * 1000 / cfg_.window_ms);
        a.count = st.count;
        return a;
    }
    return std::nullopt;
}

/* ---- BusFloodDetector ---- */

BusFloodDetector::BusFloodDetector() = default;
BusFloodDetector::BusFloodDetector(const Config& cfg) : cfg_(cfg) {}

std::optional<CanAlert> BusFloodDetector::feed(const CanFrame& f, uint64_t now_ms) {
    (void)f;
    if (state_.window_start == 0) state_.window_start = now_ms;
    if (now_ms - state_.window_start >= cfg_.window_ms) {
        state_.window_start = now_ms;
        state_.count        = 0;
        state_.alerted      = false;
    }
    ++state_.count;
    if (state_.count >= cfg_.fps_threshold && !state_.alerted) {
        state_.alerted = true;
        CanFrame bf;  /* synthetic: bus-wide, no single offending ID */
        CanAlert a = make_alert(DT_BUS_FLOOD, bf, state_.count * 1000 / cfg_.window_ms);
        a.count = state_.count;
        return a;
    }
    return std::nullopt;
}

/* ---- ErrorBurstDetector ---- */

ErrorBurstDetector::ErrorBurstDetector() = default;
ErrorBurstDetector::ErrorBurstDetector(const Config& cfg) : cfg_(cfg) {}

std::optional<CanAlert> ErrorBurstDetector::feed(const CanFrame& f, uint64_t now_ms) {
    (void)f;
    if (state_.window_start == 0) state_.window_start = now_ms;
    if (now_ms - state_.window_start >= cfg_.window_ms) {
        state_.window_start = now_ms;
        state_.count        = 0;
        state_.alerted      = false;
    }
    ++state_.count;
    if (state_.count >= cfg_.err_threshold && !state_.alerted) {
        state_.alerted = true;
        CanFrame bf;  /* error class, not one sender */
        CanAlert a = make_alert(DT_ERROR_BURST, bf, state_.count);
        a.count = state_.count;
        return a;
    }
    return std::nullopt;
}

/* ---- DiagFloodDetector ---- */

DiagFloodDetector::DiagFloodDetector() = default;
DiagFloodDetector::DiagFloodDetector(const Config& cfg) : cfg_(cfg) {}

std::optional<CanAlert> DiagFloodDetector::feed(const CanFrame& f, uint64_t now_ms) {
    TesterState& st = testers_[f.can_id];
    if (st.window_start == 0) st.window_start = now_ms;
    if (now_ms - st.window_start >= cfg_.window_ms) {
        st.window_start = now_ms;
        st.count        = 0;
        st.alerted      = false;
    }
    ++st.count;
    if (st.count >= cfg_.fps_threshold && !st.alerted) {
        st.alerted = true;
        CanAlert a = make_alert(DT_DIAG_FLOOD, f, st.count * 1000 / cfg_.window_ms);
        a.count = st.count;
        return a;
    }
    return std::nullopt;
}

/* ---- UdsSecAccessDetector ---- */

UdsSecAccessDetector::UdsSecAccessDetector() = default;
UdsSecAccessDetector::UdsSecAccessDetector(const Config& cfg) : cfg_(cfg) {}

std::optional<CanAlert> UdsSecAccessDetector::feed(const CanFrame& f, uint64_t now_ms) {
    if (f.len < 2 || f.data[0] != UDS_SID_SECURITY_ACCESS)
        return std::nullopt;

    const uint8_t subfn = f.data[1] & 0x7F;
    TesterState& st     = testers_[f.can_id];
    if (st.window_start == 0) st.window_start = now_ms;
    if (now_ms - st.window_start >= cfg_.window_ms) {
        st.window_start = now_ms;
        st.seeds        = 0;
        st.keys         = 0;
        st.seed_alerted = false;
        st.key_alerted  = false;
    }

    /* odd = requestSeed, even = sendKey */
    if (subfn % 2 == 1) {
        ++st.seeds;
        if (st.seeds >= cfg_.seed_threshold && !st.seed_alerted) {
            st.seed_alerted = true;
            CanAlert a = make_alert(DT_UDS_SEC_ACCESS, f, SEC_ACCESS_SEED_FLOOD);
            a.count = st.seeds;
            return a;
        }
    } else {
        ++st.keys;
        if (st.keys >= cfg_.key_threshold && !st.key_alerted) {
            st.key_alerted = true;
            CanAlert a = make_alert(DT_UDS_SEC_ACCESS, f, SEC_ACCESS_KEY_GUESS);
            a.count = st.keys;
            return a;
        }
    }
    return std::nullopt;
}

/* ---- UdsSvcScanDetector ---- */

UdsSvcScanDetector::UdsSvcScanDetector() = default;
UdsSvcScanDetector::UdsSvcScanDetector(const Config& cfg) : cfg_(cfg) {}

std::optional<CanAlert> UdsSvcScanDetector::feed(const CanFrame& f, uint64_t now_ms) {
    if (f.len < 1) return std::nullopt;

    TesterState& st = testers_[f.can_id];
    if (st.window_start == 0) st.window_start = now_ms;
    if (now_ms - st.window_start >= cfg_.window_ms) {
        st.window_start = now_ms;
        st.sids.clear();
        st.alerted = false;
    }
    st.sids.insert(f.data[0]);
    if (st.sids.size() >= cfg_.svc_threshold && !st.alerted) {
        st.alerted = true;
        CanAlert a = make_alert(DT_UDS_SVC_SCAN, f,
                                static_cast<uint32_t>(st.sids.size()));
        a.count = static_cast<uint32_t>(st.sids.size());
        return a;
    }
    return std::nullopt;
}

} /* namespace canprobe */