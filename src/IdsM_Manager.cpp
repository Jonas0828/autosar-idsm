#include "IdsM_Internal.h"
#include <algorithm>
#include <chrono>
#include <cstdint>

/* ============================================================
   C++ Class Implementation
   ============================================================ */

IdsM_Manager& IdsM_Manager::Instance() {
    static IdsM_Manager instance;
    return instance;
}

/* Steady monotonic milliseconds — basis for all filter-chain time windows. */
uint32_t IdsM_Manager::nowMs() const {
    return static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

/* Background worker loop — the MainFunction equivalent [SWS_IdsM_00901].
   SEvs are qualified asynchronously here, never on the caller's thread.
   Time-window filters (Aggregation/Threshold) additionally need periodic
   wakeups: the loop waits until the earliest pending window deadline (bounded
   by the shutdown poll interval) instead of indefinitely. */
void IdsM_Manager::worker_loop() {
    static constexpr uint32_t kShutdownPollMs = 100;

    while (m_worker_running.load()) {
        std::vector<IdsM_OwnedSEv> local_batch;
        uint32_t next_deadline_ms = 0;

        // 1. Wait for events, a window deadline, or shutdown
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            if (m_incoming_queue.empty()) {
                next_deadline_ms = expireWindows(nowMs());
                if (next_deadline_ms != 0) {
                    const uint32_t now = nowMs();
                    const uint32_t wait_ms = (next_deadline_ms > now)
                        ? std::min(next_deadline_ms - now, kShutdownPollMs)
                        : 0;
                    m_queue_cv.wait_for(lock, std::chrono::milliseconds(
                        std::max(wait_ms, 1u)));
                } else {
                    m_queue_cv.wait(lock, [this] {
                        return !m_incoming_queue.empty() || !m_worker_running.load();
                    });
                }
            }

            if (!m_worker_running.load() && m_incoming_queue.empty()) break;

            // Drain queue into local batch, decrement per-SEv pending counters
            while (!m_incoming_queue.empty()) {
                auto& sev_id = m_incoming_queue.front().security_event_id;
                if (sev_id < m_sevs.size() && m_sevs[sev_id].pending_count > 0) {
                    m_sevs[sev_id].pending_count--;
                }
                local_batch.push_back(std::move(m_incoming_queue.front()));
                m_incoming_queue.pop();
            }
        }

        // 2. Qualify each event: reporting mode -> (filter chain) -> QSEv -> sinks
        for (auto& event : local_batch) {
            std::lock_guard<std::mutex> lock(m_mutex);
            processEvent(event);
        }

        // 3. Flush/reset any due time windows (aggregation pending -> chain)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            expireWindows(nowMs());
        }
    }
}

/* Time-window bookkeeping [SWS_IdsM_01044/01063/01065]:
   - a due aggregation window releases its staged QSEv into the remaining
     chain (threshold) and then to the sinks;
   - a due threshold window resets its accumulator.
   Called with m_mutex held. Returns the earliest next deadline (absolute ms),
   0 when no window is pending. */
uint32_t IdsM_Manager::expireWindows(uint32_t now_ms) {
    uint32_t next_deadline = 0;

    for (auto& state : m_sevs) {
        /* Aggregation: window due -> pending aggregate leaves the filter as a
           single SEv carrying the accumulated count [SWS_IdsM_01044]. */
        if (state.agg_pending && state.config.aggregation_interval_ms != 0) {
            const uint32_t deadline = state.agg_window_start_ms
                                    + state.config.aggregation_interval_ms;
            if (now_ms >= deadline) {
                IdsM_OwnedQSEv released = std::move(*state.agg_pending);
                state.agg_pending.reset();
                state.agg_has_context = false;
                /* Continue through the downstream chain (threshold) */
                const uint16_t count = released.count;
                if (passThreshold(state, count, now_ms)) {
                    m_stats.events_qualified++;
                    dispatchQsev(state, released);
                }
                continue;
            }
            if (next_deadline == 0 || deadline < next_deadline) next_deadline = deadline;
        }

        /* Threshold: window due -> accumulator reset [SWS_IdsM_01063] */
        if (state.thr_window_open) {
            const uint32_t deadline = state.thr_window_start_ms
                                    + state.config.event_threshold.interval_ms;
            if (now_ms >= deadline) {
                state.thr_window_open = false;
                state.thr_accumulated = 0;
            } else if (next_deadline == 0 || deadline < next_deadline) {
                next_deadline = deadline;
            }
        }
    }
    return next_deadline;
}

/* Reporting mode evaluation [SWS_IdsM_01002/01013], then the filter chain in
   the fixed order BlockState -> ForwardEveryNth -> Aggregation -> Threshold
   [SWS_IdsM_01004] with short-circuit drop [SWS_IdsM_01005], then
   qualification and sink dispatch. */
void IdsM_Manager::processEvent(IdsM_OwnedSEv& sev) {
    if (sev.security_event_id >= m_sevs.size()) return;
    auto& state = m_sevs[sev.security_event_id];
    const uint32_t now = nowMs();

    const IdsM_Filters_ReportingModeType mode = state.reporting_mode;

    if (mode == IDSM_REPORTING_OFF) {
        m_stats.dropped_reporting_off++;
        return;
    }

    const bool brief = (mode == IDSM_REPORTING_BRIEF) ||
                       (mode == IDSM_REPORTING_BRIEF_BYPASSING_FILTERS);
    const bool bypassing = (mode == IDSM_REPORTING_BRIEF_BYPASSING_FILTERS) ||
                           (mode == IDSM_REPORTING_DETAILED_BYPASSING_FILTERS);

    // Event accepted -> mark detection status
    state.detection_status = IDSM_STATUS_VIOLATION;

    // Build the QSEv (kept as a value so the aggregation filter can stage it)
    IdsM_OwnedQSEv qsev;
    qsev.idsm_instance_id  = m_idsm_instance_id;
    qsev.external_event_id = state.config.external_event_id;
    qsev.sensor_instance_id = state.config.sensor_instance_id;
    qsev.severity          = state.config.severity;
    qsev.count             = sev.count;
    qsev.has_timestamp     = true;
    qsev.timestamp         = sev.has_timestamp ? sev.timestamp : makeInternalTimestamp();
    qsev.context_data_version = sev.context_data_version;
    if (!brief) {
        qsev.context_data = std::move(sev.context_data);
    }

    // Filter chain (skipped entirely in the BYPASSING reporting modes)
    if (!bypassing) {
        if (isBlockedByState(state)) {
            m_stats.dropped_block_state++;
            return;
        }
        if (!passForwardEveryNth(state, qsev.count)) {
            m_stats.dropped_sampling++;
            return;
        }
        /* Aggregation may absorb this SEv into its window — nothing further
           happens until the window expires (worker tick / expireWindows). */
        if (!passAggregation(state, qsev)) {
            return;
        }
        if (!passThreshold(state, qsev.count, now)) {
            m_stats.dropped_threshold++;
            return;
        }
    }

    m_stats.events_qualified++;
    dispatchQsev(state, qsev);
}

/* Block State Filter [SWS_IdsM_01020-01024]: drop if the current block state
   (set via IdsM_BswM_StateChanged) is in this SEv's blocked list. */
bool IdsM_Manager::isBlockedByState(const IdsM_SevState& sev) const {
    const auto* cfg = sev.config.block_state;
    if (!cfg) return false;
    for (uint8_t i = 0; i < cfg->num_blocked_states; ++i) {
        if (cfg->blocked_states[i] == m_block_state) return true;
    }
    return false;
}

/* Forward Every Nth [SWS_IdsM_01030-01034]: the counter is initialized to n
   (first SEv forwarded) and accumulates the SEv count values; on reaching or
   exceeding n the SEv passes unmodified and the counter resets. */
bool IdsM_Manager::passForwardEveryNth(IdsM_SevState& sev, uint16_t count) {
    const uint16_t n = sev.config.forward_every_nth;
    if (n == 0) return true;                       /* filter not configured */

    uint32_t accumulated = static_cast<uint32_t>(sev.nth_counter) + count;
    if (accumulated >= n) {
        sev.nth_counter = 0;
        return true;
    }
    sev.nth_counter = static_cast<uint16_t>(accumulated);
    return false;
}

/* Event Aggregation [SWS_IdsM_01041-01046]: the first SEv of a window is
   staged; subsequent SEvs only increment the staged count. Only the FIRST
   event's context data is kept (CP §7.6.3.1). When the window expires the
   staged QSEv continues through the remaining chain (expireWindows).
   Returns false when the SEv was absorbed into the window. */
bool IdsM_Manager::passAggregation(IdsM_SevState& sev, IdsM_OwnedQSEv& qsev) {
    const uint32_t interval = sev.config.aggregation_interval_ms;
    if (interval == 0) return true;                /* filter not configured */

    if (!sev.agg_pending) {
        /* First SEv of the window: stage a copy, open the window */
        sev.agg_pending = std::make_unique<IdsM_OwnedQSEv>(qsev);
        sev.agg_has_context = !qsev.context_data.empty();
        sev.agg_window_start_ms = nowMs();
        return false;
    }

    /* Window already open: accumulate count, keep the first context data.
       The staged copy may have count 0 (came from an early-window sensor
       count of 0 normalized elsewhere) — clamp at saturating max. */
    const uint32_t merged = static_cast<uint32_t>(sev.agg_pending->count) + qsev.count;
    sev.agg_pending->count = static_cast<uint16_t>(
        merged > 0xFFFFu ? 0xFFFFu : merged);
    /* Timestamp of the aggregate = first event's [SWS_IdsM_01043] */
    return false;
}

/* Event Threshold [SWS_IdsM_01061-01065]: within a window, SEvs are dropped
   (count still accumulates) until the accumulated count reaches the
   threshold; from then on SEvs pass immediately. The window opens with the
   first evaluated SEv and resets on expiry (expireWindows). */
bool IdsM_Manager::passThreshold(IdsM_SevState& sev, uint16_t count, uint32_t now_ms) {
    const uint16_t threshold = sev.config.event_threshold.threshold;
    if (threshold == 0) return true;               /* filter not configured */

    if (!sev.thr_window_open) {
        sev.thr_window_open      = true;
        sev.thr_window_start_ms  = now_ms;
        sev.thr_accumulated      = 0;
    }

    sev.thr_accumulated += count;
    return sev.thr_accumulated >= threshold;
}

void IdsM_Manager::dispatchQsev(const IdsM_SevState& sev, const IdsM_OwnedQSEv& qsev) {
    /* The C struct borrows qsev's vector storage — valid for the callback duration */
    IdsM_QualifiedSecurityEventType c_qsev = qsev.to_c();

    if (sev.config.sink_to_dem && m_dem_cb) {
        m_stats.sent_to_dem++;
        m_dem_cb(&c_qsev);
    }
    if (sev.config.sink_to_idsr && m_idsr_cb) {
        m_stats.sent_to_idsr++;
        m_idsr_cb(&c_qsev);
    }
}

IdsM_TimestampDataType IdsM_Manager::makeInternalTimestamp() const {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto secs = std::chrono::duration_cast<std::chrono::seconds>(now);
    const auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(now - secs);

    IdsM_TimestampDataType ts{};
    ts.seconds     = static_cast<uint32_t>(secs.count());
    ts.nanoseconds = static_cast<uint32_t>(nanos.count()) & 0x3FFFFFFFu; /* 30 bit */
    ts.source      = IDSM_TIMESTAMP_SOURCE_AUTOSAR;
    return ts;
}

STD_RETURN_TYPE IdsM_Manager::Init(const IdsM_ConfigType* config) {
    if (!config) return E_PARAM_POINTER;
    if (config->sev_count > 0 && !config->sev_configs) return E_PARAM_POINTER;

    std::lock_guard<std::mutex> lock(m_mutex);

    /* Validate configuration */
    if (config->idsm_instance_id > IDSM_INSTANCE_ID_MAX) return E_PARAM_CONFIG;
    if (config->main_function_period_ms == 0) return E_PARAM_CONFIG;
    for (uint16_t i = 0; i < config->sev_count; ++i) {
        const auto& sc = config->sev_configs[i];
        if (sc.external_event_id == IDSM_EXTERNAL_EVENT_ID_INVALID) return E_PARAM_CONFIG;
        if (sc.sensor_instance_id > 63u) return E_PARAM_CONFIG;
        if (sc.default_reporting_mode > IDSM_REPORTING_DETAILED_BYPASSING_FILTERS) {
            return E_PARAM_CONFIG;
        }
        /* Time windows must be multiples of the MainFunction period
           [SWS_IdsM_01064] (0 = filter disabled) */
        if ((sc.aggregation_interval_ms % config->main_function_period_ms) != 0) {
            return E_PARAM_CONFIG;
        }
        if ((sc.event_threshold.interval_ms % config->main_function_period_ms) != 0) {
            return E_PARAM_CONFIG;
        }
    }

    m_sevs.clear();
    m_sevs.reserve(config->sev_count);
    for (uint16_t i = 0; i < config->sev_count; ++i) {
        IdsM_SevState st{};
        st.config         = config->sev_configs[i];
        st.reporting_mode = config->sev_configs[i].default_reporting_mode;
        /* First received SEv is forwarded [SWS_IdsM_01032] */
        st.nth_counter    = config->sev_configs[i].forward_every_nth;
        m_sevs.push_back(std::move(st));
    }
    m_idsm_instance_id        = config->idsm_instance_id;
    m_main_function_period_ms = config->main_function_period_ms;
    m_block_state = 0;
    m_stats = Stats{};

    /* Start Async Thread */
    m_worker_running.store(true);
    m_worker_thread = std::thread(&IdsM_Manager::worker_loop, this);

    return E_OK;
}

STD_RETURN_TYPE IdsM_Manager::DeInit() {
    /* Stop Async Thread */
    m_worker_running.store(false);
    m_queue_cv.notify_all();
    if (m_worker_thread.joinable()) {
        m_worker_thread.join();
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    m_sevs.clear();
    m_dem_cb = nullptr;
    m_idsr_cb = nullptr;
    m_nvm_cb = nullptr;
    m_stats = Stats{};
    m_main_function_period_ms = 10;
    while (!m_incoming_queue.empty()) m_incoming_queue.pop();
    return E_OK;
}

/* Non-blocking report: validate, deep-copy, enqueue, wake worker (<1us hot path) */
void IdsM_Manager::ReportSecurityEvent(IdsM_SecurityEventIdType sev_id,
                                       const uint8_t* context_data, uint16_t context_size,
                                       uint16_t context_version, uint16_t count,
                                       const IdsM_TimestampDataType* timestamp) {
    if (!m_worker_running.load()) return;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (sev_id >= m_sevs.size()) return;   /* DET error IDSM_E_PARAM_INVALID in P2 */

        IdsM_OwnedSEv owned;
        owned.security_event_id    = sev_id;
        owned.context_data_version = context_version;
        owned.count                = (count == 0) ? 1 : count;
        if (context_data && context_size > 0) {
            owned.context_data.assign(context_data, context_data + context_size);
        }
        if (timestamp) {
            owned.has_timestamp = true;
            owned.timestamp     = *timestamp;
        }

        m_sevs[sev_id].pending_count++;
        m_incoming_queue.push(std::move(owned));
        m_stats.events_reported++;
    }

    m_queue_cv.notify_one();
}

IdsM_Filters_ReportingModeType IdsM_Manager::GetReportingMode(IdsM_SecurityEventIdType sev_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (sev_id >= m_sevs.size()) return IDSM_REPORTING_OFF;
    return m_sevs[sev_id].reporting_mode;
}

STD_RETURN_TYPE IdsM_Manager::SetReportingMode(IdsM_SecurityEventIdType sev_id,
                                               IdsM_Filters_ReportingModeType mode) {
    if (mode > IDSM_REPORTING_DETAILED_BYPASSING_FILTERS) return E_PARAM_CONFIG;
    std::lock_guard<std::mutex> lock(m_mutex);
    if (sev_id >= m_sevs.size()) return E_PARAM_CONFIG;
    m_sevs[sev_id].reporting_mode = mode;
    return E_OK;
}

void IdsM_Manager::BswM_StateChanged(IdsM_BlockStateIdType state) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_block_state = state;
}

IdsM_DetectionStatusType IdsM_Manager::GetDetectionStatus(IdsM_SecurityEventIdType sev_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (sev_id >= m_sevs.size()) return IDSM_STATUS_UNINITIALIZED;
    return m_sevs[sev_id].detection_status;
}

STD_RETURN_TYPE IdsM_Manager::ResetDetectionStatus(IdsM_SecurityEventIdType sev_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (sev_id >= m_sevs.size()) return E_PARAM_CONFIG;
    m_sevs[sev_id].detection_status = IDSM_STATUS_OK;
    return E_OK;
}

uint32_t IdsM_Manager::GetPendingEventCount(IdsM_SecurityEventIdType sev_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (sev_id >= m_sevs.size()) return 0;
    return m_sevs[sev_id].pending_count;
}

STD_RETURN_TYPE IdsM_Manager::FlushEvents(IdsM_SecurityEventIdType sev_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (sev_id >= m_sevs.size()) return E_PARAM_CONFIG;

    /* Release a pending aggregation window immediately: the staged aggregate
       continues through the remaining chain (threshold) and reaches the
       sinks without waiting for the window deadline. */
    auto& state = m_sevs[sev_id];
    if (state.agg_pending) {
        IdsM_OwnedQSEv released = std::move(*state.agg_pending);
        state.agg_pending.reset();
        state.agg_has_context = false;
        if (passThreshold(state, released.count, nowMs())) {
            m_stats.events_qualified++;
            dispatchQsev(state, released);
        }
    }
    return E_OK;
}

bool IdsM_Manager::IsSecurityEventConfigured(IdsM_SecurityEventIdType sev_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return sev_id < m_sevs.size();
}

void IdsM_Manager::SetDemReportCallback(IdsM_QsevSinkCallbackType cb) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_dem_cb = cb;
}

void IdsM_Manager::RegisterIdsrSink(IdsM_QsevSinkCallbackType cb) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_idsr_cb = cb;
}

void IdsM_Manager::SetNvmStoreCallback(IdsM_NvmStoreCallback cb) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_nvm_cb = cb;
}

IdsM_Manager::Stats IdsM_Manager::GetStats() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_stats;
}

void IdsM_Manager::ResetStats() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_stats = Stats{};
}

/* ============================================================
   C-Bridge Functions (extern "C")
   These allow IdsM.c (pure C) to call the C++ Singleton
   ============================================================ */

#ifdef __cplusplus
extern "C" {
#endif

STD_RETURN_TYPE IdsM_Core_Init(const IdsM_ConfigType* config) {
    return IdsM_Manager::Instance().Init(config);
}

STD_RETURN_TYPE IdsM_Core_DeInit(void) {
    return IdsM_Manager::Instance().DeInit();
}

void IdsM_Core_MainFunction(void) {
    /* In async mode, MainFunction is handled by the worker thread. */
}

void IdsM_Core_ReportSecurityEvent(IdsM_SecurityEventIdType sev_id,
                                   const uint8_t* context_data, uint16_t context_size,
                                   uint16_t context_version, uint16_t count,
                                   const IdsM_TimestampDataType* timestamp) {
    IdsM_Manager::Instance().ReportSecurityEvent(sev_id, context_data, context_size,
                                                 context_version, count, timestamp);
}

IdsM_Filters_ReportingModeType IdsM_Core_GetReportingMode(IdsM_SecurityEventIdType sev_id) {
    return IdsM_Manager::Instance().GetReportingMode(sev_id);
}

STD_RETURN_TYPE IdsM_Core_SetReportingMode(IdsM_SecurityEventIdType sev_id,
                                           IdsM_Filters_ReportingModeType mode) {
    return IdsM_Manager::Instance().SetReportingMode(sev_id, mode);
}

void IdsM_Core_BswM_StateChanged(IdsM_BlockStateIdType state) {
    IdsM_Manager::Instance().BswM_StateChanged(state);
}

IdsM_DetectionStatusType IdsM_Core_GetDetectionStatus(IdsM_SecurityEventIdType sev_id) {
    return IdsM_Manager::Instance().GetDetectionStatus(sev_id);
}

STD_RETURN_TYPE IdsM_Core_ResetDetectionStatus(IdsM_SecurityEventIdType sev_id) {
    return IdsM_Manager::Instance().ResetDetectionStatus(sev_id);
}

uint32_t IdsM_Core_GetPendingEventCount(IdsM_SecurityEventIdType sev_id) {
    return IdsM_Manager::Instance().GetPendingEventCount(sev_id);
}

STD_RETURN_TYPE IdsM_Core_FlushEvents(IdsM_SecurityEventIdType sev_id) {
    return IdsM_Manager::Instance().FlushEvents(sev_id);
}

boolean IdsM_Core_IsSecurityEventConfigured(IdsM_SecurityEventIdType sev_id) {
    return IdsM_Manager::Instance().IsSecurityEventConfigured(sev_id) ? true : false;
}

void IdsM_Core_SetDemReportCallback(IdsM_QsevSinkCallbackType cb) {
    IdsM_Manager::Instance().SetDemReportCallback(cb);
}

void IdsM_Core_RegisterIdsrSink(IdsM_QsevSinkCallbackType cb) {
    IdsM_Manager::Instance().RegisterIdsrSink(cb);
}

void IdsM_Core_SetNvmStoreCallback(IdsM_NvmStoreCallback cb) {
    IdsM_Manager::Instance().SetNvmStoreCallback(cb);
}

#ifdef __cplusplus
}
#endif
