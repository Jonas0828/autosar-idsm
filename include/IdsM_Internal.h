#pragma once
#include "IdsM_Types.h"

#ifdef __cplusplus

#include <vector>
#include <queue>
#include <memory>
#include <mutex>
#include <chrono>
#include <thread>
#include <atomic>
#include <condition_variable>

/* ── Ingress event (pre-qualification) ──────────────────────────────────────
   Deep-copies the caller's context data at IdsM_ReportSecurityEvent() time,
   so the caller's buffer may go out of scope immediately after the call. */
struct IdsM_OwnedSEv {
    IdsM_SecurityEventIdType security_event_id;
    std::vector<uint8_t>     context_data;      /* deep-copied from caller */
    uint16_t                 context_data_version{1};
    uint16_t                 count{1};
    bool                     has_timestamp{false};
    IdsM_TimestampDataType   timestamp{};
};

/* ── Qualified security event (post filter chain) ─────────────────────────── */
struct IdsM_OwnedQSEv {
    uint16_t                         idsm_instance_id{0};
    IdsM_ExternalSecurityEventIdType external_event_id{IDSM_EXTERNAL_EVENT_ID_INVALID};
    IdsM_SensorInstanceIdType        sensor_instance_id{0};
    IdsM_EventSeverityType           severity{IDSM_SEVERITY_LOW};
    uint16_t                         count{1};
    bool                             has_timestamp{false};
    IdsM_TimestampDataType           timestamp{};
    uint16_t                         context_data_version{1};
    std::vector<uint8_t>             context_data;

    /* Reconstruct a temporary C struct (context pointer into our vector).
       Valid only while this OwnedQSEv is alive. */
    IdsM_QualifiedSecurityEventType to_c() const {
        IdsM_QualifiedSecurityEventType q{};
        q.idsm_instance_id     = idsm_instance_id;
        q.external_event_id    = external_event_id;
        q.sensor_instance_id   = sensor_instance_id;
        q.severity             = severity;
        q.count                = count;
        q.has_timestamp        = has_timestamp ? true : false;
        q.timestamp            = timestamp;
        q.context_data_version = context_data_version;
        q.context_data         = context_data.empty() ? nullptr : context_data.data();
        q.context_data_size    = static_cast<uint16_t>(context_data.size());
        return q;
    }
};

/* ── Per-SEv runtime state ────────────────────────────────────────────────── */
struct IdsM_SevState {
    IdsM_SecurityEventConfigType    config;
    IdsM_Filters_ReportingModeType  reporting_mode{IDSM_REPORTING_OFF};
    IdsM_DetectionStatusType        detection_status{IDSM_STATUS_UNINITIALIZED};
    uint32_t                        pending_count{0};   /* queued, not yet processed */
    /* Forward Every Nth runtime counter [SWS_IdsM_01031]. Initialized to n at
       Init so the first received SEv is forwarded [SWS_IdsM_01032]. */
    uint16_t                        nth_counter{0};
    /* Event Aggregation runtime [SWS_IdsM_01041-01044] (C++ side owns the
       pending event; null when no window is open). */
    std::unique_ptr<IdsM_OwnedQSEv> agg_pending;        /* staged aggregate   */
    bool                            agg_has_context{false}; /* first event's ctx kept */
    uint32_t                        agg_window_start_ms{0};
    /* Event Threshold runtime [SWS_IdsM_01061-01065] */
    uint32_t                        thr_accumulated{0};
    uint32_t                        thr_window_start_ms{0};
    bool                            thr_window_open{false};
};

/* Global manager state (singleton pattern) */
class IdsM_Manager {
public:
    static IdsM_Manager& Instance();

    /* Public API */
    STD_RETURN_TYPE Init(const IdsM_ConfigType* config);
    STD_RETURN_TYPE DeInit();
    void ReportSecurityEvent(IdsM_SecurityEventIdType sev_id,
                             const uint8_t* context_data, uint16_t context_size,
                             uint16_t context_version, uint16_t count,
                             const IdsM_TimestampDataType* timestamp);
    IdsM_Filters_ReportingModeType GetReportingMode(IdsM_SecurityEventIdType sev_id) const;
    STD_RETURN_TYPE SetReportingMode(IdsM_SecurityEventIdType sev_id,
                                     IdsM_Filters_ReportingModeType mode);
    void BswM_StateChanged(IdsM_BlockStateIdType state);
    IdsM_DetectionStatusType GetDetectionStatus(IdsM_SecurityEventIdType sev_id);
    STD_RETURN_TYPE ResetDetectionStatus(IdsM_SecurityEventIdType sev_id);
    uint32_t GetPendingEventCount(IdsM_SecurityEventIdType sev_id);
    STD_RETURN_TYPE FlushEvents(IdsM_SecurityEventIdType sev_id);
    bool IsSecurityEventConfigured(IdsM_SecurityEventIdType sev_id) const;
    void SetDemReportCallback(IdsM_QsevSinkCallbackType cb);
    void RegisterIdsrSink(IdsM_QsevSinkCallbackType cb);
    void SetNvmStoreCallback(IdsM_NvmStoreCallback cb);

    /* Stats */
    struct Stats {
        uint32_t events_reported;        /* accepted into the ingress queue */
        uint32_t dropped_reporting_off;  /* discarded by reporting mode OFF */
        uint32_t dropped_block_state;    /* discarded by Block State filter */
        uint32_t dropped_sampling;       /* discarded by Forward Every Nth filter */
        uint32_t dropped_threshold;      /* discarded by Event Threshold filter */
        uint32_t events_qualified;       /* became QSEvs */
        uint32_t sent_to_dem;
        uint32_t sent_to_idsr;
    };
    Stats GetStats() const;
    void ResetStats();

private:
    IdsM_Manager() = default;
    ~IdsM_Manager() = default;
    IdsM_Manager(const IdsM_Manager&) = delete;
    IdsM_Manager& operator=(const IdsM_Manager&) = delete;

    /* --- ASYNC ENGINE --- */
    std::thread m_worker_thread;
    std::atomic<bool> m_worker_running{false};
    std::condition_variable m_queue_cv;
    std::queue<IdsM_OwnedSEv> m_incoming_queue;

    /* --- STATE --- */
    mutable std::mutex m_mutex;
    std::vector<IdsM_SevState> m_sevs;          /* indexed by internal SEv ID */
    uint16_t m_idsm_instance_id{0};
    uint32_t m_main_function_period_ms{10};
    IdsM_BlockStateIdType m_block_state{0};
    IdsM_QsevSinkCallbackType m_dem_cb{nullptr};
    IdsM_QsevSinkCallbackType m_idsr_cb{nullptr};
    IdsM_NvmStoreCallback m_nvm_cb{nullptr};
    Stats m_stats{};

    /* Helpers */
    void worker_loop();                          /* background thread entry */
    void processEvent(IdsM_OwnedSEv& sev);       /* reporting mode + chain + qualify + dispatch */
    uint32_t nowMs() const;                      /* steady clock, ms since epoch */
    /* Time-window bookkeeping for Aggregation/Threshold; returns the next
       absolute deadline (ms) or 0 when nothing is pending. */
    uint32_t expireWindows(uint32_t now_ms);     /* flush due aggregation windows,
                                                    reset due threshold windows */
    bool isBlockedByState(const IdsM_SevState& sev) const;   /* Block State filter */
    bool passForwardEveryNth(IdsM_SevState& sev, uint16_t count); /* Sampling filter */
    /* Event Aggregation filter [SWS_IdsM_01041-01046]: stage into the open
       window or pass through. Returns false when the SEv was absorbed. */
    bool passAggregation(IdsM_SevState& sev, IdsM_OwnedQSEv& qsev);
    /* Event Threshold filter [SWS_IdsM_01061-01065]. */
    bool passThreshold(IdsM_SevState& sev, uint16_t count, uint32_t now_ms);
    void dispatchQsev(const IdsM_SevState& sev, const IdsM_OwnedQSEv& qsev);
    IdsM_TimestampDataType makeInternalTimestamp() const;
};

#endif /* __cplusplus */
