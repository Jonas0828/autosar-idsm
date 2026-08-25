#pragma once
#include "IdsRm_Types.h"
#include "IdsM_Types.h"

#ifdef __cplusplus

#include "IdsM_Internal.h"  /* for IdsM_OwnedEvent */
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>
#include <string>
#include <vector>
#include <cstdint>

/* Forward-declare curl handle type to keep <curl/curl.h> out of the header */
typedef void CURL;

class IdsRm_Manager {
public:
    static IdsRm_Manager& Instance();

    /* Lifecycle */
    STD_RETURN_TYPE Init(const IdsRm_ConfigType* config);
    STD_RETURN_TYPE DeInit();

    /* Enable / Disable */
    STD_RETURN_TYPE Enable();
    STD_RETURN_TYPE Disable();
    bool            IsEnabled() const;

    /* Runtime config updates (thread-safe) */
    STD_RETURN_TYPE SetSocUrl(const char* url);
    STD_RETURN_TYPE SetAuthToken(const char* token);

    /* Stats */
    IdsRm_StatsType GetStats() const;
    void            ResetStats();

    /* DEM callback target — must be non-blocking (<1µs).
       Called by IdsM worker thread while IdsM holds its own mutex. */
    void OnDemEvent(const IdsM_EventReportType* event);

private:
    IdsRm_Manager()  = default;
    ~IdsRm_Manager() = default;
    IdsRm_Manager(const IdsRm_Manager&)            = delete;
    IdsRm_Manager& operator=(const IdsRm_Manager&) = delete;

    /* Async engine — same pattern as IdsM_Manager */
    std::thread              m_worker_thread;
    std::atomic<bool>        m_worker_running{false};
    std::mutex               m_queue_mutex;   /* held only for enqueue/dequeue */
    std::condition_variable  m_queue_cv;
    std::queue<IdsM_OwnedEvent> m_event_queue;

    /* Module state */
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_enabled{false};

    /* Config — protected by m_config_mutex */
    mutable std::mutex m_config_mutex;
    std::string  m_soc_url;
    std::string  m_auth_token;
    uint32_t     m_timeout_ms{5000U};
    uint8_t      m_retry_count{3U};

    /* Stats — protected by m_stats_mutex */
    mutable std::mutex m_stats_mutex;
    IdsRm_StatsType    m_stats{};

    /* libcurl handle: created once in worker thread, reused for keep-alive */
    CURL* m_curl_handle{nullptr};

    /* Worker */
    void worker_loop();

    /* HTTP */
    bool postWithRetry(const IdsM_OwnedEvent& event);
    bool postEvent(const IdsM_OwnedEvent& event);
    void buildJsonPayload(const IdsM_OwnedEvent& event, std::string& out) const;
    const char* severityToString(IdsM_EventSeverityType sev) const;

    /* curl lifecycle (called from worker thread only) */
    void initCurl();
    void cleanupCurl();
};

#endif /* __cplusplus */
