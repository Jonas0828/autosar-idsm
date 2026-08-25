#include "IdsRm_Internal.h"
#include "IdsM.h"
#include <curl/curl.h>
#include <cstring>
#include <cstdio>
#include <chrono>
#include <thread>
#include <mutex>

/* Forward declaration — defined in the C-bridge section at the bottom */
extern "C" void IdsRm_Core_DemCallbackShim(const IdsM_EventReportType* event);

/* curl_global_init must be called exactly once per process and is not
   thread-safe. Use call_once so repeated Init/DeInit cycles in tests
   and production are safe. Cleanup is registered via atexit. */
static void curl_global_init_once() {
    static std::once_flag flag;
    std::call_once(flag, [] {
        curl_global_init(CURL_GLOBAL_ALL);
        std::atexit(curl_global_cleanup);
    });
}

/* ───────────────────────── Singleton ───────────────────────────────────── */

IdsRm_Manager& IdsRm_Manager::Instance() {
    static IdsRm_Manager instance;
    return instance;
}

/* ───────────────────────── Lifecycle ───────────────────────────────────── */

STD_RETURN_TYPE IdsRm_Manager::Init(const IdsRm_ConfigType* config) {
    if (m_initialized.load()) return E_NOT_OK;

    {
        std::lock_guard<std::mutex> lock(m_config_mutex);
        m_soc_url    = std::string(config->soc_url,
                                   strnlen(config->soc_url,    IDSRM_MAX_URL_LEN   - 1));
        m_auth_token = std::string(config->auth_token,
                                   strnlen(config->auth_token, IDSRM_MAX_TOKEN_LEN - 1));
        m_timeout_ms  = config->timeout_ms;
        m_retry_count = (config->retry_count <= IDSRM_MAX_RETRY_COUNT)
                            ? config->retry_count : IDSRM_MAX_RETRY_COUNT;
    }

    {
        std::lock_guard<std::mutex> slock(m_stats_mutex);
        m_stats = IdsRm_StatsType{};
    }

    m_enabled.store(config->enabled);

    curl_global_init_once();

    /* Register C shim as the DEM callback with IDSM */
    IdsM_SetDemReportCallback(IdsRm_Core_DemCallbackShim);

    m_worker_running.store(true);
    m_worker_thread = std::thread(&IdsRm_Manager::worker_loop, this);

    m_initialized.store(true);
    return E_OK;
}

STD_RETURN_TYPE IdsRm_Manager::DeInit() {
    if (!m_initialized.load()) return E_IDSRM_NOT_INIT;

    /* Unregister first so no new events arrive after we start shutdown */
    IdsM_SetDemReportCallback(nullptr);

    m_worker_running.store(false);
    m_queue_cv.notify_all();
    if (m_worker_thread.joinable()) {
        m_worker_thread.join();
    }
    /* curl handle cleaned up inside worker_loop before it returns */

    m_initialized.store(false);
    m_enabled.store(false);
    return E_OK;
}

/* ───────────────────────── Enable / Disable ─────────────────────────────── */

STD_RETURN_TYPE IdsRm_Manager::Enable() {
    if (!m_initialized.load()) return E_IDSRM_NOT_INIT;
    m_enabled.store(true);
    return E_OK;
}

STD_RETURN_TYPE IdsRm_Manager::Disable() {
    if (!m_initialized.load()) return E_IDSRM_NOT_INIT;
    m_enabled.store(false);
    return E_OK;
}

bool IdsRm_Manager::IsEnabled() const {
    return m_initialized.load() && m_enabled.load();
}

/* ───────────────────────── Runtime Config ───────────────────────────────── */

STD_RETURN_TYPE IdsRm_Manager::SetSocUrl(const char* url) {
    if (!m_initialized.load()) return E_IDSRM_NOT_INIT;
    std::lock_guard<std::mutex> lock(m_config_mutex);
    m_soc_url = std::string(url, strnlen(url, IDSRM_MAX_URL_LEN - 1));
    return E_OK;
}

STD_RETURN_TYPE IdsRm_Manager::SetAuthToken(const char* token) {
    if (!m_initialized.load()) return E_IDSRM_NOT_INIT;
    std::lock_guard<std::mutex> lock(m_config_mutex);
    m_auth_token = std::string(token, strnlen(token, IDSRM_MAX_TOKEN_LEN - 1));
    return E_OK;
}

/* ───────────────────────── Stats ────────────────────────────────────────── */

IdsRm_StatsType IdsRm_Manager::GetStats() const {
    std::lock_guard<std::mutex> lock(m_stats_mutex);
    return m_stats;
}

void IdsRm_Manager::ResetStats() {
    std::lock_guard<std::mutex> lock(m_stats_mutex);
    m_stats = IdsRm_StatsType{};
}

/* ───────────────────────── DEM callback ─────────────────────────────────── */

void IdsRm_Manager::OnDemEvent(const IdsM_EventReportType* event) {
    /* Fast exit — relaxed load avoids a full memory barrier on the hot path */
    if (!m_enabled.load(std::memory_order_relaxed)) {
        std::lock_guard<std::mutex> slock(m_stats_mutex);
        m_stats.events_dropped++;
        return;
    }

    {
        std::lock_guard<std::mutex> qlock(m_queue_mutex);
        if (m_event_queue.size() >= IDSRM_DEFAULT_QUEUE_DEPTH) {
            std::lock_guard<std::mutex> slock(m_stats_mutex);
            m_stats.events_dropped++;
            return;
        }
        m_event_queue.push(IdsM_OwnedEvent::from(*event));
    }

    {
        std::lock_guard<std::mutex> slock(m_stats_mutex);
        m_stats.events_received++;
    }

    m_queue_cv.notify_one();
}

/* ───────────────────────── Worker loop ──────────────────────────────────── */

void IdsRm_Manager::worker_loop() {
    initCurl();

    while (m_worker_running.load()) {
        std::vector<IdsM_OwnedEvent> batch;

        {
            std::unique_lock<std::mutex> lock(m_queue_mutex);
            m_queue_cv.wait(lock, [this] {
                return !m_event_queue.empty() || !m_worker_running.load();
            });

            if (!m_worker_running.load() && m_event_queue.empty()) break;

            /* Drain entire queue in one lock hold */
            while (!m_event_queue.empty()) {
                batch.push_back(std::move(m_event_queue.front()));
                m_event_queue.pop();
            }
        }

        for (const auto& event : batch) {
            postWithRetry(event);
        }
    }

    /* Best-effort drain of any events that arrived during shutdown */
    std::vector<IdsM_OwnedEvent> remaining;
    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        while (!m_event_queue.empty()) {
            remaining.push_back(std::move(m_event_queue.front()));
            m_event_queue.pop();
        }
    }
    for (const auto& event : remaining) {
        postWithRetry(event);
    }

    cleanupCurl();
}

/* ───────────────────────── HTTP POST with retry ─────────────────────────── */

bool IdsRm_Manager::postWithRetry(const IdsM_OwnedEvent& event) {
    uint8_t max_retries;
    {
        std::lock_guard<std::mutex> lock(m_config_mutex);
        max_retries = m_retry_count;
    }

    for (uint8_t attempt = 0; attempt <= max_retries; ++attempt) {
        if (postEvent(event)) {
            std::lock_guard<std::mutex> slock(m_stats_mutex);
            m_stats.events_posted++;
            return true;
        }

        {
            std::lock_guard<std::mutex> slock(m_stats_mutex);
            m_stats.http_retries++;
        }

        if (attempt < max_retries) {
            /* Exponential backoff: 100ms, 200ms, 400ms ... */
            std::this_thread::sleep_for(
                std::chrono::milliseconds(100U << attempt));
        }
    }

    std::lock_guard<std::mutex> slock(m_stats_mutex);
    m_stats.events_failed++;
    return false;
}

/* ───────────────────────── Single HTTP POST ─────────────────────────────── */

static size_t discard_response(char*, size_t size, size_t nmemb, void*) {
    return size * nmemb;
}

bool IdsRm_Manager::postEvent(const IdsM_OwnedEvent& event) {
    if (!m_curl_handle) return false;

    std::string url, token;
    uint32_t timeout_ms;
    {
        std::lock_guard<std::mutex> lock(m_config_mutex);
        url        = m_soc_url;
        token      = m_auth_token;
        timeout_ms = m_timeout_ms;
    }

    std::string json_body;
    buildJsonPayload(event, json_body);

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    if (!token.empty()) {
        std::string auth_hdr = "Authorization: Bearer " + token;
        headers = curl_slist_append(headers, auth_hdr.c_str());
    }

    curl_easy_setopt(m_curl_handle, CURLOPT_URL,           url.c_str());
    curl_easy_setopt(m_curl_handle, CURLOPT_HTTPHEADER,    headers);
    curl_easy_setopt(m_curl_handle, CURLOPT_POSTFIELDS,    json_body.c_str());
    curl_easy_setopt(m_curl_handle, CURLOPT_POSTFIELDSIZE, (long)json_body.size());
    curl_easy_setopt(m_curl_handle, CURLOPT_TIMEOUT_MS,    (long)timeout_ms);
    curl_easy_setopt(m_curl_handle, CURLOPT_WRITEFUNCTION, discard_response);

    CURLcode res = curl_easy_perform(m_curl_handle);

    long http_code = 0;
    curl_easy_getinfo(m_curl_handle, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);
    /* Reset per-request options but keep the TCP connection open */
    curl_easy_reset(m_curl_handle);
    /* Restore persistent options cleared by reset */
    curl_easy_setopt(m_curl_handle, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(m_curl_handle, CURLOPT_NOSIGNAL,      1L);

    return (res == CURLE_OK) && (http_code >= 200) && (http_code < 300);
}

/* ───────────────────────── JSON builder ─────────────────────────────────── */

void IdsRm_Manager::buildJsonPayload(const IdsM_OwnedEvent& event,
                                      std::string& out) const {
    /* Build hex string from payload bytes */
    std::string payload_hex;
    payload_hex.reserve(event.payload.size() * 2);
    for (uint8_t byte : event.payload) {
        char hex[3];
        std::snprintf(hex, sizeof(hex), "%02X", byte);
        payload_hex += hex;
    }

    /* Use std::string instead of fixed buffer — payload can be any size */
    char header[256];
    std::snprintf(header, sizeof(header),
        "{\"monitor_id\":%u,\"event_id\":%u,"
        "\"timestamp_ms\":%u,\"severity\":\"%s\","
        "\"payload\":\"",
        static_cast<unsigned>(event.monitor_id),
        static_cast<unsigned>(event.event_id),
        static_cast<unsigned>(event.timestamp_ms),
        severityToString(event.severity));

    char trailer[64];
    std::snprintf(trailer, sizeof(trailer),
        "\",\"payload_len\":%u}",
        static_cast<unsigned>(event.payload.size()));

    out.clear();
    out.reserve(std::strlen(header) + payload_hex.size() + std::strlen(trailer));
    out += header;
    out += payload_hex;
    out += trailer;
}

const char* IdsRm_Manager::severityToString(IdsM_EventSeverityType sev) const {
    switch (sev) {
        case IDSM_SEVERITY_LOW:      return "LOW";
        case IDSM_SEVERITY_MEDIUM:   return "MEDIUM";
        case IDSM_SEVERITY_HIGH:     return "HIGH";
        case IDSM_SEVERITY_CRITICAL: return "CRITICAL";
        default:                     return "UNKNOWN";
    }
}

/* ───────────────────────── curl lifecycle ───────────────────────────────── */

void IdsRm_Manager::initCurl() {
    m_curl_handle = curl_easy_init();
    if (m_curl_handle) {
        /* NOSIGNAL is mandatory in multi-threaded programs */
        curl_easy_setopt(m_curl_handle, CURLOPT_NOSIGNAL,      1L);
        /* Keep TCP connection alive to avoid per-event handshake overhead */
        curl_easy_setopt(m_curl_handle, CURLOPT_TCP_KEEPALIVE, 1L);
    }
}

void IdsRm_Manager::cleanupCurl() {
    if (m_curl_handle) {
        curl_easy_cleanup(m_curl_handle);
        m_curl_handle = nullptr;
    }
}

/* ───────────────────────── C bridge functions ───────────────────────────── */

#ifdef __cplusplus
extern "C" {
#endif

void IdsRm_Core_DemCallbackShim(const IdsM_EventReportType* event) {
    IdsRm_Manager::Instance().OnDemEvent(event);
}

STD_RETURN_TYPE IdsRm_Core_Init(const IdsRm_ConfigType* config) {
    return IdsRm_Manager::Instance().Init(config);
}

STD_RETURN_TYPE IdsRm_Core_DeInit(void) {
    return IdsRm_Manager::Instance().DeInit();
}

STD_RETURN_TYPE IdsRm_Core_Enable(void) {
    return IdsRm_Manager::Instance().Enable();
}

STD_RETURN_TYPE IdsRm_Core_Disable(void) {
    return IdsRm_Manager::Instance().Disable();
}

boolean IdsRm_Core_IsEnabled(void) {
    return IdsRm_Manager::Instance().IsEnabled() ? true : false;
}

STD_RETURN_TYPE IdsRm_Core_SetSocUrl(const char* url) {
    return IdsRm_Manager::Instance().SetSocUrl(url);
}

STD_RETURN_TYPE IdsRm_Core_SetAuthToken(const char* token) {
    return IdsRm_Manager::Instance().SetAuthToken(token);
}

IdsRm_StatsType IdsRm_Core_GetStats(void) {
    return IdsRm_Manager::Instance().GetStats();
}

void IdsRm_Core_ResetStats(void) {
    IdsRm_Manager::Instance().ResetStats();
}

#ifdef __cplusplus
}
#endif
