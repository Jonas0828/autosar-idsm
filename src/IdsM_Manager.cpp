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

/* Background Worker Loop */
void IdsM_Manager::worker_loop() {
    while (m_worker_running.load()) {
        std::vector<IdsM_OwnedEvent> local_batch;

        // 1. Wait for events or shutdown signal
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_queue_cv.wait(lock, [this] {
                return !m_incoming_queue.empty() || !m_worker_running.load();
            });

            if (!m_worker_running.load() && m_incoming_queue.empty()) break;

            // Drain queue into local batch
            while (!m_incoming_queue.empty()) {
                local_batch.push_back(std::move(m_incoming_queue.front()));
                m_incoming_queue.pop();
            }
        }

        // 2. Process events (find monitor & buffer)
        for (auto& event : local_batch) {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto it = m_monitors.find(event.monitor_id);

            if (it != m_monitors.end() && it->second.active && isMonitorEnabledInMode(it->second)) {
                it->second.status = IDSM_STATUS_VIOLATION;

                IdsM_InternalEvent internal_evt{};
                internal_evt.report = std::move(event);
                internal_evt.first_seen_ns = getTimestampNs();
                internal_evt.occurrence_count = 1;

                if (it->second.event_buffer.size() >= it->second.config.event_buffer_size) {
                    it->second.event_buffer.pop();
                }
                it->second.event_buffer.push(std::move(internal_evt));
                // ✅ DO NOT set last_report_ns here!
            }
        }

        // 3. Process monitors (Flood protection & DEM forwarding)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            uint64_t now_ns = getTimestampNs();
            for (auto& [id, mon] : m_monitors) {
                if (!mon.active || !isMonitorEnabledInMode(mon)) continue;

                while (!mon.event_buffer.empty()) {
                    auto& evt = mon.event_buffer.front();
                    if (!isFloodProtected(mon, now_ns)) {
                        forwardToDem(evt.report);
                        mon.last_report_ns = now_ns; // ✅ SET ONLY AFTER SUCCESSFUL FORWARD
                        mon.event_buffer.pop();
                    } else {
                        break; // Flood protection active, stop processing this monitor
                    }
                }
            }
        }

        // Prevent 100% CPU usage
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

STD_RETURN_TYPE IdsM_Manager::Init(const IdsM_MonitorConfigType* config, uint16_t count) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!config && count > 0) return E_PARAM_POINTER;
    
    for (uint16_t i = 0; i < count; ++i) {
        IdsM_InternalMonitor mon{};
        mon.config = config[i];
        mon.status = IDSM_STATUS_UNINITIALIZED;
        mon.active = false;
        m_monitors[config[i].monitor_id] = mon;
    }
    m_current_mode = IDSM_PRE_RUN_MODE;
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
    m_monitors.clear();
    m_current_mode = IDSM_POST_RUN_MODE;
    m_dem_cb = nullptr;
    m_nvm_cb = nullptr;
    m_stats = Stats{};
    /* Drain any leftover events from the incoming queue */
    while (!m_incoming_queue.empty()) m_incoming_queue.pop();
    return E_OK;
}

STD_RETURN_TYPE IdsM_Manager::SetOperatingMode(IdsM_OperatingModeType mode) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (mode > IDSM_POST_RUN_MODE) return E_MODE_INVALID;
    
    if (m_current_mode != mode) {
        m_current_mode = mode;
        m_stats.mode_transitions++;
        
        for (auto& [id, mon] : m_monitors) {
            mon.active = isMonitorEnabledInMode(mon);
            if (!mon.active) {
                mon.status = IDSM_STATUS_UNINITIALIZED;
                while (!mon.event_buffer.empty()) mon.event_buffer.pop();
            }
        }
    }
    return E_OK;
}

IdsM_OperatingModeType IdsM_Manager::GetOperatingMode() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_current_mode;
}

/* Non-blocking ReportEvent */
STD_RETURN_TYPE IdsM_Manager::ReportEvent(const IdsM_EventReportType* event) {
    if (!event) return E_PARAM_POINTER;
    if (!m_worker_running.load()) return E_NOT_OK;
    
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_monitors.find(event->monitor_id);
        if (it == m_monitors.end() || !it->second.active || !isMonitorEnabledInMode(it->second)) {
            return E_MODE_INVALID;
        }
        m_incoming_queue.push(IdsM_OwnedEvent::from(*event));
    }
    
    m_queue_cv.notify_one(); // Wake up worker immediately
    return E_OK;
}

IdsM_DetectionStatusType IdsM_Manager::GetDetectionStatus(IdsM_MonitorIdType monitor_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_monitors.find(monitor_id);
    return (it != m_monitors.end()) ? it->second.status : IDSM_STATUS_UNINITIALIZED;
}

STD_RETURN_TYPE IdsM_Manager::ResetDetectionStatus(IdsM_MonitorIdType monitor_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_monitors.find(monitor_id);
    if (it == m_monitors.end()) return E_PARAM_CONFIG;
    it->second.status = IDSM_STATUS_OK;
    return E_OK;
}

uint32_t IdsM_Manager::GetPendingEventCount(IdsM_MonitorIdType monitor_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_monitors.find(monitor_id);
    return (it != m_monitors.end()) ? static_cast<uint32_t>(it->second.event_buffer.size()) : 0;
}

STD_RETURN_TYPE IdsM_Manager::FlushEvents(IdsM_MonitorIdType monitor_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_monitors.find(monitor_id);
    if (it == m_monitors.end()) return E_PARAM_CONFIG;
    
    auto& mon = it->second;
    while (!mon.event_buffer.empty()) {
        forwardToDem(mon.event_buffer.front().report);
        mon.event_buffer.pop();
    }
    return E_OK;
}

void IdsM_Manager::SetDemReportCallback(IdsM_DemReportCallback cb) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_dem_cb = cb;
}

void IdsM_Manager::SetNvmStoreCallback(IdsM_NvmStoreCallback cb) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_nvm_cb = cb;
}

bool IdsM_Manager::isMonitorEnabledInMode(const IdsM_InternalMonitor& mon) const {
    switch (m_current_mode) {
        case IDSM_PRE_RUN_MODE: return mon.config.enabled_in_pre_run;
        case IDSM_RUN_MODE: return mon.config.enabled_in_run;
        case IDSM_POST_RUN_MODE: return mon.config.enabled_in_post_run;
        default: return false;
    }
}

bool IdsM_Manager::isFloodProtected(const IdsM_InternalMonitor& mon, uint64_t now_ns) const {
    if (mon.config.flood_protection_ms == 0) return false;
    if (mon.last_report_ns == 0) return false;
    uint64_t min_interval_ns = static_cast<uint64_t>(mon.config.flood_protection_ms) * 1000000ULL;
    return (now_ns - mon.last_report_ns) < min_interval_ns;
}

void IdsM_Manager::forwardToDem(const IdsM_OwnedEvent& event) {
    m_stats.events_flushed_to_dem++;
    if (m_dem_cb) {
        /* Reconstruct C struct; pointer is valid while 'event' is alive */
        IdsM_EventReportType c_evt = event.to_c();
        m_dem_cb(&c_evt);
    }
}

uint64_t IdsM_Manager::getTimestampNs() const {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
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

STD_RETURN_TYPE IdsM_Core_Init(const IdsM_MonitorConfigType* config, uint16_t count) {
    return IdsM_Manager::Instance().Init(config, count);
}

STD_RETURN_TYPE IdsM_Core_DeInit(void) {
    return IdsM_Manager::Instance().DeInit();
}

void IdsM_Core_MainFunction(void) {
    // In async mode, MainFunction is handled by the worker thread.
    // This is kept for API compatibility but does nothing here.
}

STD_RETURN_TYPE IdsM_Core_SetOperatingMode(IdsM_OperatingModeType mode) {
    return IdsM_Manager::Instance().SetOperatingMode(mode);
}

IdsM_OperatingModeType IdsM_Core_GetOperatingMode(void) {
    return IdsM_Manager::Instance().GetOperatingMode();
}

STD_RETURN_TYPE IdsM_Core_ReportEvent(const IdsM_EventReportType* event) {
    return IdsM_Manager::Instance().ReportEvent(event);
}

IdsM_DetectionStatusType IdsM_Core_GetDetectionStatus(IdsM_MonitorIdType monitor_id) {
    return IdsM_Manager::Instance().GetDetectionStatus(monitor_id);
}

STD_RETURN_TYPE IdsM_Core_ResetDetectionStatus(IdsM_MonitorIdType monitor_id) {
    return IdsM_Manager::Instance().ResetDetectionStatus(monitor_id);
}

uint32_t IdsM_Core_GetPendingEventCount(IdsM_MonitorIdType monitor_id) {
    return IdsM_Manager::Instance().GetPendingEventCount(monitor_id);
}

STD_RETURN_TYPE IdsM_Core_FlushEvents(IdsM_MonitorIdType monitor_id) {
    return IdsM_Manager::Instance().FlushEvents(monitor_id);
}

void IdsM_Core_SetDemReportCallback(IdsM_DemReportCallback cb) {
    IdsM_Manager::Instance().SetDemReportCallback(cb);
}

void IdsM_Core_SetNvmStoreCallback(IdsM_NvmStoreCallback cb) {
    IdsM_Manager::Instance().SetNvmStoreCallback(cb);
}

#ifdef __cplusplus
}
#endif