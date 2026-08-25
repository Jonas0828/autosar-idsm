#include "IdsM.h"
#include "IdsM_Manager_Wrapper.h"  /* ADD: Include the C wrapper header */

STD_RETURN_TYPE IdsM_Init(const IdsM_MonitorConfigType* config, uint16_t config_count) {
    return IdsM_Core_Init(config, config_count);  /* Call wrapper, not C++ directly */
}

STD_RETURN_TYPE IdsM_DeInit(void) {
    return IdsM_Core_DeInit();
}

void IdsM_MainFunction(void) {
    IdsM_Core_MainFunction();
}

STD_RETURN_TYPE IdsM_SetOperatingMode(IdsM_OperatingModeType mode) {
    return IdsM_Core_SetOperatingMode(mode);
}

IdsM_OperatingModeType IdsM_GetOperatingMode(void) {
    return IdsM_Core_GetOperatingMode();
}

STD_RETURN_TYPE IdsM_ReportEvent(const IdsM_EventReportType* event) {
    if (!event) return E_PARAM_POINTER;
    return IdsM_Core_ReportEvent(event);
}

IdsM_DetectionStatusType IdsM_GetDetectionStatus(IdsM_MonitorIdType monitor_id) {
    return IdsM_Core_GetDetectionStatus(monitor_id);
}

STD_RETURN_TYPE IdsM_ResetDetectionStatus(IdsM_MonitorIdType monitor_id) {
    return IdsM_Core_ResetDetectionStatus(monitor_id);
}

uint32_t IdsM_GetPendingEventCount(IdsM_MonitorIdType monitor_id) {
    return IdsM_Core_GetPendingEventCount(monitor_id);
}

STD_RETURN_TYPE IdsM_FlushEvents(IdsM_MonitorIdType monitor_id) {
    return IdsM_Core_FlushEvents(monitor_id);
}

void IdsM_SetDemReportCallback(IdsM_DemReportCallback cb) {
    IdsM_Core_SetDemReportCallback(cb);
}

void IdsM_SetNvmStoreCallback(IdsM_NvmStoreCallback cb) {
    IdsM_Core_SetNvmStoreCallback(cb);
}