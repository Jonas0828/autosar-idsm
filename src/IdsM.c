#include "IdsM.h"
#include "IdsM_Manager_Wrapper.h"  /* C wrapper bridging to the C++ manager */
#include <stddef.h>                /* NULL */

STD_RETURN_TYPE IdsM_Init(const IdsM_ConfigType* config) {
    if (!config) return E_PARAM_POINTER;
    return IdsM_Core_Init(config);
}

STD_RETURN_TYPE IdsM_DeInit(void) {
    return IdsM_Core_DeInit();
}

void IdsM_MainFunction(void) {
    IdsM_Core_MainFunction();
}

void IdsM_ReportSecurityEvent(IdsM_SecurityEventIdType securityEventId,
                              const uint8* contextData,
                              uint16 contextDataSize,
                              uint16 contextDataVersion,
                              uint16 count,
                              const IdsM_TimestampDataType* timestamp) {
    IdsM_Core_ReportSecurityEvent(securityEventId, contextData, contextDataSize,
                                  contextDataVersion, count, timestamp);
}

IdsM_Filters_ReportingModeType IdsM_GetReportingMode(IdsM_SecurityEventIdType securityEventId) {
    return IdsM_Core_GetReportingMode(securityEventId);
}

STD_RETURN_TYPE IdsM_SetReportingMode(IdsM_SecurityEventIdType securityEventId,
                                      IdsM_Filters_ReportingModeType mode) {
    return IdsM_Core_SetReportingMode(securityEventId, mode);
}

void IdsM_BswM_StateChanged(IdsM_BlockStateIdType state) {
    IdsM_Core_BswM_StateChanged(state);
}

IdsM_DetectionStatusType IdsM_GetDetectionStatus(IdsM_SecurityEventIdType securityEventId) {
    return IdsM_Core_GetDetectionStatus(securityEventId);
}

STD_RETURN_TYPE IdsM_ResetDetectionStatus(IdsM_SecurityEventIdType securityEventId) {
    return IdsM_Core_ResetDetectionStatus(securityEventId);
}

uint32 IdsM_GetPendingEventCount(IdsM_SecurityEventIdType securityEventId) {
    return IdsM_Core_GetPendingEventCount(securityEventId);
}

STD_RETURN_TYPE IdsM_FlushEvents(IdsM_SecurityEventIdType securityEventId) {
    return IdsM_Core_FlushEvents(securityEventId);
}

boolean IdsM_IsSecurityEventConfigured(IdsM_SecurityEventIdType securityEventId) {
    return IdsM_Core_IsSecurityEventConfigured(securityEventId);
}

void IdsM_SetDemReportCallback(IdsM_QsevSinkCallbackType cb) {
    IdsM_Core_SetDemReportCallback(cb);
}

void IdsM_RegisterIdsrSink(IdsM_QsevSinkCallbackType cb) {
    IdsM_Core_RegisterIdsrSink(cb);
}

void IdsM_SetNvmStoreCallback(IdsM_NvmStoreCallback cb) {
    IdsM_Core_SetNvmStoreCallback(cb);
}

/* Deprecated compatibility wrapper: monitor_id doubles as the internal SEv ID;
   event_id/severity are ignored (identity and severity come from SEv config). */
STD_RETURN_TYPE IdsM_ReportEvent(const IdsM_EventReportType* event) {
    if (!event) return E_PARAM_POINTER;
    if (!IdsM_Core_IsSecurityEventConfigured(event->monitor_id)) return E_PARAM_CONFIG;
    IdsM_Core_ReportSecurityEvent(event->monitor_id,
                                  event->payload, event->payload_len,
                                  1u /* contextDataVersion */, 1u /* count */,
                                  NULL /* timestamp */);
    return E_OK;
}
