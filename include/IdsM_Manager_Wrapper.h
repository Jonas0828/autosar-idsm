#pragma once
#include "IdsM_Types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* C-compatible wrapper functions that bridge to C++ IdsM_Manager */
STD_RETURN_TYPE IdsM_Core_Init(const IdsM_ConfigType* config);
STD_RETURN_TYPE IdsM_Core_DeInit(void);
void IdsM_Core_MainFunction(void);
void IdsM_Core_ReportSecurityEvent(IdsM_SecurityEventIdType sev_id,
                                   const uint8* context_data, uint16 context_size,
                                   uint16 context_version, uint16 count,
                                   const IdsM_TimestampDataType* timestamp);
IdsM_Filters_ReportingModeType IdsM_Core_GetReportingMode(IdsM_SecurityEventIdType sev_id);
STD_RETURN_TYPE IdsM_Core_SetReportingMode(IdsM_SecurityEventIdType sev_id,
                                           IdsM_Filters_ReportingModeType mode);
void IdsM_Core_BswM_StateChanged(IdsM_BlockStateIdType state);
IdsM_DetectionStatusType IdsM_Core_GetDetectionStatus(IdsM_SecurityEventIdType sev_id);
STD_RETURN_TYPE IdsM_Core_ResetDetectionStatus(IdsM_SecurityEventIdType sev_id);
uint32 IdsM_Core_GetPendingEventCount(IdsM_SecurityEventIdType sev_id);
STD_RETURN_TYPE IdsM_Core_FlushEvents(IdsM_SecurityEventIdType sev_id);
boolean IdsM_Core_IsSecurityEventConfigured(IdsM_SecurityEventIdType sev_id);
void IdsM_Core_SetDemReportCallback(IdsM_QsevSinkCallbackType cb);
void IdsM_Core_RegisterIdsrSink(IdsM_QsevSinkCallbackType cb);
void IdsM_Core_SetNvmStoreCallback(IdsM_NvmStoreCallback cb);

#ifdef __cplusplus
}
#endif
