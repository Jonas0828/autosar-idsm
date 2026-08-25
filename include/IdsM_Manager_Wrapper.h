#pragma once
#include "IdsM_Types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* C-compatible wrapper functions that bridge to C++ IdsM_Manager */
STD_RETURN_TYPE IdsM_Core_Init(const IdsM_MonitorConfigType* config, uint16_t count);
STD_RETURN_TYPE IdsM_Core_DeInit(void);
void IdsM_Core_MainFunction(void);
STD_RETURN_TYPE IdsM_Core_SetOperatingMode(IdsM_OperatingModeType mode);
IdsM_OperatingModeType IdsM_Core_GetOperatingMode(void);
STD_RETURN_TYPE IdsM_Core_ReportEvent(const IdsM_EventReportType* event);
IdsM_DetectionStatusType IdsM_Core_GetDetectionStatus(IdsM_MonitorIdType monitor_id);
STD_RETURN_TYPE IdsM_Core_ResetDetectionStatus(IdsM_MonitorIdType monitor_id);
uint32_t IdsM_Core_GetPendingEventCount(IdsM_MonitorIdType monitor_id);
STD_RETURN_TYPE IdsM_Core_FlushEvents(IdsM_MonitorIdType monitor_id);
void IdsM_Core_SetDemReportCallback(IdsM_DemReportCallback cb);
void IdsM_Core_SetNvmStoreCallback(IdsM_NvmStoreCallback cb);

#ifdef __cplusplus
}
#endif