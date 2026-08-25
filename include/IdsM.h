#pragma once
#include "IdsM_Types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* [SWS_IdM_00100] Initialization */
STD_RETURN_TYPE IdsM_Init(const IdsM_MonitorConfigType* config, uint16 config_count);

/* [SWS_IdM_00101] De-initialization */
STD_RETURN_TYPE IdsM_DeInit(void);

/* [SWS_IdM_00102] Main function (periodic runnable) */
void IdsM_MainFunction(void);

/* [SWS_IdM_00103] Set operating mode */
STD_RETURN_TYPE IdsM_SetOperatingMode(IdsM_OperatingModeType mode);

/* [SWS_IdM_00104] Get current operating mode */
IdsM_OperatingModeType IdsM_GetOperatingMode(void);

/* [SWS_IdM_00200] Report event from detector/algorithm */
STD_RETURN_TYPE IdsM_ReportEvent(const IdsM_EventReportType* event);

/* [SWS_IdM_00201] Get detection status for a monitor */
IdsM_DetectionStatusType IdsM_GetDetectionStatus(IdsM_MonitorIdType monitor_id);

/* [SWS_IdM_00202] Reset detection status for a monitor */
STD_RETURN_TYPE IdsM_ResetDetectionStatus(IdsM_MonitorIdType monitor_id);

/* [SWS_IdM_00203] Get pending event count */
uint32 IdsM_GetPendingEventCount(IdsM_MonitorIdType monitor_id);

/* [SWS_IdM_00204] Flush pending events (simulate DEM sync) */
STD_RETURN_TYPE IdsM_FlushEvents(IdsM_MonitorIdType monitor_id);

/* [SWS_IdM_00300] Register DEM report callback */
void IdsM_SetDemReportCallback(IdsM_DemReportCallback cb);

/* [SWS_IdM_00301] Register NVM store callback */
void IdsM_SetNvmStoreCallback(IdsM_NvmStoreCallback cb);

#ifdef __cplusplus
}
#endif