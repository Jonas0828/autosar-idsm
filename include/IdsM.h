#pragma once
#include "IdsM_Types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* [SWS_IdsM_00100] Initialization: configures SEvs, filter chains, sinks;
   starts the async worker thread (MainFunction equivalent). */
STD_RETURN_TYPE IdsM_Init(const IdsM_ConfigType* config);

/* [SWS_IdsM_00101] De-initialization */
STD_RETURN_TYPE IdsM_DeInit(void);

/* [SWS_IdsM_00102] Main function — no-op in this async implementation;
   the worker thread performs the periodic processing. */
void IdsM_MainFunction(void);

/* [SWS_IdsM_91038] Report a security event (R24-11 reporting API).
   Non-blocking: deep-copies context data into the ingress queue (<1us).
   count: occurrences already aggregated by the sensor, range [1, 65535].
   timestamp: NULL -> IdsM stamps internally (AUTOSAR source). */
void IdsM_ReportSecurityEvent(IdsM_SecurityEventIdType securityEventId,
                              const uint8* contextData,
                              uint16 contextDataSize,
                              uint16 contextDataVersion,
                              uint16 count,
                              const IdsM_TimestampDataType* timestamp);

/* Runtime query/update of the per-SEv reporting mode (RS_Ids_00700) */
IdsM_Filters_ReportingModeType IdsM_GetReportingMode(IdsM_SecurityEventIdType securityEventId);
STD_RETURN_TYPE IdsM_SetReportingMode(IdsM_SecurityEventIdType securityEventId,
                                      IdsM_Filters_ReportingModeType mode);

/* [SWS_IdsM_91026] BswM notification of the current IdsM block state.
   Drives the Block State filters (evaluated asynchronously in the worker). */
void IdsM_BswM_StateChanged(IdsM_BlockStateIdType state);

/* Register the Dem sink callback (QSEv storage; simulated) */
void IdsM_SetDemReportCallback(IdsM_QsevSinkCallbackType cb);

/* Register the IdsR sink callback (QSEv propagation; IdsRm uses this) */
void IdsM_RegisterIdsrSink(IdsM_QsevSinkCallbackType cb);

/* [SWS_IdsM_00301] Register NVM store callback (simulated) */
void IdsM_SetNvmStoreCallback(IdsM_NvmStoreCallback cb);

/* Detection status (project extension, per security event) */
IdsM_DetectionStatusType IdsM_GetDetectionStatus(IdsM_SecurityEventIdType securityEventId);
STD_RETURN_TYPE IdsM_ResetDetectionStatus(IdsM_SecurityEventIdType securityEventId);

/* Number of reported events for this SEv not yet processed by the worker */
uint32 IdsM_GetPendingEventCount(IdsM_SecurityEventIdType securityEventId);

/* Flush buffered events for this SEv to the sinks (no-op until the
   aggregation filter lands; validates the SEv ID) */
STD_RETURN_TYPE IdsM_FlushEvents(IdsM_SecurityEventIdType securityEventId);

/* TRUE if the SEv ID refers to a configured security event */
boolean IdsM_IsSecurityEventConfigured(IdsM_SecurityEventIdType securityEventId);

/* ── Deprecated compatibility API (removed next iteration) ─────────────────
   monitor_id is interpreted as the internal SEv ID; event_id and severity
   are ignored (both now come from the SEv configuration). */
STD_RETURN_TYPE IdsM_ReportEvent(const IdsM_EventReportType* event);

#ifdef __cplusplus
}
#endif
