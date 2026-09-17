#pragma once
#include "IdsRm_Types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize IDSRM, register as the IDSM IdsR sink (receives QSEvs after
   qualification), and start background worker.
   Must be called after IdsM_Init(). Calls curl_global_init internally. */
STD_RETURN_TYPE IdsRm_Init(const IdsRm_ConfigType* config);

/* Stop background worker, flush in-flight events, curl cleanup, unregister IdsR sink.
   Calls curl_global_cleanup internally. */
STD_RETURN_TYPE IdsRm_DeInit(void);

/* Enable forwarding. No-op if already enabled. */
STD_RETURN_TYPE IdsRm_Enable(void);

/* Disable forwarding. Events received while disabled are silently dropped.
   Worker thread keeps running so re-enable is instant. */
STD_RETURN_TYPE IdsRm_Disable(void);

/* Returns true if initialized AND enabled. */
boolean IdsRm_IsEnabled(void);

/* Update SOC URL at runtime (thread-safe). Takes effect on next POST. */
STD_RETURN_TYPE IdsRm_SetSocUrl(const char* url);

/* Update auth bearer token at runtime (thread-safe).
   Pass "" to remove the Authorization header. */
STD_RETURN_TYPE IdsRm_SetAuthToken(const char* token);

/* Local UDS sink for the production vehicle path: forward every event as
   one NDJSON line (same JSON schema as the HTTP body) to a unix-domain
   STREAM socket served by the IDSM manager APK. Fire-and-forget: events
   are dropped while the peer is down (the APK owns the durable queue).
   If soc_url is empty and a sink is configured, the HTTP path is skipped.
   Callable before IdsRm_Init() (applied at init) or at runtime.
   Pass "" or NULL to disable. */
STD_RETURN_TYPE IdsRm_SetLocalSink(const char* path);

/* Get a snapshot of operational statistics. */
IdsRm_StatsType IdsRm_GetStats(void);

/* Reset all statistics counters to zero. */
void IdsRm_ResetStats(void);

#ifdef __cplusplus
}
#endif
