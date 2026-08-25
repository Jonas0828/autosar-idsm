#pragma once
#include "IdsRm_Types.h"
#include "IdsM_Types.h"

/* C-bridge declarations consumed by IdsRm.c.
   Implementations live in IdsRm_Manager.cpp. */

#ifdef __cplusplus
extern "C" {
#endif

STD_RETURN_TYPE IdsRm_Core_Init(const IdsRm_ConfigType* config);
STD_RETURN_TYPE IdsRm_Core_DeInit(void);
STD_RETURN_TYPE IdsRm_Core_Enable(void);
STD_RETURN_TYPE IdsRm_Core_Disable(void);
boolean         IdsRm_Core_IsEnabled(void);
STD_RETURN_TYPE IdsRm_Core_SetSocUrl(const char* url);
STD_RETURN_TYPE IdsRm_Core_SetAuthToken(const char* token);
IdsRm_StatsType IdsRm_Core_GetStats(void);
void            IdsRm_Core_ResetStats(void);

/* Static C-compatible shim registered with IdsM_SetDemReportCallback */
void IdsRm_Core_DemCallbackShim(const IdsM_EventReportType* event);

#ifdef __cplusplus
}
#endif
