#include "IdsRm.h"
#include "IdsRm_Manager_Wrapper.h"

STD_RETURN_TYPE IdsRm_Init(const IdsRm_ConfigType* config) {
    if (!config) return E_PARAM_POINTER;
    return IdsRm_Core_Init(config);
}

STD_RETURN_TYPE IdsRm_DeInit(void) {
    return IdsRm_Core_DeInit();
}

STD_RETURN_TYPE IdsRm_Enable(void) {
    return IdsRm_Core_Enable();
}

STD_RETURN_TYPE IdsRm_Disable(void) {
    return IdsRm_Core_Disable();
}

boolean IdsRm_IsEnabled(void) {
    return IdsRm_Core_IsEnabled();
}

STD_RETURN_TYPE IdsRm_SetSocUrl(const char* url) {
    if (!url) return E_PARAM_POINTER;
    return IdsRm_Core_SetSocUrl(url);
}

STD_RETURN_TYPE IdsRm_SetAuthToken(const char* token) {
    if (!token) return E_PARAM_POINTER;
    return IdsRm_Core_SetAuthToken(token);
}

IdsRm_StatsType IdsRm_GetStats(void) {
    return IdsRm_Core_GetStats();
}

void IdsRm_ResetStats(void) {
    IdsRm_Core_ResetStats();
}
