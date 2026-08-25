#pragma once

#include "IdsM_Types.h"

/* IDSRM-specific return codes */
#define E_IDSRM_DISABLED    ((uint8_t)0x10)
#define E_IDSRM_NOT_INIT    ((uint8_t)0x11)
#define E_IDSRM_QUEUE_FULL  ((uint8_t)0x12)
#define E_IDSRM_HTTP_FAIL   ((uint8_t)0x13)

/* Limits */
#define IDSRM_MAX_URL_LEN       256U
#define IDSRM_MAX_TOKEN_LEN     512U
#define IDSRM_MAX_RETRY_COUNT   10U
#define IDSRM_DEFAULT_QUEUE_DEPTH 128U

/* Configuration passed to IdsRm_Init() */
typedef struct {
    char     soc_url[IDSRM_MAX_URL_LEN];      /* e.g. "http://localhost:8080/api/idsm-violations" */
    char     auth_token[IDSRM_MAX_TOKEN_LEN]; /* Bearer token; empty string = no Authorization header */
    uint32_t timeout_ms;                       /* Per-request HTTP timeout */
    uint8_t  retry_count;                      /* Retries on HTTP failure (exponential backoff) */
    boolean  enabled;                          /* Initial enabled state */
} IdsRm_ConfigType;

/* Operational statistics snapshot */
typedef struct {
    uint32_t events_received;  /* Enqueued by DEM callback */
    uint32_t events_dropped;   /* Disabled or queue full */
    uint32_t events_posted;    /* Successfully POSTed (2xx) */
    uint32_t events_failed;    /* Exhausted all retries */
    uint32_t http_retries;     /* Total retry attempts across all events */
} IdsRm_StatsType;
