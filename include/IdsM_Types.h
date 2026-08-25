#pragma once

/* AUTOSAR Standard Types (simulated) - Pure C compatible */
#include <stdint.h>
#include <stdbool.h>

typedef uint8_t  uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;
typedef bool     boolean;

/* Std_ReturnType simulation */
#define STD_RETURN_TYPE uint8_t
#define E_OK            ((uint8_t)0x00)
#define E_NOT_OK        ((uint8_t)0x01)
#define E_PARAM_POINTER ((uint8_t)0x02)
#define E_PARAM_CONFIG  ((uint8_t)0x03)
#define E_MODE_INVALID  ((uint8_t)0x04)

/* Monitor ID: Unique identifier per IDS algorithm/detector */
typedef uint16_t IdsM_MonitorIdType;

/* Event ID: Unique identifier per reported anomaly */
typedef uint16_t IdsM_EventIdType;

/* Operating Mode per [SWS_IdM_00012] */
typedef enum {
    IDSM_PRE_RUN_MODE = 0,
    IDSM_RUN_MODE     = 1,
    IDSM_POST_RUN_MODE= 2
} IdsM_OperatingModeType;

/* Detection Status per [SWS_IdM_00025] */
typedef enum {
    IDSM_STATUS_OK              = 0x00,
    IDSM_STATUS_VIOLATION       = 0x01,
    IDSM_STATUS_UNINITIALIZED   = 0x02,
    IDSM_STATUS_MODE_INVALID    = 0x03
} IdsM_DetectionStatusType;

/* Event Severity per [SWS_IdM_00030] */
typedef enum {
    IDSM_SEVERITY_LOW    = 0,
    IDSM_SEVERITY_MEDIUM = 1,
    IDSM_SEVERITY_HIGH   = 2,
    IDSM_SEVERITY_CRITICAL = 3
} IdsM_EventSeverityType;

/* Configuration structure (simulates ECUC) */
typedef struct {
    IdsM_MonitorIdType monitor_id;
    uint32_t event_buffer_size;
    uint32_t flood_protection_ms;
    IdsM_EventSeverityType severity_threshold;
    boolean enabled_in_pre_run;
    boolean enabled_in_run;
    boolean enabled_in_post_run;
} IdsM_MonitorConfigType;

/* Event report structure per [SWS_IdM_00040]
   payload is a caller-owned buffer; IDSM deep-copies it internally.
   Supports any size: CAN (13B), CAN-FD (69B), Ethernet (1514B), etc. */
typedef struct {
    IdsM_MonitorIdType     monitor_id;
    IdsM_EventIdType       event_id;
    uint32_t               timestamp_ms;
    const uint8_t*         payload;       /* caller-owned, copied on enqueue */
    uint16_t               payload_len;   /* actual byte count              */
    IdsM_EventSeverityType severity;
} IdsM_EventReportType;

/* Callback type for DEM integration (simulated) */
typedef void (*IdsM_DemReportCallback)(const IdsM_EventReportType* event);

/* Callback type for NVM integration (simulated) */
typedef void (*IdsM_NvmStoreCallback)(const IdsM_MonitorConfigType* config);

/* C++ guard for mixed C/C++ compilation */
#ifdef __cplusplus
extern "C" {
#endif

/* Public API declarations are in IdsM.h */

#ifdef __cplusplus
}
#endif