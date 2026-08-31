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

/* ── Security Event identity (CP §7.3.2 / PRS §5.1.4.3) ─────────────────────
   A SEv is identified by the tuple (external event ID, sensor instance ID).
   Sensors report via the internal ID (index into the SEv config array),
   exposed to applications as symbolic name constants. */
typedef uint16_t IdsM_SecurityEventIdType;          /* CP §8.2.2 internal ID  */
typedef uint16_t IdsM_ExternalSecurityEventIdType;  /* CP §8.2.7 external ID  */
typedef uint8_t  IdsM_SensorInstanceIdType;         /* 0..63  [PRS_Ids_00014] */

/* Event Definition ID ranges [PRS_Ids_00017]:
     0x0000-0x7FFF  AUTOSAR internal (e.g. Firewall SEvs 50-77)
     0x8000-0xFFFE  OEM / customer specific
     0xFFFF         invalid [SWS_IdsM_00604] */
#define IDSM_EXTERNAL_EVENT_ID_INVALID  ((IdsM_ExternalSecurityEventIdType)0xFFFFu)
#define IDSM_EXTERNAL_EVENT_ID_OEM_BASE ((IdsM_ExternalSecurityEventIdType)0x8000u)

/* IdsM instance ID: 10 bit (0..1023) [PRS_Ids_00013] */
#define IDSM_INSTANCE_ID_MAX  1023u

/* ── Detection Status (project extension, not in CP spec) ────────────────── */
typedef enum {
    IDSM_STATUS_OK              = 0x00,
    IDSM_STATUS_VIOLATION       = 0x01,
    IDSM_STATUS_UNINITIALIZED   = 0x02
} IdsM_DetectionStatusType;

/* Event Severity — configuration property of the SEv (R23-11), not a
   report-time parameter */
typedef enum {
    IDSM_SEVERITY_LOW      = 0,
    IDSM_SEVERITY_MEDIUM   = 1,
    IDSM_SEVERITY_HIGH     = 2,
    IDSM_SEVERITY_CRITICAL = 3
} IdsM_EventSeverityType;

/* ── Timestamp (PRS §5.1.5) ──────────────────────────────────────────────── */
typedef enum {
    IDSM_TIMESTAMP_SOURCE_AUTOSAR = 0,  /* StbM (simulated: system clock) */
    IDSM_TIMESTAMP_SOURCE_OEM     = 1   /* sensor / application provided  */
} IdsM_TimestampSourceType;

/* Wire format: 30 bit nanoseconds + 32 bit seconds + 1 bit source */
typedef struct {
    uint32_t                 seconds;      /* 32 bit [PRS_Ids_00407]          */
    uint32_t                 nanoseconds;  /* valid 30 bit [PRS_Ids_00406]    */
    IdsM_TimestampSourceType source;
} IdsM_TimestampDataType;

/* ── Reporting Mode (CP §7.6.1.1 / §8.2.4 / RS_Ids_00310) ──────────────────
   Mandatory per-SEv decision made BEFORE the filter chain:
     OFF                          discard without further processing
     BRIEF                        drop context data, then run filter chain
     DETAILED                     keep context data, then run filter chain
     BRIEF_BYPASSING_FILTERS      drop context data, qualify immediately
     DETAILED_BYPASSING_FILTERS   keep context data, qualify immediately */
typedef enum {
    IDSM_REPORTING_OFF                        = 0,
    IDSM_REPORTING_BRIEF                      = 1,
    IDSM_REPORTING_DETAILED                   = 2,
    IDSM_REPORTING_BRIEF_BYPASSING_FILTERS    = 3,
    IDSM_REPORTING_DETAILED_BYPASSING_FILTERS = 4
} IdsM_Filters_ReportingModeType;

/* ── QSEv: Qualified Security Event (CP §7.8.1 + PRS §5.1) ─────────────────
   A SEv that passed the reporting mode check and the filter chain.
   Memory form; IdsM_Protocol.c serializes it to the IDS Message wire format.
   context_data is only valid while the owning object/callback scope lives. */
typedef struct {
    uint16_t                           idsm_instance_id;     /* 10 bit valid */
    IdsM_ExternalSecurityEventIdType   external_event_id;
    IdsM_SensorInstanceIdType          sensor_instance_id;   /* 6 bit valid  */
    IdsM_EventSeverityType             severity;             /* from SEv config (project ext.) */
    uint16_t                           count;                /* >=1 [PRS_Ids_00018] */
    boolean                            has_timestamp;        /* -> header bit1 */
    IdsM_TimestampDataType             timestamp;
    uint16_t                           context_data_version; /* R24-11 */
    const uint8_t*                     context_data;         /* NULL/empty -> header bit0 = 0 */
    uint16_t                           context_data_size;
} IdsM_QualifiedSecurityEventType;

/* ── Filter chain configuration (CP §7.6) ────────────────────────────────── */
typedef uint8_t IdsM_BlockStateIdType;  /* symbolic state ID, BswM domain */

typedef struct {
    IdsM_BlockStateIdType blocked_states[8];  /* IdsMBlockState list */
    uint8_t               num_blocked_states; /* 0 = always pass   */
} IdsM_BlockStateFilterConfigType;

/* Per-SEv configuration (replaces IdsM_MonitorConfigType).
   Filter fields set to 0/NULL disable the corresponding filter. */
typedef struct {
    IdsM_ExternalSecurityEventIdType       external_event_id;
    IdsM_SensorInstanceIdType              sensor_instance_id;
    IdsM_EventSeverityType                 severity;
    IdsM_Filters_ReportingModeType         default_reporting_mode;
    /* Filter chain (evaluated in fixed order blockState -> fwdNth -> aggregation -> threshold) */
    const IdsM_BlockStateFilterConfigType* block_state;             /* NULL = disabled */
    uint16_t                               forward_every_nth;       /* 0 = disabled    */
    uint32_t                               aggregation_interval_ms; /* 0 = disabled    */
    struct {
        uint16_t threshold;               /* 0 = disabled */
        uint32_t interval_ms;
    } event_threshold;
    /* Sinks for the resulting QSEv [SWS_IdsM_01201] */
    boolean                                sink_to_dem;
    boolean                                sink_to_idsr;
} IdsM_SecurityEventConfigType;

/* Instance-level configuration (CP §8.2.1) */
typedef struct {
    uint16_t                             idsm_instance_id;        /* 10 bit valid */
    uint32_t                             main_function_period_ms; /* worker tick  */
    struct {                                       /* instance-wide, 0 = disabled */
        uint32_t max_events;
        uint32_t interval_ms;
    } rate_limitation;
    struct {
        uint32_t max_bytes;
        uint32_t interval_ms;
    } traffic_limitation;
    const IdsM_SecurityEventConfigType*  sev_configs;
    uint16_t                             sev_count;
    uint32_t                             event_buffer_size;       /* ingress queue depth */
} IdsM_ConfigType;

/* ── Sink callbacks (receive QSEvs after qualification) ──────────────────── */
typedef void (*IdsM_QsevSinkCallbackType)(const IdsM_QualifiedSecurityEventType* qsev);

/* NVM store callback (simulated) */
typedef void (*IdsM_NvmStoreCallback)(const IdsM_ConfigType* config);

/* ── Deprecated compatibility types (removed next iteration) ─────────────── */
typedef uint16_t IdsM_MonitorIdType;
typedef uint16_t IdsM_EventIdType;

typedef struct {
    IdsM_MonitorIdType     monitor_id;    /* interpreted as internal SEv ID */
    IdsM_EventIdType       event_id;      /* ignored: identity comes from SEv config */
    uint32_t               timestamp_ms;  /* converted to internal timestamp */
    const uint8_t*         payload;
    uint16_t               payload_len;
    IdsM_EventSeverityType severity;      /* ignored: severity comes from SEv config */
} IdsM_EventReportType;

#ifdef __cplusplus
extern "C" {
#endif

/* Public API declarations are in IdsM.h */

#ifdef __cplusplus
}
#endif
