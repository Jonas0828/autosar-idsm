#pragma once
/*
 * proto_doip.h — DoIP (ISO 13400) header parsing and anomaly checks.
 *
 * DoIP runs on TCP/UDP 13400. Header (8 bytes):
 *   version(1) | ~version(1) | payload_type(2) | payload_length(4)
 */
#include <cstddef>
#include <cstdint>

namespace ethprobe {

inline constexpr uint16_t DOIP_PORT = 13400;

/* payload types we care about */
inline constexpr uint16_t DOIP_PT_VEHICLE_IDENT       = 0x0001;
inline constexpr uint16_t DOIP_PT_ROUTING_ACTIVATION  = 0x0005;
inline constexpr uint16_t DOIP_PT_ALIVE_CHECK         = 0x0007;
inline constexpr uint16_t DOIP_PT_DIAG_MESSAGE        = 0x8001;
inline constexpr uint16_t DOIP_PT_DIAG_MESSAGE_ACK    = 0x8002;
inline constexpr uint16_t DOIP_PT_DIAG_MESSAGE_NACK   = 0x8003;

enum DoipError : int {
    DOIP_OK = 0,
    DOIP_ERR_TRUNCATED      = 1,  /* shorter than the 8-byte header */
    DOIP_ERR_VERSION_INVERSE = 2, /* version != ~inverse */
    DOIP_ERR_UNKNOWN_VERSION = 3, /* not 0x02/0x03 (ISO 13400-2:2012/2019) */
    DOIP_ERR_LENGTH          = 4, /* declared payload longer than available */
    DOIP_ERR_UNKNOWN_TYPE    = 5, /* reserved/unknown payload_type */
};

struct DoipInfo {
    bool     valid = false;
    uint8_t  version      = 0;
    uint16_t payload_type = 0;
    uint32_t payload_len  = 0;
    const uint8_t* payload = nullptr;   /* view into input */
    size_t         avail   = 0;         /* bytes present after header */
    int      error = DOIP_OK;
};

DoipInfo parse_doip(const uint8_t* data, size_t len);

/*
 * Inspection verdict for one DoIP message. aux values for ProbeAlert:
 *   error codes (DOIP_ERR_*) for malformed messages, or the payload_type
 *   for notable-but-valid messages (routing activation = potential
 *   unauthorized diagnostic access).
 */
struct DoipVerdict {
    bool     alert = false;
    uint32_t aux   = 0;
};

DoipVerdict inspect_doip(const DoipInfo& info);

} /* namespace ethprobe */
