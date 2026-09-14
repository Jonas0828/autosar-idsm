#include "proto_doip.h"

namespace ethprobe {

namespace {

inline uint16_t rd16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}
inline uint32_t rd32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |  static_cast<uint32_t>(p[3]);
}

bool known_payload_type(uint16_t t) {
    switch (t) {
        case 0x0000:  /* generic DoIP header NACK */
        case DOIP_PT_VEHICLE_IDENT:
        case 0x0002:  /* vehicle ident w/ VIN */
        case 0x0003:  /* vehicle ident w/ EID */
        case 0x0004:  /* vehicle ident w/ GID */
        case DOIP_PT_ROUTING_ACTIVATION:
        case 0x0006:  /* routing activation response */
        case DOIP_PT_ALIVE_CHECK:
        case 0x0008:  /* alive check response */
        case 0x4001:  /* entity status request */
        case 0x4002:  /* entity status response */
        case 0x4003:  /* power mode request */
        case 0x4004:  /* power mode response */
        case DOIP_PT_DIAG_MESSAGE:
        case DOIP_PT_DIAG_MESSAGE_ACK:
        case DOIP_PT_DIAG_MESSAGE_NACK:
            return true;
        default:
            return false;
    }
}

} /* namespace */

DoipInfo parse_doip(const uint8_t* data, size_t len) {
    DoipInfo i;
    if (data == nullptr || len < 8) {
        i.error = DOIP_ERR_TRUNCATED;
        return i;
    }
    i.version      = data[0];
    i.payload_type = rd16(data + 2);
    i.payload_len  = rd32(data + 4);
    i.payload      = data + 8;
    i.avail        = len - 8;

    if (data[0] != static_cast<uint8_t>(~data[1])) {
        i.error = DOIP_ERR_VERSION_INVERSE;
        return i;
    }
    if (i.version != 0x02 && i.version != 0x03) {
        i.error = DOIP_ERR_UNKNOWN_VERSION;
        return i;
    }
    if (i.payload_len > i.avail) {
        i.error = DOIP_ERR_LENGTH;
        return i;
    }
    if (!known_payload_type(i.payload_type)) {
        i.error = DOIP_ERR_UNKNOWN_TYPE;
        return i;
    }
    i.valid = true;
    return i;
}

DoipVerdict inspect_doip(const DoipInfo& info) {
    DoipVerdict v;
    if (!info.valid) {
        if (info.error != DOIP_ERR_TRUNCATED) {  /* truncation may be stream reassembly lag */
            v.alert = true;
            v.aux   = static_cast<uint32_t>(info.error);
        }
        return v;
    }
    /* Routing activation request: a tester is requesting diagnostic access —
       the key event for unauthorized-flashing detection (GB 44496). */
    if (info.payload_type == DOIP_PT_ROUTING_ACTIVATION) {
        v.alert = true;
        v.aux   = DOIP_PT_ROUTING_ACTIVATION;
    }
    return v;
}

} /* namespace ethprobe */
