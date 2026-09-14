#pragma once
/*
 * alert.h — shared alert type for all eth_probe detectors.
 *
 * Every detector reports through the same fixed-size context layout
 * (contextDataVersion=1) so a single SEv (ext 0x8003) can carry all probe
 * alerts per the IDSM design rule "one layout per external event ID".
 * aux semantics depend on detector_type (rule sid / DoIP payload_type /
 * SOME-IP service_id / error codes ...).
 */
#include "packet.h"

#include <cstdint>

namespace ethprobe {

enum DetectorType : uint8_t {
    DT_PORT_SCAN     = 1,
    DT_RATE_FLOOD    = 2,
    DT_FLAG_ANOMALY  = 3,
    DT_RULE_HIT      = 4,
    DT_DOIP          = 5,
    DT_SOMEIP        = 6,
    DT_REASSEMBLY    = 7,
    DT_CROSS_BORDER  = 8,
    DT_TLS           = 9,
    DT_HTTP          = 10,
    DT_DNS           = 11,
    DT_ARP           = 12,
    DT_SURICATA      = 100,  /* rail-B eve_bridge alerts */
};

/* Host-order alert record; serialized big-endian at report time (main.cpp) */
struct ProbeAlert {
    uint8_t  detector_type = 0;
    uint8_t  proto         = 0;   /* IP_PROTO_* */
    uint16_t src_port      = 0;
    uint16_t dst_port      = 0;
    uint8_t  src_ip[16]{};
    uint8_t  dst_ip[16]{};
    uint32_t count         = 1;   /* pre-aggregated occurrences */
    uint32_t aux           = 0;   /* per-detector payload */
};

/* Fill src/dst ip+port and proto from a parsed packet */
ProbeAlert make_alert(uint8_t detector_type, const ParsedPacket& pp, uint32_t aux);

} /* namespace ethprobe */
