#pragma once
/*
 * alert.h -- shared alert type for all can_probe detectors.
 *
 * Every detector reports through the same fixed-size context layout
 * (contextDataVersion=1, CAN_CONTEXT_SIZE bytes) so the IDSM design
 * rule "one layout per external event ID" holds. aux semantics depend
 * on detector_type (see the aux code constants in detectors.h).
 */
#include "frame.h"

#include <cstddef>
#include <cstdint>

namespace canprobe {

enum DetectorType : uint8_t {
    DT_UNKNOWN_ID     = 1,   /* frame ID not in the vehicle whitelist    */
    DT_ID_FLOOD       = 2,   /* single-ID flood (DoS on one message)     */
    DT_BUS_FLOOD      = 3,   /* bus-wide frame flood                     */
    DT_ERROR_BURST    = 4,   /* error frame burst (bus-off / fault inj.) */
    DT_DLC_ANOMALY    = 5,   /* invalid DLC / FD len                     */
    DT_REMOTE_FRAME   = 6,   /* unexpected remote transmission request   */
    DT_UDS_SEC_ACCESS = 7,   /* SecurityAccess (0x27) brute force        */
    DT_UDS_SVC_SCAN   = 8,   /* diagnostic service scanning              */
    DT_DIAG_FLOOD     = 9,   /* diagnostic request flood                 */
    DT_CYCLE_ANOMALY  = 10,  /* periodic message faster than min cycle   */
};
constexpr uint8_t MAX_DETECTOR_TYPE = 10;

/* frame flag bits mirrored into context[1] */
constexpr uint8_t CF_EFF = 0x01;
constexpr uint8_t CF_RTR = 0x02;
constexpr uint8_t CF_FD  = 0x04;
constexpr uint8_t CF_ERR = 0x08;

/* serialized context size (contextDataVersion=1, big-endian fields) */
constexpr size_t CAN_CONTEXT_SIZE = 16;

/* Host-order alert record; serialized big-endian at report time (main.cpp) */
struct CanAlert {
    uint8_t  detector_type = 0;
    uint32_t can_id        = 0;
    bool     eff = false;
    bool     rtr = false;
    bool     fd  = false;
    bool     err = false;
    uint32_t count = 1;   /* pre-aggregated occurrences */
    uint32_t aux   = 0;   /* per-detector payload */
};

/* Fill can_id + flags from a parsed frame */
CanAlert make_alert(uint8_t detector_type, const CanFrame& f, uint32_t aux);

} /* namespace canprobe */