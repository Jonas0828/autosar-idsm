#pragma once
/*
 * frame.h -- SocketCAN frame model for can_probe.
 *
 * Parses the two record layouts used throughout Linux:
 *   16-byte struct can_frame   -- classic CAN 2.0
 *   72-byte struct canfd_frame -- CAN-FD (CAN_RAW_FD_FRAMES / pcap)
 * Both are what a CAN_RAW socket returns and what pcap
 * LINKTYPE_CAN_SOCKETCAN (227) records contain, so live capture and
 * offline replay share one parser.
 */
#include <cstddef>
#include <cstdint>

namespace canprobe {

/* SocketCAN can_id flag bits (mirrors linux/can.h) */
constexpr uint32_t CAN_EFF_FLAG = 0x80000000U;  /* 29-bit identifier */
constexpr uint32_t CAN_RTR_FLAG = 0x40000000U;  /* remote transmission request */
constexpr uint32_t CAN_ERR_FLAG = 0x20000000U;  /* error frame */
constexpr uint32_t CAN_ID_EFF   = 0x1FFFFFFFU;
constexpr uint32_t CAN_ID_SFF   = 0x000007FFU;

/* pcap global-header network value for SocketCAN captures */
constexpr uint32_t LINKTYPE_CAN_SOCKETCAN = 227;

/* Sizes of the SocketCAN record layouts */
constexpr size_t CAN_FRAME_LEN   = 16;  /* struct can_frame  */
constexpr size_t CANFD_FRAME_LEN = 72;  /* struct canfd_frame */

/* Parsed CAN / CAN-FD frame, host order */
struct CanFrame {
    uint32_t can_id = 0;   /* identifier, flag bits stripped */
    bool     eff    = false;
    bool     rtr    = false;
    bool     err    = false;
    bool     fd     = false;
    uint8_t  dlc    = 0;   /* DLC / FD len field exactly as received */
    uint8_t  len    = 0;   /* valid payload bytes in data[] */
    uint8_t  data[64]{};
};

/*
 * Parse one raw SocketCAN record. Out-of-range DLC/len values are kept
 * in the frame (dlc as received, len clamped to the physically present
 * bytes) so the DLC-anomaly detector can report them; only structurally
 * impossible records fail (wrong size / null buffer).
 */
bool parse_can_frame(const uint8_t* data, size_t len, CanFrame& out);

/* Diagnostics addressing (ISO 15765 / UDS): functional request 0x7DF,
 * physical requests 0x7E0-0x7E7, responses 0x7E8-0x7EF. */
bool is_diag_request_id(uint32_t can_id);
bool is_diag_response_id(uint32_t can_id);

} /* namespace canprobe */