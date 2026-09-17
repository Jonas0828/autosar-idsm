#include "frame.h"

#include <cstring>

namespace canprobe {

bool parse_can_frame(const uint8_t* p, size_t n, CanFrame& out) {
    if (p == nullptr) return false;

    if (n == CAN_FRAME_LEN || n == CANFD_FRAME_LEN) {
        CanFrame f;
        uint32_t raw_id;
        /* SocketCAN stores can_id in the capture host's byte order;
           virtually always little-endian (same assumption candump makes) */
        std::memcpy(&raw_id, p, 4);

        f.eff = (raw_id & CAN_EFF_FLAG) != 0;
        f.rtr = (raw_id & CAN_RTR_FLAG) != 0;
        f.err = (raw_id & CAN_ERR_FLAG) != 0;
        f.can_id = raw_id & (f.eff ? CAN_ID_EFF : CAN_ID_SFF);

        const uint8_t dlc = p[4];  /* can_frame.dlc / canfd_frame.len */
        f.dlc = dlc;
        if (n == CAN_FRAME_LEN) {
            f.len = dlc <= 8 ? dlc : 8;  /* 8 payload bytes physically present */
            std::memcpy(f.data, p + 8, 8);
        } else {
            f.fd  = true;
            f.len = dlc <= 64 ? dlc : 64;
            std::memcpy(f.data, p + 8, 64);
        }
        out = f;
        return true;
    }
    return false;
}

bool is_diag_request_id(uint32_t id) {
    return id == 0x7DF || (id >= 0x7E0 && id <= 0x7E7);
}

bool is_diag_response_id(uint32_t id) {
    return id >= 0x7E8 && id <= 0x7EF;
}

} /* namespace canprobe */