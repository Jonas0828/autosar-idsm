#include "alert.h"

#include <cstring>

namespace ethprobe {

ProbeAlert make_alert(uint8_t detector_type, const ParsedPacket& pp, uint32_t aux) {
    ProbeAlert a;
    a.detector_type = detector_type;
    a.proto    = pp.l4_proto;
    a.src_port = pp.src_port;
    a.dst_port = pp.dst_port;
    std::memcpy(a.src_ip, pp.src_ip, 16);
    std::memcpy(a.dst_ip, pp.dst_ip, 16);
    a.aux = aux;
    return a;
}

} /* namespace ethprobe */
