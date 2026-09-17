#include "alert.h"

namespace canprobe {

CanAlert make_alert(uint8_t detector_type, const CanFrame& f, uint32_t aux) {
    CanAlert a;
    a.detector_type = detector_type;
    a.can_id        = f.can_id;
    a.eff           = f.eff;
    a.rtr           = f.rtr;
    a.fd            = f.fd;
    a.err           = f.err;
    a.aux           = aux;
    return a;
}

} /* namespace canprobe */