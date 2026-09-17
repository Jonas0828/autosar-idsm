/*
 * alert.cpp -- HostAlert factory helpers (see alert.h).
 */
#include "alert.h"

#include <cstring>

namespace hostprobe {

namespace {

/* copy the basename of s into the fixed 12-byte name field */
void fill_name(char (&dst)[12], const std::string& s) {
    std::memset(dst, 0, sizeof(dst));
    std::string base = s;
    const auto pos = base.find_last_of('/');
    if (pos != std::string::npos) base = base.substr(pos + 1);
    if (base.size() > 11) base.resize(11);
    std::memcpy(dst, base.data(), base.size());
}

} /* namespace */

HostAlert make_exec_alert(uint8_t dt, const ExecEvent& e,
                          uint8_t flags, uint32_t aux) {
    HostAlert a;
    a.detector_type = dt;
    a.flags  = flags;
    a.pid    = e.pid;
    a.uid    = e.uid;
    a.aux    = aux;
    fill_name(a.name, e.comm[0] != '\0' ? std::string(e.comm) : e.exe);
    return a;
}

HostAlert make_file_alert(uint8_t dt, const std::string& path, uint32_t mode,
                          uint8_t flags, uint32_t aux) {
    HostAlert a;
    a.detector_type = dt;
    a.flags  = flags;
    a.uid    = mode;   /* context[6..9] carries the mode for file events */
    a.aux    = aux;
    fill_name(a.name, path);
    return a;
}

HostAlert make_name_alert(uint8_t dt, const std::string& name) {
    HostAlert a;
    a.detector_type = dt;
    fill_name(a.name, name);
    return a;
}

HostAlert make_snap_alert(uint8_t dt, const SnapshotEvent& s, uint32_t aux) {
    HostAlert a;
    a.detector_type = dt;
    a.aux = aux;
    if (aux == RES_EXHAUST_MEM) {
        a.pid = s.top_mem_pid;
        a.uid = s.top_mem_uid;
        fill_name(a.name, s.top_mem_comm);
    } else {
        a.pid = s.top_cpu_pid;
        a.uid = s.top_cpu_uid;
        fill_name(a.name, s.top_cpu_comm);
    }
    return a;
}

} /* namespace hostprobe */
