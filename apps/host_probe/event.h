#pragma once
/*
 * event.h -- host event model for host_probe.
 *
 * Normalized host-side events shared by every capture source
 * (netlink PROC_CONNECTOR live, /proc poller, --events replay)
 * and every detector. Fields are host order; serialization into
 * the IDSM context blob happens in main.cpp (see alert.h layout).
 */
#include <cstddef>
#include <cstdint>
#include <string>

namespace hostprobe {

enum class HostEventKind : uint8_t {
    EXEC = 1,        /* a process image was executed                */
    FILE_SCAN = 2,   /* one monitored file hashed on a scan         */
    MODULE_SCAN = 3, /* one kernel module observed on a scan        */
    SNAPSHOT = 4,    /* periodic /proc aggregate sample             */
};

/* linux task comm limit incl. NUL */
constexpr size_t COMM_LEN = 16;

struct ExecEvent {
    uint32_t    pid         = 0;
    uint32_t    ppid        = 0;
    uint32_t    uid         = 0;
    uint32_t    euid        = 0;
    uint32_t    gid         = 0;
    uint32_t    egid        = 0;
    char        comm[COMM_LEN]        {};
    char        parent_comm[COMM_LEN] {};  /* best effort, may be "" */
    std::string exe;   /* resolved binary path, may be empty */
};

struct FileScanEvent {
    std::string path;
    uint8_t     sha256[32]{};  /* all zero when the file is missing */
    bool        present = false;
    uint32_t    mode    = 0;   /* st_mode & 07777 */
    uint32_t    uid     = 0;   /* st_uid (owner) */
};

struct ModuleScanEvent {
    std::string name;
};

struct SnapshotEvent {
    uint32_t zombies = 0;
    /* hottest process since the previous sample (by CPU time) */
    uint32_t top_cpu_pid     = 0;
    uint32_t top_cpu_uid     = 0;
    uint32_t top_cpu_ppm     = 0;    /* cpu permille (1000 = 100%) */
    char     top_cpu_comm[COMM_LEN]{};
    /* largest resident set at sample time */
    uint32_t top_mem_pid    = 0;
    uint32_t top_mem_uid    = 0;
    uint64_t top_mem_rss_kb = 0;
    char     top_mem_comm[COMM_LEN]{};
};

struct HostEvent {
    HostEventKind   kind = HostEventKind::EXEC;
    uint64_t        ts_ms = 0;
    ExecEvent       exec;
    FileScanEvent   file;
    ModuleScanEvent module;
    SnapshotEvent   snap;
};

/*
 * Text replay format (--events FILE), one event per line:
 *
 *   exec   <ts_ms> <pid> <ppid> <uid> <euid> <gid> <egid> <comm> <parent_comm> [exe path]
 *   file   <ts_ms> <path> <present 0|1> <mode_octal> <uid> <sha256_hex|->
 *   module <ts_ms> <name>
 *   snap   <ts_ms> <zombies> <cpu_pid> <cpu_uid> <cpu_ppm> <cpu_comm>
 *          <mem_pid> <mem_uid> <mem_rss_kb> <mem_comm>
 *
 * Blank lines and lines starting with '#' are ignored. Returns false
 * for unrecognized or malformed lines.
 */
bool parse_host_event(const std::string& line, HostEvent& out);

} /* namespace hostprobe */
