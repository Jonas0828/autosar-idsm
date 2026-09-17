#pragma once
/*
 * alert.h -- shared alert type for host_probe detectors.
 *
 * Every detector reports through the same fixed-size context layout
 * (contextDataVersion=1, HOST_CONTEXT_SIZE bytes) so the IDSM design
 * rule "one layout per external event ID" holds: ext 0x8021-0x802A,
 * one external event ID per detector type. aux semantics depend on
 * detector_type (see the aux code constants in detectors.h).
 */
#include "event.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace hostprobe {

enum DetectorType : uint8_t {
    DT_UNKNOWN_EXEC  = 1,  /* exec of binary not in allowlist        */
    DT_PRIV_ESC      = 2,  /* setuid-root exec by non-root user      */
    DT_FORK_FLOOD    = 3,  /* process-spawn rate storm (DoS)         */
    DT_REV_SHELL     = 4,  /* shell spawned by network-facing daemon */
    DT_FILE_MOD      = 5,  /* monitored file hash mismatch / missing */
    DT_NEW_SETUID    = 6,  /* new setuid-root file outside baseline  */
    DT_KMOD_LOAD     = 7,  /* kernel module outside baseline (Linux) */
    DT_ZOMBIE_STORM  = 8,  /* zombie process burst                   */
    DT_RES_EXHAUST   = 9,  /* per-process CPU / RSS exhaustion       */
    DT_ROOT_SHELL    = 10, /* uid-0 shell session                    */
};
constexpr uint8_t MAX_DETECTOR_TYPE = 10;

/* flag bits mirrored into context[1] */
constexpr uint8_t HF_SETUID     = 0x01;  /* exec gained root via setuid */
constexpr uint8_t HF_SETGID     = 0x02;  /* exec gained root via setgid */
constexpr uint8_t HF_MISSING    = 0x04;  /* monitored file vanished     */
constexpr uint8_t HF_NET_PARENT = 0x08;  /* parent is a network daemon  */

/* aux codes for DT_FILE_MOD */
inline constexpr uint32_t FILE_MOD_HASH = 1;  /* digest mismatch */
inline constexpr uint32_t FILE_MOD_GONE = 2;  /* file missing    */

/* aux codes for DT_RES_EXHAUST */
inline constexpr uint32_t RES_EXHAUST_CPU = 1;
inline constexpr uint32_t RES_EXHAUST_MEM = 2;

/* aux codes for DT_ROOT_SHELL */
inline constexpr uint32_t ROOT_SHELL_TTY = 1;  /* local console */
inline constexpr uint32_t ROOT_SHELL_NET = 2;  /* ssh/adb login */

/* serialized context size (contextDataVersion=1, big-endian fields):
 *   [0] detector_type   [1] flags (HF_*)
 *   [2..5] pid          [6..9] uid (file mode for file events)
 *   [10..13] count      [14..17] aux
 *   [18..29] name[12]   [30..31] reserved */
constexpr size_t HOST_CONTEXT_SIZE = 32;

/* host-order alert record; serialized big-endian at report time */
struct HostAlert {
    uint8_t  detector_type = 0;
    uint8_t  flags  = 0;
    uint32_t pid    = 0;
    uint32_t uid    = 0;
    uint32_t count  = 1;   /* pre-aggregated occurrences */
    uint32_t aux    = 0;   /* per-detector payload */
    char     name[12]{};   /* comm or file basename, NUL-padded */
};

HostAlert make_exec_alert(uint8_t dt, const ExecEvent& e,
                          uint8_t flags, uint32_t aux);
HostAlert make_file_alert(uint8_t dt, const std::string& path, uint32_t mode,
                          uint8_t flags, uint32_t aux);
HostAlert make_name_alert(uint8_t dt, const std::string& name);
HostAlert make_snap_alert(uint8_t dt, const SnapshotEvent& s, uint32_t aux);

} /* namespace hostprobe */
