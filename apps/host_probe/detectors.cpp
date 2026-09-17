/*
 * detectors.cpp -- host anomaly detector implementations (see
 * detectors.h). Alert-once semantics inside a window, per-key muting
 * afterwards; the pipeline emits through a single callback.
 */
#include "detectors.h"

#include <cstring>
#include <utility>

namespace hostprobe {

namespace {

std::string base_name(const std::string& p) {
    const auto pos = p.find_last_of('/');
    return pos == std::string::npos ? p : p.substr(pos + 1);
}

/* stable per-binary mute key: prefer exe path, fall back to comm */
std::string alert_key(const ExecEvent& e) {
    return e.exe.empty() ? std::string(e.comm) : e.exe;
}

bool muted_until(const std::map<std::string, uint64_t>& muted,
                 const std::string& key, uint64_t now_ms) {
    const auto it = muted.find(key);
    return it != muted.end() && it->second > now_ms;
}

} /* namespace */

bool is_shell_comm(const std::string& comm) {
    static const std::set<std::string> k_shells = {
        "sh", "bash", "ash", "dash", "zsh",
        "ksh", "mksh", "toysh", "csh", "tcsh", "fish"};
    return k_shells.count(comm) != 0;
}

/* ---- 1: unknown exec ---- */

void UnknownExecDetector::add_allowed(const std::string& entry) {
    if (entry.find('/') != std::string::npos)
        exact_.insert(entry);
    else
        base_.insert(entry);
}

bool UnknownExecDetector::is_allowed(const ExecEvent& e) const {
    if (!e.exe.empty()) {
        if (exact_.count(e.exe)) return true;
        if (base_.count(base_name(e.exe))) return true;
    }
    return base_.count(e.comm) != 0;
}

std::optional<HostAlert> UnknownExecDetector::feed(const ExecEvent& e,
                                                   uint64_t now_ms) {
    if (!enabled() || is_allowed(e)) return std::nullopt;
    const std::string key = alert_key(e);
    if (muted_until(muted_, key, now_ms)) return std::nullopt;
    muted_[key] = now_ms + cfg_.cooldown_ms;
    return make_exec_alert(DT_UNKNOWN_EXEC, e, 0, 0);
}

/* ---- 2: privilege escalation ---- */

std::optional<HostAlert> PrivEscDetector::feed(const ExecEvent& e,
                                               uint64_t now_ms) {
    /* euid 0 reached from a non-root real uid: setuid-root exec */
    if (e.euid != 0 || e.uid == 0) return std::nullopt;
    const std::string key = alert_key(e);
    if (muted_until(muted_, key, now_ms)) return std::nullopt;
    muted_[key] = now_ms + cfg_.cooldown_ms;
    uint8_t flags = HF_SETUID;
    if (e.egid == 0 && e.gid != 0) flags |= HF_SETGID;
    return make_exec_alert(DT_PRIV_ESC, e, flags, 0);
}

/* ---- 3: fork flood ---- */

ForkFloodDetector::ForkFloodDetector() = default;
ForkFloodDetector::ForkFloodDetector(const Config& cfg) : cfg_(cfg) {}

std::optional<HostAlert> ForkFloodDetector::feed(const ExecEvent& e,
                                                 uint64_t now_ms) {
    (void)e;
    if (!state_.started) {
        state_.started      = true;
        state_.window_start = now_ms;
    }
    if (now_ms - state_.window_start >= cfg_.window_ms) {
        state_.window_start = now_ms;
        state_.count        = 0;
        state_.alerted      = false;
    }
    ++state_.count;
    if (!state_.alerted && state_.count >= cfg_.spawn_threshold) {
        state_.alerted = true;
        HostAlert a;
        a.detector_type = DT_FORK_FLOOD;
        a.count = state_.count;
        a.aux   = state_.count;
        return a;
    }
    return std::nullopt;
}

/* ---- 4: reverse shell ---- */

RevShellDetector::RevShellDetector() {
    /* default network-facing daemons (Android + Linux servers) */
    static const char* const k_default[] = {
        "adbd", "sshd", "dropbear", "netd", "rild", "httpd", "nginx",
        "lighttpd", "inetd", "xinetd", "ftpd", "vsftpd", "proftpd",
        "telnetd", "smbd"};
    for (const char* s : k_default) net_parents_.insert(s);
}

RevShellDetector::RevShellDetector(const Config& cfg) : RevShellDetector() {
    cfg_ = cfg;
}

void RevShellDetector::add_net_parent(const std::string& comm) {
    net_parents_.insert(comm);
}

std::optional<HostAlert> RevShellDetector::feed(const ExecEvent& e,
                                                uint64_t now_ms) {
    if (!is_shell_comm(e.comm)) return std::nullopt;
    const std::string parent(e.parent_comm);
    if (parent.empty() || !net_parents_.count(parent)) return std::nullopt;
    if (muted_until(muted_, parent, now_ms)) return std::nullopt;
    muted_[parent] = now_ms + cfg_.cooldown_ms;
    HostAlert a = make_exec_alert(DT_REV_SHELL, e, HF_NET_PARENT, e.ppid);
    return a;
}

/* ---- 5: file integrity ---- */

std::optional<HostAlert> FileModDetector::feed(const FileScanEvent& f,
                                               uint64_t now_ms) {
    const auto it = baseline_.find(f.path);
    if (it == baseline_.end()) return std::nullopt;
    if (muted_until(muted_, f.path, now_ms)) return std::nullopt;

    if (!f.present) {
        muted_[f.path] = now_ms + cfg_.cooldown_ms;
        return make_file_alert(DT_FILE_MOD, f.path, 0, HF_MISSING,
                               FILE_MOD_GONE);
    }
    if (std::memcmp(f.sha256, it->second.data(), SHA256_LEN) != 0) {
        muted_[f.path] = now_ms + cfg_.cooldown_ms;
        return make_file_alert(DT_FILE_MOD, f.path, f.mode, 0, FILE_MOD_HASH);
    }
    return std::nullopt;
}

/* ---- 6: new setuid-root file ---- */

std::optional<HostAlert> NewSetuidDetector::feed(const FileScanEvent& f,
                                                 uint64_t now_ms) {
    if (!enabled()) return std::nullopt;
    if (!f.present || (f.mode & 04000) == 0 || f.uid != 0)
        return std::nullopt;
    if (baseline_paths_.count(f.path)) return std::nullopt;
    if (muted_until(muted_, f.path, now_ms)) return std::nullopt;
    muted_[f.path] = now_ms + cfg_.cooldown_ms;
    HostAlert a = make_file_alert(DT_NEW_SETUID, f.path, f.mode, HF_SETUID, 0);
    a.uid = f.uid;
    return a;
}

/* ---- 7: out-of-baseline kernel module ---- */

KmodLoadDetector::KmodLoadDetector() = default;
KmodLoadDetector::KmodLoadDetector(const Config& cfg) : cfg_(cfg) {}

std::optional<HostAlert> KmodLoadDetector::feed(const ModuleScanEvent& m,
                                                uint64_t now_ms) {
    if (!enabled() || baseline_.count(m.name)) return std::nullopt;
    if (muted_until(muted_, m.name, now_ms)) return std::nullopt;
    muted_[m.name] = now_ms + cfg_.cooldown_ms;
    return make_name_alert(DT_KMOD_LOAD, m.name);
}

/* ---- 8: zombie storm ---- */

ZombieStormDetector::ZombieStormDetector() = default;
ZombieStormDetector::ZombieStormDetector(const Config& cfg) : cfg_(cfg) {}

std::optional<HostAlert> ZombieStormDetector::feed(const SnapshotEvent& s,
                                                   uint64_t now_ms) {
    if (!state_.started) {
        state_.started      = true;
        state_.window_start = now_ms;
    }
    if (now_ms - state_.window_start >= cfg_.window_ms) {
        state_.window_start = now_ms;
        state_.max_zombies  = 0;
        state_.alerted      = false;
    }
    if (s.zombies > state_.max_zombies) state_.max_zombies = s.zombies;
    if (!state_.alerted && state_.max_zombies >= cfg_.zombie_threshold) {
        state_.alerted = true;
        HostAlert a;
        a.detector_type = DT_ZOMBIE_STORM;
        a.aux   = state_.max_zombies;
        a.count = state_.max_zombies;
        return a;
    }
    return std::nullopt;
}

/* ---- 9: resource exhaustion ---- */

std::optional<HostAlert> ResExhaustDetector::feed(const SnapshotEvent& s,
                                                  uint64_t now_ms) {
    if (now_ms < muted_until_) return std::nullopt;
    if (s.top_cpu_ppm >= cfg_.cpu_ppm_threshold) {
        muted_until_ = now_ms + cfg_.cooldown_ms;
        return make_snap_alert(DT_RES_EXHAUST, s, RES_EXHAUST_CPU);
    }
    if (s.top_mem_rss_kb >= cfg_.rss_kb_threshold) {
        muted_until_ = now_ms + cfg_.cooldown_ms;
        return make_snap_alert(DT_RES_EXHAUST, s, RES_EXHAUST_MEM);
    }
    return std::nullopt;
}

/* ---- 10: root shell ---- */

RootShellDetector::RootShellDetector() = default;
RootShellDetector::RootShellDetector(const Config& cfg) : cfg_(cfg) {}

std::optional<HostAlert> RootShellDetector::feed(const ExecEvent& e,
                                                 uint64_t now_ms) {
    if (e.uid != 0 || !is_shell_comm(e.comm)) return std::nullopt;
    const std::string key(e.comm);
    if (muted_until(muted_, key, now_ms)) return std::nullopt;
    muted_[key] = now_ms + cfg_.cooldown_ms;
    const std::string parent(e.parent_comm);
    const bool net = parent == "sshd" || parent == "adbd" ||
                     parent == "dropbear" || parent == "telnetd";
    return make_exec_alert(DT_ROOT_SHELL, e, 0,
                           net ? ROOT_SHELL_NET : ROOT_SHELL_TTY);
}

} /* namespace hostprobe */
