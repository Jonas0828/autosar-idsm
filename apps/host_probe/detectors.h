#pragma once
/*
 * detectors.h -- host anomaly detectors (GB 44495-2024 host-side IDS
 * coverage): unknown program execution, privilege escalation, fork
 * floods, reverse shells, file-integrity violations, new setuid-root
 * files, out-of-baseline kernel modules, zombie storms, per-process
 * resource exhaustion, and root shell sessions.
 *
 * All detectors are single-threaded: the capture source feeds events
 * in timestamp order. Each feed() returns an alert only when its
 * condition triggers (alert-once semantics inside a window, per-key
 * muting afterwards), matching can_probe.
 */
#include "alert.h"
#include "baseline.h"
#include "event.h"

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>

namespace hostprobe {

/* is this comm a shell? (shared by DT_REV_SHELL / DT_ROOT_SHELL) */
bool is_shell_comm(const std::string& comm);

/* ---- 1: exec of a binary outside the allowlist ---- */
class UnknownExecDetector {
public:
    struct Config {
        uint32_t cooldown_ms = 60000;  /* per-binary alert muting */
    };

    void set_config(const Config& cfg) { cfg_ = cfg; }

    /* enabled once the first allowlist entry is loaded */
    bool enabled() const { return !exact_.empty() || !base_.empty(); }
    void add_allowed(const std::string& entry);  /* path or basename */
    size_t allowed_count() const { return exact_.size() + base_.size(); }
    bool is_allowed(const ExecEvent& e) const;

    std::optional<HostAlert> feed(const ExecEvent& e, uint64_t now_ms);

private:
    Config cfg_;
    std::set<std::string> exact_, base_;
    std::map<std::string, uint64_t> muted_;  /* key: exe path or comm */
};

/* ---- 2: privilege escalation (setuid-root exec by non-root) ---- */
class PrivEscDetector {
public:
    struct Config {
        uint32_t cooldown_ms = 60000;
    };

    void set_config(const Config& cfg) { cfg_ = cfg; }

    std::optional<HostAlert> feed(const ExecEvent& e, uint64_t now_ms);

private:
    Config cfg_;
    std::map<std::string, uint64_t> muted_;  /* key: exe path or comm */
};

/* ---- 3: fork flood: exec rate in a tumbling window (DoS) ---- */
class ForkFloodDetector {
public:
    struct Config {
        uint32_t window_ms       = 1000;
        uint32_t spawn_threshold = 200;
    };

    ForkFloodDetector();
    explicit ForkFloodDetector(const Config& cfg);

    void set_config(const Config& cfg) { cfg_ = cfg; }

    /* Alerts once per window crossing with aux = observed spawns in
       the window. */
    std::optional<HostAlert> feed(const ExecEvent& e, uint64_t now_ms);

private:
    struct State {
        bool     started      = false;
        uint64_t window_start = 0;
        uint32_t count        = 0;
        bool     alerted      = false;
    };
    Config cfg_;
    State state_;
};

/* ---- 4: reverse shell: shell spawned by a network-facing daemon ----
 *
 * A shell whose parent comm is a network-facing daemon (adbd, sshd,
 * netd, httpd, ...) is the classic post-exploitation / remote-control
 * pattern. The daemon set defaults to a built-in list and can be
 * extended with a --net-parents file. */
class RevShellDetector {
public:
    struct Config {
        uint32_t cooldown_ms = 60000;  /* per-parent muting */
    };

    RevShellDetector();
    explicit RevShellDetector(const Config& cfg);

    void set_config(const Config& cfg) { cfg_ = cfg; }
    void add_net_parent(const std::string& comm);
    size_t net_parent_count() const { return net_parents_.size(); }

    /* aux = parent pid, flags carry HF_NET_PARENT */
    std::optional<HostAlert> feed(const ExecEvent& e, uint64_t now_ms);

private:
    Config cfg_;
    std::set<std::string> net_parents_;
    std::map<std::string, uint64_t> muted_;  /* key: parent comm */
};

/* ---- 5: file integrity: monitored file hash mismatch / vanished ---- */
class FileModDetector {
public:
    struct Config {
        uint32_t cooldown_ms = 600000;  /* per-path alert muting */
    };

    void set_config(const Config& cfg) { cfg_ = cfg; }

    bool enabled() const { return !baseline_.empty(); }
    void set_baseline(FileBaseline b) { baseline_ = std::move(b); }
    const FileBaseline& baseline() const { return baseline_; }

    /* Paths not in the baseline are ignored. aux = FILE_MOD_* code. */
    std::optional<HostAlert> feed(const FileScanEvent& f, uint64_t now_ms);

private:
    Config cfg_;
    FileBaseline baseline_;
    std::map<std::string, uint64_t> muted_;  /* key: path */
};

/* ---- 6: new setuid-root file outside the file baseline ---- */
class NewSetuidDetector {
public:
    struct Config {
        uint32_t cooldown_ms = 600000;
    };

    void set_config(const Config& cfg) { cfg_ = cfg; }

    bool enabled() const { return !baseline_paths_.empty(); }
    void add_baseline_path(const std::string& p) { baseline_paths_.insert(p); }
    size_t baseline_count() const { return baseline_paths_.size(); }

    std::optional<HostAlert> feed(const FileScanEvent& f, uint64_t now_ms);

private:
    Config cfg_;
    std::set<std::string> baseline_paths_;   /* known paths (from file baseline) */
    std::map<std::string, uint64_t> muted_;  /* key: path */
};

/* ---- 7: kernel module outside the baseline (Linux) ---- */
class KmodLoadDetector {
public:
    struct Config {
        uint32_t cooldown_ms = 60000;  /* per-module muting */
    };

    KmodLoadDetector();
    explicit KmodLoadDetector(const Config& cfg);

    void set_config(const Config& cfg) { cfg_ = cfg; }

    bool enabled() const { return !baseline_.empty(); }
    void add_baseline(const std::string& name) { baseline_.insert(name); }
    size_t baseline_count() const { return baseline_.size(); }

    std::optional<HostAlert> feed(const ModuleScanEvent& m, uint64_t now_ms);

private:
    Config cfg_;
    std::set<std::string> baseline_;
    std::map<std::string, uint64_t> muted_;  /* key: module name */
};

/* ---- 8: zombie storm: zombie processes in a tumbling window ---- */
class ZombieStormDetector {
public:
    struct Config {
        uint32_t window_ms       = 1000;
        uint32_t zombie_threshold = 100;
    };

    ZombieStormDetector();
    explicit ZombieStormDetector(const Config& cfg);

    void set_config(const Config& cfg) { cfg_ = cfg; }

    /* Alerts once per window crossing with aux = peak zombie count. */
    std::optional<HostAlert> feed(const SnapshotEvent& s, uint64_t now_ms);

private:
    struct State {
        bool     started      = false;
        uint64_t window_start = 0;
        uint32_t max_zombies  = 0;
        bool     alerted      = false;
    };
    Config cfg_;
    State state_;
};

/* ---- 9: resource exhaustion (per-process CPU / RSS) ---- */
class ResExhaustDetector {
public:
    struct Config {
        uint32_t cpu_ppm_threshold = 900;      /* 1000 = 100% of one core */
        uint64_t rss_kb_threshold  = 1048576;  /* 1 GiB */
        uint32_t cooldown_ms       = 60000;
    };

    void set_config(const Config& cfg) { cfg_ = cfg; }

    /* aux = RES_EXHAUST_CPU or RES_EXHAUST_MEM */
    std::optional<HostAlert> feed(const SnapshotEvent& s, uint64_t now_ms);

private:
    Config cfg_;
    uint64_t muted_until_ = 0;
};

/* ---- 10: root shell session (uid-0 shell exec) ---- */
class RootShellDetector {
public:
    struct Config {
        uint32_t cooldown_ms = 60000;  /* per-comm muting */
    };

    RootShellDetector();
    explicit RootShellDetector(const Config& cfg);

    void set_config(const Config& cfg) { cfg_ = cfg; }

    /* aux = ROOT_SHELL_TTY / ROOT_SHELL_NET */
    std::optional<HostAlert> feed(const ExecEvent& e, uint64_t now_ms);

private:
    Config cfg_;
    std::map<std::string, uint64_t> muted_;  /* key: comm */
};

} /* namespace hostprobe */
