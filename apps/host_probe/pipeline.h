#pragma once
/*
 * pipeline.h -- the host_probe detection pipeline.
 *
 * Wires host events to detectors by kind:
 *   EXEC        -> unknown-exec / priv-esc / fork-flood / rev-shell /
 *                  root-shell
 *   FILE_SCAN   -> file-mod / new-setuid
 *   MODULE_SCAN -> kmod-load
 *   SNAPSHOT    -> zombie-storm / res-exhaust
 *
 * Alerts are emitted through a single callback; the caller (main.cpp)
 * turns them into IdsM_ReportSecurityEvent() calls.
 *
 * Not thread-safe: callers must serialize feed_event() (main.cpp runs
 * the netlink source on a second thread and guards with a mutex).
 */
#include "alert.h"
#include "detectors.h"
#include "event.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace hostprobe {

class HostProbePipeline {
public:
    struct Config {
        UnknownExecDetector::Config  unknown_exec;
        PrivEscDetector::Config      priv_esc;
        ForkFloodDetector::Config    fork_flood;
        RevShellDetector::Config     rev_shell;
        FileModDetector::Config      file_mod;
        NewSetuidDetector::Config    new_setuid;
        KmodLoadDetector::Config     kmod;
        ZombieStormDetector::Config  zombie;
        ResExhaustDetector::Config   res;
        RootShellDetector::Config    root_shell;
    };

    using AlertCallback = std::function<void(const HostAlert&)>;

    explicit HostProbePipeline(AlertCallback cb);
    ~HostProbePipeline();

    HostProbePipeline(const HostProbePipeline&) = delete;
    HostProbePipeline& operator=(const HostProbePipeline&) = delete;

    /* component access for startup configuration */
    UnknownExecDetector&    unknown_exec();
    PrivEscDetector&        priv_esc();
    ForkFloodDetector&      fork_flood();
    RevShellDetector&       rev_shell();
    FileModDetector&        file_mod();
    NewSetuidDetector&      new_setuid();
    KmodLoadDetector&       kmod();
    ZombieStormDetector&    zombie();
    ResExhaustDetector&     res();
    RootShellDetector&      root_shell();
    Config&                 config();

    /*
     * Baseline loaders. Exec allowlist: one entry per line (exact path
     * with '/' or bare basename). File baseline: "sha256hex  path" per
     * line (sha256sum format); the same paths seed the new-setuid
     * detector. Module baseline: one module name per line.
     * Returns false if the file cannot be opened; *bad (if given)
     * receives the skipped line count.
     */
    bool load_exec_allowlist(const std::string& path, std::string& err,
                             size_t* bad = nullptr);
    bool load_file_baseline(const std::string& path, std::string& err,
                            size_t* bad = nullptr);
    bool load_module_baseline(const std::string& path, std::string& err,
                              size_t* bad = nullptr);

    /* Feed one normalized host event. */
    void feed_event(const HostEvent& ev);

private:
    struct Impl;
    std::unique_ptr<Impl> m_;
};

} /* namespace hostprobe */
