/*
 * main.cpp -- host_probe: lightweight host-based IDS probe for AUTOSAR
 * IDSM (Linux + Android).
 *
 * Watches host-side activity -- process executions (netlink
 * PROC_CONNECTOR live, /proc polling, or --events replay), monitored
 * file integrity, kernel modules, and /proc aggregates -- runs the
 * detection pipeline, and reports alerts as Security Events into the
 * IDSM filter chain (one SEv per detector type, ext 0x8021-0x802A,
 * host context layout v1). IDSRM forwards the resulting QSEvs to the
 * SOC endpoint over HTTP.
 *
 * Exit: SIGINT/SIGTERM stop the capture loops, then IDSRM/IDSM are shut
 * down in reverse init order (IdsRm_DeInit -> IdsM_DeInit).
 */
#include "capture.h"
#include "baseline.h"
#include "pipeline.h"

#include "../../include/IdsM.h"
#include "../../include/IdsRm.h"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <mutex>
#include <set>
#include <string>
#include <thread>

namespace {

/* SEv allocation: one SEv per detector_type so aggregation windows
 * don't merge different alert kinds (same rule as can_probe/eth_probe).
 * Internal ID = index into the SEv config array; ext ID = 0x8021+index.
 * Detector types 1..10 -> internal 0..9 (see apps/host_probe/alert.h). */
constexpr IdsM_ExternalSecurityEventIdType SEV_EXT_BASE = 0x8021;
constexpr uint8_t MAX_DETECTOR_TYPE = 10;

/* map detector_type (1..10) -> internal SEv id (0..9); 0xFFFF = invalid */
IdsM_SecurityEventIdType sev_for_detector(uint8_t detector_type) {
    if (detector_type >= 1 && detector_type <= MAX_DETECTOR_TYPE)
        return static_cast<IdsM_SecurityEventIdType>(detector_type - 1);
    return 0xFFFF;
}

std::atomic<bool> g_stop{false};
hostprobe::NetlinkProcCapture* g_nl  = nullptr;
hostprobe::ProcScanCapture*    g_scan = nullptr;

void on_signal(int) {
    g_stop.store(true);
    if (g_nl) g_nl->stop();
    if (g_scan) g_scan->stop();
}

struct Args {
    std::string events;         /* offline replay instead of live capture */
    std::string soc_url = "http://localhost:8080/api/idsm-violations";
    std::string baseline_exec;
    std::string baseline_files;
    std::string baseline_mods;
    std::string net_parents;
    uint32_t scan_ms    = 1000;
    uint32_t fork_rate  = 0;    /* 0 = detector default */
    uint32_t zombie_max = 0;
    uint32_t cpu_ppm    = 0;
    uint64_t rss_kb     = 0;
    bool no_netlink     = false;
    bool help           = false;
};

Args parse_args(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        const std::string s = argv[i];
        auto next = [&](const char* flag) -> std::string {
            if (i + 1 >= argc) {
                std::cerr << "[ERR] missing value for " << flag << "\n";
                return {};
            }
            return argv[++i];
        };
        if (s == "--events") a.events = next("--events");
        else if (s == "--soc") a.soc_url = next("--soc");
        else if (s == "--baseline-exec") a.baseline_exec = next("--baseline-exec");
        else if (s == "--baseline-files") a.baseline_files = next("--baseline-files");
        else if (s == "--baseline-mods") a.baseline_mods = next("--baseline-mods");
        else if (s == "--net-parents") a.net_parents = next("--net-parents");
        else if (s == "--scan-ms") a.scan_ms = std::stoul(next("--scan-ms"));
        else if (s == "--fork-rate") a.fork_rate = std::stoul(next("--fork-rate"));
        else if (s == "--zombie-max") a.zombie_max = std::stoul(next("--zombie-max"));
        else if (s == "--cpu-ppm") a.cpu_ppm = std::stoul(next("--cpu-ppm"));
        else if (s == "--rss-kb") a.rss_kb = std::stoull(next("--rss-kb"));
        else if (s == "--no-netlink") a.no_netlink = true;
        else if (s == "-h" || s == "--help") {
            a.help = true;
        } else {
            std::cerr << "[ERR] unknown argument: " << s << "\n";
            a.help = true;
        }
    }
    return a;
}

void print_usage(const char* prog) {
    std::cout <<
        "host_probe -- lightweight host-based IDS probe for AUTOSAR IDSM "
        "(Linux/Android)\n"
        "usage: " << prog << " [options]                 (live capture)\n"
        "       " << prog << " --events <file> [options] (offline replay)\n"
        "options:\n"
        "  --baseline-exec FILE   exec allowlist: exact path or basename per line\n"
        "                         (enables unknown-exec detection)\n"
        "  --baseline-files FILE  file integrity baseline (sha256sum format);\n"
        "                         also seeds new-setuid known paths\n"
        "  --baseline-mods FILE   kernel module baseline (enables kmod detection)\n"
        "  --net-parents FILE     extra network-daemon comms for rev-shell detect\n"
        "  --scan-ms MS           /proc poll interval (default 1000)\n"
        "  --no-netlink           force the /proc poller (no PROC_CONNECTOR)\n"
        "  --soc URL              SOC endpoint (default http://localhost:8080/api/idsm-violations)\n"
        "  --fork-rate N          fork-flood threshold, execs/window (default 200)\n"
        "  --zombie-max N         zombie-storm threshold (default 100)\n"
        "  --cpu-ppm N            CPU exhaustion threshold, permille (default 900)\n"
        "  --rss-kb N             RSS exhaustion threshold in KiB (default 1048576)\n";
}

/* Host context layout v1: fixed 32-byte big-endian blob (see alert.h):
 *   [0] detector_type  [1] flags (HF_*)
 *   [2..5] pid         [6..9] uid (file mode for file events)
 *   [10..13] count     [14..17] aux
 *   [18..29] name[12]  [30..31] reserved */
void serialize_context(const hostprobe::HostAlert& a,
                       uint8_t out[hostprobe::HOST_CONTEXT_SIZE]) {
    size_t o = 0;
    out[o++] = a.detector_type;
    out[o++] = a.flags;
    for (int i = 3; i >= 0; --i) out[o++] = static_cast<uint8_t>(a.pid >> (8 * i));
    for (int i = 3; i >= 0; --i) out[o++] = static_cast<uint8_t>(a.uid >> (8 * i));
    for (int i = 3; i >= 0; --i) out[o++] = static_cast<uint8_t>(a.count >> (8 * i));
    for (int i = 3; i >= 0; --i) out[o++] = static_cast<uint8_t>(a.aux >> (8 * i));
    std::memcpy(out + o, a.name, 12);
    o += 12;
    out[o++] = 0;
    out[o++] = 0;
}

void report_alert(const hostprobe::HostAlert& a) {
    uint8_t ctx[hostprobe::HOST_CONTEXT_SIZE];
    serialize_context(a, ctx);
    uint16_t count = static_cast<uint16_t>(a.count > 65535 ? 65535
                                           : (a.count == 0 ? 1 : a.count));
    const auto sev = sev_for_detector(a.detector_type);
    if (sev == 0xFFFF) return;  /* unknown detector: drop */
    IdsM_ReportSecurityEvent(sev, ctx, sizeof(ctx),
                             1 /* contextDataVersion */, count,
                             nullptr /* internal timestamp */);
    std::cout << "[PROBE] alert type=" << static_cast<int>(a.detector_type)
              << " pid=" << a.pid << " uid=" << a.uid
              << " name=" << a.name
              << " aux=0x" << std::hex << a.aux << std::dec << "\n";
}

} /* namespace */

int main(int argc, char** argv) {
    const Args args = parse_args(argc, argv);
    if (args.help) {
        print_usage(argv[0]);
        return 0;
    }

    /* ---- pipeline setup ---- */
    hostprobe::HostProbePipeline pipeline(&report_alert);

    if (args.fork_rate > 0) {
        hostprobe::ForkFloodDetector::Config c;
        c.spawn_threshold = args.fork_rate;
        pipeline.fork_flood().set_config(c);
    }
    if (args.zombie_max > 0) {
        hostprobe::ZombieStormDetector::Config c;
        c.zombie_threshold = args.zombie_max;
        pipeline.zombie().set_config(c);
    }
    if (args.cpu_ppm > 0 || args.rss_kb > 0) {
        hostprobe::ResExhaustDetector::Config c;
        if (args.cpu_ppm > 0) c.cpu_ppm_threshold = args.cpu_ppm;
        if (args.rss_kb > 0) c.rss_kb_threshold = args.rss_kb;
        pipeline.res().set_config(c);
    }

    if (!args.baseline_exec.empty()) {
        std::string err;
        size_t bad = 0;
        if (!pipeline.load_exec_allowlist(args.baseline_exec, err, &bad)) {
            std::cerr << "[ERR] " << err << "\n";
            return 1;
        }
        std::cout << "[IDS] exec allowlist loaded: "
                  << pipeline.unknown_exec().allowed_count()
                  << " entries (" << bad << " bad lines)\n";
    }
    if (!args.baseline_files.empty()) {
        std::string err;
        size_t bad = 0;
        if (!pipeline.load_file_baseline(args.baseline_files, err, &bad)) {
            std::cerr << "[ERR] " << err << "\n";
            return 1;
        }
        std::cout << "[IDS] file baseline loaded: "
                  << pipeline.file_mod().baseline().size()
                  << " files (" << bad << " bad lines)\n";
    }
    if (!args.baseline_mods.empty()) {
        std::string err;
        size_t bad = 0;
        if (!pipeline.load_module_baseline(args.baseline_mods, err, &bad)) {
            std::cerr << "[ERR] " << err << "\n";
            return 1;
        }
        std::cout << "[IDS] module baseline loaded: "
                  << pipeline.kmod().baseline_count()
                  << " modules (" << bad << " bad lines)\n";
    }
    if (!args.net_parents.empty()) {
        std::string err;
        size_t bad = 0;
        std::set<std::string> names;
        if (!hostprobe::load_name_set(args.net_parents, names, err, &bad)) {
            std::cerr << "[ERR] " << err << "\n";
            return 1;
        }
        for (const auto& n : names) pipeline.rev_shell().add_net_parent(n);
    }

    /* ---- IDSM init: one SEv per detector_type (ext 0x8021+i) ---- */
    IdsM_SecurityEventConfigType sevs[MAX_DETECTOR_TYPE];
    for (uint8_t i = 0; i < MAX_DETECTOR_TYPE; ++i) {
        sevs[i] = IdsM_SecurityEventConfigType{
            static_cast<IdsM_ExternalSecurityEventIdType>(SEV_EXT_BASE + i),
            0, IDSM_SEVERITY_MEDIUM, IDSM_REPORTING_DETAILED,
            nullptr, 0, 1000 /* per-type aggregation window ms */, {0, 0},
            true, true};
    }
    IdsM_ConfigType idsm_cfg{};
    idsm_cfg.idsm_instance_id        = 1;
    idsm_cfg.main_function_period_ms = 10;
    idsm_cfg.rate_limitation         = {0, 0};
    idsm_cfg.traffic_limitation      = {0, 0};
    idsm_cfg.sev_configs             = sevs;
    idsm_cfg.sev_count               = MAX_DETECTOR_TYPE;
    idsm_cfg.event_buffer_size       = 256;

    if (IdsM_Init(&idsm_cfg) != E_OK) {
        std::cerr << "[IDSM ERR] Init failed\n";
        return 1;
    }
    std::cout << "[IDSM] Initialized | 10 SEvs ext 0x8021-0x802A (one per detector type)\n";

    IdsRm_ConfigType idsrm_cfg{};
    std::strncpy(idsrm_cfg.soc_url, args.soc_url.c_str(), IDSRM_MAX_URL_LEN - 1);
    idsrm_cfg.auth_token[0] = '\0';
    idsrm_cfg.timeout_ms    = 3000;
    idsrm_cfg.retry_count   = 2;
    idsrm_cfg.enabled       = true;
    if (IdsRm_Init(&idsrm_cfg) != E_OK) {
        std::cerr << "[IDSRM ERR] Init failed\n";
        IdsM_DeInit();
        return 1;
    }
    std::cout << "[IDSRM] Initialized | Forwarding to " << idsrm_cfg.soc_url << "\n";

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    /* ---- capture ----
     * The pipeline is single-threaded; both capture sources feed it
     * under one mutex. In live mode the netlink source (when available)
     * reports exec events and the poller drives snapshots, module diffs
     * and file scans. */
    std::mutex pipe_mu;
    auto feed = [&](const hostprobe::HostEvent& ev) {
        std::lock_guard<std::mutex> lk(pipe_mu);
        pipeline.feed_event(ev);
    };

    int rc = 0;
    if (!args.events.empty()) {
        std::string err;
        std::cout << "[PROBE] replaying " << args.events << "\n";
        if (!hostprobe::replay_events(args.events, feed, err)) {
            std::cerr << "[PROBE ERR] " << err << "\n";
            rc = 1;
        } else if (!err.empty()) {
            std::cerr << "[PROBE WARN] " << err << "\n";
        }
    } else {
        hostprobe::NetlinkProcCapture nl;
        hostprobe::ProcScanCapture    scan;
        g_nl   = &nl;
        g_scan = &scan;

        std::string nlerr;
        const bool use_netlink = !args.no_netlink && nl.open(nlerr);
        if (!use_netlink) {
            std::cout << "[PROBE] netlink "
                      << (args.no_netlink ? "disabled (--no-netlink)"
                                          : "unavailable (" + nlerr + ")")
                      << ", using /proc polling for exec events\n";
        } else {
            std::cout << "[PROBE] PROC_CONNECTOR exec events enabled\n";
        }

        if (!scan.open(args.scan_ms, nlerr)) {
            std::cerr << "[PROBE ERR] " << nlerr << "\n";
            return 1;
        }
        scan.set_emit_execs(!use_netlink);
        for (const auto& kv : pipeline.file_mod().baseline())
            scan.add_scan_file(kv.first);

        std::thread nl_thread;
        if (use_netlink) {
            nl_thread = std::thread([&] {
                std::string err;
                if (!nl.run(feed, err))
                    std::cerr << "[PROBE WARN] netlink: " << err << "\n";
            });
        }

        std::cout << "[PROBE] scanning /proc every " << args.scan_ms
                  << " ms (Ctrl-C to stop)\n";
        std::string err;
        if (!scan.run(feed, err)) {
            std::cerr << "[PROBE ERR] " << err << "\n";
            rc = 1;
        }

        nl.stop();
        if (nl_thread.joinable()) nl_thread.join();
        g_nl   = nullptr;
        g_scan = nullptr;
    }

    /* ---- shutdown (reverse init order) ----
       Flush all pending aggregation windows first so tail alerts are not
       lost, then give IDSRM's HTTP worker a moment to drain its queue. */
    for (uint8_t i = 0; i < MAX_DETECTOR_TYPE; ++i)
        IdsM_FlushEvents(static_cast<IdsM_SecurityEventIdType>(i));
    std::this_thread::sleep_for(std::chrono::seconds(2));
    IdsRm_DeInit();
    IdsM_DeInit();
    std::cout << "[PROBE] shutdown complete\n";
    return rc;
}
