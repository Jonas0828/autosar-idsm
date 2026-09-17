/*
 * main.cpp -- can_probe: lightweight CAN IDS probe for AUTOSAR IDSM.
 *
 * Captures CAN/CAN-FD traffic (SocketCAN live or pcap replay), runs the
 * detection pipeline, and reports alerts as Security Events into the
 * IDSM filter chain (one SEv per detector type, ext 0x8011-0x801A,
 * CAN context layout v1). IDSRM forwards the resulting QSEvs to the
 * SOC endpoint over HTTP.
 *
 * Exit: SIGINT/SIGTERM stop the capture loop, then IDSRM/IDSM are shut
 * down in reverse init order (IdsRm_DeInit -> IdsM_DeInit).
 */
#include "capture.h"
#include "pipeline.h"

#include "../../include/IdsM.h"
#include "../../include/IdsRm.h"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

namespace {

/* SEv allocation: one SEv per detector_type so aggregation windows
 * don't merge different alert kinds (same rule as eth_probe).
 * Internal ID = index into the SEv config array; ext ID = 0x8011+index.
 * Detector types 1..10 -> internal 0..9 (see apps/can_probe/alert.h). */
constexpr IdsM_ExternalSecurityEventIdType SEV_EXT_BASE = 0x8011;
constexpr uint8_t MAX_DETECTOR_TYPE = 10;

/* map detector_type (1..10) -> internal SEv id (0..9); 0xFFFF = invalid */
IdsM_SecurityEventIdType sev_for_detector(uint8_t detector_type) {
    if (detector_type >= 1 && detector_type <= MAX_DETECTOR_TYPE)
        return static_cast<IdsM_SecurityEventIdType>(detector_type - 1);
    return 0xFFFF;
}

std::atomic<bool> g_stop{false};
canprobe::LiveCanCapture* g_cap = nullptr;

void on_signal(int) {
    g_stop.store(true);
    if (g_cap) g_cap->stop();
}

struct Args {
    std::string iface;
    std::string pcap;
    std::string soc_url = "http://localhost:8080/api/idsm-violations";
    std::string ids_file;
    uint32_t window_ms   = 0;   /* 0 = per-detector defaults */
    uint32_t id_fps      = 0;   /* 0 = default */
    uint32_t bus_fps     = 0;
    uint32_t diag_fps    = 0;
    uint32_t err_max     = 0;
    uint32_t sec_seeds   = 0;
    uint32_t sec_keys    = 0;
    uint32_t svc_max     = 0;
    bool help = false;
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
        if (s == "-i" || s == "--iface") a.iface = next("-i");
        else if (s == "--pcap") a.pcap = next("--pcap");
        else if (s == "--soc") a.soc_url = next("--soc");
        else if (s == "--ids") a.ids_file = next("--ids");
        else if (s == "--window") a.window_ms = std::stoul(next("--window"));
        else if (s == "--id-fps") a.id_fps = std::stoul(next("--id-fps"));
        else if (s == "--bus-fps") a.bus_fps = std::stoul(next("--bus-fps"));
        else if (s == "--diag-fps") a.diag_fps = std::stoul(next("--diag-fps"));
        else if (s == "--err-max") a.err_max = std::stoul(next("--err-max"));
        else if (s == "--sec-seeds") a.sec_seeds = std::stoul(next("--sec-seeds"));
        else if (s == "--sec-keys") a.sec_keys = std::stoul(next("--sec-keys"));
        else if (s == "--svc-max") a.svc_max = std::stoul(next("--svc-max"));
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
        "can_probe -- lightweight CAN IDS probe for AUTOSAR IDSM\n"
        "usage: " << prog << " -i <iface> [options]    (live capture, root)\n"
        "       " << prog << " --pcap <file> [options] (offline replay)\n"
        "options:\n"
        "  --soc URL          SOC endpoint (default http://localhost:8080/api/idsm-violations)\n"
        "  --ids FILE         CAN ID whitelist: 'hex_id [min_interval_ms]' per line\n"
        "                     (enables unknown-ID + cycle-time detection)\n"
        "  --window MS        common detector window (default per-detector)\n"
        "  --id-fps N         per-ID flood threshold (default 100)\n"
        "  --bus-fps N        bus-wide flood threshold (default 1000)\n"
        "  --diag-fps N       diagnostic request flood threshold (default 50)\n"
        "  --err-max N        error frame burst threshold (default 20)\n"
        "  --sec-seeds N      SecurityAccess requestSeed threshold (default 5)\n"
        "  --sec-keys N       SecurityAccess sendKey threshold (default 5)\n"
        "  --svc-max N        diagnostic service-scan threshold (default 8)\n";
}
/* CAN context layout v1: fixed 16-byte big-endian blob (see alert.h):
 *   [0] detector_type  [1] frame flags (CF_*)
 *   [2..5] can_id      [6..7] reserved
 *   [8..11] count      [12..15] aux */
void serialize_context(const canprobe::CanAlert& a, uint8_t out[canprobe::CAN_CONTEXT_SIZE]) {
    size_t o = 0;
    out[o++] = a.detector_type;
    out[o++] = static_cast<uint8_t>(
        (a.eff ? canprobe::CF_EFF : 0) | (a.rtr ? canprobe::CF_RTR : 0) |
        (a.fd ? canprobe::CF_FD : 0) | (a.err ? canprobe::CF_ERR : 0));
    for (int i = 3; i >= 0; --i) out[o++] = static_cast<uint8_t>(a.can_id >> (8 * i));
    out[o++] = 0;
    out[o++] = 0;
    for (int i = 3; i >= 0; --i) out[o++] = static_cast<uint8_t>(a.count >> (8 * i));
    for (int i = 3; i >= 0; --i) out[o++] = static_cast<uint8_t>(a.aux >> (8 * i));
}

void report_alert(const canprobe::CanAlert& a) {
    uint8_t ctx[canprobe::CAN_CONTEXT_SIZE];
    serialize_context(a, ctx);
    uint16_t count = static_cast<uint16_t>(a.count > 65535 ? 65535
                                           : (a.count == 0 ? 1 : a.count));
    const auto sev = sev_for_detector(a.detector_type);
    if (sev == 0xFFFF) return;  /* unknown detector: drop */
    IdsM_ReportSecurityEvent(sev, ctx, sizeof(ctx),
                             1 /* contextDataVersion */, count,
                             nullptr /* internal timestamp */);
    std::cout << "[PROBE] alert type=" << static_cast<int>(a.detector_type)
              << " id=0x" << std::hex << a.can_id
              << " aux=0x" << a.aux << std::dec << "\n";
}

} /* namespace */

int main(int argc, char** argv) {
    const Args args = parse_args(argc, argv);
    if (args.help || (args.iface.empty() && args.pcap.empty())) {
        print_usage(argv[0]);
        return args.help ? 0 : 1;
    }

    /* ---- pipeline setup ---- */
    canprobe::CanProbePipeline pipeline(&report_alert);

    const uint32_t window = args.window_ms > 0 ? args.window_ms : 1000;
    if (args.id_fps > 0 || args.window_ms > 0) {
        pipeline.id_flood().set_config(canprobe::IdFloodDetector::Config{
            window, args.id_fps > 0 ? args.id_fps : 100});
    }
    if (args.bus_fps > 0 || args.window_ms > 0) {
        pipeline.bus_flood().set_config(canprobe::BusFloodDetector::Config{
            window, args.bus_fps > 0 ? args.bus_fps : 1000});
    }
    if (args.err_max > 0 || args.window_ms > 0) {
        pipeline.err_burst().set_config(canprobe::ErrorBurstDetector::Config{
            window, args.err_max > 0 ? args.err_max : 20});
    }
    if (args.diag_fps > 0 || args.window_ms > 0) {
        pipeline.diag_flood().set_config(canprobe::DiagFloodDetector::Config{
            window, args.diag_fps > 0 ? args.diag_fps : 50});
    }
    if (args.sec_seeds > 0 || args.sec_keys > 0) {
        canprobe::UdsSecAccessDetector::Config c;
        if (args.sec_seeds > 0) c.seed_threshold = args.sec_seeds;
        if (args.sec_keys > 0) c.key_threshold = args.sec_keys;
        pipeline.sec_access().set_config(c);
    }
    if (args.svc_max > 0) {
        canprobe::UdsSvcScanDetector::Config c;
        c.svc_threshold = args.svc_max;
        pipeline.svc_scan().set_config(c);
    }

    if (!args.ids_file.empty()) {
        std::string err;
        size_t bad = 0;
        if (!pipeline.load_ids(args.ids_file, err, &bad)) {
            std::cerr << "[ERR] " << err << "\n";
            return 1;
        }
        std::cout << "[IDS] whitelist loaded: " << pipeline.unknown_id().known_count()
                  << " known IDs (" << bad << " bad lines)\n";
    }

    /* ---- IDSM init: one SEv per detector_type (ext 0x8011+i) so each
       kind aggregates independently, same rule as eth_probe. ---- */
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
    std::cout << "[IDSM] Initialized | 10 SEvs ext 0x8011-0x801A (one per detector type)\n";

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

    /* ---- capture ---- */
    int rc = 0;
    if (!args.pcap.empty()) {
        std::string err;
        std::cout << "[PROBE] replaying " << args.pcap << "\n";
        if (!canprobe::replay_pcap(args.pcap,
                [&](const uint8_t* d, size_t n, uint64_t ts) {
                    pipeline.feed_raw(d, n, ts);
                }, err)) {
            std::cerr << "[PROBE ERR] " << err << "\n";
            rc = 1;
        }
    } else {
        canprobe::LiveCanCapture cap;
        g_cap = &cap;
        std::string err;
        if (!cap.open(args.iface, err)) {
            std::cerr << "[PROBE ERR] " << err << "\n";
            rc = 1;
        } else {
            std::cout << "[PROBE] capturing on " << args.iface << " (Ctrl-C to stop)\n";
            if (!cap.run([&](const uint8_t* d, size_t n, uint64_t ts) {
                    pipeline.feed_raw(d, n, ts);
                }, err)) {
                std::cerr << "[PROBE ERR] " << err << "\n";
                rc = 1;
            }
        }
        g_cap = nullptr;
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