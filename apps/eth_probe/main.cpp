/*
 * main.cpp — eth_probe: lightweight Ethernet IDS probe for AUTOSAR IDSM.
 *
 * Captures traffic (AF_PACKET live or pcap replay), runs the detection
 * pipeline, and reports alerts as Security Events into the IDSM filter
 * chain (single SEv ext 0x8003, context layout v1). IDSRM forwards the
 * resulting QSEvs to the SOC endpoint over HTTP.
 *
 * Exit: SIGINT/SIGTERM stop the capture loop, then IDSRM/IDSM are shut
 * down in reverse init order (IdsRm_DeInit → IdsM_DeInit).
 */
#include "alert.h"
#include "capture.h"
#include "pipeline.h"
#include "proto_someip.h"

#include "../../include/IdsM.h"
#include "../../include/IdsRm.h"

#include <chrono>
#include <csignal>
#include <thread>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {

/* SEv symbolic name (simulate configuration-generated code) */
#define SEV_ETH_PROBE ((IdsM_SecurityEventIdType)0)  /* ext 0x8003 */

std::atomic<bool> g_stop{false};
ethprobe::LiveCapture* g_cap = nullptr;

void on_signal(int) {
    g_stop.store(true);
    if (g_cap) g_cap->stop();
}

struct Args {
    std::string iface;
    std::string pcap;
    std::string soc_url = "http://localhost:8080/api/idsm-violations";
    std::string rules_file;
    std::string cidr_file;
    std::vector<std::string> home_nets;
    ethprobe::VarMap vars;
    uint16_t someip_port = ethprobe::SOMEIP_DEFAULT_PORT;
    std::vector<uint16_t> someip_services;
    uint32_t scan_ports = 0;   /* 0 = default */
    uint32_t flood_pps  = 0;
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
        else if (s == "--rules") a.rules_file = next("--rules");
        else if (s == "--cidr") a.cidr_file = next("--cidr");
        else if (s == "--someip-port") a.someip_port = static_cast<uint16_t>(
            std::stoul(next("--someip-port")));
        else if (s == "--scan-ports") a.scan_ports = std::stoul(next("--scan-ports"));
        else if (s == "--flood-pps") a.flood_pps = std::stoul(next("--flood-pps"));
        else if (s.rfind("--var", 0) == 0) {
            const std::string kv = next("--var");
            const auto eq = kv.find('=');
            if (eq != std::string::npos) a.vars[kv.substr(0, eq)] = kv.substr(eq + 1);
        } else if (s == "--home-net") {
            /* comma-separated CIDR list */
            const std::string list = next("--home-net");
            size_t pos = 0;
            while (pos <= list.size()) {
                const auto comma = list.find(',', pos);
                a.home_nets.push_back(list.substr(
                    pos, comma == std::string::npos ? comma : comma - pos));
                if (comma == std::string::npos) break;
                pos = comma + 1;
            }
        } else if (s == "--someip-services") {
            const std::string list = next("--someip-services");
            size_t pos = 0;
            while (pos <= list.size()) {
                const auto comma = list.find(',', pos);
                a.someip_services.push_back(static_cast<uint16_t>(std::stoul(
                    list.substr(pos, comma == std::string::npos ? comma : comma - pos),
                    nullptr, 0)));
                if (comma == std::string::npos) break;
                pos = comma + 1;
            }
        } else if (s == "-h" || s == "--help") {
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
        "eth_probe — lightweight Ethernet IDS probe for AUTOSAR IDSM\n"
        "usage: " << prog << " -i <iface> [options]    (live capture, root)\n"
        "       " << prog << " --pcap <file> [options] (offline replay)\n"
        "options:\n"
        "  --soc URL              SOC endpoint (default http://localhost:8080/api/idsm-violations)\n"
        "  --rules FILE           Suricata-syntax-subset rules file\n"
        "  --var KEY=VALUE        rule variable (e.g. --var HOME_NET=10.0.0.0/8)\n"
        "  --cidr FILE            domestic CIDR list (enables cross-border detection)\n"
        "  --home-net CIDR,...    vehicle-internal nets (default RFC1918+link-local)\n"
        "  --someip-port N        SOME/IP port (default 30490)\n"
        "  --someip-services IDS  SOME/IP-SD offer whitelist (comma-sep, hex ok)\n"
        "  --scan-ports N         port-scan unique-port threshold (default 20)\n"
        "  --flood-pps N          rate-flood pps threshold (default 1000)\n";
}

/* Context layout v1: fixed 46-byte big-endian blob (see alert.h) */
void serialize_context(const ethprobe::ProbeAlert& a, uint8_t out[46]) {
    size_t o = 0;
    out[o++] = a.detector_type;
    out[o++] = a.proto;
    out[o++] = static_cast<uint8_t>(a.src_port >> 8);
    out[o++] = static_cast<uint8_t>(a.src_port);
    out[o++] = static_cast<uint8_t>(a.dst_port >> 8);
    out[o++] = static_cast<uint8_t>(a.dst_port);
    std::memcpy(out + o, a.src_ip, 16); o += 16;
    std::memcpy(out + o, a.dst_ip, 16); o += 16;
    for (int i = 3; i >= 0; --i) out[o++] = static_cast<uint8_t>(a.count >> (8 * i));
    for (int i = 3; i >= 0; --i) out[o++] = static_cast<uint8_t>(a.aux >> (8 * i));
}

void report_alert(const ethprobe::ProbeAlert& a) {
    uint8_t ctx[46];
    serialize_context(a, ctx);
    uint16_t count = static_cast<uint16_t>(a.count > 65535 ? 65535
                                           : (a.count == 0 ? 1 : a.count));
    IdsM_ReportSecurityEvent(SEV_ETH_PROBE, ctx, sizeof(ctx),
                             1 /* contextDataVersion */, count,
                             nullptr /* internal timestamp */);
    std::cout << "[PROBE] alert type=" << static_cast<int>(a.detector_type)
              << " aux=0x" << std::hex << a.aux << std::dec << "\n";
}

} /* namespace */

int main(int argc, char** argv) {
    const Args args = parse_args(argc, argv);
    if (args.help || (args.iface.empty() && args.pcap.empty())) {
        print_usage(argv[0]);
        return args.help ? 0 : 1;
    }

    /* ---- pipeline setup ---- */
    ethprobe::ProbePipeline pipeline(&report_alert);
    pipeline.config().someip_port = args.someip_port;
    if (args.scan_ports > 0) {
        pipeline.port_scan().set_config(
            ethprobe::PortScanDetector::Config{10000, args.scan_ports});
    }
    if (args.flood_pps > 0) {
        pipeline.rate_flood().set_config(
            ethprobe::RateFloodDetector::Config{1000, args.flood_pps});
    }

    if (!args.rules_file.empty()) {
        std::vector<std::string> warnings;
        const size_t n = pipeline.rules().load_file(args.rules_file, args.vars, warnings);
        for (const auto& w : warnings) std::cerr << "[RULES] " << w << "\n";
        std::cout << "[RULES] loaded " << n << " rules ("
                  << pipeline.rules().skipped_count() << " skipped)\n";
    }
    if (!args.cidr_file.empty()) {
        size_t bad = 0;
        if (!pipeline.geoip().load_cidrs(args.cidr_file, &bad)) {
            std::cerr << "[ERR] cannot load CIDR file: " << args.cidr_file << "\n";
            return 1;
        }
        std::cout << "[GEOIP] " << pipeline.geoip().cidr_count()
                  << " domestic CIDRs (" << bad << " bad lines)\n";
    }
    if (!args.home_nets.empty() && !pipeline.geoip().set_home_nets(args.home_nets)) {
        std::cerr << "[ERR] bad --home-net CIDR\n";
        return 1;
    }
    if (!args.someip_services.empty()) {
        ethprobe::SomeipSdTracker::Config sd_cfg;
        sd_cfg.service_whitelist.insert(args.someip_services.begin(),
                                        args.someip_services.end());
        pipeline.sd_tracker().set_config(sd_cfg);
    }

    /* ---- IDSM init (single SEv: ext 0x8003, all probe alerts) ---- */
    IdsM_SecurityEventConfigType sevs[1] = {
        /* extId,  inst, severity,           reporting mode,          filters...,        dem,  idsr */
        {0x8003, 0, IDSM_SEVERITY_MEDIUM, IDSM_REPORTING_DETAILED,
         nullptr, 0, 1000 /* aggregation window ms */, {0, 0}, true, true},
    };
    IdsM_ConfigType idsm_cfg{};
    idsm_cfg.idsm_instance_id        = 1;
    idsm_cfg.main_function_period_ms = 10;
    idsm_cfg.rate_limitation         = {0, 0};
    idsm_cfg.traffic_limitation      = {0, 0};
    idsm_cfg.sev_configs             = sevs;
    idsm_cfg.sev_count               = 1;
    idsm_cfg.event_buffer_size       = 256;

    if (IdsM_Init(&idsm_cfg) != E_OK) {
        std::cerr << "[IDSM ERR] Init failed\n";
        return 1;
    }
    std::cout << "[IDSM] Initialized | SEv 0: Ethernet-IDS(ext 0x8003)\n";

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
        if (!ethprobe::replay_pcap(args.pcap,
                [&](const uint8_t* d, size_t n, uint64_t ts) {
                    pipeline.feed_frame(d, n, ts);
                }, err)) {
            std::cerr << "[PROBE ERR] " << err << "\n";
            rc = 1;
        }
    } else {
        ethprobe::LiveCapture cap;
        g_cap = &cap;
        std::string err;
        if (!cap.open(args.iface, err)) {
            std::cerr << "[PROBE ERR] " << err << "\n";
            rc = 1;
        } else {
            std::cout << "[PROBE] capturing on " << args.iface << " (Ctrl-C to stop)\n";
            if (!cap.run([&](const uint8_t* d, size_t n, uint64_t ts) {
                    pipeline.feed_frame(d, n, ts);
                    pipeline.tick(ts);
                }, err)) {
                std::cerr << "[PROBE ERR] " << err << "\n";
                rc = 1;
            }
        }
        g_cap = nullptr;
    }

    /* ---- shutdown (reverse init order) ----
       Flush the pending aggregation window first so tail alerts are not
       lost, then give IDSRM's HTTP worker a moment to drain its queue. */
    IdsM_FlushEvents(SEV_ETH_PROBE);
    std::this_thread::sleep_for(std::chrono::seconds(2));
    IdsRm_DeInit();
    IdsM_DeInit();
    std::cout << "[PROBE] shutdown complete\n";
    return rc;
}
