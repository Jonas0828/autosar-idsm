/*
 * main.cpp — eve_bridge: Suricata EVE → AUTOSAR IDSM bridge (rail B).
 *
 * Listens on a Unix stream socket for Suricata's eve-log (filetype:
 * unix_stream), parses each alert JSON line, and reports it as a Security
 * Event into the IDSM filter chain: SEv ext 0x8010 / sensor instance 1,
 * detector_type 100 (DT_SURICATA), aux = Suricata signature_id.
 *
 * Reconnect-on-accept: the bridge is the listen side; Suricata connects.
 */
#include "eve.h"

#include "../../include/IdsM.h"
#include "../../include/IdsRm.h"

#include <atomic>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace {

/* SEv symbolic name (simulate configuration-generated code) */
#define SEV_SURICATA ((IdsM_SecurityEventIdType)0)  /* ext 0x8010 */

/* detector_type 100 = DT_SURICATA (see apps/eth_probe/alert.h) */
constexpr uint8_t DT_SURICATA = 100;

std::atomic<bool> g_stop{false};
int g_listen_fd = -1;

void on_signal(int) {
    g_stop.store(true);
    if (g_listen_fd >= 0) ::close(g_listen_fd);  /* unblocks accept() */
}

uint8_t proto_number(const std::string& proto) {
    if (proto == "TCP") return 6;
    if (proto == "UDP") return 17;
    if (proto == "ICMP") return 1;
    return 0;
}

void report_alert(const evebridge::EveAlert& a) {
    /* same 46-byte context layout as eth_probe (version 1) */
    uint8_t ctx[46];
    size_t o = 0;
    ctx[o++] = DT_SURICATA;
    ctx[o++] = proto_number(a.proto);
    ctx[o++] = static_cast<uint8_t>(a.src_port >> 8);
    ctx[o++] = static_cast<uint8_t>(a.src_port);
    ctx[o++] = static_cast<uint8_t>(a.dest_port >> 8);
    ctx[o++] = static_cast<uint8_t>(a.dest_port);
    uint8_t ip[16];
    evebridge::ip_literal_to_bytes(a.src_ip, ip);
    std::memcpy(ctx + o, ip, 16); o += 16;
    evebridge::ip_literal_to_bytes(a.dest_ip, ip);
    std::memcpy(ctx + o, ip, 16); o += 16;
    for (int i = 3; i >= 0; --i) ctx[o++] = 0;  /* count = 1 (written below) */
    ctx[o - 4] = 0; ctx[o - 3] = 0; ctx[o - 2] = 0; ctx[o - 1] = 1;
    for (int i = 3; i >= 0; --i)
        ctx[o++] = static_cast<uint8_t>(a.signature_id >> (8 * i));

    IdsM_ReportSecurityEvent(SEV_SURICATA, ctx, sizeof(ctx),
                             1 /* contextDataVersion */, 1, nullptr);
    std::cout << "[BRIDGE] alert sid=" << a.signature_id << " \""
              << a.signature << "\" " << a.src_ip << " -> " << a.dest_ip << "\n";
}

/* Serve one accepted connection until EOF or stop; returns false on error */
bool serve_connection(int fd) {
    std::string buf;
    char chunk[4096];
    while (!g_stop.load()) {
        const ssize_t n = ::recv(fd, chunk, sizeof(chunk), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return true;  /* Suricata closed; back to accept */
        buf.append(chunk, static_cast<size_t>(n));
        /* EVE records are newline-delimited */
        size_t pos;
        while ((pos = buf.find('\n')) != std::string::npos) {
            const std::string line = buf.substr(0, pos);
            buf.erase(0, pos + 1);
            if (line.empty()) continue;
            const auto alert = evebridge::parse_eve_alert(line);
            if (alert.valid) report_alert(alert);
        }
    }
    return true;
}

} /* namespace */

int main(int argc, char** argv) {
    std::string sock_path = "/tmp/suricata-eve.sock";
    std::string soc_url   = "http://localhost:8080/api/idsm-violations";
    for (int i = 1; i < argc; ++i) {
        const std::string s = argv[i];
        if (s == "--sock" && i + 1 < argc) sock_path = argv[++i];
        else if (s == "--soc" && i + 1 < argc) soc_url = argv[++i];
        else {
            std::cout << "usage: " << argv[0] << " [--sock PATH] [--soc URL]\n";
            return 0;
        }
    }

    /* ---- IDSM init: SEv ext 0x8010 / sensor instance 1 ---- */
    IdsM_SecurityEventConfigType sevs[1] = {
        {0x8010, 1, IDSM_SEVERITY_HIGH, IDSM_REPORTING_DETAILED,
         nullptr, 0, 0 /* no aggregation: Suricata alerts are pre-filtered */,
         {0, 0}, true, true},
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
    std::cout << "[IDSM] Initialized | SEv 0: Suricata(ext 0x8010, sensor 1)\n";

    IdsRm_ConfigType idsrm_cfg{};
    std::strncpy(idsrm_cfg.soc_url, soc_url.c_str(), IDSRM_MAX_URL_LEN - 1);
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

    /* ---- listen ---- */
    ::unlink(sock_path.c_str());
    g_listen_fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_listen_fd < 0) {
        std::cerr << "[BRIDGE ERR] socket: " << std::strerror(errno) << "\n";
        IdsRm_DeInit(); IdsM_DeInit();
        return 1;
    }
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);
    if (::bind(g_listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0 ||
        ::listen(g_listen_fd, 4) < 0) {
        std::cerr << "[BRIDGE ERR] bind/listen on " << sock_path << ": "
                  << std::strerror(errno) << "\n";
        ::close(g_listen_fd);
        IdsRm_DeInit(); IdsM_DeInit();
        return 1;
    }
    std::cout << "[BRIDGE] listening on " << sock_path
              << " (waiting for Suricata eve-log unix_stream)\n";

    while (!g_stop.load()) {
        const int fd = ::accept(g_listen_fd, nullptr, nullptr);
        if (fd < 0) {
            if (errno == EINTR) continue;
            break;  /* listen socket closed by signal handler */
        }
        std::cout << "[BRIDGE] Suricata connected\n";
        serve_connection(fd);
        ::close(fd);
        if (!g_stop.load()) std::cout << "[BRIDGE] Suricata disconnected; waiting\n";
    }

    ::unlink(sock_path.c_str());
    IdsRm_DeInit();
    IdsM_DeInit();
    std::cout << "[BRIDGE] shutdown complete\n";
    return 0;
}
