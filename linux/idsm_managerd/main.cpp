/*
 * idsm_managerd -- Linux 车端管理守护进程。
 *
 * 与 Android IdsmManager APK 同职责同协议: 探针 --sink 上报的 NDJSON
 * 经本进程持久化(JSONL+游标)后走 MQTT/TLS 上云; 云端规则包验签后
 * 原子切换并重启探针。一条命令即可在普通 Linux 网关上跑完整车规链路。
 *
 *   idsm_managerd \
 *       --socket /run/idsm/probe.sock \
 *       --data-dir /var/lib/idsm \
 *       --broker mqtt.example.com:8883 --vin LXXXXXXX \
 *       --pubkey-b64 <ED25519_SPKI_B64> \
 *       --reload-cmd "systemctl restart idsm-host-probe.service idsm-eth-probe.service"
 */
#include "alert_queue.h"
#include "mqtt_uploader.h"
#include "rule_manager.h"
#include "socket_server.h"

#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

namespace {

std::atomic<bool> g_running{true};

void onSignal(int) { g_running.store(false); }

struct Args {
    std::string socket_path{"/run/idsm/probe.sock"};
    std::string data_dir{"/var/lib/idsm"};
    std::string rules_dir;   /* 空 = <data-dir>/rules */
    std::string seed_dir{"/etc/idsm/v0"};
    std::string broker{"localhost:8883"};
    std::string vin{"UNKNOWN_VIN"};
    std::string token;
    std::string cafile;
    std::string pubkey_b64;
    std::string reload_cmd;
    unsigned    socket_perm{0660};
};

void usage(const char* argv0) {
    std::fprintf(stderr,
        "idsm_managerd -- Linux IDSM manager (UDS sink -> MQTT/TLS cloud)\n"
        "usage: %s [options]\n"
        "  --socket PATH       UDS listen path (default /run/idsm/probe.sock)\n"
        "  --data-dir DIR      queue dir, alerts.jsonl+cursor (default /var/lib/idsm)\n"
        "  --rules-dir DIR     rule versions + current symlink (default <data-dir>/rules)\n"
        "  --seed-dir DIR      image-shipped baseline v0 (default /etc/idsm/v0)\n"
        "  --broker HOST:PORT  MQTT broker (default localhost:8883)\n"
        "  --vin VIN           vehicle id for topics ids/{alerts,rules}/<vin>\n"
        "  --token TOKEN       short-lived auth token (prod: refresh before connect)\n"
        "  --cafile FILE       TLS CA for broker\n"
        "  --pubkey-b64 B64    Ed25519 rule-signing public key (SPKI, base64)\n"
        "  --reload-cmd CMD    executed after rule switch (e.g. systemctl restart ...)\n"
        "  --socket-perm OCT   socket file mode (default 660)\n",
        argv0);
}

bool parseArgs(int argc, char** argv, Args& a) {
    bool ok = true;
    for (int i = 1; i < argc; ++i) {
        const std::string k = argv[i];
        auto next = [&](const char* what) -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "missing value for %s\n", what);
                ok = false;
                return {};
            }
            return argv[++i];
        };
        if (k == "--socket")           a.socket_path = next(k.c_str());
        else if (k == "--data-dir")    a.data_dir = next(k.c_str());
        else if (k == "--rules-dir")   a.rules_dir = next(k.c_str());
        else if (k == "--seed-dir")    a.seed_dir = next(k.c_str());
        else if (k == "--broker")      a.broker = next(k.c_str());
        else if (k == "--vin")         a.vin = next(k.c_str());
        else if (k == "--token")       a.token = next(k.c_str());
        else if (k == "--cafile")      a.cafile = next(k.c_str());
        else if (k == "--pubkey-b64")  a.pubkey_b64 = next(k.c_str());
        else if (k == "--reload-cmd")  a.reload_cmd = next(k.c_str());
        else if (k == "--socket-perm") a.socket_perm =
            static_cast<unsigned>(std::strtoul(next(k.c_str()).c_str(), nullptr, 8));
        else if (k == "--help")        { usage(argv[0]); std::exit(0); }
        else {
            std::fprintf(stderr, "unknown option %s\n", k.c_str());
            return false;
        }
        if (!ok) return false;
    }
    return true;
}

}  /* namespace */

int main(int argc, char** argv) {
    Args args;
    if (!parseArgs(argc, argv, args)) {
        usage(argv[0]);
        return 2;
    }
    if (args.rules_dir.empty()) args.rules_dir = args.data_dir + "/rules";

    std::signal(SIGTERM, onSignal);
    std::signal(SIGINT, onSignal);
    std::signal(SIGPIPE, SIG_IGN);

    std::string err;
    idsm::AlertQueue queue;
    if (!queue.open(args.data_dir, err)) {
        std::fprintf(stderr, "[IDSMD] queue open failed: %s\n", err.c_str());
        return 1;
    }

    idsm::RuleManager rules(args.rules_dir, args.reload_cmd,
                            args.pubkey_b64, args.seed_dir);
    if (!rules.seedFromImageDefaults(err)) {
        std::fprintf(stderr, "[IDSMD] seed failed: %s\n", err.c_str());
        return 1;
    }

    idsm::MqttConfig mcfg;
    {
        const auto colon = args.broker.rfind(':');
        if (colon != std::string::npos) {
            mcfg.host = args.broker.substr(0, colon);
            mcfg.port = std::atoi(args.broker.c_str() + colon + 1);
        } else {
            mcfg.host = args.broker;
        }
        mcfg.vin = args.vin;
        mcfg.token = args.token;
        mcfg.cafile = args.cafile;
    }
    auto uploader = idsm::MqttUploader::create(mcfg);
    if (!uploader->start(
            [&rules](const std::string&, const std::string& payload) {
                std::string e;
                if (!rules.applyBundle(payload, e)) {
                    std::fprintf(stderr, "[IDSMD] rule bundle rejected: %s\n",
                                 e.c_str());
                } else {
                    std::fprintf(stderr, "[IDSMD] rules activated, probes reloaded\n");
                }
            },
            err)) {
        /* 无 broker 不上线只是不能上云, 本地接收/排队继续 */
        std::fprintf(stderr, "[IDSMD] mqtt start failed (queueing only): %s\n",
                     err.c_str());
    }

    idsm::SocketServer server;
    if (!server.start(args.socket_path, args.socket_perm,
                      [&queue](const std::string& line) {
                          std::string e;
                          queue.append(line, e);
                      },
                      err)) {
        std::fprintf(stderr, "[IDSMD] socket server failed: %s\n", err.c_str());
        return 1;
    }
    std::fprintf(stderr, "[IDSMD] listening %s, vin=%s, broker=%s:%d\n",
                 args.socket_path.c_str(), mcfg.vin.c_str(),
                 mcfg.host.c_str(), mcfg.port);

    /* 上传循环: pending -> JSON array -> QoS1 -> 推进游标 */
    while (g_running.load()) {
        auto batch = queue.pending(64);
        if (batch.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }
        std::string arr = "[";
        for (size_t i = 0; i < batch.size(); ++i) {
            if (i) arr += ",";
            arr += batch[i];   /* 原始 NDJSON 行本身是合法 JSON 对象 */
        }
        arr += "]";
        if (uploader->publishAlerts(arr, err)) {
            queue.markUploaded(err);
        } else {
            std::fprintf(stderr, "[IDSMD] publish failed, retry later: %s\n",
                         err.c_str());
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }

    server.stop();
    uploader->stop();
    queue.close();
    std::fprintf(stderr, "[IDSMD] shutdown complete\n");
    return 0;
}
