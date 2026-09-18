/*
 * idsm_managerd -- Linux 车端管理守护进程(VSOC 设备接入设计 v1.0 车端落地)。
 *
 * 探针按 nodeType 分 UDS 通道上报(sink),本进程构造 alert_{host|eth|can}
 * 信封发布到 oc/devices/{device_id}/sys/idps/{host|eth|can}/log;
 * 云端签名规则包验签后原子切换并 reload-cmd 重启探针。
 *
 *   idsm_managerd \
 *       --manufacturer caic --model-code t99 --vin LXXXXXXX202000001 \
 *       --socket /run/idsm/host.sock \
 *       --sink NIDPS=/run/idsm/eth.sock --sink CIDS=/run/idsm/can.sock \
 *       --ecu-code 0x01 \
 *       --broker mqtt.example.com:8883 --no-tls  # 实验室 mock 用 --no-tls \
 *       --pubkey-b64 <ED25519_SPKI_B64> \
 *       --reload-cmd "systemctl restart idsm-host-probe idsm-eth-probe"
 */
#include "alert_queue.h"
#include "mqtt_uploader.h"
#include "rule_manager.h"
#include "socket_server.h"
#include "vsoc_envelope.h"

#include <sys/stat.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <list>
#include <map>
#include <string>
#include <thread>
#include <vector>

namespace {

std::atomic<bool> g_running{true};

void onSignal(int) { g_running.store(false); }

struct Args {
    /* device_id 三段式: --device-id 直给,或三段拼 */
    std::string manufacturer{"caic"};
    std::string model_code{"t99"};
    std::string vin{"UNKNOWN_VIN"};
    std::string device_id;          /* 空 = 三段拼接 */

    /* nodeType -> UDS 路径; host 默认走 --socket */
    std::string socket_path{"/run/idsm/host.sock"};
    std::map<std::string, std::string> sinks;   /* 额外 --sink NIDPS=path */

    std::string data_dir{"/var/lib/idsm"};
    std::string rules_dir;          /* 空 = <data-dir>/rules */
    std::string seed_dir{"/etc/idsm/v0"};
    std::string broker{"localhost:8883"};
    std::string token;
    std::string cafile;
    std::string pubkey_b64;
    std::string reload_cmd;
    std::string ecu_code{"0x00"};
    bool        tls{true};
    unsigned    socket_perm{0660};
};

void usage(const char* argv0) {
    std::fprintf(stderr,
        "idsm_managerd -- Linux IDSM manager (VSOC v1.0 vehicle-side)\n"
        "usage: %s [options]\n"
        "  --device-id ID       三段式设备编号(优先于三段拼)\n"
        "  --manufacturer M     厂商/租户(默认 caic)\n"
        "  --model-code CODE    车型编码(默认 t99)\n"
        "  --vin VIN            车架号(默认 UNKNOWN_VIN)\n"
        "  --socket PATH        HIDPS sink 路径(默认 /run/idsm/host.sock)\n"
        "  --sink NT=PATH       额外探针 sink, NT=HIDPS|NIDPS|CIDS, 可重复\n"
        "  --ecu-code CODE      本机 ECU 编码(默认 0x00, 数据字典)\n"
        "  --data-dir DIR       队列根目录(默认 /var/lib/idsm)\n"
        "  --rules-dir DIR      规则版本目录(默认 <data-dir>/rules)\n"
        "  --seed-dir DIR       出厂基线 v0(默认 /etc/idsm/v0)\n"
        "  --broker HOST:PORT   MQTT broker(默认 localhost:8883)\n"
        "  --no-tls             实验室明文 tcp(mock 云)\n"
        "  --token TOKEN        短期令牌\n"
        "  --cafile FILE        TLS CA\n"
        "  --pubkey-b64 B64     规则签名 Ed25519 公钥(SPKI base64)\n"
        "  --reload-cmd CMD     规则切换后执行(如 systemctl restart ...)\n"
        "  --socket-perm OCT    sink 文件权限(默认 660)\n",
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
        if (k == "--device-id")       a.device_id = next(k.c_str());
        else if (k == "--manufacturer") a.manufacturer = next(k.c_str());
        else if (k == "--model-code") a.model_code = next(k.c_str());
        else if (k == "--vin")        a.vin = next(k.c_str());
        else if (k == "--socket")     a.socket_path = next(k.c_str());
        else if (k == "--sink") {
            const std::string spec = next(k.c_str());
            const auto eq = spec.find('=');
            if (eq == std::string::npos ||
                spec.substr(0, eq).empty() || spec.substr(eq + 1).empty()) {
                std::fprintf(stderr, "bad --sink (want NIDPS=/path.sock)\n");
                return false;
            }
            a.sinks[spec.substr(0, eq)] = spec.substr(eq + 1);
        }
        else if (k == "--ecu-code")   a.ecu_code = next(k.c_str());
        else if (k == "--data-dir")   a.data_dir = next(k.c_str());
        else if (k == "--rules-dir")  a.rules_dir = next(k.c_str());
        else if (k == "--seed-dir")   a.seed_dir = next(k.c_str());
        else if (k == "--broker")     a.broker = next(k.c_str());
        else if (k == "--token")      a.token = next(k.c_str());
        else if (k == "--cafile")     a.cafile = next(k.c_str());
        else if (k == "--pubkey-b64") a.pubkey_b64 = next(k.c_str());
        else if (k == "--reload-cmd") a.reload_cmd = next(k.c_str());
        else if (k == "--no-tls")     a.tls = false;
        else if (k == "--socket-perm")
            a.socket_perm = static_cast<unsigned>(
                std::strtoul(next(k.c_str()).c_str(), nullptr, 8));
        else if (k == "--help")       { usage(argv[0]); std::exit(0); }
        else {
            std::fprintf(stderr, "unknown option %s\n", k.c_str());
            return false;
        }
        if (!ok) return false;
    }
    if (a.device_id.empty()) {
        a.device_id = a.manufacturer + "_" + a.model_code + "_" + a.vin;
    }
    if (a.rules_dir.empty()) a.rules_dir = a.data_dir + "/rules";
    return true;
}

/* rules/current 软链目标 -> ruleVersion(去 v 前缀);无则 unknown */
std::string currentRuleVersion(const std::string& rules_dir) {
    std::error_code ec;
    const auto target = std::filesystem::read_symlink(
        std::filesystem::path(rules_dir) / "current", ec);
    if (ec) return "unknown";
    std::string v = target.filename().string();
    if (!v.empty() && v[0] == 'v') v.erase(0, 1);
    return v.empty() ? "unknown" : v;
}

struct NodeChannel {
    std::string   node_type;
    std::string   sock_path;
    std::string   queue_dir;
    idsm::SocketServer server;
    idsm::AlertQueue   queue;
};

}  /* namespace */

int main(int argc, char** argv) {
    Args args;
    if (!parseArgs(argc, argv, args)) {
        usage(argv[0]);
        return 2;
    }

    std::signal(SIGTERM, onSignal);
    std::signal(SIGINT, onSignal);
    std::signal(SIGPIPE, SIG_IGN);

    std::string err;

    /* nodeType 校验 + 组通道表 */
    std::map<std::string, std::string> all_sinks = args.sinks;
    all_sinks.emplace("HIDPS", args.socket_path);   /* host 默认通道 */
    std::list<NodeChannel> channels;
    for (const auto& [nt, path] : all_sinks) {
        if (std::string(idsm::nodeTypeToTopicSeg(nt)) == "unknown") {
            std::fprintf(stderr, "[IDSMD] bad nodeType %s (HIDPS/NIDPS/CIDS)\n",
                         nt.c_str());
            return 2;
        }
        channels.emplace_back();   /* 原地构造, 成员不可移动 */
        NodeChannel& ch = channels.back();
        ch.node_type = nt;
        ch.sock_path = path;
        ch.queue_dir = args.data_dir + "/q-" + idsm::nodeTypeToTopicSeg(nt);
        std::error_code ec;
        std::filesystem::create_directories(ch.queue_dir, ec);
    }

    for (auto& ch : channels) {
        if (!ch.queue.open(ch.queue_dir, err)) {
            std::fprintf(stderr, "[IDSMD] queue open(%s) failed: %s\n",
                         ch.queue_dir.c_str(), err.c_str());
            return 1;
        }
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
        mcfg.device_id = args.device_id;
        mcfg.manufacturer = args.manufacturer;
        mcfg.model_code = args.model_code;
        mcfg.token = args.token;
        mcfg.tls = args.tls;
        mcfg.cafile = args.cafile;
    }
    idsm::DeviceIdentity self_id;
    self_id.ecu = args.ecu_code;
    self_id.vmodel = args.model_code;
    for (const auto& ch : channels) self_id.node_types.push_back(ch.node_type);

    auto uploader = idsm::MqttUploader::create(mcfg);
    if (!uploader->start(
            [&rules, self_id](const std::string&, const std::string& payload) {
                std::string e;
                const auto r = rules.applyBundle(payload, self_id, e);
                if (r == idsm::RuleApply::Rejected) {
                    std::fprintf(stderr, "[IDSMD] rule bundle rejected: %s\n",
                                 e.c_str());
                } else if (r == idsm::RuleApply::Applied) {
                    std::fprintf(stderr,
                                 "[IDSMD] rules activated, probes reloaded\n");
                }
            },
            err)) {
        std::fprintf(stderr,
                     "[IDSMD] mqtt start failed (queueing only): %s\n",
                     err.c_str());
    }

    for (auto& ch : channels) {
        if (!ch.server.start(ch.sock_path, args.socket_perm,
                             [&ch](const std::string& line) {
                                 std::string e;
                                 ch.queue.append(line, e);
                             },
                             err)) {
            std::fprintf(stderr, "[IDSMD] socket %s failed: %s\n",
                         ch.sock_path.c_str(), err.c_str());
            return 1;
        }
        std::fprintf(stderr, "[IDSMD] sink %s -> %s\n",
                     ch.node_type.c_str(), ch.sock_path.c_str());
    }
    std::fprintf(stderr,
                 "[IDSMD] device_id=%s ecu=%s broker=%s:%d tls=%d\n",
                 args.device_id.c_str(), args.ecu_code.c_str(),
                 mcfg.host.c_str(), mcfg.port, static_cast<int>(mcfg.tls));

    /* 上报循环: 逐通道 pending -> 信封 -> 分管道发布 -> 推进游标 */
    while (g_running.load()) {
        bool any = false;
        const std::string rule_ver = currentRuleVersion(args.rules_dir);
        for (auto& ch : channels) {
            auto batch = ch.queue.pending(64);
            if (batch.empty()) continue;
            any = true;
            std::string env = idsm::buildAlertEnvelope(
                args.manufacturer, args.device_id, ch.node_type,
                args.ecu_code, rule_ver, batch, err);
            if (env.empty()) {
                /* 全部解析失败: 丢弃本批并推进, 防毒丸卡死队列 */
                std::fprintf(stderr, "[IDSMD] envelope drop batch: %s\n",
                             err.c_str());
                ch.queue.markUploaded(err);
                continue;
            }
            const std::string topic = "oc/devices/" + args.device_id +
                "/sys/idps/" + idsm::nodeTypeToTopicSeg(ch.node_type) + "/log";
            if (uploader->publish(topic, env, err)) {
                ch.queue.markUploaded(err);
            } else {
                std::fprintf(stderr,
                             "[IDSMD] publish failed, retry later: %s\n",
                             err.c_str());
                std::this_thread::sleep_for(std::chrono::seconds(5));
                break;
            }
        }
        if (!any) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }

    for (auto& ch : channels) {
        ch.server.stop();
        ch.queue.close();
    }
    uploader->stop();
    std::fprintf(stderr, "[IDSMD] shutdown complete\n");
    return 0;
}
