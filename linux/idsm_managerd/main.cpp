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
#include "cert_manager.h"
#include "config_manager.h"
#include "log_snapshot.h"
#include "mqtt_uploader.h"
#include "property_report.h"
#include "registration.h"
#include "rule_manager.h"
#include "socket_server.h"
#include "vsoc_envelope.h"

#include <sys/stat.h>
#include <unistd.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <filesystem>
#include <list>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

std::atomic<bool> g_running{true};
/* 探针连接数变化 -> 立即增量属性上报(8.3) */
std::atomic<bool> g_report_now{false};

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
    std::string config_dir;         /* 空 = <data-dir>/config */
    std::string snapshot_dir;       /* 空 = <data-dir>/snapshots */
    std::string seed_dir{"/etc/idsm/v0"};
    std::string broker{"localhost:8883"};
    std::string token;
    std::string cafile;
    std::string cert_file;          /* 车端业务证书(双向 TLS + 续期, 3.3) */
    std::string key_file;
    std::string device_serial;      /* 产线注入(一型一证 cert 绑定校验) */
    std::string pubkey_b64;
    std::string reload_cmd;
    std::string ecu_code{"0x00"};
    bool        registration{false};   /* --register: 一型一证 init 流程 */
    bool        renew_cert{false};     /* --renew-cert: 证书续期客户端 */
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
        "  --config-dir DIR     配置下发目录(默认 <data-dir>/config)\n"
        "  --snapshot-dir DIR   日志快照暂存目录(默认 <data-dir>/snapshots)\n"
        "  --seed-dir DIR       出厂基线 v0(默认 /etc/idsm/v0)\n"
        "  --broker HOST:PORT   MQTT broker(默认 localhost:8883)\n"
        "  --no-tls             实验室明文 tcp(mock 云)\n"
        "  --token TOKEN        短期令牌\n"
        "  --register           走一型一证 init 流程(无 --token 且\n"
        "                       无本地凭据时向注册服务换 clientId+token)\n"
        "  --cafile FILE        TLS CA\n"
        "  --cert-file FILE     车端业务证书(双向 TLS; 配合 --renew-cert)\n"
        "  --key-file FILE      车端私钥\n"
        "  --device-serial SN   产线注入序列号(cert 通道 MES 绑定校验)\n"
        "  --renew-cert         剩余有效期 < 1/3 时自动走 sys/cert 续期\n"
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
        else if (k == "--config-dir") a.config_dir = next(k.c_str());
        else if (k == "--snapshot-dir") a.snapshot_dir = next(k.c_str());
        else if (k == "--seed-dir")   a.seed_dir = next(k.c_str());
        else if (k == "--broker")     a.broker = next(k.c_str());
        else if (k == "--token")      a.token = next(k.c_str());
        else if (k == "--cafile")     a.cafile = next(k.c_str());
        else if (k == "--cert-file")  a.cert_file = next(k.c_str());
        else if (k == "--key-file")   a.key_file = next(k.c_str());
        else if (k == "--device-serial") a.device_serial = next(k.c_str());
        else if (k == "--pubkey-b64") a.pubkey_b64 = next(k.c_str());
        else if (k == "--reload-cmd") a.reload_cmd = next(k.c_str());
        else if (k == "--register")   a.registration = true;
        else if (k == "--renew-cert") a.renew_cert = true;
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
    if (a.config_dir.empty()) a.config_dir = a.data_dir + "/config";
    if (a.snapshot_dir.empty()) a.snapshot_dir = a.data_dir + "/snapshots";
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
    std::shared_ptr<std::atomic<int>> peers;   /* 已连接探针数 */
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
        ch.peers = std::make_shared<std::atomic<int>>(0);
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
    idsm::ConfigManager configs(args.config_dir, args.reload_cmd,
                                args.pubkey_b64);
    idsm::LogSnapshotManager snapshots(args.snapshot_dir);

    /* 证书续期客户端(3.3): --renew-cert 且配了业务证书才启用 */
    std::unique_ptr<idsm::CertManager> cert_mgr;
    if (args.renew_cert && !args.cert_file.empty()) {
        cert_mgr = std::make_unique<idsm::CertManager>(
            args.cert_file, args.key_file, args.device_id,
            args.device_serial, args.manufacturer);
    } else if (args.renew_cert) {
        std::fprintf(stderr, "[IDSMD] --renew-cert ignored: no --cert-file\n");
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
        mcfg.cert_file = args.cert_file;
        mcfg.key_file = args.key_file;
    }
    idsm::DeviceIdentity self_id;
    self_id.ecu = args.ecu_code;
    self_id.vmodel = args.model_code;
    for (const auto& ch : channels) self_id.node_types.push_back(ch.node_type);

    /* LWT(5.3): 属性同通道, nodeStatus=0 单节点(管理组件宿主节点) */
    {
        idsm::NodeProperty down_node;
        down_node.ecu_code = args.ecu_code;
        down_node.node_type =
            channels.empty() ? "HIDPS" : channels.front().node_type;
        for (const auto& ch : channels)
            if (ch.node_type == "HIDPS") down_node.node_type = "HIDPS";
        down_node.node_status = 0;
        down_node.node_version = "idsm_managerd/1.0.0";
        down_node.rule_version = "unknown";
        mcfg.will_topic = idsm::propertyTopic(args.device_id);
        mcfg.will_payload = idsm::buildPropertyReport(
            args.manufacturer, {down_node},
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
    }

    /* 凭据: --token 直给 > 本地凭据文件; --register 且无有效凭据时
     * 走一型一证 init 流程换 clientId+token(4.2) */
    enum class RegState { Disabled, NeedRegister, Waiting, Registered };
    struct RegContext {
        RegState state{RegState::Disabled};
        idsm::Credentials creds;
        idsm::Credentials pending;      /* 响应回调解析结果 */
        std::atomic<bool> response_ready{false};
        std::string request_id;
        std::string err;
    } reg;
    idsm::CredentialStore cred_store(args.data_dir + "/credentials.json");
    long long reg_deadline_ms = 0;
    long long reg_next_attempt_ms = 0;
    int reg_attempts = 0;
    const std::string reg_req_topic_base =
        "oc/devices/" + args.device_id + "/sys/init/request/rid=";
    if (!args.token.empty()) {
        reg.creds.client_id = "idsm-" + args.device_id;
        reg.creds.token = args.token;
        reg.state = RegState::Registered;
    } else {
        std::string ce;
        if (cred_store.load(reg.creds, ce) && !ce.empty()) {
            std::fprintf(stderr, "[IDSMD] credentials unreadable, re-register\n");
            reg.creds = idsm::Credentials{};
        }
        const long long now_sec = std::time(nullptr);
        if (reg.creds.validAt(now_sec)) {
            reg.state = RegState::Registered;
            std::fprintf(stderr, "[IDSMD] loaded credentials for %s\n",
                         reg.creds.client_id.c_str());
        } else if (args.registration) {
            reg.state = RegState::NeedRegister;
        }
    }
    if (reg.state == RegState::Registered) {
        mcfg.client_id = reg.creds.client_id;
        mcfg.token = reg.creds.token;
    }

    /* 拒绝/失败事件上报队列(10.4 闭环: 拒绝 -> sys/events/up -> 云端重发) */
    std::mutex events_mu;
    std::deque<std::string> pending_events;
    auto push_event = [&events_mu, &pending_events, &args](idsm::EventItem item) {
        std::lock_guard<std::mutex> lock(events_mu);
        pending_events.push_back(idsm::buildEventUpEnvelope(
            args.manufacturer, {std::move(item)}));
    };

    /* 证书续期状态机(3.3/4.3, 语义同注册状态机) */
    struct CertCtx {
        enum class St { Idle, Waiting };
        St st{St::Idle};
        std::string rid;
        std::string pending_payload;
        std::atomic<bool> response_ready{false};
        long long deadline_ms{0};
        long long next_attempt_ms{0};
        int attempts{0};
    } cert;
    const std::string cert_req_topic_base =
        "oc/devices/" + args.device_id + "/sys/cert/request/rid=";

    auto uploader = idsm::MqttUploader::create(mcfg);
    if (!uploader->start(
            [&](const std::string& topic, const std::string& payload) {
                std::string e;
                if (topic.find("/sys/init/response/") != std::string::npos) {
                    /* 注册响应(4.3): 网络线程只解析, 主循环落盘+重连 */
                    if (idsm::parseInitResponse(payload, reg.request_id,
                                                reg.pending, e)) {
                        reg.response_ready.store(true);
                    }
                    return;
                }
                if (topic.find("/sys/cert/response/") != std::string::npos) {
                    /* 证书响应: 主循环原子换证 + reloadTls */
                    cert.pending_payload = payload;
                    cert.response_ready.store(true);
                    return;
                }
                if (topic.find("/sys/log/report/negative-ack") !=
                    std::string::npos) {
                    /* 快照补片(11.2), 仅 24h 内受理 */
                    const long long nack_now =
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now()
                                .time_since_epoch()).count();
                    if (!snapshots.onNack(payload, nack_now, e)) {
                        std::fprintf(stderr, "[IDSMD] snapshot nack: %s\n",
                                     e.c_str());
                    }
                    return;
                }
                if (topic.find("/sys/idps/config/update") !=
                    std::string::npos) {
                    const auto r = configs.applyBundle(payload, self_id, e);
                    if (r == idsm::ConfigApply::Rejected) {
                        std::fprintf(stderr,
                                     "[IDSMD] config bundle rejected: %s\n",
                                     e.c_str());
                        push_event({"CONFIG_REJECT", e, "MEDIUM", 0});
                    } else if (r == idsm::ConfigApply::Applied) {
                        std::fprintf(stderr,
                                     "[IDSMD] config applied, probes reloaded\n");
                    }
                    return;
                }
                const auto r = rules.applyBundle(payload, self_id, e);
                if (r == idsm::RuleApply::Rejected) {
                    std::fprintf(stderr, "[IDSMD] rule bundle rejected: %s\n",
                                 e.c_str());
                    /* 10.4: 拒绝(含 upgrade_type=2 显式拒绝)不静默,
                     * 经 sys/events/up 上报, 云端可重发 */
                    push_event({"RULE_REJECT", e, "MEDIUM", 0});
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
        ch.server.setOnPeerChange(
            [peers = ch.peers](int n) {
                peers->store(n);
                g_report_now.store(true);   /* 8.3 节点上下线即时增量上报 */
            });
        if (!ch.server.start(ch.sock_path, args.socket_perm,
                             [&ch, &snapshots](const std::string& line) {
                                 /* 探针下行命令(与告警行同通道, NDJSON):
                                  * {"cmd":"log_upload","file":...,
                                  *  "event_id":...,"remark":...}
                                  * -> 快照分包上传(11 章) */
                                 if (line.find("\"cmd\"") != std::string::npos) {
                                     try {
                                         const auto j =
                                             nlohmann::json::parse(line);
                                         if (j.value("cmd", "") == "log_upload") {
                                             idsm::SnapshotRequest req;
                                             req.file = j.value("file", "");
                                             req.event_id =
                                                 j.value("event_id", "");
                                             req.remark = j.value("remark", "");
                                             std::string se;
                                             const long long now_ms =
                                                 std::chrono::duration_cast<
                                                     std::chrono::milliseconds>(
                                                     std::chrono::system_clock::
                                                     now().time_since_epoch())
                                                     .count();
                                             const auto tid =
                                                 snapshots.stageUpload(req, now_ms, se);
                                             if (tid.empty()) {
                                                 std::fprintf(stderr,
                                                     "[IDSMD] log_upload rejected: %s\n",
                                                     se.c_str());
                                             } else {
                                                 std::fprintf(stderr,
                                                     "[IDSMD] snapshot staged: %s\n",
                                                     tid.c_str());
                                             }
                                             return;
                                         }
                                     } catch (...) { /* 回落按告警行处理 */ }
                                 }
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

    std::srand(static_cast<unsigned>(std::time(nullptr)) ^ ::getpid());
    long long next_report_ms = 0;   /* 属性/心跳定时 */

    /* 上报循环: 逐通道 pending -> 信封 -> 分管道发布 -> 推进游标 */
    while (g_running.load()) {
        bool any = false;
        const std::string rule_ver = currentRuleVersion(args.rules_dir);
        const long long now_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();

        /* 注册响应落盘 + 热更新凭据触发重连(4.3/4.4) */
        if (reg.response_ready.exchange(false)) {
            std::string e;
            if (cred_store.save(reg.pending, e) &&
                uploader->updateCredentials(reg.pending.client_id,
                                            reg.pending.token, e)) {
                reg.creds = reg.pending;
                reg.state = RegState::Registered;
                next_report_ms = now_ms + 5000;   /* 重连后 5s 内全量(8.3) */
                std::fprintf(stderr, "[IDSMD] registered: client_id=%s\n",
                             reg.creds.client_id.c_str());
            } else {
                reg.state = RegState::NeedRegister;
                reg_next_attempt_ms = now_ms + 10000;
                std::fprintf(stderr, "[IDSMD] credential apply failed: %s\n",
                             e.c_str());
            }
            reg.pending = idsm::Credentials{};
        }

        /* 注册状态机(4.2): 指数退避重试, 响应 30s 超时 */
        if (reg.state == RegState::NeedRegister && uploader->connected() &&
            now_ms >= reg_next_attempt_ms) {
            reg.request_id = idsm::newRequestId();
            std::string e;
            const std::string req = idsm::buildInitRequest(
                args.manufacturer, reg.request_id, now_ms, args.vin,
                args.model_code, {args.ecu_code});
            /* rid={request_id} 为键值型单段, MQTT 不允许嵌入式 +
             * 通配(7 章"rid=+"写法不成立), 按自己的 request_id 精确订阅 */
            const std::string resp_topic =
                "oc/devices/" + args.device_id + "/sys/init/response/rid=" +
                reg.request_id;
            if (uploader->subscribe(resp_topic, e) &&
                uploader->publish(reg_req_topic_base + reg.request_id,
                                  req, e)) {
                reg.state = RegState::Waiting;
                reg_deadline_ms = now_ms + 30000;
                ++reg_attempts;
                std::fprintf(stderr, "[IDSMD] init request rid=%s (attempt %d)\n",
                             reg.request_id.c_str(), reg_attempts);
            } else {
                reg_next_attempt_ms = now_ms + 10000;
            }
        } else if (reg.state == RegState::Waiting &&
                   now_ms > reg_deadline_ms) {
            reg.state = RegState::NeedRegister;
            const long long backoff =
                std::min<long long>(60000, 5000LL * (reg_attempts + 1));
            reg_next_attempt_ms = now_ms + backoff;
            std::fprintf(stderr, "[IDSMD] init timeout, retry in %llds\n",
                         backoff / 1000);
        }

        /* 属性/心跳(8.3): CONNECT 后 5s 内全量 + 300s±10% 周期;
         * 未注册(NeedRegister/Waiting)时不发, 真实 broker 会拒 */
        if (uploader->connected() &&
            (reg.state == RegState::Registered ||
             reg.state == RegState::Disabled) &&
            (now_ms >= next_report_ms || g_report_now.exchange(false))) {
            std::vector<idsm::NodeProperty> nodes;
            for (const auto& ch : channels) {
                idsm::NodeProperty n;
                n.ecu_code = args.ecu_code;
                n.node_type = ch.node_type;
                n.node_version = "idsm_managerd/1.0.0";
                /* nodeStatus 接 UDS 真实连接状态(8 章):
                 * 探针掉线 -> 0 离线, 重连 -> 1 在线 */
                n.node_status = ch.peers->load() > 0 ? 1 : 0;
                n.rule_version = rule_ver;
                nodes.push_back(std::move(n));
            }
            std::string e;
            if (uploader->publish(idsm::propertyTopic(args.device_id),
                                  idsm::buildPropertyReport(
                                      args.manufacturer, nodes, now_ms), e)) {
                next_report_ms = idsm::nextReportTimeMs(
                    now_ms, static_cast<unsigned>(std::rand()));
                std::fprintf(stderr, "[IDSMD] property report (%zu nodes)\n",
                             nodes.size());
            } else {
                next_report_ms = now_ms + 10000;   /* 发布失败稍后重试 */
            }
        }

        /* 拒绝/失败事件闭环上报(10.4): sys/events/up */
        if (uploader->connected()) {
            std::string ev;
            {
                std::lock_guard<std::mutex> lock(events_mu);
                if (!pending_events.empty()) {
                    ev = pending_events.front();
                    pending_events.pop_front();
                }
            }
            if (!ev.empty()) {
                std::string e;
                if (!uploader->publish(idsm::MqttUploader::eventUpTopic(
                                           args.device_id), ev, e)) {
                    std::lock_guard<std::mutex> lock(events_mu);
                    pending_events.push_front(ev);
                }
            }
        }

        /* 日志快照分包上传(11 章): 断网时持久在 pending/, 恢复后续传 */
        {
            std::string e;
            const bool progressed = snapshots.pump(
                args.manufacturer, args.device_id, args.ecu_code, now_ms,
                [&uploader](const std::string& topic,
                            const std::string& payload) {
                    std::string pe;
                    return uploader->publish(topic, payload, pe);
                },
                e);
            if (!e.empty()) {
                std::fprintf(stderr, "[IDSMD] snapshot pump: %s\n", e.c_str());
            }
            if (progressed) any = true;
        }

        /* 证书续期状态机(3.3/4.3): 剩余 < 1/3 自动申请, 归 PKI */
        if (cert_mgr &&
            (reg.state == RegState::Registered ||
             reg.state == RegState::Disabled)) {
            if (cert.st == CertCtx::St::Idle && uploader->connected() &&
                now_ms >= cert.next_attempt_ms) {
                std::string ce;
                if (!cert_mgr->needsRenewal(now_ms / 1000, ce)) {
                    if (!ce.empty()) {
                        std::fprintf(stderr, "[IDSMD] cert renewal off: %s\n",
                                     ce.c_str());
                        cert_mgr.reset();   /* 证书不可读, 停用续期 */
                    } else {
                        cert.next_attempt_ms = now_ms + 6LL * 3600 * 1000;
                    }
                } else {
                    cert.rid = idsm::newRequestId();
                    const std::string req =
                        cert_mgr->buildRequest(cert.rid, now_ms, ce);
                    const std::string resp_topic =
                        "oc/devices/" + args.device_id +
                        "/sys/cert/response/rid=" + cert.rid;
                    if (!req.empty() &&
                        uploader->subscribe(resp_topic, ce) &&
                        uploader->publish(cert_req_topic_base + cert.rid,
                                          req, ce)) {
                        cert.st = CertCtx::St::Waiting;
                        cert.deadline_ms = now_ms + 30000;
                        ++cert.attempts;
                        std::fprintf(stderr,
                                     "[IDSMD] cert renewal request rid=%s "
                                     "(attempt %d)\n",
                                     cert.rid.c_str(), cert.attempts);
                    } else {
                        cert.next_attempt_ms = now_ms + 3600 * 1000;
                        std::fprintf(stderr,
                                     "[IDSMD] cert request failed: %s\n",
                                     ce.c_str());
                    }
                }
            } else if (cert.st == CertCtx::St::Waiting) {
                if (cert.response_ready.exchange(false)) {
                    std::string ce;
                    if (cert_mgr->applyResponse(cert.pending_payload,
                                                cert.rid, ce)) {
                        std::string e2;
                        if (uploader->reloadTls(args.cert_file, args.key_file,
                                                e2)) {
                            /* 重叠期双认(<=7 天, 3.3), 12h 后再评估 */
                            cert.next_attempt_ms = now_ms + 12LL * 3600 * 1000;
                            std::fprintf(stderr,
                                         "[IDSMD] cert renewed, tls reloaded\n");
                        } else {
                            std::fprintf(stderr,
                                         "[IDSMD] tls reload failed: %s\n",
                                         e2.c_str());
                        }
                    } else {
                        /* rc!=0 模糊码(6.5, PKI 类返 1004): 24h 退避 */
                        cert.next_attempt_ms = now_ms + 24LL * 3600 * 1000;
                        std::fprintf(stderr,
                                     "[IDSMD] cert renewal rejected: %s\n",
                                     ce.c_str());
                    }
                    cert.st = CertCtx::St::Idle;
                } else if (now_ms > cert.deadline_ms) {
                    cert.st = CertCtx::St::Idle;
                    const long long backoff =
                        std::min<long long>(60000, 5000LL * (cert.attempts + 1));
                    cert.next_attempt_ms = now_ms + backoff;
                    std::fprintf(stderr, "[IDSMD] cert renewal timeout, "
                                         "retry in %llds\n", backoff / 1000);
                }
            }
        }

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
