/*
 * test_managerd.cpp -- Linux 管理守护进程(idsm_managerd)组件测试:
 * 持久队列断点续传、base64/canonical 与 Android 侧一致性、
 * Ed25519 规则包验签+原子切换+reload、UDS 收包。
 */
#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <chrono>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <string>
#include <thread>
#include <vector>

#include "alert_queue.h"
#include "base64.h"
#include "property_report.h"
#include "registration.h"
#include "rule_manager.h"
#include "socket_server.h"
#include "vsoc_envelope.h"

namespace fs = std::filesystem;

static std::string tmpDir(const char* tag) {
    const auto d = fs::path(testing::TempDir()) /
                   ("idsmd_" + std::to_string(::getpid()) + "_" + tag);
    fs::remove_all(d);
    fs::create_directories(d);
    return d.string();
}

/* ───────────────────────── base64 ─────────────────────────── */

TEST(ManagerdBase64, RoundTrip) {
    const std::string in = "\x01\x02\xfb\xff"
        "hello-idSM-0123456789+/==";
    std::string enc = idsm::base64Encode(in);
    EXPECT_EQ(enc, "AQL7/2hlbGxvLWlkU00tMDEyMzQ1Njc4OSsvPT0=");
    std::string dec;
    ASSERT_TRUE(idsm::base64Decode(enc, dec));
    EXPECT_EQ(dec, in);
    /* 坏输入拒绝 */
    EXPECT_FALSE(idsm::base64Decode("abc", dec));
    EXPECT_FALSE(idsm::base64Decode("a=b=", dec));
}

/* ─────────────────────── 持久队列 ─────────────────────────── */

TEST(ManagerdQueue, AppendPendingMarkAndReopen) {
    const auto dir = tmpDir("queue");
    std::string err;

    idsm::AlertQueue q;
    ASSERT_TRUE(q.open(dir, err)) << err;
    for (int i = 0; i < 3; ++i) {
        ASSERT_TRUE(q.append("{\"event_id\":" + std::to_string(32800 + i) + "}", err));
    }

    /* 第一批 2 条, 确认后剩 1 条 */
    auto batch = q.pending(2);
    ASSERT_EQ(batch.size(), 2u);
    EXPECT_NE(batch[0].find("32800"), std::string::npos);
    ASSERT_TRUE(q.markUploaded(err)) << err;

    auto rest = q.pending(10);
    ASSERT_EQ(rest.size(), 1u);
    EXPECT_NE(rest[0].find("32802"), std::string::npos);
    q.close();

    /* 重启(进程崩溃场景): 游标持久化, 从断点续传 */
    idsm::AlertQueue q2;
    ASSERT_TRUE(q2.open(dir, err)) << err;
    auto resumed = q2.pending(10);
    ASSERT_EQ(resumed.size(), 1u);
    EXPECT_NE(resumed[0].find("32802"), std::string::npos);
    ASSERT_TRUE(q2.markUploaded(err)) << err;

    /* 全部上传完毕 -> 文件压缩, 追加新事件从干净状态开始 */
    ASSERT_TRUE(q2.append("{\"event_id\":999}", err));
    q2.close();
    idsm::AlertQueue q3;
    ASSERT_TRUE(q3.open(dir, err)) << err;
    auto fresh = q3.pending(10);
    ASSERT_EQ(fresh.size(), 1u);
    EXPECT_NE(fresh[0].find("999"), std::string::npos);
}

/* ─── 规则包验签 + 原子切换(VSOC v1.0 10.1/10.2, 与 mock_vsoc.py 互操作) ─── */

namespace {

struct Ed25519Key {
    std::string pubkey_spki_b64;
    EVP_PKEY* pkey;
};

Ed25519Key makeEd25519() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    EXPECT_NE(pctx, nullptr);
    EXPECT_EQ(EVP_PKEY_keygen_init(pctx), 1);
    EVP_PKEY* pkey = nullptr;
    EXPECT_EQ(EVP_PKEY_keygen(pctx, &pkey), 1);
    EVP_PKEY_CTX_free(pctx);

    unsigned char* der = nullptr;
    const int len = i2d_PUBKEY(pkey, &der);   /* SPKI DER */
    EXPECT_GT(len, 0);
    Ed25519Key k{idsm::base64Encode(der, static_cast<size_t>(len)), pkey};
    OPENSSL_free(der);
    return k;
}

std::string signEd25519(EVP_PKEY* pkey, const std::string& data) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EXPECT_EQ(EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey), 1);
    size_t siglen = 0;
    EXPECT_EQ(EVP_DigestSign(ctx, nullptr, &siglen,
                             reinterpret_cast<const uint8_t*>(data.data()),
                             data.size()), 1);
    std::string sig(siglen, '\0');
    EXPECT_EQ(EVP_DigestSign(ctx,
                             reinterpret_cast<uint8_t*>(&sig[0]), &siglen,
                             reinterpret_cast<const uint8_t*>(data.data()),
                             data.size()), 1);
    sig.resize(siglen);
    EVP_MD_CTX_free(ctx);
    return sig;
}

/* pubkey_id: sha256(raw Ed25519 公钥) hex 前 16(与 mock python 一致) */
std::string pubkeyIdHex16(EVP_PKEY* pkey) {
    uint8_t raw[32];
    size_t raw_len = sizeof(raw);
    EXPECT_EQ(EVP_PKEY_get_raw_public_key(pkey, raw, &raw_len), 1);
    EXPECT_EQ(raw_len, 32u);
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    EVP_Digest(raw, sizeof(raw), digest, &dlen, EVP_sha256(), nullptr);
    static const char hex[] = "0123456789abcdef";
    std::string out;
    for (int i = 0; i < 8; ++i) {
        out += hex[digest[i] >> 4];
        out += hex[digest[i] & 0x0f];
    }
    return out;
}

/* 与 mock_vsoc.py sign_rule_bundle 同构的测试包构造(测试自用) */
nlohmann::json makeBundleV1(EVP_PKEY* signer,
                            long long seq, const std::string& version,
                            const std::string& target_ecu,
                            const std::string& target_node,
                            const std::string& target_vmodel,
                            const std::vector<std::string>& rules,
                            long long issued_at, long long expires_at) {
    std::vector<std::string> payload;
    for (size_t i = 0; i < rules.size(); ++i) {
        payload.push_back("rule:" + std::to_string(10000 + i) + ":" +
                          idsm::base64Encode(
                              reinterpret_cast<const uint8_t*>(rules[i].data()),
                              rules[i].size()));
    }
    std::sort(payload.begin(), payload.end());
    const std::string canonical = idsm::canonicalRuleBytes(
        seq, "caic", version, false, target_ecu, target_node, target_vmodel,
        issued_at, expires_at, 1, payload);
    nlohmann::json b;
    b["msg_type"] = "rule_update";
    b["protocol_version"] = "1.0";
    b["timestamp"] = 0;
    b["manufacturer"] = "caic";
    b["seq"] = seq;
    b["version"] = version;
    b["rollback"] = false;
    b["target"] = {{"ecu", target_ecu},
                   {"nodeType", target_node},
                   {"vmodel", target_vmodel}};
    b["upgrade_type"] = 1;
    b["rules"] = rules;
    b["issued_at"] = issued_at;
    b["expires_at"] = expires_at;
    b["sig_alg"] = "Ed25519";
    b["pubkey_id"] = pubkeyIdHex16(signer);
    b["signature"] = idsm::base64Encode(signEd25519(signer, canonical));
    return b;
}

idsm::DeviceIdentity testIdentity() {
    idsm::DeviceIdentity id;
    id.ecu = "0x01";
    id.vmodel = "t99";
    id.node_types = {"HIDPS", "NIDPS"};
    return id;
}

}  /* namespace */

TEST(ManagerdRules, CanonicalMatchesPythonBaseline) {
    /* 与 tools/vsoc_mock/mock_vsoc.py canonical_bytes 逐字节对齐的钉桩
     * (固定输入, 不含时间, 永不过期; 由 python 侧生成) */
    const std::vector<std::string> payload = {"rule:10000:YQ==",
                                              "rule:10001:Yg=="};
    EXPECT_EQ(idsm::canonicalRuleBytes(42, "caic", "v8", false,
                                       "0x01", "NIDPS", "t99",
                                       1700000000, 1700604800, 1, payload),
              "seq=42\n"
              "tenant=caic\n"
              "version=v8\n"
              "rollback=0\n"
              "target_ecu=0x01\n"
              "target_node=NIDPS\n"
              "target_vmodel=t99\n"
              "issued_at=1700000000\n"
              "expires_at=1700604800\n"
              "upgrade_type=1\n"
              "rule:10000:YQ==\n"
              "rule:10001:Yg==\n");
}

TEST(ManagerdRules, SignedBundleSwitchesAtomicallyAndReloads) {
    const auto dir = tmpDir("rules");
    const auto seed = tmpDir("seed");
    const auto marker = fs::path(dir) / "reloaded.marker";
    const auto key = makeEd25519();
    const auto now = std::time(nullptr);

    idsm::RuleManager rm(dir,
                         "touch " + marker.string(),
                         key.pubkey_spki_b64, seed);
    std::string err;

    /* 出厂基线播种 */
    {
        std::ofstream(fs::path(seed) / "exec.txt") << "/usr/sbin/sshd\n";
    }
    ASSERT_TRUE(rm.seedFromImageDefaults(err)) << err;
    EXPECT_TRUE(fs::exists(fs::path(dir) / "v0" / "exec.txt"));
    EXPECT_TRUE(fs::is_symlink(fs::path(dir) / "current"));

    /* 签名规则包: 应用成功 + 原子切换 + reload 触发 */
    auto bundle = makeBundleV1(key.pkey, 2, "v2", "0x01", "NIDPS", "t99",
                               {"alert tcp any any -> any 3389 (msg:\"RDP\"; sid:10001;)"},
                               now - 60, now + 7 * 24 * 3600);
    ASSERT_EQ(rm.applyBundle(bundle.dump(), testIdentity(), err),
              idsm::RuleApply::Applied) << err;
    EXPECT_TRUE(fs::exists(marker));
    EXPECT_TRUE(fs::exists(fs::path(dir) / "v2" / "rule_10000.rules"));
    EXPECT_EQ(fs::read_symlink(fs::path(dir) / "current").string(), "v2");
    /* rules.new 已被 rename 消费 */
    EXPECT_FALSE(fs::exists(fs::path(dir) / "rules.new"));

    /* 防回滚: 同序号重放 -> 拒绝, current 不变 */
    EXPECT_EQ(rm.applyBundle(bundle.dump(), testIdentity(), err),
              idsm::RuleApply::Rejected);
    EXPECT_EQ(fs::read_symlink(fs::path(dir) / "current").string(), "v2");

    /* 篡改签名 -> 拒绝 */
    auto bad = bundle;
    bad["signature"] = idsm::base64Encode(std::string(64, 'A'));
    EXPECT_EQ(rm.applyBundle(bad.dump(), testIdentity(), err),
              idsm::RuleApply::Rejected);

    /* 未命中本机(target.nodeType=CIDS 非托管) -> 跳过, 但序号已消费 */
    auto skip = makeBundleV1(key.pkey, 3, "v3", "0x01", "CIDS", "t99",
                             {"alert ... sid:10002;"}, now - 60,
                             now + 7 * 24 * 3600);
    EXPECT_EQ(rm.applyBundle(skip.dump(), testIdentity(), err),
              idsm::RuleApply::Skipped);
    EXPECT_EQ(fs::read_symlink(fs::path(dir) / "current").string(), "v2");

    /* 过期包 -> 拒绝 */
    auto expired = makeBundleV1(key.pkey, 4, "v4", "0x01", "NIDPS", "t99",
                                {"alert ... sid:10003;"}, now - 8 * 24 * 3600,
                                now - 24 * 3600 - 3600);
    EXPECT_EQ(rm.applyBundle(expired.dump(), testIdentity(), err),
              idsm::RuleApply::Rejected);

    /* 更高 seq 的合法包 -> 应用(v3 目录名防穿越: 非法 version 拒绝) */
    auto v5 = makeBundleV1(key.pkey, 5, "v5", "all", "all", "all",
                           {"alert ... sid:10004;"}, now - 60,
                           now + 7 * 24 * 3600);
    EXPECT_EQ(rm.applyBundle(v5.dump(), testIdentity(), err),
              idsm::RuleApply::Applied) << err;
    EXPECT_EQ(fs::read_symlink(fs::path(dir) / "current").string(), "v5");

    auto evil = v5;
    evil["seq"] = 6;
    evil["version"] = "../evil";
    EXPECT_EQ(rm.applyBundle(evil.dump(), testIdentity(), err),
              idsm::RuleApply::Rejected);

    EVP_PKEY_free(key.pkey);
}

/* python 签名 -> C++ 验签全链路互操作; 向量由 ctest fixture 现场生成
 * (tools/vsoc_mock/gen_rule_vector.py, 时间戳随生成时刻走, 永不过期) */
TEST(ManagerdRulesInterop, PythonSignedBundleApplies) {
    const char* vec_path = std::getenv("RULE_VECTOR_JSON");
    if (vec_path == nullptr) {
        GTEST_SKIP() << "RULE_VECTOR_JSON not set (run under ctest)";
    }
    nlohmann::json vec;
    {
        std::ifstream is(vec_path);
        ASSERT_TRUE(is.good()) << "open " << vec_path;
        vec = nlohmann::json::parse(is);
    }

    const auto dir = tmpDir("rulesinterop");
    const auto seed = tmpDir("seedinterop");
    const auto key_b64 = vec["pubkey_spki_b64"].get<std::string>();
    idsm::RuleManager rm(dir, "", key_b64, seed);
    std::string err;

    const auto& bundle = vec["bundle"];
    ASSERT_EQ(rm.applyBundle(bundle.dump(), testIdentity(), err),
              idsm::RuleApply::Applied) << err;

    /* canonical 逐字节对齐 python 基准 */
    const auto& t = bundle["target"];
    std::vector<std::string> payload;
    for (size_t i = 0; i < bundle["rules"].size(); ++i) {
        const std::string r = bundle["rules"][i].get<std::string>();
        payload.push_back("rule:" + std::to_string(10000 + i) + ":" +
                          idsm::base64Encode(
                              reinterpret_cast<const uint8_t*>(r.data()),
                              r.size()));
    }
    std::sort(payload.begin(), payload.end());
    EXPECT_EQ(idsm::canonicalRuleBytes(
                  bundle["seq"].get<long long>(),
                  bundle["manufacturer"].get<std::string>(),
                  bundle["version"].get<std::string>(),
                  bundle["rollback"].get<bool>(),
                  t["ecu"].get<std::string>(),
                  t["nodeType"].get<std::string>(),
                  t["vmodel"].get<std::string>(),
                  bundle["issued_at"].get<long long>(),
                  bundle["expires_at"].get<long long>(),
                  bundle["upgrade_type"].get<int>(), payload),
              vec["canonical"].get<std::string>());

    /* 规则内容落盘一致 */
    const std::string ver = bundle["version"].get<std::string>();
    std::ifstream got(fs::path(dir) / ver / "rule_10000.rules");
    const std::string content((std::istreambuf_iterator<char>(got)),
                              std::istreambuf_iterator<char>());
    EXPECT_EQ(content, bundle["rules"][0].get<std::string>());

    /* 重放同包 -> 防回滚拒绝 */
    EXPECT_EQ(rm.applyBundle(bundle.dump(), testIdentity(), err),
              idsm::RuleApply::Rejected);
}

/* ─────────────────────── UDS 收包 ─────────────────────────── */

/* ─────────── 一型一证注册(4 章) + 属性/心跳(8 章) ─────────── */

TEST(ManagerdRegistration, CredentialStoreRoundTrip) {
    const auto dir = tmpDir("credstore");
    const auto path = (fs::path(dir) / "credentials.json").string();
    idsm::CredentialStore store(path);
    std::string err;

    /* 不存在: false 且 err 为空 */
    idsm::Credentials out;
    EXPECT_FALSE(store.load(out, err));
    EXPECT_TRUE(err.empty());

    /* 保存 -> 读回 */
    idsm::Credentials in;
    in.client_id = "vehicle_t99_abcdef0123456789";
    in.token = "tok-123";
    in.token_expire = 1893456000;
    ASSERT_TRUE(store.save(in, err)) << err;
    ASSERT_TRUE(store.load(out, err)) << err;
    EXPECT_EQ(out.client_id, in.client_id);
    EXPECT_EQ(out.token, in.token);
    EXPECT_EQ(out.token_expire, in.token_expire);
    EXPECT_TRUE(out.validAt(1700000000));
    EXPECT_FALSE(out.validAt(1893456000 + 1));   /* 过期 */

    /* 损坏文件 -> false + err */
    {
        std::ofstream os(path, std::ios::trunc);
        os << "not-json{";
    }
    EXPECT_FALSE(store.load(out, err));
    EXPECT_FALSE(err.empty());
}

TEST(ManagerdRegistration, RequestIdIsUuidV4) {
    const auto id = idsm::newRequestId();
    ASSERT_EQ(id.size(), 36u);
    EXPECT_EQ(id[8], '-');
    EXPECT_EQ(id[13], '-');
    EXPECT_EQ(id[14], '4');       /* version 4 */
    EXPECT_EQ(id[18], '-');
    EXPECT_TRUE(id[19] == '8' || id[19] == '9' ||
                id[19] == 'a' || id[19] == 'b');   /* variant 10xx */
}

TEST(ManagerdRegistration, BuildInitRequestMatchesSpec) {
    const auto req = nlohmann::json::parse(idsm::buildInitRequest(
        "caic", "rid-001", 1726640000000LL, "LXXXXXXX202000001", "t99",
        {"0x01", "0x02"}));
    EXPECT_EQ(req["request_id"], "rid-001");
    EXPECT_EQ(req["timestamp"], 1726640000000LL);
    EXPECT_EQ(req["manufacturer"], "caic");
    EXPECT_EQ(req["type"], 1);
    EXPECT_EQ(req["content"]["vin"], "LXXXXXXX202000001");
    EXPECT_EQ(req["content"]["modelId"], "t99");
    ASSERT_TRUE(req["content"]["ecuList"].is_array());
    EXPECT_EQ(req["content"]["ecuList"].size(), 2u);
}

TEST(ManagerdRegistration, ParseInitResponse) {
    nlohmann::json resp;
    resp["rc"] = 0;
    resp["rn"] = "register_response";
    resp["request_id"] = "b7d2f1a0-3c4e-4a2b-9d1f-2e8a6b0c4d5f";
    resp["timestamp"] = 1726640000000LL;
    resp["paras"] = {{"msg", "注册成功"},
                     {"client_id", "vehicle_t99_AbCdEf1234567890"},
                     {"token", "jwt-example"},
                     {"token_expire", 1726647200}};
    idsm::Credentials got;
    std::string err;
    ASSERT_TRUE(idsm::parseInitResponse(
        resp.dump(), "b7d2f1a0-3c4e-4a2b-9d1f-2e8a6b0c4d5f", got, err)) << err;
    EXPECT_EQ(got.client_id, "vehicle_t99_AbCdEf1234567890");
    EXPECT_EQ(got.token, "jwt-example");
    EXPECT_EQ(got.token_expire, 1726647200);

    /* request_id 不匹配 -> 拒绝 */
    EXPECT_FALSE(idsm::parseInitResponse(resp.dump(), "other-rid", got, err));
    /* rc != 0 -> 拒绝 */
    resp["rc"] = 1002;
    EXPECT_FALSE(idsm::parseInitResponse(resp.dump(),
                                         "b7d2f1a0-3c4e-4a2b-9d1f-2e8a6b0c4d5f",
                                         got, err));
}

TEST(ManagerdProperty, BuildsEnvelopeAndSchedulesHeartbeat) {
    idsm::NodeProperty n;
    n.ecu_code = "0x01";
    n.node_type = "HIDPS";
    n.node_version = "idsm_managerd/1.0.0";
    n.node_status = 1;
    n.rule_version = "v0";
    const auto env = nlohmann::json::parse(
        idsm::buildPropertyReport("caic", {n}, 1726640000000LL));
    EXPECT_EQ(env["msg_type"], "property");
    EXPECT_EQ(env["protocol_version"], "1.0");
    EXPECT_EQ(env["timestamp"], 1726640000000LL);
    EXPECT_EQ(env["manufacturer"], "caic");
    ASSERT_TRUE(env["content"].is_array());
    ASSERT_EQ(env["content"].size(), 1u);
    const auto& c = env["content"][0];
    EXPECT_EQ(c["ecuCode"], "0x01");
    EXPECT_EQ(c["ecuOs"], "Linux");
    EXPECT_EQ(c["nodeType"], "HIDPS");
    EXPECT_EQ(c["nodeStatus"], 1);
    EXPECT_EQ(c["ruleVersion"], "v0");
    EXPECT_EQ(c["nodeVersion"], "idsm_managerd/1.0.0");

    /* 心跳周期 300s ± 10% */
    for (unsigned jitter : {0u, 12345u, 59999u}) {
        const auto next = idsm::nextReportTimeMs(1000000LL, jitter);
        EXPECT_GE(next - 1000000LL, 270000LL);
        EXPECT_LE(next - 1000000LL, 330000LL);
    }

    /* LWT 主题与属性上报同通道(5.3) */
    EXPECT_EQ(idsm::propertyTopic("caic_t99_vin"),
              "oc/devices/caic_t99_vin/sys/property/report");
}

TEST(ManagerdSocket, ReceivesNdjsonLines) {
    const auto dir = tmpDir("sock");
    const auto path = (fs::path(dir) / "probe.sock").string();

    std::mutex mu;
    std::vector<std::string> lines;
    idsm::SocketServer server;
    std::string err;
    ASSERT_TRUE(server.start(path, 0660,
                             [&](const std::string& l) {
                                 std::lock_guard<std::mutex> g(mu);
                                 lines.push_back(l);
                             },
                             err))
        << err;

    const int c = ::socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_GE(c, 0);
    sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    ASSERT_EQ(::connect(c, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);

    /* 两行一次发 + 半行分包,验证粘包/拆包处理 */
    const std::string all =
        "{\"event_id\":1}\n{\"event_id\":"
        "2}\n{\"eve";
    ASSERT_EQ(::write(c, all.data(), all.size()),
              static_cast<ssize_t>(all.size()));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    ASSERT_EQ(::write(c, "nt_id\":3}", 9), 9);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    ::close(c);

    server.stop();   /* stop 会 join 连接线程, 尾部半行也收完 */
    std::lock_guard<std::mutex> g(mu);
    ASSERT_EQ(lines.size(), 3u);
    EXPECT_NE(lines[0].find("\"event_id\":1"), std::string::npos);
    EXPECT_NE(lines[2].find("\"event_id\":3"), std::string::npos);
}

/* ─────────── VSOC 信封(v1.0 第 6/9 章)─────────── */

TEST(ManagerdEnvelope, HostEventTypeNames) {
    EXPECT_STREQ(idsm::hostEventTypeName(0x8021), "DT_UNKNOWN_EXEC");
    EXPECT_STREQ(idsm::hostEventTypeName(0x8025), "DT_FILE_MOD");
    EXPECT_STREQ(idsm::hostEventTypeName(0x802A), "DT_ROOT_SHELL");
    EXPECT_STREQ(idsm::hostEventTypeName(0x9999), "EVT_9999");
}

TEST(ManagerdEnvelope, NodeTypeTopicSeg) {
    EXPECT_STREQ(idsm::nodeTypeToTopicSeg("HIDPS"), "host");
    EXPECT_STREQ(idsm::nodeTypeToTopicSeg("NIDPS"), "eth");
    EXPECT_STREQ(idsm::nodeTypeToTopicSeg("CIDS"), "can");
    EXPECT_STREQ(idsm::nodeTypeToTopicSeg("BOGUS"), "unknown");
}

TEST(ManagerdEnvelope, BuildsDesignCompliantEnvelope) {
    const std::vector<std::string> lines = {
        "{\"event_id\":32805,\"severity\":\"MEDIUM\","
        "\"timestamp_s\":1726640000,\"timestamp_ns\":123456789,"
        "\"ids_message\":\"2300408025ABCD\",\"payload\":\"abcd\"}",
        "{\"event_id\":32801,\"severity\":\"HIGH\","
        "\"timestamp_s\":1726640001,\"timestamp_ns\":0,"
        "\"ids_message\":\"2300408021EF01\"}",
    };
    std::string err;
    const std::string env = idsm::buildAlertEnvelope(
        "caic", "caic_t99_LXXXXXXX202000001", "HIDPS", "0x01", "7",
        lines, err);
    ASSERT_FALSE(env.empty()) << err;

    const auto j = nlohmann::json::parse(env);
    EXPECT_EQ(j.at("msg_type"), "alert_host");
    EXPECT_EQ(j.at("protocol_version"), "1.0");
    EXPECT_EQ(j.at("manufacturer"), "caic");
    const auto& content = j.at("content");
    ASSERT_EQ(content.size(), 2u);

    const auto& e0 = content[0];
    /* eventId = device_id-HIDPS-sha256 前 32 hex, 前缀固定 */
    EXPECT_EQ(e0.at("eventId").get<std::string>().substr(
                  0, std::string("caic_t99_LXXXXXXX202000001-HIDPS-").size()),
              "caic_t99_LXXXXXXX202000001-HIDPS-");
    EXPECT_EQ(e0.at("eventType"), "DT_FILE_MOD");   /* 0x8025 */
    EXPECT_EQ(e0.at("severity"), "MEDIUM");
    EXPECT_EQ(e0.at("timestamp"), 1726640000123LL);  /* ns -> ms 截断 */
    EXPECT_EQ(e0.at("ecuCode"), "0x01");
    EXPECT_EQ(e0.at("nodeType"), "HIDPS");
    EXPECT_EQ(e0.at("ruleVersion"), "7");
    EXPECT_EQ(e0.at("replay"), false);
    EXPECT_EQ(e0.at("raw").at("event_id"), 32805);

    EXPECT_EQ(content[1].at("eventType"), "DT_UNKNOWN_EXEC");  /* 0x8021 */
    EXPECT_EQ(content[1].at("severity"), "HIGH");
}

TEST(ManagerdEnvelope, EventIdDeterministicAndDistinct) {
    const std::string did = "caic_t99_LXXXXXXX202000001";
    const auto a = idsm::makeEventId(did, "HIDPS", "2300408025ABCD");
    const auto b = idsm::makeEventId(did, "HIDPS", "2300408025ABCD");
    const auto c = idsm::makeEventId(did, "HIDPS", "2300408025ABCE");
    const auto d = idsm::makeEventId(did, "NIDPS", "2300408025ABCD");
    EXPECT_EQ(a, b);            /* 幂等键确定性 */
    EXPECT_NE(a, c);            /* 不同消息不同 id */
    EXPECT_NE(a, d);            /* 不同 nodeType 不同 id */
    EXPECT_EQ(a.size(), did.size() + 1 + 5 + 1 + 32);
}

TEST(ManagerdEnvelope, AllBadLinesRejected) {
    std::string err;
    const std::string env = idsm::buildAlertEnvelope(
        "caic", "did", "HIDPS", "0x00", "1",
        {"not json", "{\"foo\":1}"}, err);
    EXPECT_TRUE(env.empty());
    EXPECT_FALSE(err.empty());
}
