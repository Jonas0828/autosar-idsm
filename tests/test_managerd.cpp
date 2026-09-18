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
#include <cstring>
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

/* ─────────── 规则包验签 + 原子切换(与 APK 同格式) ─────────── */

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

nlohmann::json makeBundle(long long version,
                          const std::map<std::string, std::string>& files,
                          EVP_PKEY* signer) {
    /* canonical 必须按文件名排序(APK 用 toSortedMap) */
    std::map<std::string, std::string> sha_b64;
    nlohmann::json f = nlohmann::json::object();
    for (const auto& [name, bytes] : files) {
        f[name] = idsm::base64Encode(bytes);
        uint8_t digest[EVP_MAX_MD_SIZE];
        unsigned int dlen = 0;
        EVP_Digest(bytes.data(), bytes.size(), digest, &dlen, EVP_sha256(), nullptr);
        sha_b64[name] = idsm::base64Encode(digest, dlen);
    }
    const std::string canonical = idsm::canonicalRuleBytes(version, sha_b64);
    nlohmann::json b;
    b["version"] = version;
    b["files"] = f;
    b["signature"] = idsm::base64Encode(
        signEd25519(signer, canonical));
    return b;
}

}  /* namespace */

TEST(ManagerdRules, CanonicalMatchesApkFormat) {
    /* 与 Android RuleManager.canonicalBytes 逐字节对齐的钉桩 */
    std::map<std::string, std::string> m{{"b.txt", "QUJD"}, {"a.txt", "REVG"}};
    EXPECT_EQ(idsm::canonicalRuleBytes(7, m),
              "v7\n"
              "a.txt:REVG\n"
              "b.txt:QUJD\n");
}

TEST(ManagerdRules, SignedBundleSwitchesAtomicallyAndReloads) {
    const auto dir = tmpDir("rules");
    const auto seed = tmpDir("seed");
    const auto marker = fs::path(dir) / "reloaded.marker";
    const auto key = makeEd25519();

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
    auto bundle = makeBundle(2, {{"exec.txt", "/usr/bin/nc\n"}, {"mods.txt", "x\n"}},
                             key.pkey);
    ASSERT_TRUE(rm.applyBundle(bundle.dump(), err)) << err;
    EXPECT_TRUE(fs::exists(marker));
    const auto v2 = fs::path(dir) / "v2";
    EXPECT_TRUE(fs::exists(v2 / "exec.txt"));
    std::ifstream got(v2 / "exec.txt");
    const std::string content((std::istreambuf_iterator<char>(got)),
                              std::istreambuf_iterator<char>());
    EXPECT_EQ(content, "/usr/bin/nc\n");
    EXPECT_EQ(fs::read_symlink(fs::path(dir) / "current").string(), "v2");
    /* rules.new 已被 rename 消费 */
    EXPECT_FALSE(fs::exists(fs::path(dir) / "rules.new"));

    /* 篡改签名 -> 拒绝, current 不变 */
    auto bad = bundle;
    bad["signature"] = idsm::base64Encode(std::string(64, 'A'));
    EXPECT_FALSE(rm.applyBundle(bad.dump(), err));
    EXPECT_EQ(fs::read_symlink(fs::path(dir) / "current").string(), "v2");

    /* 路径穿越文件名 -> 拒绝 */
    auto evil = makeBundle(3, {{"../evil.txt", "x\n"}}, key.pkey);
    EXPECT_FALSE(rm.applyBundle(evil.dump(), err));

    EVP_PKEY_free(key.pkey);
}

/* ─────────────────────── UDS 收包 ─────────────────────────── */

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
