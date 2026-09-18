/*
 * rule_manager.cpp -- 云端签名规则包验签、防回滚、原子切换与分发。
 * 规则包格式与 canonical 字节序列见 rule_manager.h(设计文档 10.1/10.2,
 * 互操作基准: tools/vsoc_mock/mock_vsoc.py 的 canonical_bytes)。
 */
#include "rule_manager.h"

#include "base64.h"

#include <nlohmann/json.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <fcntl.h>
#include <unistd.h>

namespace idsm {

namespace fs = std::filesystem;

namespace {

constexpr long long kClockSkewToleranceSec = 24LL * 3600;

std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}

bool targetMatches(const std::string& want, const std::string& have) {
    const std::string w = toLower(want);
    return w == "all" || w == toLower(have);
}

/* version 字符串用作目录名, 只允许安全字符(防路径穿越) */
bool validVersionName(const std::string& v) {
    if (v.empty() || v == "." || v == "..") return false;
    return v.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                               "abcdefghijklmnopqrstuvwxyz"
                               "0123456789._-") == std::string::npos;
}

}  /* namespace */

RuleManager::RuleManager(std::string rules_dir,
                         std::string reload_cmd,
                         std::string pubkey_b64_spki,
                         std::string seed_dir)
    : m_rules_dir(std::move(rules_dir)),
      m_reload_cmd(std::move(reload_cmd)),
      m_pubkey_b64(std::move(pubkey_b64_spki)),
      m_seed_dir(std::move(seed_dir)) {}

bool RuleManager::seedFromImageDefaults(std::string& err) {
    const fs::path current = fs::path(m_rules_dir) / "current";
    std::error_code ec;
    if (fs::exists(current, ec)) return true;
    if (!fs::is_directory(m_seed_dir, ec)) return true;  /* 无出厂基线可播 */
    fs::create_directories(m_rules_dir, ec);

    const fs::path v0 = fs::path(m_rules_dir) / "v0";
    fs::remove_all(v0, ec);
    fs::copy(m_seed_dir, v0,
             fs::copy_options::recursive | fs::copy_options::overwrite_existing, ec);
    if (ec) {
        err = "seed copy: " + ec.message();
        return false;
    }
    const fs::path link_tmp = fs::path(m_rules_dir) / "current.tmp";
    fs::remove(link_tmp, ec);
    fs::create_symlink("v0", link_tmp, ec);
    fs::rename(link_tmp, current, ec);
    if (ec) {
        err = "seed symlink: " + ec.message();
        return false;
    }
    return true;
}

RuleApply RuleManager::applyBundle(const std::string& json_text,
                                   const DeviceIdentity& self,
                                   std::string& err) {
    nlohmann::json bundle;
    try {
        bundle = nlohmann::json::parse(json_text);
    } catch (const std::exception& e) {
        err = std::string("json parse: ") + e.what();
        return RuleApply::Rejected;
    }

    /* ── 1. 字段完整性与类型 ─────────────────────────────── */
    for (const char* k : {"msg_type", "manufacturer", "seq", "version",
                          "rollback", "target", "upgrade_type",
                          "issued_at", "expires_at", "sig_alg",
                          "pubkey_id", "signature"}) {
        if (!bundle.contains(k)) {
            err = std::string("bundle missing ") + k;
            return RuleApply::Rejected;
        }
    }
    if (bundle["msg_type"].get<std::string>() != "rule_update") {
        err = "msg_type != rule_update";
        return RuleApply::Rejected;
    }
    if (bundle["sig_alg"].get<std::string>() != "Ed25519") {
        err = "sig_alg != Ed25519";
        return RuleApply::Rejected;
    }
    const long long seq = bundle["seq"].get<long long>();
    const std::string version = bundle["version"].get<std::string>();
    const bool rollback = bundle["rollback"].get<bool>();
    const int upgrade_type = bundle["upgrade_type"].get<int>();
    const long long issued_at = bundle["issued_at"].get<long long>();
    const long long expires_at = bundle["expires_at"].get<long long>();
    const std::string tenant = bundle["manufacturer"].get<std::string>();
    const std::string pubkey_id = bundle["pubkey_id"].get<std::string>();
    const std::string signature = bundle["signature"].get<std::string>();

    if (seq <= 0) {
        err = "bad seq";
        return RuleApply::Rejected;
    }
    if (!validVersionName(version)) {
        err = "illegal version: " + version;
        return RuleApply::Rejected;
    }
    if (upgrade_type != 1 && upgrade_type != 2) {
        err = "bad upgrade_type";
        return RuleApply::Rejected;
    }
    if (upgrade_type == 2) {
        err = "upgrade_type=2 (download_uri) not supported by managerd";
        return RuleApply::Rejected;
    }
    if (!bundle.contains("rules") || !bundle["rules"].is_array() ||
        bundle["rules"].empty()) {
        err = "upgrade_type=1 requires non-empty rules[]";
        return RuleApply::Rejected;
    }
    const auto& target = bundle["target"];
    for (const char* k : {"ecu", "nodeType", "vmodel"}) {
        if (!target.contains(k) || !target[k].is_string()) {
            err = std::string("target missing ") + k;
            return RuleApply::Rejected;
        }
    }

    /* ── 2. 时效: ±24h 车端时钟偏差容忍(10.1 ③) ────────── */
    const long long now = static_cast<long long>(std::time(nullptr));
    if (expires_at < now - kClockSkewToleranceSec) {
        err = "bundle expired";
        return RuleApply::Rejected;
    }
    if (issued_at > now + kClockSkewToleranceSec) {
        err = "bundle issued in the future";
        return RuleApply::Rejected;
    }

    /* ── 3. 防回滚: seq 必须单调递增(10.1) ─────────────── */
    const long long max_seq = loadMaxSeq();
    if (seq <= max_seq) {
        err = "seq rollback rejected (max_seq=" + std::to_string(max_seq) + ")";
        return RuleApply::Rejected;
    }

    /* ── 4. 构造 canonical 字节序列(与 python 基准逐字节一致) ── */
    std::vector<std::string> payload_lines;
    std::vector<std::string> rule_texts;
    for (size_t i = 0; i < bundle["rules"].size(); ++i) {
        const std::string rule = bundle["rules"][i].get<std::string>();
        rule_texts.push_back(rule);
        payload_lines.push_back("rule:" + std::to_string(10000 + i) + ":" +
                                base64Encode(
                                    reinterpret_cast<const uint8_t*>(rule.data()),
                                    rule.size()));
    }
    std::sort(payload_lines.begin(), payload_lines.end());

    const std::string canonical = canonicalRuleBytes(
        seq, tenant, version, rollback,
        target["ecu"].get<std::string>(),
        target["nodeType"].get<std::string>(),
        target["vmodel"].get<std::string>(),
        issued_at, expires_at, upgrade_type, payload_lines);

    /* ── 5. Ed25519 验签 + 公钥指纹(pubkey_id)匹配 ─────── */
    if (!verifySignature(canonical, signature, err)) {
        return RuleApply::Rejected;
    }
    {
        std::string want = configuredPubkeyId(err);
        if (want.empty()) return RuleApply::Rejected;
        if (toLower(want) != toLower(pubkey_id)) {
            err = "pubkey_id mismatch (want " + want + ", got " + pubkey_id + ")";
            return RuleApply::Rejected;
        }
    }

    /* ── 6. target 判定: 未命中本机则安全跳过 ──────────── */
    const bool ecu_hit = targetMatches(target["ecu"].get<std::string>(), self.ecu);
    const bool vmodel_hit =
        targetMatches(target["vmodel"].get<std::string>(), self.vmodel);
    bool node_hit = targetMatches(target["nodeType"].get<std::string>(), "all");
    if (!node_hit) {
        for (const auto& nt : self.node_types) {
            if (targetMatches(target["nodeType"].get<std::string>(), nt)) {
                node_hit = true;
                break;
            }
        }
    }
    if (!ecu_hit || !vmodel_hit || !node_hit) {
        /* 序号已消费, 防止同包换个 target 重放刷序号 */
        if (!storeMaxSeq(seq, err)) return RuleApply::Rejected;
        err.clear();
        return RuleApply::Skipped;
    }

    /* ── 7. 原子切换: rules.new/ -> rename {version}/ -> 换 current 软链 */
    std::error_code ec;
    const fs::path dir(m_rules_dir);
    fs::create_directories(dir, ec);
    const fs::path tmp = dir / "rules.new";
    fs::remove_all(tmp, ec);
    fs::create_directory(tmp, ec);
    for (size_t i = 0; i < rule_texts.size(); ++i) {
        const fs::path f = tmp / ("rule_" + std::to_string(10000 + i) + ".rules");
        std::ofstream os(f, std::ios::binary | std::ios::trunc);
        os << rule_texts[i];
        os.flush();
        os.close();
        const int fd = ::open(f.c_str(), O_RDONLY);
        if (fd >= 0) {
            ::fsync(fd);
            ::close(fd);
        }
    }
    const fs::path target_dir = dir / version;
    fs::remove_all(target_dir, ec);
    fs::rename(tmp, target_dir, ec);
    if (ec) {
        err = "rename rules.new: " + ec.message();
        return RuleApply::Rejected;
    }
    const fs::path dirfd_path = dir;
    if (const int dfd = ::open(dirfd_path.c_str(), O_RDONLY); dfd >= 0) {
        ::fsync(dfd);
        ::close(dfd);
    }
    const fs::path link_tmp = dir / "current.tmp";
    fs::remove(link_tmp, ec);
    fs::create_symlink(version, link_tmp, ec);
    fs::rename(link_tmp, dir / "current", ec);
    if (ec) {
        err = "current swap: " + ec.message();
        return RuleApply::Rejected;
    }
    if (!storeMaxSeq(seq, err)) return RuleApply::Rejected;

    /* ── 8. 通知探针重载 ────────────────────────────────── */
    if (!runReload(err)) return RuleApply::Rejected;
    return RuleApply::Applied;
}

bool RuleManager::verifySignature(const std::string& canonical,
                                  const std::string& sig_b64,
                                  std::string& err) const {
    if (m_pubkey_b64.empty()) {
        err = "no rule signing pubkey configured (--pubkey-b64)";
        return false;
    }
    std::string der;
    if (!base64Decode(m_pubkey_b64, der)) {
        err = "pubkey b64 decode failed";
        return false;
    }
    /* SPKI DER -> PEM -> EVP_PKEY */
    const std::string pem =
        "-----BEGIN PUBLIC KEY-----\n" +
        base64Encode(reinterpret_cast<const uint8_t*>(der.data()), der.size()) +
        "\n-----END PUBLIC KEY-----\n";
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    EVP_PKEY* pkey = bio ? PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr) : nullptr;
    if (bio) BIO_free(bio);
    if (!pkey) {
        err = "pubkey parse failed";
        return false;
    }
    std::string sig;
    const bool sig_ok = base64Decode(sig_b64, sig);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = false;
    if (sig_ok && ctx &&
        EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
        ok = EVP_DigestVerify(ctx,
                              reinterpret_cast<const uint8_t*>(sig.data()), sig.size(),
                              reinterpret_cast<const uint8_t*>(canonical.data()),
                              canonical.size()) == 1;
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    if (!ok) err = "Ed25519 signature mismatch";
    return ok;
}

/* 公钥指纹: sha256(Ed25519 raw 32 字节) hex 前 16(10.2 pubkey_id) */
std::string RuleManager::configuredPubkeyId(std::string& err) const {
    std::string der;
    if (!base64Decode(m_pubkey_b64, der)) {
        err = "pubkey b64 decode failed";
        return "";
    }
    const std::string pem =
        "-----BEGIN PUBLIC KEY-----\n" +
        base64Encode(reinterpret_cast<const uint8_t*>(der.data()), der.size()) +
        "\n-----END PUBLIC KEY-----\n";
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    EVP_PKEY* pkey = bio ? PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr) : nullptr;
    if (bio) BIO_free(bio);
    if (!pkey) {
        err = "pubkey parse failed";
        return "";
    }
    uint8_t raw[32];
    size_t raw_len = sizeof(raw);
    if (EVP_PKEY_get_raw_public_key(pkey, raw, &raw_len) != 1 || raw_len != 32) {
        EVP_PKEY_free(pkey);
        err = "pubkey is not Ed25519 raw-extractable";
        return "";
    }
    EVP_PKEY_free(pkey);
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    EVP_Digest(raw, sizeof(raw), digest, &dlen, EVP_sha256(), nullptr);
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(16);
    for (int i = 0; i < 8; ++i) {   /* 前 16 hex = 摘要前 8 字节 */
        out += hex[digest[i] >> 4];
        out += hex[digest[i] & 0x0f];
    }
    return out;
}

long long RuleManager::loadMaxSeq() const {
    std::ifstream is(fs::path(m_rules_dir) / "max_seq");
    long long seq = 0;
    is >> seq;
    return is ? seq : 0;
}

bool RuleManager::storeMaxSeq(long long seq, std::string& err) const {
    const fs::path state = fs::path(m_rules_dir) / "max_seq";
    const fs::path tmp = fs::path(m_rules_dir) / "max_seq.tmp";
    {
        std::ofstream os(tmp, std::ios::binary | std::ios::trunc);
        os << seq << "\n";
        os.flush();
        os.close();
        if (!os) {
            err = "max_seq write failed";
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp, state, ec);
    if (ec) {
        err = "max_seq rename: " + ec.message();
        return false;
    }
    return true;
}

bool RuleManager::runReload(std::string& err) const {
    if (m_reload_cmd.empty()) return true;
    const int rc = std::system(m_reload_cmd.c_str());
    if (rc != 0) {
        err = "reload cmd failed: " + m_reload_cmd;
        return false;
    }
    return true;
}

std::string canonicalRuleBytes(long long seq, const std::string& tenant,
                               const std::string& version, bool rollback,
                               const std::string& target_ecu,
                               const std::string& target_node,
                               const std::string& target_vmodel,
                               long long issued_at, long long expires_at,
                               int upgrade_type,
                               const std::vector<std::string>& payload_lines) {
    std::string out =
        "seq=" + std::to_string(seq) + "\n" +
        "tenant=" + tenant + "\n" +
        "version=" + version + "\n" +
        "rollback=" + std::string(rollback ? "1" : "0") + "\n" +
        "target_ecu=" + target_ecu + "\n" +
        "target_node=" + target_node + "\n" +
        "target_vmodel=" + target_vmodel + "\n" +
        "issued_at=" + std::to_string(issued_at) + "\n" +
        "expires_at=" + std::to_string(expires_at) + "\n" +
        "upgrade_type=" + std::to_string(upgrade_type) + "\n";
    for (const auto& line : payload_lines) {
        out += line + "\n";
    }
    return out;
}

}  /* namespace idsm */
