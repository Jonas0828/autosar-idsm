/*
 * config_manager.cpp -- 云端签名配置包验签、防回滚与落地。
 * 配置包格式与 canonical 字节序列见 config_manager.h(设计文档 10.3,
 * 互操作基准: tools/vsoc_mock/mock_vsoc.py 的 canonical_config_bytes)。
 */
#include "config_manager.h"

#include "base64.h"
#include "rule_manager.h"   /* DeviceIdentity */

#include <nlohmann/json.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
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

bool validVersionName(const std::string& v) {
    if (v.empty() || v == "." || v == "..") return false;
    return v.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                               "abcdefghijklmnopqrstuvwxyz"
                               "0123456789._-") == std::string::npos;
}

/* canonical 的稳定性前提: item JSON 值限 ASCII 可打印(nlohmann 按
 * UTF-8 原样输出, python ensure_ascii 也等价于 ASCII 值原样) */
bool isAsciiPrintable(const std::string& s) {
    return std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return c >= 0x20 && c <= 0x7e;
    });
}

/* config/current/{name} 原子写: tmp + fsync + rename */
bool atomicWrite(const fs::path& file, const std::string& content,
                 std::string& err) {
    const fs::path tmp = file.string() + ".tmp";
    {
        std::ofstream os(tmp, std::ios::binary | std::ios::trunc);
        os << content;
        os.flush();
        os.close();
        if (!os) {
            err = "write " + tmp.string();
            return false;
        }
    }
    const int fd = ::open(tmp.c_str(), O_RDONLY);
    if (fd >= 0) {
        ::fsync(fd);
        ::close(fd);
    }
    std::error_code ec;
    fs::rename(tmp, file, ec);
    if (ec) {
        err = "rename " + file.string() + ": " + ec.message();
        return false;
    }
    return true;
}

void appendAudit(const fs::path& log_file, const nlohmann::json& entry) {
    const int fd = ::open(log_file.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return;
    const std::string line = entry.dump() + "\n";
    (void)::write(fd, line.data(), line.size());
    ::fsync(fd);
    ::close(fd);
}

}  /* namespace */

bool ConfigManager::validListName(const std::string& name) {
    static const char* kNames[] = {
        "app_w_list", "process_w_list",
        "fw_ip_w_list", "fw_ip_b_list",
        "fw_port_w_list", "fw_port_b_list",
    };
    for (const char* n : kNames) {
        if (name == n) return true;
    }
    return false;
}

ConfigManager::ConfigManager(std::string config_dir,
                             std::string reload_cmd,
                             std::string pubkey_b64_spki)
    : m_config_dir(std::move(config_dir)),
      m_reload_cmd(std::move(reload_cmd)),
      m_pubkey_b64(std::move(pubkey_b64_spki)) {}

ConfigApply ConfigManager::applyBundle(const std::string& json_text,
                                       const DeviceIdentity& self,
                                       std::string& err) {
    nlohmann::json bundle;
    try {
        bundle = nlohmann::json::parse(json_text);
    } catch (const std::exception& e) {
        err = std::string("json parse: ") + e.what();
        return ConfigApply::Rejected;
    }

    /* ── 1. 字段完整性与类型 ─────────────────────────────── */
    for (const char* k : {"msg_type", "manufacturer", "seq", "version",
                          "rollback", "target", "config_type", "items",
                          "issued_at", "expires_at", "sig_alg",
                          "pubkey_id", "signature"}) {
        if (!bundle.contains(k)) {
            err = std::string("bundle missing ") + k;
            return ConfigApply::Rejected;
        }
    }
    if (bundle["msg_type"].get<std::string>() != "config_update") {
        err = "msg_type != config_update";
        return ConfigApply::Rejected;
    }
    if (bundle["sig_alg"].get<std::string>() != "Ed25519") {
        err = "sig_alg != Ed25519";
        return ConfigApply::Rejected;
    }
    const long long seq = bundle["seq"].get<long long>();
    const std::string version = bundle["version"].get<std::string>();
    const bool rollback = bundle["rollback"].get<bool>();
    const int config_type = bundle["config_type"].get<int>();
    const long long issued_at = bundle["issued_at"].get<long long>();
    const long long expires_at = bundle["expires_at"].get<long long>();
    const std::string tenant = bundle["manufacturer"].get<std::string>();
    const std::string pubkey_id = bundle["pubkey_id"].get<std::string>();
    const std::string signature = bundle["signature"].get<std::string>();

    if (seq <= 0) {
        err = "bad seq";
        return ConfigApply::Rejected;
    }
    if (!validVersionName(version)) {
        err = "illegal version: " + version;
        return ConfigApply::Rejected;
    }
    if (config_type != 1 && config_type != 2) {
        err = "bad config_type";
        return ConfigApply::Rejected;
    }
    if (!bundle["items"].is_array() || bundle["items"].empty()) {
        err = "items[] required and non-empty";
        return ConfigApply::Rejected;
    }
    const auto& target = bundle["target"];
    for (const char* k : {"ecu", "nodeType", "vmodel"}) {
        if (!target.contains(k) || !target[k].is_string()) {
            err = std::string("target missing ") + k;
            return ConfigApply::Rejected;
        }
    }

    /* ── item 语义校验(验签前先拒格式错误) ─────────────── */
    struct Item {
        std::string canonical_line;   /* item:{name}:{b64(json)} */
        std::string name;
        nlohmann::json value;
        std::string item_version;
    };
    std::vector<Item> items;
    for (const auto& it : bundle["items"]) {
        if (!it.is_object() || !it.contains("config_name") ||
            !it.contains("config_value") || !it.contains("config_version")) {
            err = "item missing config_name/config_value/config_version";
            return ConfigApply::Rejected;
        }
        Item item;
        item.name = it["config_name"].get<std::string>();
        item.value = it["config_value"];
        item.item_version = it["config_version"].get<std::string>();
        if (!isAsciiPrintable(item.name) || !isAsciiPrintable(item.item_version)) {
            err = "item non-ascii name/version";
            return ConfigApply::Rejected;
        }
        if (config_type == 1) {
            if (!validListName(item.name)) {
                err = "unknown config_name: " + item.name;
                return ConfigApply::Rejected;
            }
            if (!item.value.is_array()) {
                err = item.name + ": config_value must be array<string>";
                return ConfigApply::Rejected;
            }
            for (const auto& v : item.value) {
                if (!v.is_string() || !isAsciiPrintable(v.get<std::string>())) {
                    err = item.name + ": non-ascii or non-string entry";
                    return ConfigApply::Rejected;
                }
            }
        } else {
            /* config_type=2: 仅 rule_enable, {rule_id: 0|1} */
            if (item.name != "rule_enable") {
                err = "config_type=2 only supports rule_enable, got " + item.name;
                return ConfigApply::Rejected;
            }
            if (!item.value.is_object() || item.value.empty()) {
                err = "rule_enable: config_value must be non-empty object";
                return ConfigApply::Rejected;
            }
            for (const auto& [k, v] : item.value.items()) {
                if (!v.is_number_integer() ||
                    (v.get<long long>() != 0 && v.get<long long>() != 1)) {
                    err = "rule_enable: value of " + k + " must be 0|1";
                    return ConfigApply::Rejected;
                }
            }
        }
        /* canonical item JSON: nlohmann 对象键即 ASCII 升序(std::map),
         * dump() 默认紧凑无空格, 与 python
         * json.dumps(sort_keys=True, separators=(",",":")) 逐字节一致 */
        nlohmann::json canon_item = {
            {"config_name", item.name},
            {"config_value", item.value},
            {"config_version", item.item_version},
        };
        const std::string canon_json = canon_item.dump();
        if (!isAsciiPrintable(canon_json)) {
            err = "item canonical json not ascii";
            return ConfigApply::Rejected;
        }
        item.canonical_line = "item:" + item.name + ":" +
            base64Encode(reinterpret_cast<const uint8_t*>(canon_json.data()),
                         canon_json.size());
        items.push_back(std::move(item));
    }

    /* ── 2. 时效: ±24h 车端时钟偏差容忍(10.1 ③) ────────── */
    const long long now = static_cast<long long>(std::time(nullptr));
    if (expires_at < now - kClockSkewToleranceSec) {
        err = "bundle expired";
        return ConfigApply::Rejected;
    }
    if (issued_at > now + kClockSkewToleranceSec) {
        err = "bundle issued in the future";
        return ConfigApply::Rejected;
    }

    /* ── 3. 防回滚: seq 单调递增(配置独立序号空间) ─────── */
    const long long max_seq = loadMaxSeq();
    if (seq <= max_seq) {
        err = "seq rollback rejected (max_seq=" + std::to_string(max_seq) + ")";
        return ConfigApply::Rejected;
    }

    /* ── 4. canonical 字节序列(与 python 基准逐字节一致) ── */
    std::vector<std::string> payload_lines;
    for (const auto& item : items) {
        payload_lines.push_back(item.canonical_line);
    }
    std::sort(payload_lines.begin(), payload_lines.end());

    const std::string canonical = canonicalConfigBytes(
        seq, tenant, version, rollback,
        target["ecu"].get<std::string>(),
        target["nodeType"].get<std::string>(),
        target["vmodel"].get<std::string>(),
        issued_at, expires_at, config_type, payload_lines);

    /* ── 5. Ed25519 验签 + 公钥指纹(pubkey_id)匹配 ─────── */
    if (!verifySignature(canonical, signature, err)) {
        return ConfigApply::Rejected;
    }
    {
        std::string want = configuredPubkeyId(err);
        if (want.empty()) return ConfigApply::Rejected;
        if (toLower(want) != toLower(pubkey_id)) {
            err = "pubkey_id mismatch (want " + want + ", got " + pubkey_id + ")";
            return ConfigApply::Rejected;
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
        if (!storeMaxSeq(seq, err)) return ConfigApply::Rejected;
        err.clear();
        return ConfigApply::Skipped;
    }

    /* ── 7. 落地(整体成功前不写任何文件; 各文件独立原子写) ── */
    std::error_code ec;
    const fs::path dir(m_config_dir);
    const fs::path current = dir / "current";
    fs::create_directories(current, ec);

    nlohmann::json versions = nlohmann::json::object();
    const fs::path versions_file = current / "_versions.json";
    if (fs::exists(versions_file, ec)) {
        try {
            std::ifstream is(versions_file);
            is >> versions;
        } catch (...) {
            versions = nlohmann::json::object();
        }
    }

    for (const auto& item : items) {
        if (config_type == 1) {
            std::string body;
            for (const auto& v : item.value) {
                body += v.get<std::string>() + "\n";
            }
            if (!atomicWrite(current / (item.name + ".list"), body, err)) {
                return ConfigApply::Rejected;
            }
        } else {
            /* rule_enable: value 键 ASCII 升序(std::map 天然有序) */
            if (!atomicWrite(current / "rule_enable.json",
                             item.value.dump() + "\n", err)) {
                return ConfigApply::Rejected;
            }
        }
        versions[item.name] = item.item_version;
        /* 审计留痕(10.3): 高危操作双人复核的车端侧记录 */
        appendAudit(dir / "audit.log", {
            {"ts", now},
            {"seq", seq},
            {"version", version},
            {"config_type", config_type},
            {"config_name", item.name},
        });
    }
    if (!atomicWrite(versions_file, versions.dump(1) + "\n", err)) {
        return ConfigApply::Rejected;
    }
    if (!storeMaxSeq(seq, err)) return ConfigApply::Rejected;

    /* ── 8. 通知探针重载(名单/使能探针侧生效) ─────────── */
    if (!runReload(err)) return ConfigApply::Rejected;
    return ConfigApply::Applied;
}

bool ConfigManager::verifySignature(const std::string& canonical,
                                    const std::string& sig_b64,
                                    std::string& err) const {
    if (m_pubkey_b64.empty()) {
        err = "no config signing pubkey configured (--pubkey-b64)";
        return false;
    }
    std::string der;
    if (!base64Decode(m_pubkey_b64, der)) {
        err = "pubkey b64 decode failed";
        return false;
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

std::string ConfigManager::configuredPubkeyId(std::string& err) const {
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

long long ConfigManager::loadMaxSeq() const {
    std::ifstream is(fs::path(m_config_dir) / "max_seq");
    long long seq = 0;
    is >> seq;
    return is ? seq : 0;
}

bool ConfigManager::storeMaxSeq(long long seq, std::string& err) const {
    const fs::path state = fs::path(m_config_dir) / "max_seq";
    const fs::path tmp = fs::path(m_config_dir) / "max_seq.tmp";
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

bool ConfigManager::runReload(std::string& err) const {
    if (m_reload_cmd.empty()) return true;
    const int rc = std::system(m_reload_cmd.c_str());
    if (rc != 0) {
        err = "reload cmd failed: " + m_reload_cmd;
        return false;
    }
    return true;
}

std::string canonicalConfigBytes(long long seq, const std::string& tenant,
                                 const std::string& version, bool rollback,
                                 const std::string& target_ecu,
                                 const std::string& target_node,
                                 const std::string& target_vmodel,
                                 long long issued_at, long long expires_at,
                                 int config_type,
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
        "config_type=" + std::to_string(config_type) + "\n";
    for (const auto& line : payload_lines) {
        out += line + "\n";
    }
    return out;
}

}  /* namespace idsm */
