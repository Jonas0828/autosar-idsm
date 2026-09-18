#include "rule_manager.h"

#include "base64.h"

#include <nlohmann/json.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <fcntl.h>
#include <unistd.h>

namespace idsm {

namespace fs = std::filesystem;

/* 与 Android 侧 AlertQueue/files 对象遍历保持一致: 文件名排序 */
std::string canonicalRuleBytes(
    long long version, const std::map<std::string, std::string>& name_to_b64) {
    std::string out = "v" + std::to_string(version) + "\n";
    for (const auto& [name, b64] : name_to_b64) {
        out += name + ":" + b64 + "\n";
    }
    return out;
}

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

bool RuleManager::applyBundle(const std::string& json_text, std::string& err) {
    nlohmann::json bundle;
    try {
        bundle = nlohmann::json::parse(json_text);
    } catch (const std::exception& e) {
        err = std::string("json parse: ") + e.what();
        return false;
    }
    if (!bundle.contains("version") || !bundle.contains("files") ||
        !bundle.contains("signature")) {
        err = "bundle missing version/files/signature";
        return false;
    }
    const long long version = bundle["version"].get<long long>();
    if (version <= 0) {
        err = "bad version";
        return false;
    }

    /* 1. 还原文件并校验文件名(防路径穿越) */
    std::map<std::string, std::string> decoded;   /* name -> bytes */
    std::map<std::string, std::string> name_to_sha_b64;
    for (const auto& [name, b64] : bundle["files"].items()) {
        if (name.empty() || name.find('/') != std::string::npos ||
            name.find("..") != std::string::npos) {
            err = "illegal file name: " + name;
            return false;
        }
        std::string bytes;
        if (!base64Decode(b64.get<std::string>(), bytes)) {
            err = "bad base64 for " + name;
            return false;
        }
        decoded[name] = std::move(bytes);
        /* sha256 -> b64, canonical 与 APK 一致 */
        uint8_t digest[EVP_MAX_MD_SIZE];
        unsigned int dlen = 0;
        EVP_Digest(decoded[name].data(), decoded[name].size(),
                   digest, &dlen, EVP_sha256(), nullptr);
        name_to_sha_b64[name] =
            base64Encode(digest, static_cast<size_t>(dlen));
    }

    /* 2. Ed25519 验签 */
    const std::string canonical = canonicalRuleBytes(version, name_to_sha_b64);
    if (!verifySignature(canonical, bundle["signature"].get<std::string>(), err)) {
        return false;
    }

    /* 3. 原子切换: rules.new/ -> rename v{version}/ -> 换 current 软链 */
    std::error_code ec;
    const fs::path dir(m_rules_dir);
    fs::create_directories(dir, ec);
    const fs::path tmp = dir / "rules.new";
    fs::remove_all(tmp, ec);
    fs::create_directory(tmp, ec);
    for (const auto& [name, bytes] : decoded) {
        const fs::path f = tmp / name;
        std::ofstream os(f, std::ios::binary | std::ios::trunc);
        os << bytes;
        os.flush();
        os.close();
        const int fd = ::open(f.c_str(), O_RDONLY);
        if (fd >= 0) {
            ::fsync(fd);
            ::close(fd);
        }
    }
    const fs::path target = dir / ("v" + std::to_string(version));
    fs::remove_all(target, ec);
    fs::rename(tmp, target, ec);
    if (ec) {
        err = "rename rules.new: " + ec.message();
        return false;
    }
    const fs::path dirfd_path = dir;
    if (const int dfd = ::open(dirfd_path.c_str(), O_RDONLY); dfd >= 0) {
        ::fsync(dfd);
        ::close(dfd);
    }
    const fs::path link_tmp = dir / "current.tmp";
    fs::remove(link_tmp, ec);
    fs::create_symlink("v" + std::to_string(version), link_tmp, ec);
    fs::rename(link_tmp, dir / "current", ec);
    if (ec) {
        err = "current swap: " + ec.message();
        return false;
    }

    /* 4. 通知探针重载 */
    if (!runReload(err)) return false;
    return true;
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

bool RuleManager::runReload(std::string& err) const {
    if (m_reload_cmd.empty()) return true;
    const int rc = std::system(m_reload_cmd.c_str());
    if (rc != 0) {
        err = "reload cmd failed rc=" + std::to_string(rc);
        return false;
    }
    return true;
}

}  /* namespace idsm */
