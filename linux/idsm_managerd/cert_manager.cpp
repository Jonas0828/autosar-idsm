/*
 * cert_manager.cpp -- 业务证书续期客户端(设计文档 3.3 / 4.3)。
 */
#include "cert_manager.h"

#include <nlohmann/json.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <fcntl.h>
#include <unistd.h>

namespace idsm {

namespace fs = std::filesystem;

namespace {

/* ASN1_TIME -> unix 秒; 失败返回 0 */
long long asn1ToUnix(const ASN1_TIME* t) {
    std::tm tmv {};
    if (ASN1_TIME_to_tm(t, &tmv) != 1) return 0;
    return static_cast<long long>(timegm(&tmv));
}

X509* readCert(const std::string& path) {
    BIO* bio = BIO_new_file(path.c_str(), "r");
    if (!bio) return nullptr;
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return cert;
}

EVP_PKEY* readKey(const std::string& path) {
    BIO* bio = BIO_new_file(path.c_str(), "r");
    if (!bio) return nullptr;
    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return key;
}

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

}  /* namespace */

CertManager::CertManager(std::string cert_file, std::string key_file,
                         std::string device_id, std::string device_serial,
                         std::string manufacturer)
    : m_cert_file(std::move(cert_file)),
      m_key_file(std::move(key_file)),
      m_device_id(std::move(device_id)),
      m_device_serial(std::move(device_serial)),
      m_manufacturer(std::move(manufacturer)) {}

bool CertManager::needsRenewal(long long now_sec, std::string& err) const {
    if (m_cert_file.empty()) {
        err = "no cert file configured (--cert-file)";
        return false;
    }
    X509* cert = readCert(m_cert_file);
    if (!cert) {
        err = "cert unreadable: " + m_cert_file;
        return false;
    }
    const long long not_before =
        asn1ToUnix(X509_get0_notBefore(cert));
    const long long not_after =
        asn1ToUnix(X509_get0_notAfter(cert));
    X509_free(cert);
    if (not_after <= not_before || not_after == 0) {
        err = "cert validity window invalid";
        return false;
    }
    /* 剩余 < 总有效期 1/3 -> 续期(3.3) */
    const long long total = not_after - not_before;
    return now_sec > not_after - total / 3;
}

std::string CertManager::buildRequest(const std::string& request_id,
                                      long long now_ms,
                                      std::string& err) const {
    if (m_key_file.empty()) {
        err = "no key file configured (--key-file)";
        return {};
    }
    EVP_PKEY* pkey = readKey(m_key_file);
    if (!pkey) {
        err = "private key unreadable: " + m_key_file;
        return {};
    }

    /* CSR(PKCS#10): subject CN=device_id, 复用设备私钥签名 */
    X509_REQ* req = X509_REQ_new();
    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const uint8_t*>(
                                   m_device_id.c_str()),
                               -1, -1, 0);
    bool ok = req && name &&
              X509_REQ_set_subject_name(req, name) == 1 &&
              X509_REQ_set_pubkey(req, pkey) == 1;
    if (ok) {
        /* Ed25519 自带摘要, 其余(RSA/EC)用 SHA-256 */
        const EVP_MD* md = EVP_PKEY_base_id(pkey) == EVP_PKEY_ED25519
                               ? nullptr : EVP_sha256();
        ok = X509_REQ_sign(req, pkey, md) > 0;
    }
    if (name) X509_NAME_free(name);

    std::string csr_pem;
    if (ok) {
        BIO* out = BIO_new(BIO_s_mem());
        if (out && PEM_write_bio_X509_REQ(out, req) == 1) {
            BUF_MEM* bm = nullptr;
            BIO_get_mem_ptr(out, &bm);
            if (bm) csr_pem.assign(bm->data, bm->length);
        }
        if (out) BIO_free(out);
    }
    if (req) X509_REQ_free(req);
    EVP_PKEY_free(pkey);
    if (csr_pem.empty()) {
        err = "csr generation failed";
        return {};
    }

    nlohmann::json content;
    content["csr_pem"] = csr_pem;
    if (!m_device_serial.empty()) content["device_serial"] = m_device_serial;
    content["cert_type"] = "business";
    content["renew"] = true;

    nlohmann::json req_json;
    req_json["request_id"] = request_id;
    req_json["timestamp"] = now_ms;
    req_json["manufacturer"] = m_manufacturer;
    req_json["type"] = 2;                /* 1=注册, 2=证书 */
    req_json["content"] = std::move(content);
    return req_json.dump();
}

bool CertManager::applyResponse(const std::string& payload,
                                const std::string& expect_request_id,
                                std::string& err) const {
    nlohmann::json resp;
    try {
        resp = nlohmann::json::parse(payload);
    } catch (const std::exception& e) {
        err = std::string("cert response parse: ") + e.what();
        return false;
    }
    if (resp.value("request_id", "") != expect_request_id) {
        err = "request_id mismatch";
        return false;
    }
    const int rc = resp.value("rc", -1);
    if (rc != 0) {
        /* 模糊化(6.5): 终端只拿到通用码, 详情在云端审计 */
        err = "cert apply rc=" + std::to_string(rc);
        return false;
    }
    const auto& paras = resp.at("paras");
    const std::string cert_pem = paras.at("cert_pem").get<std::string>();
    if (cert_pem.empty()) {
        err = "cert response missing cert_pem";
        return false;
    }
    /* 原子换证, 旧证备份 .bak(重叠期 <= 7 天, 云端双认, 3.3) */
    std::error_code ec;
    if (fs::exists(m_cert_file, ec)) {
        fs::rename(m_cert_file, m_cert_file + ".bak", ec);
    }
    if (!atomicWrite(m_cert_file, cert_pem, err)) return false;
    return true;
}

}  /* namespace idsm */
