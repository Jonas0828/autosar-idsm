/*
 * registration.cpp -- 一型一证动态注册(设计文档第 4 章), 见 registration.h。
 */
#include "registration.h"

#include <nlohmann/json.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <fcntl.h>
#include <unistd.h>

namespace idsm {

namespace fs = std::filesystem;

bool CredentialStore::load(Credentials& out, std::string& err) const {
    std::ifstream is(m_path);
    if (!is.good()) return false;   /* 不存在: 首次运行 */
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(is);
        out.client_id = j.at("client_id").get<std::string>();
        out.token = j.at("token").get<std::string>();
        out.token_expire = j.value("token_expire", 0LL);
    } catch (const std::exception& e) {
        err = std::string("credentials parse: ") + e.what();
        return false;
    }
    return true;
}

bool CredentialStore::save(const Credentials& c, std::string& err) const {
    std::error_code ec;
    fs::create_directories(fs::path(m_path).parent_path(), ec);
    const fs::path tmp = fs::path(m_path).string() + ".tmp";
    {
        nlohmann::json j;
        j["client_id"] = c.client_id;
        j["token"] = c.token;
        j["token_expire"] = c.token_expire;
        std::ofstream os(tmp, std::ios::binary | std::ios::trunc);
        os << j.dump(2) << "\n";
        os.flush();
        os.close();
        if (!os) {
            err = "credentials write failed";
            return false;
        }
    }
    const int fd = ::open(tmp.c_str(), O_RDONLY);
    if (fd >= 0) {
        ::fsync(fd);
        ::close(fd);
    }
    fs::rename(tmp, m_path, ec);
    if (ec) {
        err = "credentials rename: " + ec.message();
        return false;
    }
    return true;
}

std::string newRequestId() {
    std::array<uint8_t, 16> b{};
    const int fd = ::open("/dev/urandom", O_RDONLY);
    bool ok = false;
    if (fd >= 0) {
        ok = ::read(fd, b.data(), b.size()) ==
             static_cast<ssize_t>(b.size());
        ::close(fd);
    }
    if (!ok) {
        const auto now = std::chrono::system_clock::now()
                             .time_since_epoch().count();
        std::memcpy(b.data(), &now, sizeof(now));
        for (size_t i = 8; i < b.size(); ++i) {
            b[i] = static_cast<uint8_t>(std::rand() >> (i % 8));
        }
    }
    b[6] = static_cast<uint8_t>((b[6] & 0x0f) | 0x40);   /* version 4 */
    b[8] = static_cast<uint8_t>((b[8] & 0x3f) | 0x80);   /* variant 10xx */
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(36);
    for (int i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) out += '-';
        out += hex[b[i] >> 4];
        out += hex[b[i] & 0x0f];
    }
    return out;
}

std::string buildInitRequest(const std::string& manufacturer,
                             const std::string& request_id,
                             long long timestamp_ms,
                             const std::string& vin,
                             const std::string& model_code,
                             const std::vector<std::string>& ecu_list) {
    nlohmann::json content;
    content["vin"] = vin;
    content["modelId"] = model_code;
    if (!ecu_list.empty()) content["ecuList"] = ecu_list;

    nlohmann::json req;
    req["request_id"] = request_id;
    req["timestamp"] = timestamp_ms;
    req["manufacturer"] = manufacturer;
    req["type"] = 1;
    req["content"] = std::move(content);
    return req.dump();
}

bool parseInitResponse(const std::string& payload,
                       const std::string& expect_request_id,
                       Credentials& out,
                       std::string& err) {
    nlohmann::json resp;
    try {
        resp = nlohmann::json::parse(payload);
    } catch (const std::exception& e) {
        err = std::string("init response parse: ") + e.what();
        return false;
    }
    const int rc = resp.value("rc", -1);
    if (rc != 0) {
        err = "register rc=" + std::to_string(rc) + " (" +
              resp.value("rn", "register_response") + ")";
        return false;
    }
    if (resp.value("rn", "") != "register_response") {
        err = "rn != register_response";
        return false;
    }
    if (resp.value("request_id", "") != expect_request_id) {
        err = "request_id mismatch";
        return false;
    }
    const auto& paras = resp.at("paras");
    out.client_id = paras.at("client_id").get<std::string>();
    out.token = paras.at("token").get<std::string>();
    out.token_expire = paras.value("token_expire", 0LL);
    if (out.client_id.empty() || out.token.empty()) {
        err = "init response missing client_id/token";
        return false;
    }
    return true;
}

}  /* namespace idsm */
