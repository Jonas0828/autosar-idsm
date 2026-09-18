/*
 * log_snapshot.cpp -- 日志快照分包上传(设计文档 11 章, 元消息 A.7)。
 * 持久目录布局:
 *   <dir>/pending/<transfer_id>/meta.json + chunk_NNNN(原始字节)
 *   <dir>/done/<transfer_id>/           全部发布完成(保留备查)
 *   <dir>/expired/<transfer_id>/        超过 24h 清理
 * meta.json: {transfer_id, filename, total_size, total_chunks, sha256,
 *   log_time, event_id, ecu_code, remark, created_ms, replay,
 *   meta_sent, next_chunks:[index...]}
 */
#include "log_snapshot.h"

#include "base64.h"

#include <nlohmann/json.hpp>

#include <openssl/evp.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <fcntl.h>
#include <random>
#include <sstream>
#include <unistd.h>

namespace idsm {

namespace fs = std::filesystem;

namespace {

std::string sha256HexFile(const fs::path& file, std::string& err) {
    std::ifstream is(file, std::ios::binary);
    if (!is) {
        err = "open " + file.string();
        return {};
    }
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        err = "md ctx";
        return {};
    }
    EVP_DigestInit(ctx, EVP_sha256());
    char buf[64 * 1024];
    while (is) {
        is.read(buf, sizeof(buf));
        const auto n = is.gcount();
        if (n > 0) {
            EVP_DigestUpdate(ctx, buf, static_cast<size_t>(n));
        }
    }
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    EVP_DigestFinal(ctx, digest, &dlen);
    EVP_MD_CTX_free(ctx);
    std::string out;
    out.reserve(dlen * 2);
    for (unsigned int i = 0; i < dlen; ++i) {
        char b[3];
        std::snprintf(b, sizeof(b), "%02x", digest[i]);
        out += b;
    }
    return out;
}

std::string sha256HexBytes(const uint8_t* data, size_t len) {
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    EVP_Digest(data, len, digest, &dlen, EVP_sha256(), nullptr);
    std::string out;
    out.reserve(dlen * 2);
    for (unsigned int i = 0; i < dlen; ++i) {
        char b[3];
        std::snprintf(b, sizeof(b), "%02x", digest[i]);
        out += b;
    }
    return out;
}

std::string newTransferId() {
    std::random_device rd;
    const uint64_t a = (static_cast<uint64_t>(rd()) << 32) ^ rd();
    const uint64_t b = (static_cast<uint64_t>(rd()) << 32) ^ rd();
    char buf[33];
    std::snprintf(buf, sizeof(buf), "%016llx%016llx",
                  static_cast<unsigned long long>(a),
                  static_cast<unsigned long long>(b));
    return buf;
}

/* ISO8601 本地时间带时区偏移, 如 2026-09-18T10:20:30+08:00 */
std::string iso8601Local(long long ms) {
    const std::time_t t = static_cast<std::time_t>(ms / 1000);
    std::tm tmv {};
    localtime_r(&t, &tmv);
    char base[32];
    std::strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &tmv);
    char zone[8];
    std::strftime(zone, sizeof(zone), "%z", &tmv);   /* +0800 */
    std::string z = zone;
    if (z.size() == 5) z.insert(3, ":");
    std::ostringstream os;
    os << base << "." << std::setw(3) << std::setfill('0')
       << static_cast<int>(ms % 1000) << z;
    return os.str();
}

bool saveMeta(const fs::path& dir, const nlohmann::json& meta,
              std::string& err) {
    const fs::path tmp = dir / "meta.json.tmp";
    {
        std::ofstream os(tmp, std::ios::binary | std::ios::trunc);
        os << meta.dump(1);
        os.flush();
        os.close();
        if (!os) {
            err = "meta write failed";
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp, dir / "meta.json", ec);
    if (ec) {
        err = "meta rename: " + ec.message();
        return false;
    }
    return true;
}

nlohmann::json buildMetaEnvelope(const nlohmann::json& meta,
                                 const std::string& manufacturer,
                                 const std::string& ecu_code,
                                 long long now_ms) {
    nlohmann::json env = {
        {"msg_type", "log_snapshot"},
        {"protocol_version", "1.0"},
        {"timestamp", now_ms},
        {"manufacturer", manufacturer},
        {"transfer_id", meta.at("transfer_id")},
        {"filename", meta.at("filename")},
        {"total_size", meta.at("total_size")},
        {"total_chunks", meta.at("total_chunks")},
        {"sha256", meta.at("sha256")},
        {"log_time", meta.at("log_time")},
        {"ecuCode", ecu_code.empty()
                        ? meta.value("ecu_code", std::string()) : ecu_code},
        {"replay", meta.value("replay", false)},
    };
    if (meta.contains("event_id") && !meta["event_id"].get<std::string>().empty()) {
        env["event_id"] = meta["event_id"];
    }
    if (meta.contains("remark") && !meta["remark"].get<std::string>().empty()) {
        env["remark"] = meta["remark"];
    }
    return env;
}

}  /* namespace */

LogSnapshotManager::LogSnapshotManager(std::string snapshot_dir)
    : m_dir(std::move(snapshot_dir)) {}

std::string LogSnapshotManager::stageUpload(const SnapshotRequest& req,
                                            long long now_ms,
                                            std::string& err) {
    std::error_code ec;
    const fs::path file(req.file);
    if (!fs::is_regular_file(file, ec)) {
        err = "snapshot file not found: " + req.file;
        return {};
    }
    const auto size = fs::file_size(file, ec);
    if (ec || size == 0) {
        err = "snapshot file unreadable or empty: " + req.file;
        return {};
    }
    if (size > kSnapshotMaxFileSize) {
        err = "snapshot file too large (" + std::to_string(size) + " bytes)";
        return {};
    }

    const std::string sha = sha256HexFile(file, err);
    if (sha.empty()) return {};

    const std::string tid = newTransferId();
    const fs::path dir = fs::path(m_dir) / "pending" / tid;
    fs::create_directories(dir / "chunks", ec);
    if (ec) {
        err = "mkdir: " + ec.message();
        return {};
    }

    /* 切分片 */
    std::ifstream is(file, std::ios::binary);
    std::vector<char> buf(kSnapshotChunkSize);
    size_t total_chunks = 0;
    while (is) {
        is.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        const auto n = is.gcount();
        if (n <= 0) break;
        char name[32];
        std::snprintf(name, sizeof(name), "chunk_%06zu", total_chunks);
        std::ofstream os(dir / "chunks" / name, std::ios::binary | std::ios::trunc);
        os.write(buf.data(), n);
        os.close();
        if (!os) {
            err = std::string("chunk write: ") + name;
            return {};
        }
        ++total_chunks;
    }

    nlohmann::json next = nlohmann::json::array();
    for (size_t i = 0; i < total_chunks; ++i) next.push_back(i);

    nlohmann::json meta = {
        {"transfer_id", tid},
        {"filename", file.filename().string()},
        {"total_size", size},
        {"total_chunks", total_chunks},
        {"sha256", sha},
        {"log_time", iso8601Local(now_ms)},
        {"event_id", req.event_id},
        {"ecu_code", std::string()},
        {"remark", req.remark},
        {"created_ms", now_ms},
        /* 断网缓存补传: 暂存超过 5 分钟才发布 -> replay=true(11.3) */
        {"replay", false},
        {"meta_sent", false},
        {"next_chunks", std::move(next)},
    };
    if (!saveMeta(dir, meta, err)) return {};
    return tid;
}

bool LogSnapshotManager::pump(const std::string& manufacturer,
                              const std::string& device_id,
                              const std::string& ecu_code,
                              long long now_ms,
                              const std::function<bool(const std::string&,
                                                       const std::string&)>& publish,
                              std::string& err) {
    const fs::path pending = fs::path(m_dir) / "pending";
    std::error_code ec;
    if (!fs::is_directory(pending, ec)) return false;

    /* 按创建时间排序, 先入先出 */
    std::vector<fs::path> transfers;
    for (const auto& e : fs::directory_iterator(pending, ec)) {
        if (e.is_directory()) transfers.push_back(e.path());
    }
    std::sort(transfers.begin(), transfers.end());

    bool progressed = false;
    for (const auto& dir : transfers) {
        nlohmann::json meta;
        {
            std::ifstream is(dir / "meta.json");
            if (!is) continue;
            try {
                is >> meta;
            } catch (...) {
                continue;
            }
        }

        /* 24h 过期清理(11.3) */
        if (now_ms - meta.value("created_ms", 0LL) > kSnapshotTransferTtlMs) {
            fs::create_directories(fs::path(m_dir) / "expired", ec);
            fs::rename(dir, fs::path(m_dir) / "expired" / dir.filename(), ec);
            std::fprintf(stderr, "[IDSMD] snapshot %s expired, moved to expired/\n",
                         dir.filename().c_str());
            continue;
        }

        const std::string topic = "oc/devices/" + device_id + "/sys/log/report";

        /* 元消息只发一次; 补传(replay)语义: 暂存超 5 分钟 */
        if (!meta.value("meta_sent", false)) {
            meta["replay"] = now_ms - meta.value("created_ms", now_ms) >
                             5LL * 60 * 1000;
            if (!publish(topic,
                         buildMetaEnvelope(meta, manufacturer, ecu_code,
                                           now_ms).dump())) {
                (void)saveMeta(dir, meta, err);
                return progressed;
            }
            meta["meta_sent"] = true;
            if (!saveMeta(dir, meta, err)) return progressed;
            progressed = true;
        }

        auto& next = meta["next_chunks"];
        int sent = 0;
        while (!next.empty() && sent < kSnapshotChunksPerPump) {
            const size_t idx = next[0].get<size_t>();
            char name[32];
            std::snprintf(name, sizeof(name), "chunk_%06zu", idx);
            std::ifstream cs(dir / "chunks" / name, std::ios::binary);
            if (!cs) {
                err = std::string("chunk missing: ") + name;
                return progressed;
            }
            std::string data((std::istreambuf_iterator<char>(cs)),
                             std::istreambuf_iterator<char>());
            const std::string chunk_sha =
                sha256HexBytes(reinterpret_cast<const uint8_t*>(data.data()),
                               data.size());
            const nlohmann::json env = {
                {"msg_type", "log_snapshot_chunk"},
                {"protocol_version", "1.0"},
                {"timestamp", now_ms},
                {"manufacturer", manufacturer},
                {"transfer_id", meta.at("transfer_id")},
                {"chunk_index", idx},
                {"chunk_sha256", chunk_sha},
                {"data", base64Encode(
                    reinterpret_cast<const uint8_t*>(data.data()), data.size())},
            };
            if (!publish(topic, env.dump())) {
                (void)saveMeta(dir, meta, err);
                return progressed;
            }
            next.erase(next.begin());
            ++sent;
            progressed = true;
        }

        if (next.empty()) {
            fs::create_directories(fs::path(m_dir) / "done", ec);
            fs::rename(dir, fs::path(m_dir) / "done" / dir.filename(), ec);
            std::fprintf(stderr, "[IDSMD] snapshot %s uploaded (%zu chunks)\n",
                         meta.value("transfer_id", std::string()).c_str(),
                         static_cast<size_t>(meta.value("total_chunks", 0ULL)));
        } else if (!saveMeta(dir, meta, err)) {
            return progressed;
        }
        if (sent >= kSnapshotChunksPerPump) return progressed;   /* 下轮继续 */
    }
    return progressed;
}

bool LogSnapshotManager::onNack(const std::string& payload, long long now_ms,
                                std::string& err) {
    nlohmann::json nack;
    try {
        nack = nlohmann::json::parse(payload);
    } catch (const std::exception& e) {
        err = std::string("nack parse: ") + e.what();
        return false;
    }
    const std::string tid = nack.value("transfer_id", std::string());
    if (tid.empty()) {
        err = "nack missing transfer_id";
        return false;
    }
    fs::path dir = fs::path(m_dir) / "pending" / tid;
    std::error_code ec;
    if (!fs::is_directory(dir, ec)) {
        /* 全部片已发布完毕(transfer 在 done/): 24h 窗口内云端仍可
         * 索补片(11.2), 移回 pending/ 重发缺失 index(幂等覆盖) */
        const fs::path done_dir = fs::path(m_dir) / "done" / tid;
        if (fs::is_directory(done_dir, ec)) {
            fs::rename(done_dir, dir, ec);
            if (ec) {
                err = "nack reactivate: " + ec.message();
                return false;
            }
        }
    }
    if (!fs::is_directory(dir, ec)) {
        err = "unknown or finished transfer: " + tid;
        return false;
    }
    nlohmann::json meta;
    {
        std::ifstream is(dir / "meta.json");
        if (!is) {
            err = "meta unreadable";
            return false;
        }
        try {
            is >> meta;
        } catch (const std::exception& e) {
            err = std::string("meta parse: ") + e.what();
            return false;
        }
    }
    /* 重发仅限 24 h 内(11.2) */
    if (now_ms - meta.value("created_ms", 0LL) > kSnapshotTransferTtlMs) {
        err = "transfer expired, nack ignored";
        return false;
    }
    if (!nack.contains("missing") || !nack["missing"].is_array() ||
        nack["missing"].empty()) {
        err = "nack missing indices";
        return false;
    }
    const size_t total = meta.value("total_chunks", 0ULL);
    std::vector<size_t> missing;
    for (const auto& v : nack["missing"]) {
        if (!v.is_number_unsigned() || v.get<size_t>() >= total) {
            err = "nack bad chunk index";
            return false;
        }
        missing.push_back(v.get<size_t>());
    }
    std::sort(missing.begin(), missing.end());
    missing.erase(std::unique(missing.begin(), missing.end()), missing.end());
    meta["next_chunks"] = missing;
    if (!saveMeta(dir, meta, err)) return false;
    std::fprintf(stderr, "[IDSMD] snapshot %s nack: %zu chunks to resend\n",
                 tid.c_str(), missing.size());
    return true;
}

}  /* namespace idsm */
