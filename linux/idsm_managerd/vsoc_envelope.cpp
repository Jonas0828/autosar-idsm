#include "vsoc_envelope.h"

#include <nlohmann/json.hpp>

#include <openssl/evp.h>

#include <chrono>
#include <cstdio>
#include <map>

namespace idsm {

static std::string sha256Hex(const std::string& in) {
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    EVP_Digest(in.data(), in.size(), digest, &dlen, EVP_sha256(), nullptr);
    std::string out;
    out.reserve(static_cast<size_t>(dlen) * 2);
    for (unsigned int i = 0; i < dlen; ++i) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", digest[i]);
        out += buf;
    }
    return out;
}

bool parseAlertLine(const std::string& line, ParsedAlert& out, std::string& err) {
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(line);
    } catch (const std::exception& e) {
        err = std::string("json: ") + e.what();
        return false;
    }
    try {
        out.event_id = j.at("event_id").get<uint32_t>();
        out.severity = j.value("severity", std::string("MEDIUM"));
        const int64_t s = j.value("timestamp_s", int64_t{0});
        const int64_t ns = j.value("timestamp_ns", int64_t{0});
        out.timestamp_ms = s * 1000 + ns / 1000000;
        out.ids_message_hex = j.value("ids_message", std::string());
        if (out.ids_message_hex.empty()) {
            /* 无 ids_message 时退化为整行派生, 保证 eventId 仍可去重 */
            out.ids_message_hex = sha256Hex(line);
        }
    } catch (const std::exception& e) {
        err = std::string("field: ") + e.what();
        return false;
    }
    return true;
}

const char* hostEventTypeName(uint32_t event_id) {
    static const std::map<uint32_t, const char*> kNames = {
        {0x8021, "DT_UNKNOWN_EXEC"},
        {0x8022, "DT_PRIV_ESC"},
        {0x8023, "DT_FORK_FLOOD"},
        {0x8024, "DT_REVERSE_SHELL"},
        {0x8025, "DT_FILE_MOD"},
        {0x8026, "DT_NEW_SETUID"},
        {0x8027, "DT_KMOD"},
        {0x8028, "DT_ZOMBIE_STORM"},
        {0x8029, "DT_RES_EXHAUST"},
        {0x802A, "DT_ROOT_SHELL"},
    };
    const auto it = kNames.find(event_id);
    if (it != kNames.end()) return it->second;
    static thread_local char buf[16];
    std::snprintf(buf, sizeof(buf), "EVT_%04X", event_id);
    return buf;
}

std::string makeEventId(const std::string& device_id,
                        const std::string& node_type,
                        const std::string& ids_message_hex) {
    return device_id + "-" + node_type + "-" + sha256Hex(ids_message_hex).substr(0, 32);
}

const char* nodeTypeToTopicSeg(const std::string& node_type) {
    if (node_type == "HIDPS") return "host";
    if (node_type == "NIDPS") return "eth";
    if (node_type == "CIDS") return "can";
    return "unknown";
}

std::string buildEventUpEnvelope(const std::string& manufacturer,
                                 const std::vector<EventItem>& items) {
    const long long now_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    nlohmann::json content = nlohmann::json::array();
    for (const auto& it : items) {
        content.push_back({
            {"eventType", it.event_type},
            {"severity", it.severity},
            {"timestamp", it.timestamp_ms > 0 ? it.timestamp_ms : now_ms},
            {"detail", it.detail},
        });
    }
    const nlohmann::json env = {
        {"msg_type", "event_up"},
        {"protocol_version", "1.0"},
        {"timestamp", now_ms},
        {"manufacturer", manufacturer},
        {"content", std::move(content)},
    };
    return env.dump();
}

std::string buildAlertEnvelope(const std::string& manufacturer,
                               const std::string& device_id,
                               const std::string& node_type,
                               const std::string& ecu_code,
                               const std::string& rule_version,
                               const std::vector<std::string>& raw_lines,
                               std::string& err) {
    nlohmann::json content = nlohmann::json::array();
    size_t dropped = 0;
    for (const auto& line : raw_lines) {
        ParsedAlert a;
        std::string perr;
        if (!parseAlertLine(line, a, perr)) {
            ++dropped;
            continue;
        }
        nlohmann::json raw;
        try {
            raw = nlohmann::json::parse(line);
        } catch (...) {
            raw = nlohmann::json::object();
        }
        std::string event_type;
        if (node_type == "HIDPS") {
            event_type = hostEventTypeName(a.event_id);
        } else {
            char buf[16];
            std::snprintf(buf, sizeof(buf), "EVT_%04X", a.event_id);
            event_type = buf;
        }
        content.push_back({
            {"eventId", makeEventId(device_id, node_type, a.ids_message_hex)},
            {"eventType", event_type},
            {"severity", a.severity},
            {"timestamp", a.timestamp_ms},
            {"ecuCode", ecu_code},
            {"nodeType", node_type},
            {"ruleVersion", rule_version},
            {"replay", false},
            {"raw", std::move(raw)},
        });
    }
    if (content.empty()) {
        err = "no valid alert lines (" + std::to_string(dropped) + " dropped)";
        return {};
    }
    const nlohmann::json env = {
        {"msg_type", std::string("alert_") + nodeTypeToTopicSeg(node_type)},
        {"protocol_version", "1.0"},
        {"timestamp",
         std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch()).count()},
        {"manufacturer", manufacturer},
        {"content", std::move(content)},
    };
    return env.dump();
}

}  /* namespace idsm */
