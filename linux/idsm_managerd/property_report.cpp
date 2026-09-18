/*
 * property_report.cpp -- 设备属性/心跳上报与 LWT 遗嘱(5.2/5.3/8 章)。
 */
#include "property_report.h"

#include <nlohmann/json.hpp>

#include <cstdlib>

namespace idsm {

std::string buildPropertyReport(const std::string& manufacturer,
                                const std::vector<NodeProperty>& nodes,
                                long long timestamp_ms) {
    nlohmann::json content = nlohmann::json::array();
    for (const auto& n : nodes) {
        nlohmann::json e;
        e["ecuCode"] = n.ecu_code;
        e["ecuOs"] = n.ecu_os;
        e["nodeType"] = n.node_type;
        e["nodeVersion"] = n.node_version;
        e["nodeStatus"] = n.node_status;
        e["ruleVersion"] = n.rule_version;
        if (!n.remark.empty()) e["remark"] = n.remark;
        content.push_back(std::move(e));
    }
    nlohmann::json env;
    env["msg_type"] = "property";
    env["protocol_version"] = "1.0";
    env["timestamp"] = timestamp_ms;
    env["manufacturer"] = manufacturer;
    env["content"] = std::move(content);
    return env.dump();
}

std::string propertyTopic(const std::string& device_id) {
    return "oc/devices/" + device_id + "/sys/property/report";
}

long long nextReportTimeMs(long long now_ms, unsigned random_jitter_ms) {
    /* 300s ± 10% 抖动; 抖动由调用方用 rand 或 urandom 生成 */
    const long long base = 300000;
    const long long half = base / 10;
    const long long jitter =
        random_jitter_ms % static_cast<unsigned>(2 * half + 1);
    return now_ms + base - half + jitter;
}

}  /* namespace idsm */
