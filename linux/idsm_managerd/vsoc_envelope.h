/*
 * vsoc_envelope.h -- 检测日志上报信封构造(VSOC 接入设计 v1.0 第 6/9 章)。
 *
 * 探针 UDS NDJSON 行 -> alert_{host|eth|can} 信封 content 条目:
 *   eventId(确定性派生, 幂等键)/eventType/severity/timestamp/
 *   ecuCode/nodeType/ruleVersion/replay/raw(原始行透传)
 * canonical 规则签名等格式见 rule_manager, 与 tools/vsoc_mock/mock_vsoc.py
 * 的 python 参考实现互操作。
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace idsm {

/* 探针 NDJSON 行解析出的告警字段 */
struct ParsedAlert {
    uint32_t    event_id{0};        /* IdsRM 外发事件 id(如 0x8025) */
    std::string severity;           /* LOW/MEDIUM/HIGH/CRITICAL */
    int64_t     timestamp_ms{0};    /* 探针时间戳换算 */
    std::string ids_message_hex;    /* 完整 IDSM 消息 hex, eventId 派生源 */
};

/* 解析一行探针 NDJSON;失败返回 false 并填 err */
bool parseAlertLine(const std::string& line, ParsedAlert& out, std::string& err);

/* HIDPS 事件类型名(0x8021-0x802A, 与 host_probe 检测器一一对应);
 * 非该范围返回 "EVT_%04X" 形式 */
const char* hostEventTypeName(uint32_t event_id);

/* 确定性 eventId: {device_id}-{nodeType}-{sha256(ids_message_hex) 前 32 hex} */
std::string makeEventId(const std::string& device_id,
                        const std::string& node_type,
                        const std::string& ids_message_hex);

/* nodeType -> topic 段: HIDPS->host, NIDPS->eth, CIDS->can */
const char* nodeTypeToTopicSeg(const std::string& node_type);

/* 批量构造 alert 信封 JSON;raw_lines 全部非法时返回空串并置 err */
std::string buildAlertEnvelope(const std::string& manufacturer,
                               const std::string& device_id,
                               const std::string& node_type,
                               const std::string& ecu_code,
                               const std::string& rule_version,
                               const std::vector<std::string>& raw_lines,
                               std::string& err);

/* 上行事件条目(sys/events/up, 7 章): 规则/配置拒绝、快照失败等
 * 管理事件经此通道上报, 形成"拒绝->上报->重发"闭环(10.4);
 * 设计未约束其 content schema, 此处取 alert 同风格子集。 */
struct EventItem {
    std::string event_type;                 /* 如 RULE_REJECT / CONFIG_REJECT */
    std::string detail;                     /* 车端本地原因(仅辅助排查) */
    std::string severity{"LOW"};            /* LOW/MEDIUM/HIGH/CRITICAL */
    long long   timestamp_ms{0};            /* 0 = 取当前时刻 */
};

/* 构造 event_up 信封 JSON */
std::string buildEventUpEnvelope(const std::string& manufacturer,
                                 const std::vector<EventItem>& items);

}  /* namespace idsm */
