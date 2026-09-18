/*
 * property_report.h -- 设备属性/心跳上报与 LWT 遗嘱(设计文档 5.2/5.3/8 章)。
 *
 * topic: oc/devices/{device_id}/sys/property/report (QoS1, retain false)。
 * content 为探针节点数组, {device_id, ecuCode, nodeType} 三元组定位节点;
 * 周期 300s ±10% 抖动, MQTT CONNECT 后 5s 内全量, 节点上下线/ruleVersion
 * 变化即时增量上报。
 *
 * LWT(5.3): CONNECT 携带 will, topic 与属性上报同通道, payload 为
 * nodeStatus=0 的单节点数组, broker 代发置离线。
 */
#pragma once

#include <string>
#include <vector>

namespace idsm {

struct NodeProperty {
    std::string ecu_code;       /* 8.2 数据字典, 如 "0x01" */
    std::string ecu_os{"Linux"};
    std::string node_type;      /* HIDPS / NIDPS / CIDS */
    std::string node_version;   /* 探针/管理组件软件版本 */
    int         node_status{1}; /* 0 离线 / 1 在线 / -1 异常 */
    std::string rule_version;   /* 管理组件 current 指向(10.4) */
    std::string remark;         /* 异常原因(nodeStatus=-1 必填) */
};

/* 构造属性上报信封(6.1 外层 + 8.1 content) */
std::string buildPropertyReport(const std::string& manufacturer,
                                const std::vector<NodeProperty>& nodes,
                                long long timestamp_ms);

std::string propertyTopic(const std::string& device_id);

/* 下一次全量上报时刻: base + 300s ± 10% 抖动(5.2) */
long long nextReportTimeMs(long long now_ms, unsigned random_jitter_ms);

}  /* namespace idsm */
