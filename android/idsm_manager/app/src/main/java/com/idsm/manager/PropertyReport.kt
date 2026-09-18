package com.idsm.manager

import org.json.JSONArray
import org.json.JSONObject
import kotlin.random.Random

/**
 * PropertyReport -- 设备属性/心跳上报与 LWT 遗嘱(设计文档 5.2/5.3/8 章)。
 *
 * topic: oc/devices/{device_id}/sys/property/report (QoS1, retain false)。
 * content 为探针节点数组, {device_id, ecuCode, nodeType} 三元组定位节点;
 * 周期 300s ±10% 抖动, MQTT CONNECT 后 5s 内全量, 节点上下线/ruleVersion
 * 变化即时增量上报。
 *
 * LWT(5.3): CONNECT 携带 will, 同通道, payload 为 nodeStatus=0 单节点数组,
 * broker 代发置离线。
 */
object PropertyReport {

    data class NodeProperty(
        val ecuCode: String,
        val ecuOs: String = "Android",
        val nodeType: String,
        val nodeVersion: String,
        val nodeStatus: Int = 1,   /* 0 离线 / 1 在线 / -1 异常 */
        val ruleVersion: String,
        val remark: String = "",
    )

    fun buildReport(nodes: List<NodeProperty>, timestampMs: Long): String {
        val content = JSONArray()
        for (n in nodes) {
            content.put(JSONObject().apply {
                put("ecuCode", n.ecuCode)
                put("ecuOs", n.ecuOs)
                put("nodeType", n.nodeType)
                put("nodeVersion", n.nodeVersion)
                put("nodeStatus", n.nodeStatus)
                put("ruleVersion", n.ruleVersion)
                if (n.remark.isNotEmpty()) put("remark", n.remark)
            })
        }
        return JSONObject().apply {
            put("msg_type", "property")
            put("protocol_version", "1.0")
            put("timestamp", timestampMs)
            put("manufacturer", DeviceIdentity.manufacturer)
            put("content", content)
        }.toString()
    }

    /** LWT 载荷: nodeStatus=0 单节点数组(5.3) */
    fun buildLwtPayload(primaryNodeType: String): String =
        buildReport(
            listOf(
                NodeProperty(
                    ecuCode = DeviceIdentity.ecuCode(),
                    nodeType = primaryNodeType,
                    nodeVersion = "idsm_manager_apk/1.0.0",
                    nodeStatus = 0,
                    ruleVersion = "unknown",
                )
            ),
            timestampMs = System.currentTimeMillis(),
        )

    /** 下一次全量上报时刻: base + 300s ± 10% 抖动(5.2) */
    fun nextReportTimeMs(nowMs: Long): Long {
        val jitter = Random.nextLong(-30_000, 30_001)
        return nowMs + 300_000 + jitter
    }
}
