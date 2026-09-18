package com.idsm.manager

import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

/**
 * VsocEnvelope -- 检测日志上报信封构造(设计文档第 6/9 章)。
 *
 * 探针 UDS NDJSON 行 -> alert_{host|eth|can} 信封 content 条目:
 * eventId(确定性派生, 幂等键)/eventType/severity/timestamp/
 * ecuCode/nodeType/ruleVersion/replay/raw(原始行透传)。
 *
 * 与 linux/idsm_managerd/vsoc_envelope.cpp 逐字段一致, 同一 mock 云
 * (tools/vsoc_mock/mock_vsoc.py 校验器)对两侧一视同仁。
 */
object VsocEnvelope {

    data class ParsedAlert(
        val eventId: Long,          /* IdsRM 外发事件 id(如 0x8025) */
        val severity: String,       /* LOW/MEDIUM/HIGH/CRITICAL */
        val timestampMs: Long,      /* 探针时间戳换算 */
        val idsMessageHex: String,  /* 完整 IDSM 消息 hex, eventId 派生源 */
    )

    /** HIDPS 事件类型名(0x8021-0x802A, 与 host_probe 检测器一一对应) */
    private val hostEventNames = mapOf(
        0x8021L to "DT_UNKNOWN_EXEC",
        0x8022L to "DT_PRIV_ESC",
        0x8023L to "DT_FORK_FLOOD",
        0x8024L to "DT_REVERSE_SHELL",
        0x8025L to "DT_FILE_MOD",
        0x8026L to "DT_NEW_SETUID",
        0x8027L to "DT_KMOD",
        0x8028L to "DT_ZOMBIE_STORM",
        0x8029L to "DT_RES_EXHAUST",
        0x802AL to "DT_ROOT_SHELL",
    )

    fun parseAlertLine(line: String): ParsedAlert? = try {
        val j = JSONObject(line)
        val idsMessage = j.optString("ids_message")
        ParsedAlert(
            eventId = j.getLong("event_id"),
            severity = j.optString("severity", "MEDIUM"),
            timestampMs = j.optLong("timestamp_s") * 1000 +
                    j.optLong("timestamp_ns") / 1_000_000,
            /* 无 ids_message 时退化为整行派生, 保证 eventId 仍可去重 */
            idsMessageHex = if (idsMessage.isEmpty()) sha256Hex(line)
                            else idsMessage,
        )
    } catch (e: Exception) {
        null
    }

    fun eventTypeName(nodeType: String, eventId: Long): String {
        if (nodeType == "HIDPS") {
            hostEventNames[eventId]?.let { return it }
        }
        return "EVT_%04X".format(eventId)
    }

    /** 确定性 eventId: {device_id}-{nodeType}-{sha256(ids_message_hex) 前 32 hex} */
    fun makeEventId(deviceId: String, nodeType: String, idsMessageHex: String): String =
        "$deviceId-$nodeType-${sha256Hex(idsMessageHex).take(32)}"

    /**
     * 批量构造 alert 信封; 全部行非法时返回 null(调用方丢批推进, 防毒丸卡死队列)。
     */
    fun buildAlertEnvelope(
        nodeType: String,
        ecuCode: String,
        ruleVersion: String,
        rawLines: List<String>,
    ): String? {
        val content = JSONArray()
        for (line in rawLines) {
            val a = parseAlertLine(line) ?: continue
            val raw = runCatching { JSONObject(line) }.getOrElse { JSONObject() }
            content.put(JSONObject().apply {
                put("eventId", makeEventId(DeviceIdentity.deviceId(), nodeType,
                                           a.idsMessageHex))
                put("eventType", eventTypeName(nodeType, a.eventId))
                put("severity", a.severity)
                put("timestamp", a.timestampMs)
                put("ecuCode", ecuCode)
                put("nodeType", nodeType)
                put("ruleVersion", ruleVersion)
                put("replay", false)
                put("raw", raw)
            })
        }
        if (content.length() == 0) return null
        val seg = DeviceIdentity.nodeTypeToTopicSeg(nodeType)
        if (seg == "unknown") return null
        return JSONObject().apply {
            put("msg_type", "alert_$seg")
            put("protocol_version", "1.0")
            put("timestamp", System.currentTimeMillis())
            put("manufacturer", DeviceIdentity.manufacturer)
            put("content", content)
        }.toString()
    }

    private fun sha256Hex(inBytes: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(inBytes.toByteArray())
        return digest.joinToString("") { "%02x".format(it) }
    }
}
