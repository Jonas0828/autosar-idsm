package com.idsm.manager

import android.os.SystemProperties

/**
 * DeviceIdentity -- 本机身份(设计文档第 3/7/8 章)。
 *
 * device_id 三段式 `{manufacturer}_{model_code}_{vin}`, 由 OEM 产线
 * 经 persist 属性注入; 与 linux/idsm_managerd 的 --device-id 完全一致。
 */
object DeviceIdentity {

    val manufacturer: String
        get() = SystemProperties.get("persist.idsm.manufacturer", "caic")

    val modelCode: String
        get() = SystemProperties.get("persist.idsm.model_code", "t99")

    val vin: String
        get() = SystemProperties.get("persist.idsm.vin", "UNKNOWN_VIN")

    /** 三段式设备编号 */
    fun deviceId(): String = "${manufacturer}_${modelCode}_${vin}"

    /** 本机 ECU 编码(8.2 数据字典, 默认 0x02 座舱主机) */
    fun ecuCode(): String = SystemProperties.get("persist.idsm.ecu_code", "0x02")

    /** 本机托管的探针节点(属性上报覆盖范围, 8.1) */
    fun nodeTypes(): List<String> =
        SystemProperties.get("persist.idsm.nodes", "HIDPS,NIDPS")
            .split(",").map { it.trim() }.filter { it.isNotEmpty() }

    /* ── topic 体系(7 章), 与 linux/idsm_managerd 逐字一致 ── */

    fun alertTopic(nodeType: String): String =
        "oc/devices/${deviceId()}/sys/idps/${topicSeg(nodeType)}/log"

    fun propertyTopic(): String =
        "oc/devices/${deviceId()}/sys/property/report"

    fun ruleTopic(): String =
        "oc/devices/${deviceId()}/sys/idps/rule/update"

    fun ruleBroadcastTopic(): String =
        "oc/vmodel/${manufacturer}_${modelCode}/sys/idps/rule/update"

    fun initRequestTopic(requestId: String): String =
        "oc/devices/${deviceId()}/sys/init/request/rid=$requestId"

    fun initResponseTopic(requestId: String): String =
        "oc/devices/${deviceId()}/sys/init/response/rid=$requestId"

    fun nodeTypeToTopicSeg(nodeType: String): String = topicSeg(nodeType)

    private fun topicSeg(nodeType: String): String = when (nodeType) {
        "HIDPS" -> "host"
        "NIDPS" -> "eth"
        "CIDS" -> "can"
        else -> "unknown"
    }
}
