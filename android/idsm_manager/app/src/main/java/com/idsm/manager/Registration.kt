package com.idsm.manager

import android.content.Context
import org.json.JSONObject
import java.io.File
import java.util.UUID

/**
 * Registration -- 一型一证动态注册(设计文档第 4 章), 与
 * linux/idsm_managerd/registration.cpp 同协议。
 *
 * 量产默认"一机一证"(产线烧录业务证书, CN=device_id, 跳过注册);
 * 本模块覆盖"一型一证": 预置证书环境用车架号/车型向注册服务换
 * clientId + 短期 token, 凭 token 重连 MQTT(username=clientId)。
 * 凭据持久化于 APK device-protected 目录, 重启免重复注册;
 * token 过期(2h, 产线 PDI/库存期常见)重新 init, 云端幂等轮换(4.4)。
 *
 * 开关: persist.idsm.register=1 启用; persist.idsm.token 直配令牌
 * (车队测试); 两者皆无则读取本地凭据, 无有效凭据且不启用注册时
 * 保持匿名连接(仅 mock 云/降级环境可用)。
 */
object Registration {

    data class Credentials(
        val clientId: String,
        val token: String,
        val tokenExpireSec: Long = 0,
    ) {
        fun validAt(nowSec: Long): Boolean =
            clientId.isNotEmpty() && token.isNotEmpty() &&
                    (tokenExpireSec == 0L || tokenExpireSec > nowSec)
    }

    /** 凭据本地持久化(JSON 原子写) */
    class CredentialStore(context: Context) {
        private val file = File(
            context.createDeviceProtectedStorageContext().filesDir,
            "credentials.json",
        )

        fun load(): Pair<Credentials?, String?> {
            if (!file.exists()) return null to null
            return try {
                val j = JSONObject(file.readText())
                Credentials(
                    clientId = j.getString("client_id"),
                    token = j.getString("token"),
                    tokenExpireSec = j.optLong("token_expire", 0),
                ) to null
            } catch (e: Exception) {
                null to "credentials parse: ${e.message}"
            }
        }

        fun save(c: Credentials): String? {
            return try {
                val tmp = File(file.parentFile, "credentials.json.tmp")
                tmp.writeText(JSONObject().apply {
                    put("client_id", c.clientId)
                    put("token", c.token)
                    put("token_expire", c.tokenExpireSec)
                }.toString(2))
                if (!tmp.renameTo(file)) return "credentials rename failed"
                null
            } catch (e: Exception) {
                "credentials save: ${e.message}"
            }
        }
    }

    fun enabled(): Boolean =
        SysProps.get("persist.idsm.register", "0") == "1"

    /** 车队测试直配令牌(--token 等价) */
    fun cliToken(): String = SysProps.get("persist.idsm.token", "")

    fun newRequestId(): String = UUID.randomUUID().toString()

    /** 构造注册请求(6.1 信封 + 4.3 content) */
    fun buildInitRequest(requestId: String, timestampMs: Long): String {
        val content = JSONObject().apply {
            put("vin", DeviceIdentity.vin)
            put("modelId", DeviceIdentity.modelCode)
            put("ecuList", org.json.JSONArray().apply {
                put(DeviceIdentity.ecuCode())
            })
        }
        return JSONObject().apply {
            put("request_id", requestId)
            put("timestamp", timestampMs)
            put("manufacturer", DeviceIdentity.manufacturer)
            put("type", 1)
            put("content", content)
        }.toString()
    }

    /**
     * 解析注册响应: 校验 rc/rn/request_id 并提取 paras.client_id/token。
     * rc != 0 返回 null(err 带对外模糊原因, 6.5)。
     */
    fun parseInitResponse(
        payload: String,
        expectRequestId: String,
    ): Pair<Credentials?, String?> = try {
        val resp = JSONObject(payload)
        val rc = resp.optInt("rc", -1)
        if (rc != 0) {
            null to "register rc=$rc (${resp.optString("rn", "register_response")})"
        } else if (resp.optString("rn") != "register_response") {
            null to "rn != register_response"
        } else if (resp.optString("request_id") != expectRequestId) {
            null to "request_id mismatch"
        } else {
            val paras = resp.getJSONObject("paras")
            val c = Credentials(
                clientId = paras.getString("client_id"),
                token = paras.getString("token"),
                tokenExpireSec = paras.optLong("token_expire", 0),
            )
            if (c.clientId.isEmpty() || c.token.isEmpty()) {
                null to "init response missing client_id/token"
            } else {
                c to null
            }
        }
    } catch (e: Exception) {
        null to "init response parse: ${e.message}"
    }
}
