package com.idsm.manager

import android.content.Context
import android.util.Log
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * ConfigManager -- 云端签名配置包验签、防回滚与落地(设计 v1.0 10.3)。
 *
 * 与 linux/idsm_managerd/config_manager.cpp 同协议: msg_type=config_update,
 * 签名体系与规则包一致(同 Ed25519 公钥), seq 配置独立序号空间防回滚,
 * target 未命中安全跳过且序号照常消费。
 *
 * canonical 字节序列与 C++/python(mock_vsoc canonical_config_bytes)
 * 逐字节一致:
 *   seq/tenant/version/rollback/target_ecu/target_node/target_vmodel/
 *   issued_at/expires_at/config_type 行 + `item:{name}:{b64(json)}` 排序行,
 *   item JSON 键 ASCII 升序、紧凑分隔、值限 ASCII。
 *
 * config_type=1(黑白名单)落地 current/{name}.list(一行一条, 原子写);
 * config_type=2(策略使能 rule_enable {rule_id:0|1})落地
 * current/rule_enable.json, 审计留痕 audit.log(10.3 高危操作双人复核的
 * 车端审计侧)。应用成功置 idsm.reload 通知 init 重启命中的探针。
 *
 * 任一步失败整体拒绝, 当前配置不受影响(10.4); 拒绝原因经 onReject
 * 由调用方发 sys/events/up 上报, 形成"拒绝->上报->重发"闭环。
 */
class ConfigManager(private val context: Context) {

    enum class Result { Applied, Skipped, Rejected }

    private val configDir: File = run {
        val dp = context.createDeviceProtectedStorageContext()
        File(dp.filesDir, "config")
    }
    private val current = File(configDir, "current")
    private val maxSeqFile = File(configDir, "max_seq")
    private val auditFile = File(configDir, "audit.log")

    /** 拒绝原因回调(10.4 闭环) */
    var onReject: ((reason: String) -> Unit)? = null

    fun start() {
        configDir.mkdirs()
        current.mkdirs()
    }

    fun onCloudMessage(payload: ByteArray) {
        val err = apply(String(payload))
        if (err != null && err != "SKIP") {
            Log.e(TAG, "config bundle rejected: $err")
            onReject?.invoke(err)
        }
    }

    /** @return null = 应用成功; "SKIP" = 未命中 target; 其余 = 拒绝原因 */
    private fun apply(bundleText: String): String? {
        val bundle = try {
            JSONObject(bundleText)
        } catch (e: Exception) {
            return "json parse: ${e.message}"
        }

        /* ── 1. 字段完整性与类型 ─────────────────────────── */
        if (bundle.optString("msg_type") != "config_update")
            return "msg_type != config_update"
        if (bundle.optString("sig_alg") != "Ed25519")
            return "sig_alg != Ed25519"
        val seq = bundle.optLong("seq", -1)
        val version = bundle.optString("version")
        val rollback = bundle.optBoolean("rollback", false)
        val configType = bundle.optInt("config_type", -1)
        val issuedAt = bundle.optLong("issued_at", -1)
        val expiresAt = bundle.optLong("expires_at", -1)
        val tenant = bundle.optString("manufacturer")
        val pubkeyId = bundle.optString("pubkey_id")
        val signature = bundle.optString("signature")
        if (seq <= 0) return "bad seq"
        if (!validVersionName(version)) return "illegal version: $version"
        if (configType != 1 && configType != 2) return "bad config_type"
        val itemsArr = runCatching { bundle.getJSONArray("items") }.getOrNull()
            ?: return "items[] required"
        if (itemsArr.length() == 0) return "empty items[]"
        val target = runCatching { bundle.getJSONObject("target") }.getOrNull()
            ?: return "target missing"
        val tEcu = target.optString("ecu")
        val tNode = target.optString("nodeType")
        val tVmodel = target.optString("vmodel")

        /* ── item 语义校验 + canonical 行(与 C++/python 逐字节一致) ── */
        data class Item(
            val name: String,
            val value: JSONObject,
            val itemVersion: String,
            val canonicalLine: String,
        )
        val items = mutableListOf<Item>()
        for (i in 0 until itemsArr.length()) {
            val it = runCatching { itemsArr.getJSONObject(i) }.getOrNull()
                ?: return "item $i not object"
            val name = it.optString("config_name")
            val value = runCatching { it.getJSONObject("config_value") }.getOrNull()
            val versionStr = it.optString("config_version")
            if (!isAscii(name) || !isAscii(versionStr))
                return "item $i non-ascii name/version"
            if (configType == 1) {
                if (name !in LIST_NAMES) return "unknown config_name: $name"
                val arr = runCatching { it.getJSONArray("config_value") }.getOrNull()
                    ?: return "$name: config_value must be array<string>"
                for (j in 0 until arr.length()) {
                    val v = runCatching { arr.getString(j) }.getOrNull()
                        ?: return "$name: non-string entry"
                    if (!isAscii(v)) return "$name: non-ascii entry"
                }
            } else {
                if (name != "rule_enable")
                    return "config_type=2 only supports rule_enable, got $name"
                val obj = value ?: return "rule_enable: config_value must be object"
                if (obj.length() == 0) return "rule_enable: empty object"
                val keys = obj.keys()
                while (keys.hasNext()) {
                    val v = obj.optInt(keys.next(), -1)
                    if (v != 0 && v != 1) return "rule_enable: value must be 0|1"
                }
            }
            /* canonical item JSON: 键固定升序(config_name < config_value <
             * config_version), 紧凑无空格。必须手工拼: org.json 会转义
             * '/' 且键无序, 与 C++(nlohmann)/python(json.dumps) 不一致 */
            val canonJson = buildCanonItemJson(configType, name, it, versionStr)
            if (!isAscii(canonJson)) return "item $i canonical json not ascii"
            val line = "item:$name:${android.util.Base64.encodeToString(
                canonJson.toByteArray(), android.util.Base64.NO_WRAP)}"
            items.add(Item(name, it, versionStr, line))
        }

        /* ── 2. 时效: ±24h 时钟偏差容忍(10.1 ③) ─────────── */
        val nowSec = System.currentTimeMillis() / 1000
        if (expiresAt < nowSec - CLOCK_SKEW_SEC) return "bundle expired"
        if (issuedAt > nowSec + CLOCK_SKEW_SEC)
            return "bundle issued in the future"

        /* ── 3. 防回滚: seq 单调递增(配置独立序号空间) ───── */
        val maxSeq = loadMaxSeq()
        if (seq <= maxSeq) return "seq rollback rejected (max_seq=$maxSeq)"

        /* ── 4. canonical 字节序列(与 C++/python 逐字节一致) ── */
        val payloadLines = items.map { it.canonicalLine }.sorted()
        val canonical = canonicalBytes(seq, tenant, version, rollback,
                                       tEcu, tNode, tVmodel,
                                       issuedAt, expiresAt, configType,
                                       payloadLines)

        /* ── 5. Ed25519 验签 + 公钥指纹(pubkey_id)匹配 ────── */
        val sigBytes = android.util.Base64.decode(
            signature, android.util.Base64.DEFAULT)
        try {
            verifyEd25519(canonical, sigBytes)
        } catch (e: Exception) {
            return "Ed25519 signature mismatch: ${e.message}"
        }
        val wantKeyId = configuredPubkeyId()
        if (!wantKeyId.equals(pubkeyId, ignoreCase = true))
            return "pubkey_id mismatch (want $wantKeyId, got $pubkeyId)"

        /* ── 6. target 判定: 未命中本机则安全跳过 ─────────── */
        val nodeHit = tNode.equals("all", true) ||
                DeviceIdentity.nodeTypes().any { it.equals(tNode, true) }
        val hit = tEcu.equals(DeviceIdentity.ecuCode(), true) ||
                tEcu.equals("all", true)
        val vHit = tVmodel.equals(DeviceIdentity.modelCode, true) ||
                tVmodel.equals("all", true)
        if (!hit || !vHit || !nodeHit) {
            /* 序号已消费, 防同包换 target 重放刷序号 */
            saveMaxSeq(seq)
            Log.i(TAG, "config v$version seq=$seq not targeted at us, skipped")
            return "SKIP"
        }

        /* ── 7. 落地(整体成功前不写任何文件) ─────────────── */
        val versionsFile = File(current, "_versions.json")
        val versions = runCatching {
            JSONObject(versionsFile.readText())
        }.getOrElse { JSONObject() }
        for (item in items) {
            if (configType == 1) {
                val arr = item.value.getJSONArray("config_value")
                val body = StringBuilder()
                for (j in 0 until arr.length()) {
                    body.append(arr.getString(j)).append('\n')
                }
                atomicWrite(File(current, "${item.name}.list"), body.toString())
            } else {
                /* rule_enable: JSONObject 键字典序即 ASCII 升序, 与 C++
                 * std::map 及 python sort_keys 逐字节一致 */
                val obj = item.value.getJSONObject("config_value")
                atomicWrite(File(current, "rule_enable.json"),
                            "$obj\n")
            }
            versions.put(item.name, item.itemVersion)
            /* 审计留痕(10.3): 高危操作双人复核的车端侧记录 */
            auditFile.appendText(JSONObject().apply {
                put("ts", nowSec)
                put("seq", seq)
                put("version", version)
                put("config_type", configType)
                put("config_name", item.name)
            }.toString() + "\n")
        }
        atomicWrite(versionsFile, versions.toString(1) + "\n")
        saveMaxSeq(seq)

        /* ── 8. 通知 init 重启命中的探针(名单/使能生效) ───── */
        DeviceIdentity.nodeTypes().forEach { nt ->
            val seg = DeviceIdentity.nodeTypeToTopicSeg(nt)
            if (seg != "unknown" &&
                (tNode.equals("all", true) || tNode.equals(nt, true))) {
                SysProps.set("idsm.reload", seg)
            }
        }
        Log.i(TAG, "config v$version seq=$seq type=$configType applied")
        return null
    }

    private fun validVersionName(v: String): Boolean {
        if (v.isEmpty() || v == "." || v == "..") return false
        return v.all {
            it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' ||
                it == '.' || it == '_' || it == '-'
        }
    }

    private fun isAscii(s: String): Boolean = s.all { it.code in 0x20..0x7e }

    /** json 字符串字面量: 仅转义 " 与 \, 与 python json.dumps(ensure_ascii
     * 对 ASCII 值)逐字节一致(org.json 会额外转义 '/', 不可用) */
    private fun jsonStr(s: String): String =
        "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

    /* canonical item JSON(键升序、紧凑): config_type=1 值为字符串数组,
     * config_type=2 值为 {rule_id:0|1} 且键按 ASCII 升序 */
    private fun buildCanonItemJson(
        configType: Int, name: String, item: JSONObject, version: String,
    ): String {
        val sb = StringBuilder("{\"config_name\":").append(jsonStr(name))
        if (configType == 1) {
            val arr = item.getJSONArray("config_value")
            sb.append(",\"config_value\":[")
            for (j in 0 until arr.length()) {
                if (j > 0) sb.append(',')
                sb.append(jsonStr(arr.getString(j)))
            }
            sb.append(']')
        } else {
            val obj = item.getJSONObject("config_value")
            val keys = obj.keys().asSequence().sorted().toList()
            sb.append(",\"config_value\":{")
            keys.forEachIndexed { i, k ->
                if (i > 0) sb.append(',')
                sb.append(jsonStr(k)).append(':').append(obj.getInt(k))
            }
            sb.append('}')
        }
        sb.append("},\"config_version\":").append(jsonStr(version))
        sb.append('}')
        return sb.toString()
    }

    private fun atomicWrite(f: File, content: String) {
        val tmp = File(f.parentFile ?: current, f.name + ".tmp")
        tmp.writeText(content)
        tmp.renameTo(f)
    }

    private fun loadMaxSeq(): Long =
        runCatching { maxSeqFile.readText().trim().toLong() }.getOrDefault(0)

    private fun saveMaxSeq(seq: Long) {
        val tmp = File(configDir, "max_seq.tmp")
        tmp.writeText("$seq\n")
        tmp.renameTo(maxSeqFile)
    }

    /** 公钥指纹: sha256(Ed25519 raw 32 字节) hex 前 16(10.2 pubkey_id) */
    private fun configuredPubkeyId(): String {
        val pub = android.util.Base64.decode(
            RuleManager.RULE_SIGNING_PUBKEY_B64, android.util.Base64.DEFAULT)
        val keyFactory = java.security.KeyFactory.getInstance("Ed25519")
        val encoded = keyFactory.generatePublic(X509EncodedKeySpec(pub)).encoded
        val raw = encoded.copyOfRange(encoded.size - 32, encoded.size)
        return MessageDigest.getInstance("SHA-256").digest(raw)
            .take(8)
            .joinToString("") { "%02x".format(it) }
    }

    private fun verifyEd25519(data: ByteArray, sig: ByteArray) {
        val pub = android.util.Base64.decode(
            RuleManager.RULE_SIGNING_PUBKEY_B64, android.util.Base64.DEFAULT)
        val keyFactory = java.security.KeyFactory.getInstance("Ed25519")
        val key = keyFactory.generatePublic(X509EncodedKeySpec(pub))
        val s = Signature.getInstance("Ed25519")
        s.initVerify(key)
        s.update(data)
        check(s.verify(sig)) { "verify failed" }
    }

    companion object {
        private const val TAG = "IdsmConfig"
        private const val CLOCK_SKEW_SEC = 24L * 3600

        /** config_type=1 允许的名单名(10.3) */
        val LIST_NAMES = setOf(
            "app_w_list", "process_w_list",
            "fw_ip_w_list", "fw_ip_b_list",
            "fw_port_w_list", "fw_port_b_list",
        )

        /** canonical 字节序列(10.3), payloadLines 须已 ASCII 升序 */
        fun canonicalBytes(
            seq: Long, tenant: String, version: String, rollback: Boolean,
            targetEcu: String, targetNode: String, targetVmodel: String,
            issuedAt: Long, expiresAt: Long, configType: Int,
            payloadLines: List<String>,
        ): ByteArray {
            val sb = StringBuilder()
            sb.append("seq=").append(seq).append('\n')
            sb.append("tenant=").append(tenant).append('\n')
            sb.append("version=").append(version).append('\n')
            sb.append("rollback=").append(if (rollback) 1 else 0).append('\n')
            sb.append("target_ecu=").append(targetEcu).append('\n')
            sb.append("target_node=").append(targetNode).append('\n')
            sb.append("target_vmodel=").append(targetVmodel).append('\n')
            sb.append("issued_at=").append(issuedAt).append('\n')
            sb.append("expires_at=").append(expiresAt).append('\n')
            sb.append("config_type=").append(configType).append('\n')
            payloadLines.forEach { sb.append(it).append('\n') }
            return sb.toString().toByteArray()
        }
    }
}
