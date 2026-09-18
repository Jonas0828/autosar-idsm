package com.idsm.manager

import android.os.SystemProperties
import android.util.Log
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * RuleManager -- 云端签名规则包验签、防回滚、原子切换与分发。
 *
 * 规则包格式(VSOC 设备接入设计 v1.0 10.2):
 * ```json
 * {
 *   "msg_type": "rule_update", "protocol_version": "1.0",
 *   "manufacturer": "caic",
 *   "seq": 42, "version": "v8", "rollback": false,
 *   "target": {"ecu": "0x01|all", "nodeType": "NIDPS|all", "vmodel": "t99|all"},
 *   "upgrade_type": 1, "rules": ["alert tcp ... (sid:10001;)"],
 *   "issued_at": 1700000000, "expires_at": 1700604800,
 *   "sig_alg": "Ed25519", "pubkey_id": "<sha256(raw公钥)hex[:16]>",
 *   "signature": "<base64 Ed25519 over canonical bytes>"
 * }
 * ```
 * canonical 字节序列(10.1)与 linux/idsm_managerd/rule_manager.cpp、
 * tools/vsoc_mock/mock_vsoc.py 的 canonical_bytes 逐字节一致:
 *   seq/tenant/version/rollback/target_ecu/target_node/target_vmodel/
 *   issued_at/expires_at/upgrade_type 行 + `rule:{10000+i}:{b64}` 排序行。
 *
 * 防回滚: seq 平台级单调递增, seq <= 已应用最大 seq 拒绝(1005);
 * 授权回滚(rollback=1)的 seq 同样递增, 只放开 version 回退。
 * 时效: issued/expires 校验容忍 ±24h 车端时钟偏差(10.1 ③)。
 * target 未命中本机 -> 安全跳过且序号照常消费, 防同包换 target 重放刷序号。
 *
 * 分发路径: 验签通过 -> 写入 rules.new/ -> fsync -> 原子 rename 成
 * {version}/ 并更新 current 软链 -> 置属性 idsm.reload={host|eth|can}
 * (init .rc 监听并重启探针)。探针重启后从 current 读新基线。
 */
class RuleManager(private val context: android.content.Context) {

    enum class Result { Applied, Skipped, Rejected }

    // device protected 存储: 冷启动(direct boot)阶段即可读, 探针重启不等解锁
    private val rulesDir: File = run {
        val dp = context.createDeviceProtectedStorageContext()
        File(dp.filesDir, "rules")
    }
    private val current = File(rulesDir, "current")
    private val maxSeqFile = File(rulesDir, "max_seq")

    /** 当前生效策略版本(属性上报 ruleVersion 回读, 8.1) */
    fun currentVersion(): String {
        val t = runCatching { current.canonicalFile.name }.getOrNull()
            ?: return "unknown"
        return if (t.startsWith("v")) t.substring(1) else t
    }

    fun start() {
        rulesDir.mkdirs()
        seedFromImageDefaults()
    }

    /** 首次启动: 镜像出厂基线(/vendor/etc/idsm/v0)拷为 v0 并指 current */
    private fun seedFromImageDefaults() {
        if (current.exists()) return
        val factory = File("/vendor/etc/idsm/v0")
        if (!factory.isDirectory) return
        val v0 = File(rulesDir, "v0")
        v0.deleteRecursively()
        factory.copyRecursively(v0)
        symlinkAtomic("v0", current)
    }

    fun onCloudMessage(payload: ByteArray) {
        val err = apply(String(payload))
        if (err != null && err != "SKIP")
            Log.e(TAG, "rule bundle rejected: $err")
    }

    /** @return 错误原因; null = 应用成功, "SKIP" = 未命中 target */
    private fun apply(bundleText: String): String? {
        val bundle = try {
            JSONObject(bundleText)
        } catch (e: Exception) {
            return "json parse: ${e.message}"
        }

        /* ── 1. 字段完整性与类型 ─────────────────────────── */
        if (bundle.optString("msg_type") != "rule_update")
            return "msg_type != rule_update"
        if (bundle.optString("sig_alg") != "Ed25519")
            return "sig_alg != Ed25519"
        val seq = bundle.optLong("seq", -1)
        val version = bundle.optString("version")
        val rollback = bundle.optBoolean("rollback", false)
        val upgradeType = bundle.optInt("upgrade_type", -1)
        val issuedAt = bundle.optLong("issued_at", -1)
        val expiresAt = bundle.optLong("expires_at", -1)
        val tenant = bundle.optString("manufacturer")
        val pubkeyId = bundle.optString("pubkey_id")
        val signature = bundle.optString("signature")
        if (seq <= 0) return "bad seq"
        if (!validVersionName(version)) return "illegal version: $version"
        if (upgradeType != 1)
            return "unsupported upgrade_type=$upgradeType"
        val rulesArr = runCatching { bundle.getJSONArray("rules") }.getOrNull()
            ?: return "upgrade_type=1 requires rules[]"
        if (rulesArr.length() == 0) return "empty rules[]"
        val target = runCatching { bundle.getJSONObject("target") }.getOrNull()
            ?: return "target missing"
        val tEcu = target.optString("ecu")
        val tNode = target.optString("nodeType")
        val tVmodel = target.optString("vmodel")

        /* ── 2. 时效: ±24h 车端时钟偏差容忍(10.1 ③) ─────── */
        val nowSec = System.currentTimeMillis() / 1000
        if (expiresAt < nowSec - CLOCK_SKEW_SEC) return "bundle expired"
        if (issuedAt > nowSec + CLOCK_SKEW_SEC) return "bundle issued in the future"

        /* ── 3. 防回滚: seq 单调递增(10.1) ──────────────── */
        val maxSeq = loadMaxSeq()
        if (seq <= maxSeq) return "seq rollback rejected (max_seq=$maxSeq)"

        /* ── 4. canonical 字节序列(与 C++/python 逐字节一致) ── */
        val ruleTexts = (0 until rulesArr.length()).map { rulesArr.getString(it) }
        val payloadLines = ruleTexts.mapIndexed { i, r ->
            "rule:${10000 + i}:${android.util.Base64.encodeToString(
                r.toByteArray(), android.util.Base64.NO_WRAP)}"
        }.sorted()
        val canonical = canonicalBytes(seq, tenant, version, rollback,
                                       tEcu, tNode, tVmodel,
                                       issuedAt, expiresAt, upgradeType,
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
                DeviceIdentity.nodeTypes().any {
                    it.equals(tNode, true)
                }
        val hit = tEcu.equals(DeviceIdentity.ecuCode(), true) ||
                tEcu.equals("all", true)
        val vHit = tVmodel.equals(DeviceIdentity.modelCode, true) ||
                tVmodel.equals("all", true)
        if (!hit || !vHit || !nodeHit) {
            /* 序号已消费, 防同包换 target 重放刷序号 */
            saveMaxSeq(seq)
            Log.i(TAG, "rule v$version seq=$seq not targeted at us, skipped")
            return "SKIP"
        }

        /* ── 7. 原子切换: rules.new/ -> rename {version}/ -> 换 current ── */
        val tmp = File(rulesDir, "rules.new")
        tmp.deleteRecursively()
        tmp.mkdirs()
        ruleTexts.forEachIndexed { i, text ->
            val f = File(tmp, "rule_${10000 + i}.rules")
            f.writeText(text)
            fsync(f)
        }
        val targetDir = File(rulesDir, version)
        targetDir.deleteRecursively()
        check(tmp.renameTo(targetDir)) { "rename failed" }
        fsync(rulesDir)
        symlinkAtomic(version, current)
        saveMaxSeq(seq)

        /* ── 8. 通知 init 重启命中的探针(属性 + sepolicy 白名单) ── */
        DeviceIdentity.nodeTypes().forEach { nt ->
            val seg = DeviceIdentity.nodeTypeToTopicSeg(nt)
            if (seg != "unknown" &&
                (tNode.equals("all", true) || tNode.equals(nt, true))) {
                SystemProperties.set("idsm.reload", seg)
            }
        }
        Log.i(TAG, "rules v$version seq=$seq activated")
        return null
    }

    private fun validVersionName(v: String): Boolean {
        if (v.isEmpty() || v == "." || v == "..") return false
        /* 与 C++ 一致: 仅 ASCII 字母数字与 ._- */
        return v.all {
            it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' ||
                it == '.' || it == '_' || it == '-'
        }
    }

    /** canonical 字节序列(10.1), payloadLines 须已 ASCII 升序 */
    private fun canonicalBytes(
        seq: Long, tenant: String, version: String, rollback: Boolean,
        targetEcu: String, targetNode: String, targetVmodel: String,
        issuedAt: Long, expiresAt: Long, upgradeType: Int,
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
        sb.append("upgrade_type=").append(upgradeType).append('\n')
        payloadLines.forEach { sb.append(it).append('\n') }
        return sb.toString().toByteArray()
    }

    /** 公钥指纹: sha256(Ed25519 raw 32 字节) hex 前 16(10.2 pubkey_id) */
    private fun configuredPubkeyId(): String {
        val pub = android.util.Base64.decode(
            RULE_SIGNING_PUBKEY_B64, android.util.Base64.DEFAULT)
        val keyFactory = java.security.KeyFactory.getInstance("Ed25519")
        val encoded = keyFactory.generatePublic(X509EncodedKeySpec(pub)).encoded
        val raw = encoded.copyOfRange(encoded.size - 32, encoded.size)
        return MessageDigest.getInstance("SHA-256").digest(raw)
            .take(8)
            .joinToString("") { "%02x".format(it) }
    }

    private fun verifyEd25519(data: ByteArray, sig: ByteArray) {
        // 公钥常量内嵌(APK 平台签名保护, 替换公钥必须 OTA)
        val pub = android.util.Base64.decode(
            RULE_SIGNING_PUBKEY_B64, android.util.Base64.DEFAULT)
        val keyFactory = java.security.KeyFactory.getInstance("Ed25519")
        // Android 12+ Conscrypt 原生支持 Ed25519; 低版本靠 IdsmApp 注册的
        // BouncyCastle provider(见 build.gradle.kts 依赖)
        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(keyFactory.generatePublic(X509EncodedKeySpec(pub)))
        verifier.update(data)
        check(verifier.verify(sig)) { "Ed25519 signature mismatch" }
    }

    private fun loadMaxSeq(): Long =
        runCatching { maxSeqFile.readText().trim().toLong() }.getOrDefault(0L)

    private fun saveMaxSeq(seq: Long) {
        val tmp = File(rulesDir, "max_seq.tmp")
        tmp.writeText("$seq\n")
        check(tmp.renameTo(maxSeqFile)) { "max_seq rename failed" }
    }

    private fun symlinkAtomic(target: String, link: File) {
        val tmp = File(rulesDir, "current.tmp")
        tmp.delete()
        android.system.Os.symlink(target, tmp.absolutePath)
        check(tmp.renameTo(link)) { "current swap failed" }
    }

    private fun fsync(f: File) {
        java.io.RandomAccessFile(f, "r").use { it.fd.sync() }
    }

    companion object {
        private const val TAG = "IdsmRules"
        private const val CLOCK_SKEW_SEC = 24L * 3600
        private const val RULE_SIGNING_PUBKEY_B64 =
            "REPLACE_WITH_RULE_SIGNING_ED25519_PUBKEY_B64"
    }
}
