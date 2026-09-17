package com.idsm.manager

import android.os.SystemProperties
import android.util.Log
import org.json.JSONObject
import java.io.File
import java.security.Signature

/**
 * RuleManager -- 云端规则包的验签、原子切换、回滚与分发。
 *
 * 规则包格式(下行 MQTT payload):
 * ```json
 * {
 *   "version": 7,
 *   "files": {
 *     "exec.txt":   "<base64>",
 *     "files.txt":  "<base64>",
 *     "mods.txt":   "<base64>",
 *     "eth.rules":  "<base64>"
 *   },
 *   "signature": "<base64 Ed25519 over canonical bytes>"
 * }
 * ```
 * canonical bytes = "v{version}\n" 对每个文件名排序后
 *   "{name}:{sha256(file_bytes)}\n" 拼接。
 *
 * 分发路径: 验签通过 → 写入 APK 私有目录 rules.new/ → fsync →
 * 原子 rename 成 rules/{version}/ 并更新 current 软链 →
 * 置属性 idsm.reload=host / idsm.reload=eth(init .rc 监听并重启探针)。
 * 探针重启后从 current 读新基线,天然失败回滚(重启失败 init 再拉起旧版? 见 docs)。
 */
class RuleManager(private val context: android.content.Context, private val uploader: MqttUploader) {

    // device protected 存储: 冷启动(direct boot)阶段即可读,探针重启不等解锁
    private val rulesDir: File = run {
        val dp = context.createDeviceProtectedStorageContext()
        File(dp.filesDir, "rules")
    }
    private val current = File(rulesDir, "current")

    fun start() {
        rulesDir.mkdirs()
        seedFromImageDefaults()
    }

    /** 首次启动:镜像出厂基线(/vendor/etc/idsm/v0)拷为 v0 并指 current */
    private fun seedFromImageDefaults() {
        if (current.exists()) return
        val factory = File("/vendor/etc/idsm/v0")
        if (!factory.isDirectory) return
        val v0 = File(rulesDir, "v0")
        v0.deleteRecursively()
        factory.copyRecursively(v0)
        val linkTmp = File(rulesDir, "current.tmp")
        linkTmp.delete()
        android.system.Os.symlink("v0", linkTmp.absolutePath)
        linkTmp.renameTo(current)
    }

    fun onCloudMessage(topic: String, payload: ByteArray) {
        try {
            val bundle = JSONObject(String(payload))
            apply(bundle)
        } catch (e: Exception) {
            Log.e(TAG, "rule bundle rejected", e)
        }
    }

    private fun apply(bundle: JSONObject) {
        val version = bundle.getLong("version")
        val files = bundle.getJSONObject("files")
        val signature = bundle.getString("signature")

        // 1. 还原各文件字节
        val decoded = sortedMapOf<String, ByteArray>()
        files.keys().forEach { name ->
            if (name.contains("/") || name.contains("..")) throw SecurityException("bad name $name")
            decoded[name] = android.util.Base64.decode(
                files.getString(name), android.util.Base64.DEFAULT
            )
        }

        // 2. Ed25519 验签(canonical 字节,公钥内置于 APK)
        val canonical = canonicalBytes(version, decoded)
        verifyEd25519(canonical, android.util.Base64.decode(signature, android.util.Base64.DEFAULT))

        // 3. 原子切换: rules.new/ → rename 到 rules/{version}/
        val tmp = File(rulesDir, "rules.new")
        tmp.deleteRecursively()
        tmp.mkdirs()
        decoded.forEach { (name, bytes) ->
            val f = File(tmp, name)
            f.writeBytes(bytes)
            fsync(f)
        }
        val target = File(rulesDir, "v$version")
        target.deleteRecursively()
        check(tmp.renameTo(target)) { "rename failed" }
        fsync(rulesDir)

        // 4. 更新 current 软链(原子:临时链 + rename)
        val linkTmp = File(rulesDir, "current.tmp")
        linkTmp.delete()
        android.system.Os.symlink("v$version", linkTmp.absolutePath)
        check(linkTmp.renameTo(current)) { "current swap failed" }

        // 5. 通知 init 重启探针(APK 无 root 权限,走属性 + sepolicy 白名单)
        SystemProperties.set("idsm.reload", "host")
        SystemProperties.set("idsm.reload", "eth")
        Log.i(TAG, "rules v$version activated")
    }

    private fun canonicalBytes(version: Long, files: Map<String, ByteArray>): ByteArray {
        val sb = StringBuilder("v$version\n")
        files.toSortedMap().forEach { (name, bytes) ->
            val digest = java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
            sb.append(name).append(":")
                .append(android.util.Base64.encodeToString(digest, android.util.Base64.NO_WRAP))
                .append("\n")
        }
        return sb.toString().toByteArray()
    }

    private fun verifyEd25519(data: ByteArray, sig: ByteArray) {
        // 公钥常量内嵌(APK 平台签名保护,替换公钥必须 OTA)
        val pub = android.util.Base64.decode(RULE_SIGNING_PUBKEY_B64, android.util.Base64.DEFAULT)
        val spec = java.security.spec.X509EncodedKeySpec(pub)
        // Android 12+ Conscrypt 原生支持 Ed25519;低版本靠 IdsmApp 注册的
        // BouncyCastle provider(见 build.gradle.kts 依赖)
        val keyFactory = java.security.KeyFactory.getInstance("Ed25519")
        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(keyFactory.generatePublic(spec))
        verifier.update(data)
        check(verifier.verify(sig)) { "Ed25519 signature mismatch" }
    }

    private fun fsync(f: File) {
        java.io.RandomAccessFile(f, "r").use { it.fd.sync() }
    }

    companion object {
        private const val TAG = "IdsmRules"
        private const val RULE_SIGNING_PUBKEY_B64 =
            "REPLACE_WITH_RULE_SIGNING_ED25519_PUBKEY_B64"
    }
}
