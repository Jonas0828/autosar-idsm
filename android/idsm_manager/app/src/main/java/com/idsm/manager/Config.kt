package com.idsm.manager

import java.security.MessageDigest
import java.security.cert.X509Certificate
import javax.net.ssl.X509TrustManager

/** 云端接入配置。OEM 集成时替换为实际 broker/公钥指纹 */
object Broker {
    const val HOST = "idsm-mqtt.example.com"
    const val PORT = 8883

    /** broker 证书公钥 sha256(base64),防系统 CA 被植入后的中间人 */
    const val PINNED_PUBKEY_SHA256 = "REPLACE_WITH_BROKER_PUBKEY_SHA256_B64"
}

/**
 * PinningTrustManager -- 只信任指纹匹配的证书链,其余一律拒绝。
 * 证书轮换时随 APK OTA 更新指纹,不用依赖系统 CA 撤销链路。
 */
class PinningTrustManager(private val pinnedSha256B64: String) : X509TrustManager {

    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
        val leaf = chain[0]
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(leaf.publicKey.encoded)
        val got = android.util.Base64.encodeToString(
            digest, android.util.Base64.NO_WRAP
        )
        check(got == pinnedSha256B64) {
            "broker cert pin mismatch: got $got"
        }
    }

    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
        throw UnsupportedOperationException("client auth not used")
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
}
