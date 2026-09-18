package com.idsm.manager

import android.content.Context
import android.util.Log
import org.eclipse.paho.client.mqttv3.MqttAsyncClient
import org.eclipse.paho.client.mqttv3.MqttConnectOptions
import org.eclipse.paho.client.mqttv3.MqttMessage
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory

/**
 * MqttUploader -- MQTT/TLS 上云。
 *
 *  - 双向认证或 server-pinning 由 [buildSocketFactory] 决定(骨架默认
 *    pin 云端 broker 证书公钥 sha256,防仿冒 CA 签发的假证书)
 *  - 令牌短期有效:连接前经 [refreshToken] 换取,过期由 broker 断开触发重连
 *  - 告警 QoS1 + 本地已落库,broker ack 后才置 uploaded,语义至少一次
 *  - 断网退避重连;车机蜂窝/以太网共存时依赖系统路由,不做网络判断
 *
 * topic 规划(VIN 级隔离):
 *  上行 ids/alerts/{vin}    告警批量(JSON array)
 *  下行 ids/rules/{vin}     规则包(转 [RuleManager])
 *  上行 ids/status/{vin}    在线状态/心跳(骨架略)
 */
class MqttUploader(
    private val context: Context,
    private val queue: AlertQueue,
) {
    private val running = AtomicBoolean(false)
    private var client: MqttAsyncClient? = null
    private var onDownlink: ((String, ByteArray) -> Unit)? = null
    private var thread: Thread? = null

    fun start(onDownlink: (String, ByteArray) -> Unit) {
        this.onDownlink = onDownlink
        running.set(true)
        thread = Thread({ loop() }, "idsm-mqtt").apply { start() }
    }

    fun stop() {
        running.set(false)
        runCatching { client?.disconnect() }
        thread?.join(2000)
    }

    private fun loop() {
        var backoffMs = 1000L
        while (running.get()) {
            try {
                connectAndPump()
                backoffMs = 1000L
            } catch (e: Exception) {
                Log.w(TAG, "mqtt cycle failed, backoff ${backoffMs}ms", e)
                Thread.sleep(backoffMs)
                backoffMs = (backoffMs * 2).coerceAtMost(60_000)
            }
        }
    }

    private fun connectAndPump() {
        val c = MqttAsyncClient(
            "ssl://${Broker.HOST}:${Broker.PORT}", clientId(),
            MemoryPersistence()
        )
        client = c
        val opts = MqttConnectOptions().apply {
            userName = clientId()
            password = refreshToken().toCharArray()
            socketFactory = buildSocketFactory()
            isAutomaticReconnect = false   // 退避策略归 loop() 统一管
            isCleanSession = false         // 未确认的 QoS1 由 broker 重发
        }
        c.connect(opts).waitForCompletion(10_000)
        c.subscribe("ids/rules/${vin()}", 1) { topic, msg ->
            onDownlink?.invoke(topic, msg.payload)
        }
        Log.i(TAG, "connected, pumping alerts")

        while (running.get() && c.isConnected) {
            val batch = queue.pending(64)
            if (batch.isEmpty()) {
                Thread.sleep(500)
                continue
            }
            val arr = JSONArray()
            batch.forEach { (_, e) -> arr.put(JSONObject().apply {
                put("event_id", e.eventId)
                put("severity", e.severity)
                put("ts_s", e.timestampS)          // 探针时间戳,见 docs/vehicle-production.md
                put("ts_ns", e.timestampNs)
                put("ids_message", e.idsMessage)   // 完整 IDSM 消息(hex),云端可原样入库
                put("payload", e.payload)
            }) }
            val msg = MqttMessage(arr.toString().toByteArray()).apply {
                qos = 1
                isRetained = false
            }
            c.publish("ids/alerts/${vin()}", msg).waitForCompletion(10_000)
            queue.markUploaded(batch.map { it.first })
        }
    }

    /** TLS pinning: 只信任指定公钥指纹,忽略系统 CA 库 */
    private fun buildSocketFactory(): SSLSocketFactory {
        val tm = PinningTrustManager(Broker.PINNED_PUBKEY_SHA256)
        return SSLContext.getInstance("TLS").apply {
            init(null, arrayOf(tm), null)
        }.socketFactory
    }

    /** VIN/令牌由 OEM 集成时注入;骨架从系统属性读取 */
    private fun vin(): String =
        android.os.SystemProperties.get("persist.idsm.vin", "UNKNOWN_VIN")

    private fun clientId(): String = "idsm-${vin()}"

    private fun refreshToken(): String {
        // TODO(OEM): 经 TLS 向令牌服务换取短期 JWT;骨架返回占位
        return android.os.SystemProperties.get("persist.idsm.token", "")
    }

    companion object {
        private const val TAG = "IdsmMqtt"
    }
}
