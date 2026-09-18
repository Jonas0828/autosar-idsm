package com.idsm.manager

import android.content.Context
import android.util.Log
import org.eclipse.paho.client.mqttv3.IMqttMessageListener
import org.eclipse.paho.client.mqttv3.MqttAsyncClient
import org.eclipse.paho.client.mqttv3.MqttConnectOptions
import org.eclipse.paho.client.mqttv3.MqttMessage
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory

/**
 * MqttUploader -- MQTT 上云(VSOC 设备接入设计 v1.0 第 5/6/7/9 章),
 * 与 linux/idsm_managerd 同协议、同 topic、同信封。
 *
 *  - 上行: alert_{host|eth|can} 信封 -> oc/devices/{device_id}/sys/idps/...
 *    /log (QoS1); 属性/心跳 -> sys/property/report (QoS1, 300s±10%)
 *  - 下行: 签名规则包 sys/idps/rule/update (单车 + 车型广播) -> RuleManager
 *  - 注册: 一型一证 init 流程(4 章), 凭据持久化, token 过期重注册;
 *    未拿到令牌前匿名 CONNECT(带空密码会被认证插件拒绝, 同 managerd)
 *  - LWT(5.3): CONNECT 携带 will, broker 代发置离线
 *  - 双向认证或 server-pinning 由 [buildSocketFactory] 决定(默认 pin
 *    云端 broker 证书公钥 sha256); 实验室明文 persist.idsm.plain=1
 *  - 断网退避重连; 车机蜂窝/以太网共存时依赖系统路由, 不做网络判断
 */
class MqttUploader(
    private val context: Context,
    private val queue: AlertQueue,
    private val rules: RuleManager,
    private val configs: ConfigManager,
    private val snapshots: LogSnapshotManager,
    private val peers: (nodeType: String) -> Int,
) {
    private val running = AtomicBoolean(false)
    private var client: MqttAsyncClient? = null
    private var thread: Thread? = null
    /** 探针连接数变化 -> 立即增量属性上报(8.3) */
    val reportNow = AtomicBoolean(false)
    /* 拒绝/失败事件队列(10.4 闭环), pump 中经 sys/events/up 上报 */
    private val pendingEvents = java.util.concurrent.ConcurrentLinkedQueue<Pair<String, String>>()

    /** 规则包下行回调(网络线程); 注册响应由内部状态机处理 */
    private var onRuleDownlink: ((ByteArray) -> Unit)? = null

    private val credStore = Registration.CredentialStore(context)
    private val creds = AtomicReference<Registration.Credentials?>()

    fun start(onRuleDownlink: (ByteArray) -> Unit) {
        this.onRuleDownlink = onRuleDownlink
        /* 拒绝闭环(10.4): 规则/配置拒绝经 sys/events/up 上报云端重发 */
        rules.onReject = { enqueueEvent("RULE_REJECT", it) }
        configs.onReject = { enqueueEvent("CONFIG_REJECT", it) }
        running.set(true)
        thread = Thread({ loop() }, "idsm-mqtt").apply { start() }
    }

    private fun enqueueEvent(type: String, detail: String) {
        pendingEvents.add(type to detail)
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
                if (!running.get()) break
                Log.w(TAG, "mqtt cycle failed, backoff ${backoffMs}ms", e)
                Thread.sleep(backoffMs)
                backoffMs = (backoffMs * 2).coerceAtMost(60_000)
            }
        }
    }

    private fun connectAndPump() {
        resolveCredentials()
        val c = MqttAsyncClient(brokerUrl(), transportClientId(), MemoryPersistence())
        client = c
        val token = creds.get()?.token.orEmpty()
        val opts = MqttConnectOptions().apply {
            /* 未拿到令牌前保持匿名 CONNECT(带用户名但空密码会被认证插件拒绝) */
            if (token.isNotEmpty()) {
                userName = creds.get()?.clientId
                password = token.toCharArray()
            }
            /* LWT(5.3): 属性同通道, nodeStatus=0 单节点, QoS1 retain false */
            val primary = DeviceIdentity.nodeTypes().firstOrNull() ?: "HIDPS"
            setWill(DeviceIdentity.propertyTopic(),
                    PropertyReport.buildLwtPayload(primary).toByteArray(),
                    1, false)
            keepAliveInterval = 60
            isAutomaticReconnect = false   // 退避策略归 loop() 统一管
            isCleanSession = true
            if (!plainText()) socketFactory = buildSocketFactory()
        }
        c.connect(opts).waitForCompletion(10_000)
        c.subscribe(DeviceIdentity.ruleTopic(), 1, ruleListener)
        c.subscribe(DeviceIdentity.ruleBroadcastTopic(), 1, ruleListener)
        c.subscribe(DeviceIdentity.configTopic(), 1, configListener)
        c.subscribe(DeviceIdentity.configBroadcastTopic(), 1, configListener)
        c.subscribe(DeviceIdentity.snapshotNackTopic(), 1, nackListener)
        Log.i(TAG, "connected device_id=${DeviceIdentity.deviceId()} " +
                   "auth=${if (token.isEmpty()) "anonymous" else "token"}")

        /* 一型一证注册: 匿名连上后发 init 请求; 成功后断开用新凭据重连 */
        if (needRegistration()) {
            doRegistration(c)
            runCatching { c.disconnect() }
            return   // 外层 loop 以新凭据重连
        }

        pump(c)
    }

    /* ── 注册(4 章) ─────────────────────────────────────── */

    private fun needRegistration(): Boolean {
        val cli = Registration.cliToken()
        if (cli.isNotEmpty()) return false          // 车队测试直配
        if (!Registration.enabled()) return false   // 一机一证直连
        return creds.get() == null                  // 无有效本地凭据
    }

    private fun resolveCredentials() {
        val cli = Registration.cliToken()
        if (cli.isNotEmpty()) {
            creds.set(Registration.Credentials("idsm-${DeviceIdentity.deviceId()}", cli))
            return
        }
        val (stored, err) = credStore.load()
        if (err != null) Log.w(TAG, "credentials unreadable: $err")
        if (stored != null && stored.validAt(System.currentTimeMillis() / 1000)) {
            creds.set(stored)
            Log.i(TAG, "loaded credentials for ${stored.clientId}")
        }
    }

    private fun doRegistration(c: MqttAsyncClient) {
        val requestId = Registration.newRequestId()
        val responseRef = AtomicReference<String?>(null)
        c.subscribe(DeviceIdentity.initResponseTopic(requestId), 1,
                    IMqttMessageListener { _, msg ->
                        responseRef.set(String(msg.payload))
                    }).waitForCompletion(10_000)   // 订阅先就绪再发请求
        val req = Registration.buildInitRequest(requestId, System.currentTimeMillis())
        c.publish(DeviceIdentity.initRequestTopic(requestId),
                  MqttMessage(req.toByteArray()).apply { qos = 1 })
            .waitForCompletion(10_000)
        Log.i(TAG, "init request rid=$requestId")

        /* 等响应 30s; 超时抛异常走外层退避重试 */
        val deadline = System.currentTimeMillis() + 30_000
        while (responseRef.get() == null && System.currentTimeMillis() < deadline) {
            if (!running.get()) return
            Thread.sleep(200)
        }
        val payload = responseRef.get() ?: throw java.util.concurrent
            .TimeoutException("init response timeout")
        val (got, err) = Registration.parseInitResponse(payload, requestId)
        if (got == null) throw IllegalStateException("init rejected: $err")
        val saveErr = credStore.save(got)
        if (saveErr != null) Log.e(TAG, "credential save failed: $saveErr")
        creds.set(got)
        Log.i(TAG, "registered: client_id=${got.clientId}")
    }

    /* ── 上行泵: 告警信封 + 属性心跳 ─────────────────────── */

    private fun pump(c: MqttAsyncClient) {
        var nextReportMs = System.currentTimeMillis()   // CONNECT 后 5s 内全量
        while (running.get() && c.isConnected) {
            val now = System.currentTimeMillis()

            /* 属性/心跳(8.3): 全量节点数组, 300s ± 10% 周期 */
            if (now >= nextReportMs || reportNow.getAndSet(false)) {
                val nodes = DeviceIdentity.nodeTypes().map { nt ->
                    PropertyReport.NodeProperty(
                        ecuCode = DeviceIdentity.ecuCode(),
                        nodeType = nt,
                        nodeVersion = "idsm_manager_apk/1.0.0",
                        /* nodeStatus 接 UDS 真实连接状态(8 章) */
                        nodeStatus = if (peers(nt) > 0) 1 else 0,
                        ruleVersion = rules.currentVersion(),
                    )
                }
                publishQos1(c, DeviceIdentity.propertyTopic(),
                            PropertyReport.buildReport(nodes, now))
                nextReportMs = PropertyReport.nextReportTimeMs(now)
                Log.i(TAG, "property report (${nodes.size} nodes)")
            }

            /* 拒绝/失败事件闭环上报(10.4): sys/events/up */
            var ev = pendingEvents.poll()
            while (ev != null) {
                val (type, detail) = ev
                runCatching {
                    publishQos1(c, DeviceIdentity.eventUpTopic(),
                                VsocEnvelope.buildEventUp(
                                    listOf(VsocEnvelope.EventItem(
                                        eventType = type, detail = detail,
                                        severity = "MEDIUM"))))
                }
                ev = pendingEvents.poll()
            }

            /* 日志快照分包上传(11 章): 断网暂存, 恢复后续传 */
            try {
                snapshots.pump(DeviceIdentity.ecuCode(), now) { topic, payload ->
                    publishQos1(c, topic, payload)
                    true
                }
            } catch (e: Exception) {
                Log.w(TAG, "snapshot pump failed", e)
            }

            /* 逐 nodeType 通道: 队列批次 -> 信封 -> 发布 -> 推进游标 */
            var any = false
            for (nodeType in DeviceIdentity.nodeTypes()) {
                val batch = queue.pending(nodeType, 64)
                if (batch.isEmpty()) continue
                any = true
                val envelope = VsocEnvelope.buildAlertEnvelope(
                    nodeType = nodeType,
                    ecuCode = DeviceIdentity.ecuCode(),
                    ruleVersion = rules.currentVersion(),
                    rawLines = batch.map { it.raw },
                )
                if (envelope == null) {
                    /* 全部解析失败: 丢批推进, 防毒丸卡死队列 */
                    Log.e(TAG, "envelope drop batch (${batch.size} lines)")
                    queue.markUploaded(batch.map { it.id })
                    continue
                }
                publishQos1(c, DeviceIdentity.alertTopic(nodeType), envelope)
                queue.markUploaded(batch.map { it.id })
            }
            if (!any && now < nextReportMs) Thread.sleep(500)
        }
    }

    private val ruleListener = IMqttMessageListener { _, msg ->
        onRuleDownlink?.invoke(msg.payload)
    }

    private val configListener = IMqttMessageListener { _, msg ->
        configs.onCloudMessage(msg.payload)
    }

    private val nackListener = IMqttMessageListener { _, msg ->
        /* 快照补片(11.2), 仅 24h 内受理 */
        snapshots.onNack(String(msg.payload), System.currentTimeMillis())
    }

    private fun publishQos1(c: MqttAsyncClient, topic: String, payload: String) {
        c.publish(topic, MqttMessage(payload.toByteArray()).apply {
            qos = 1
            isRetained = false
        }).waitForCompletion(10_000)
    }

    private fun brokerUrl(): String {
        val scheme = if (plainText()) "tcp" else "ssl"
        return "$scheme://${Broker.HOST}:${Broker.PORT}"
    }

    /** 实验室明文(mock 云): persist.idsm.plain=1 */
    private fun plainText(): Boolean =
        SysProps.get("persist.idsm.plain", "0") == "1"

    /** TLS pinning: 只信任指定公钥指纹, 忽略系统 CA 库 */
    private fun buildSocketFactory(): SSLSocketFactory {
        val tm = PinningTrustManager(Broker.PINNED_PUBKEY_SHA256)
        return SSLContext.getInstance("TLS").apply {
            init(null, arrayOf(tm), null)
        }.socketFactory
    }

    /** 传输层 clientId(匿名连接同样需要; username 才是鉴权身份) */
    private fun transportClientId(): String =
        "idsm-${DeviceIdentity.deviceId()}"

    companion object {
        private const val TAG = "IdsmMqtt"
    }
}
