package com.idsm.manager

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.util.Log

/**
 * ProbeSocketServer -- 监听 abstract UDS, 接收探针 NDJSON 行。
 *
 * v1.0 起按 nodeType 分通道(与 linux/idsm_managerd 的 --socket/--sink
 * 一一对应): @idsm_host / @idsm_eth / @idsm_can, 探针启动时以 root
 * 身份 connect 到各自通道(C++ 侧 --sink @idsm_host 等, 见 vendor .rc)。
 * 探针端是 fire-and-forget: APK 不在则事件丢弃, 持久化责任在本组件。
 */
class ProbeSocketServer(
    private val queue: AlertQueue,
    private val snapshots: LogSnapshotManager,
) {

    @Volatile private var running = false
    private val threads = mutableListOf<Thread>()
    private val peerCounts = java.util.concurrent.ConcurrentHashMap<String, java.util.concurrent.atomic.AtomicInteger>()

    /** 探针连接数变化回调(nodeType, 新连接数); 属性上报即时增量(8.3) */
    @Volatile var onPeerChange: ((nodeType: String, peers: Int) -> Unit)? = null

    /** 当前已连接探针数(nodeStatus 真实数据源, 8 章) */
    fun peerCount(nodeType: String): Int =
        peerCounts[nodeType]?.get() ?: 0

    fun start() {
        running = true
        CHANNELS.forEach { (name, nodeType) ->
            threads += Thread({ loop(name, nodeType) }, "idsm-probe-$name")
                .apply { start() }
        }
    }

    fun stop() {
        running = false
        // 触发各 accept 退出: 自连一次
        CHANNELS.forEach { (name, _) ->
            runCatching {
                LocalSocket().connect(LocalServerSocket(name).localSocketAddress)
            }
        }
        threads.forEach { it.join(1000) }
    }

    private fun loop(name: String, nodeType: String) {
        while (running) {
            var server: LocalServerSocket? = null
            try {
                server = LocalServerSocket(name)   // abstract namespace
                Log.i(TAG, "listening on @$name ($nodeType)")
                while (running) {
                    val conn = server.accept() ?: continue
                    Thread({ handle(conn, nodeType) }, "idsm-probe-conn")
                        .start()
                }
            } catch (e: Exception) {
                if (running) {
                    Log.w(TAG, "server @$name restart after error", e)
                    Thread.sleep(1000)
                }
            } finally {
                runCatching { server?.close() }
            }
        }
    }

    private fun handle(conn: LocalSocket, nodeType: String) {
        val counter = peerCounts.getOrPut(nodeType) { java.util.concurrent.atomic.AtomicInteger(0) }
        val peers = counter.incrementAndGet()
        onPeerChange?.invoke(nodeType, peers)
        conn.inputStream.bufferedReader().use { reader ->
            while (running) {
                val line = reader.readLine() ?: break
                if (line.isBlank()) continue
                /* 探针下行命令(与告警行同通道): log_upload -> 快照分包(11 章) */
                if (line.contains("\"cmd\"") && routeCommand(line)) continue
                /* 原行进队, 信封解析在发送侧(VsocEnvelope), 与 managerd 一致 */
                queue.enqueue(nodeType, line)
            }
        }
        runCatching { conn.close() }
        onPeerChange?.invoke(nodeType, counter.decrementAndGet())
    }

    /* {"cmd":"log_upload","file":...,"event_id":...,"remark":...} */
    private fun routeCommand(line: String): Boolean = try {
        val j = org.json.JSONObject(line)
        if (j.optString("cmd") != "log_upload") false
        else {
            val tid = snapshots.stageUpload(
                LogSnapshotManager.Request(
                    file = j.optString("file"),
                    eventId = j.optString("event_id"),
                    remark = j.optString("remark"),
                ),
                System.currentTimeMillis(),
            )
            tid != null
        }
    } catch (e: Exception) {
        false   /* 非命令行, 回落按告警处理 */
    }

    companion object {
        private const val TAG = "IdsmProbeServer"

        /** 通道表与 vendor .rc 中探针的 --sink 参数一致 */
        val CHANNELS = linkedMapOf(
            "idsm_host" to "HIDPS",
            "idsm_eth" to "NIDPS",
            "idsm_can" to "CIDS",
        )
    }
}
