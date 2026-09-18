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
class ProbeSocketServer(private val queue: AlertQueue) {

    @Volatile private var running = false
    private val threads = mutableListOf<Thread>()

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
        conn.inputStream.bufferedReader().use { reader ->
            while (running) {
                val line = reader.readLine() ?: break
                if (line.isBlank()) continue
                /* 原行进队, 信封解析在发送侧(VsocEnvelope), 与 managerd 一致 */
                queue.enqueue(nodeType, line)
            }
        }
        runCatching { conn.close() }
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
