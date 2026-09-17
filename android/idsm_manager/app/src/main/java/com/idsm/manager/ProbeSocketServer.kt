package com.idsm.manager

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.util.Log
import org.json.JSONObject

/**
 * ProbeSocketServer -- 监听 abstract UDS "idsm_probe",接收探针 NDJSON 行。
 *
 * host_probe / eth_probe 启动时以 root 身份 connect 到本 socket
 * (C++ 侧 --sink @idsm_probe,见 src/IdsRm_Manager.cpp sink_connect)。
 * 探针端是 fire-and-forget:APK 不在则事件丢弃,持久化责任在本组件。
 */
class ProbeSocketServer(private val queue: AlertQueue) {

    @Volatile private var running = false
    private var thread: Thread? = null

    fun start() {
        running = true
        thread = Thread({ loop() }, "idsm-probe-server").apply { start() }
    }

    fun stop() {
        running = false
        // 触发 accept 退出:自连一次
        runCatching { LocalSocket().connect(LocalServerSocket(NAME).localSocketAddress) }
        thread?.join(1000)
    }

    private fun loop() {
        while (running) {
            var server: LocalServerSocket? = null
            try {
                server = LocalServerSocket(NAME)   // abstract namespace
                Log.i(TAG, "listening on @$NAME")
                while (running) {
                    val conn = server.accept() ?: continue
                    Thread({ handle(conn) }, "idsm-probe-conn").start()
                }
            } catch (e: Exception) {
                if (running) {
                    Log.w(TAG, "server restart after error", e)
                    Thread.sleep(1000)
                }
            } finally {
                runCatching { server?.close() }
            }
        }
    }

    private fun handle(conn: LocalSocket) {
        conn.inputStream.bufferedReader().use { reader ->
            while (running) {
                val line = reader.readLine() ?: break
                if (line.isBlank()) continue
                try {
                    val obj = JSONObject(line)
                    queue.enqueue(
                        AlertQueue.Entry(
                            eventId = obj.optLong("event_id"),
                            severity = obj.optString("severity"),
                            idsMessage = obj.optString("ids_message"),
                            payload = obj.optString("payload"),
                            timestampS = obj.optLong("timestamp_s"),
                            timestampNs = obj.optLong("timestamp_ns"),
                        )
                    )
                } catch (e: Exception) {
                    Log.w(TAG, "bad NDJSON line dropped: ${line.take(80)}")
                }
            }
        }
        runCatching { conn.close() }
    }

    companion object {
        private const val TAG = "IdsmProbeServer"
        const val NAME = "idsm_probe"
    }
}
