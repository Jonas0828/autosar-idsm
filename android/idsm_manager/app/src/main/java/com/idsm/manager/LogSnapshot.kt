package com.idsm.manager

import android.content.Context
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * LogSnapshot -- 日志快照分包上传(设计 v1.0 第 11 章)。
 *
 * 与 linux/idsm_managerd/log_snapshot.cpp 同协议: >256KB 取证文件分包,
 * 元消息(A.7 扁平信封) + ≤128KB 分片(chunk_sha256 + base64 data),
 * 走 oc/devices/{device_id}/sys/log/report (QoS1)。
 *
 * 触发: 探针经 UDS 下行命令行 {"cmd":"log_upload","file":...,
 * "event_id":...,"remark":...}(与 managerd 一致, ProbeSocketServer 路由)。
 * 断网暂存 device-protected 目录 pending/<tid>/, 恢复后补传(replay=true,
 * 11.3); 云端整体 sha256 失败经 negative-ack 索补片, 24h 内重发(11.2)。
 */
class LogSnapshotManager(context: Context) {

    data class Request(
        val file: String,
        val eventId: String = "",
        val remark: String = "",
    )

    private val root: File = run {
        val dp = context.createDeviceProtectedStorageContext()
        File(dp.filesDir, "snapshots")
    }
    private val rng = SecureRandom()

    /** 暂存一次上传: 读文件、切分片、落盘 pending/<tid>/; 返回 transfer_id */
    fun stageUpload(req: Request, nowMs: Long): String? {
        val f = File(req.file)
        if (!f.isFile || f.length() == 0L || f.length() > MAX_FILE_SIZE) {
            Log.e(TAG, "snapshot rejected: ${req.file}")
            return null
        }
        val data = f.readBytes()
        val tid = newTransferId()
        val dir = File(root, "pending/$tid")
        val chunksDir = File(dir, "chunks")
        if (!chunksDir.mkdirs()) return null

        var count = 0
        var off = 0
        while (off < data.size) {
            val n = minOf(CHUNK_SIZE, data.size - off)
            File(chunksDir, chunkName(count)).writeBytes(data.copyOfRange(off, off + n))
            off += n
            ++count
        }
        val meta = JSONObject().apply {
            put("transfer_id", tid)
            put("filename", f.name)
            put("total_size", data.size)
            put("total_chunks", count)
            put("sha256", sha256Hex(data))
            put("log_time", isoLocal(nowMs))
            put("event_id", req.eventId)
            put("ecu_code", "")
            put("remark", req.remark)
            put("created_ms", nowMs)
            put("replay", false)
            put("meta_sent", false)
            put("next_chunks", JSONArray().apply {
                for (i in 0 until count) put(i)
            })
        }
        saveMeta(dir, meta)
        Log.i(TAG, "snapshot staged: $tid (${data.size}B x$count)")
        return tid
    }

    /** 发布进行中的 transfer; publish 返回 false 即停下轮续。无进展返回 false */
    fun pump(
        ecuCode: String,
        nowMs: Long,
        publish: (topic: String, payload: String) -> Boolean,
    ): Boolean {
        val pending = File(root, "pending")
        val dirs = pending.listFiles()?.filter { it.isDirectory }?.sortedBy { it.name }
            ?: return false
        var progressed = false
        for (dir in dirs) {
            val metaFile = File(dir, "meta.json")
            val meta = runCatching { JSONObject(metaFile.readText()) }.getOrNull()
                ?: continue

            /* 24h 过期清理(11.3) */
            if (nowMs - meta.optLong("created_ms") > TTL_MS) {
                File(root, "expired").mkdirs()
                dir.renameTo(File(root, "expired/${dir.name}"))
                continue
            }
            val topic = DeviceIdentity.snapshotTopic()

            if (!meta.optBoolean("meta_sent")) {
                /* 补传语义: 暂存超 5 分钟 -> replay=true(11.3) */
                meta.put("replay", nowMs - meta.optLong("created_ms") > 5 * 60 * 1000)
                val env = JSONObject().apply {
                    put("msg_type", "log_snapshot")
                    put("protocol_version", "1.0")
                    put("timestamp", nowMs)
                    put("manufacturer", DeviceIdentity.manufacturer)
                    put("transfer_id", meta.getString("transfer_id"))
                    put("filename", meta.getString("filename"))
                    put("total_size", meta.getInt("total_size"))
                    put("total_chunks", meta.getInt("total_chunks"))
                    put("sha256", meta.getString("sha256"))
                    put("log_time", meta.getString("log_time"))
                    put("ecuCode", ecuCode)
                    put("replay", meta.getBoolean("replay"))
                    if (meta.optString("event_id").isNotEmpty())
                        put("event_id", meta.getString("event_id"))
                    if (meta.optString("remark").isNotEmpty())
                        put("remark", meta.getString("remark"))
                }
                if (!publish(topic, env.toString())) {
                    saveMeta(dir, meta)
                    return progressed
                }
                meta.put("meta_sent", true)
                saveMeta(dir, meta)
                progressed = true
            }

            val next = meta.getJSONArray("next_chunks")
            var sent = 0
            while (next.length() > 0 && sent < CHUNKS_PER_PUMP) {
                val idx = next.getInt(0)
                val chunk = File(dir, "chunks/${chunkName(idx)}")
                if (!chunk.isFile) return progressed
                val raw = chunk.readBytes()
                val env = JSONObject().apply {
                    put("msg_type", "log_snapshot_chunk")
                    put("protocol_version", "1.0")
                    put("timestamp", nowMs)
                    put("manufacturer", DeviceIdentity.manufacturer)
                    put("transfer_id", meta.getString("transfer_id"))
                    put("chunk_index", idx)
                    put("chunk_sha256", sha256Hex(raw))
                    put("data", android.util.Base64.encodeToString(
                        raw, android.util.Base64.NO_WRAP))
                }
                if (!publish(topic, env.toString())) {
                    saveMeta(dir, meta)
                    return progressed
                }
                removeFirst(next)
                ++sent
                progressed = true
            }
            if (next.length() == 0) {
                File(root, "done").mkdirs()
                dir.renameTo(File(root, "done/${dir.name}"))
                Log.i(TAG, "snapshot uploaded: ${meta.getString("transfer_id")}")
            } else {
                saveMeta(dir, meta)
            }
            if (sent >= CHUNKS_PER_PUMP) return progressed
        }
        return progressed
    }

    /** negative-ack 消费端: 缺失 index 重排(24h 内, done/ 可重激活) */
    fun onNack(payload: String, nowMs: Long): Boolean {
        val nack = runCatching { JSONObject(payload) }.getOrNull() ?: return false
        val tid = nack.optString("transfer_id")
        if (tid.isEmpty()) return false
        var dir = File(root, "pending/$tid")
        if (!dir.isDirectory) {
            val done = File(root, "done/$tid")
            if (done.isDirectory) {
                dir = File(root, "pending/$tid")
                done.renameTo(dir)
            }
        }
        if (!dir.isDirectory) return false
        val metaFile = File(dir, "meta.json")
        val meta = runCatching { JSONObject(metaFile.readText()) }.getOrNull()
            ?: return false
        if (nowMs - meta.optLong("created_ms") > TTL_MS) return false
        val missing = runCatching { nack.getJSONArray("missing") }.getOrNull()
            ?: return false
        val total = meta.getInt("total_chunks")
        val indices = (0 until missing.length()).map { missing.getInt(it) }
            .filter { it in 0 until total }.sorted().distinct()
        if (indices.isEmpty()) return false
        meta.put("next_chunks", JSONArray().apply {
            indices.forEach { put(it) }
        })
        saveMeta(dir, meta)
        Log.i(TAG, "snapshot nack: $tid resend ${indices.size} chunks")
        return true
    }

    private fun newTransferId(): String {
        val b = ByteArray(16)
        rng.nextBytes(b)
        return b.joinToString("") { "%02x".format(it) }
    }

    private fun chunkName(idx: Int) = "chunk_%06d".format(idx)

    private fun saveMeta(dir: File, meta: JSONObject) {
        val tmp = File(dir, "meta.json.tmp")
        tmp.writeText(meta.toString(1))
        tmp.renameTo(File(dir, "meta.json"))
    }

    private fun removeFirst(arr: JSONArray) {
        /* org.json 无 remove(0) 以外的廉价头部删除, 整体重建 */
        val rest = JSONArray()
        for (i in 1 until arr.length()) rest.put(arr.get(i))
        for (i in 0 until arr.length()) arr.remove(0)
        for (i in 0 until rest.length()) arr.put(rest.get(i))
    }

    private fun sha256Hex(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(data)
            .joinToString("") { "%02x".format(it) }

    private fun isoLocal(ms: Long): String =
        SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX", Locale.US)
            .format(Date(ms))

    companion object {
        private const val TAG = "IdsmSnapshot"
        const val CHUNK_SIZE = 128 * 1024      /* 每片原始字节上限(11.2) */
        const val TTL_MS = 24L * 3600 * 1000   /* transfer 有效期(11.3) */
        const val MAX_FILE_SIZE = 64L * 1024 * 1024
        const val CHUNKS_PER_PUMP = 8          /* 防饿死告警队列 */
    }
}
