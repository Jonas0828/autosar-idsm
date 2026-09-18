package com.idsm.manager

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/**
 * AlertQueue -- SQLite 持久队列。
 *
 * 探针事件先落库再上报: APK 被 lmk 杀掉、断网、车熄火断电, 恢复后都能
 * 续传。uploaded=0 即待发送; 上传成功置 1, 保留最近 N 条用于本地审计。
 *
 * v2: 增加 node_type / raw 列 —— v1.0 信封按 nodeType 分通道上报,
 * raw 保留探针 NDJSON 原行(信封 raw 字段透传, 与 managerd 一致)。
 */
class AlertQueue(context: Context) :
    SQLiteOpenHelper(context, "idsm_alerts.db", null, 2) {

    data class Entry(
        val id: Long,
        val nodeType: String,       /* HIDPS / NIDPS / CIDS(按接入的 socket 标记) */
        val raw: String,            /* 探针 NDJSON 原行, 信封 raw 字段透传 */
    )

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE alerts(
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 node_type TEXT DEFAULT 'HIDPS',
                 raw TEXT,
                 uploaded INTEGER DEFAULT 0,
                 recv_s INTEGER  -- APK 本地接收时间, 云端对账用
               )"""
        )
        db.execSQL("CREATE INDEX idx_pending ON alerts(uploaded, id)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldV: Int, newV: Int) {
        if (oldV < 2) {
            /* v1 表有 event_id/severity/... 列; raw 退化为空串即可,
             * 老记录仍可上报(eventId 派生源缺失时退化为整行, 见 VsocEnvelope) */
            db.execSQL(
                "ALTER TABLE alerts ADD COLUMN node_type TEXT DEFAULT 'HIDPS'"
            )
            db.execSQL("ALTER TABLE alerts ADD COLUMN raw TEXT DEFAULT ''")
        }
    }

    @Synchronized
    fun enqueue(nodeType: String, rawLine: String) {
        writableDatabase.execSQL(
            "INSERT INTO alerts(node_type,raw,recv_s) VALUES(?,?,strftime('%s','now'))",
            arrayOf(nodeType, rawLine)
        )
        trim()
    }

    /** 待发送事件, batch 上限避免单条 MQTT 消息过大 */
    @Synchronized
    fun pending(nodeType: String, limit: Int = 64): List<Entry> {
        val out = mutableListOf<Entry>()
        readableDatabase.rawQuery(
            "SELECT id,node_type,raw FROM alerts" +
                " WHERE uploaded=0 AND node_type=? ORDER BY id LIMIT ?",
            arrayOf(nodeType, limit)
        ).use { c ->
            while (c.moveToNext()) {
                out += Entry(c.getLong(0), c.getString(1), c.getString(2))
            }
        }
        return out
    }

    @Synchronized
    fun markUploaded(ids: Collection<Long>) {
        if (ids.isEmpty()) return
        writableDatabase.execSQL(
            "UPDATE alerts SET uploaded=1 WHERE id IN (${ids.joinToString(",")})"
        )
    }

    /** 只保留最近 MAX_KEEP 条已上传记录 */
    private fun trim() {
        writableDatabase.execSQL(
            "DELETE FROM alerts WHERE uploaded=1 AND id NOT IN" +
                " (SELECT id FROM alerts WHERE uploaded=1 ORDER BY id DESC LIMIT $MAX_KEEP)"
        )
    }

    companion object {
        private const val MAX_KEEP = 5000
    }
}
