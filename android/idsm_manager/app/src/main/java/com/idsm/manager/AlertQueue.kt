package com.idsm.manager

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/**
 * AlertQueue -- SQLite 持久队列。
 *
 * 探针事件先落库再上报:APK 被 lmk 杀掉、断网、车熄火断电,恢复后都能
 * 续传。uploaded=0 即待发送;上传成功置 1,保留最近 N 条用于本地审计。
 */
class AlertQueue(context: Context) :
    SQLiteOpenHelper(context, "idsm_alerts.db", null, 1) {

    data class Entry(
        val eventId: Long,
        val severity: String,
        val idsMessage: String,
        val payload: String,
        val timestampS: Long,
        val timestampNs: Long,
    )

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE alerts(
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 event_id INTEGER, severity TEXT,
                 ids_message TEXT, payload TEXT,
                 ts_s INTEGER, ts_ns INTEGER,
                 uploaded INTEGER DEFAULT 0,
                 recv_s INTEGER  -- APK 本地接收时间,云端对账用
               )"""
        )
        db.execSQL("CREATE INDEX idx_pending ON alerts(uploaded, id)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldV: Int, newV: Int) {}

    @Synchronized
    fun enqueue(e: Entry) {
        writableDatabase.execSQL(
            "INSERT INTO alerts(event_id,severity,ids_message,payload,ts_s,ts_ns,recv_s)" +
                " VALUES(?,?,?,?,?,?,strftime('%s','now'))",
            arrayOf(e.eventId, e.severity, e.idsMessage, e.payload,
                    e.timestampS, e.timestampNs)
        )
        trim()
    }

    /** 待发送事件,batch 上限避免单条 MQTT 消息过大 */
    @Synchronized
    fun pending(limit: Int = 64): List<Pair<Long, Entry>> {
        val out = mutableListOf<Pair<Long, Entry>>()
        readableDatabase.rawQuery(
            "SELECT id,event_id,severity,ids_message,payload,ts_s,ts_ns FROM alerts" +
                " WHERE uploaded=0 ORDER BY id LIMIT ?",
            arrayOf(limit)
        ).use { c ->
            while (c.moveToNext()) {
                out += c.getLong(0) to Entry(
                    c.getLong(1), c.getString(2), c.getString(3),
                    c.getString(4), c.getLong(5), c.getLong(6)
                )
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
