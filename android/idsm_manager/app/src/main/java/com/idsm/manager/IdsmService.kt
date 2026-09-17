package com.idsm.manager

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.IBinder

/**
 * IdsmService -- 车规管理核心服务。
 *
 * 生命周期: init 拉起(见 vendor .rc 中 APK 由 persistent 属性保证常驻),
 * BOOT_COMPLETED 兜底。持有四个协作组件:
 *  - [ProbeSocketServer] 收探针告警(UDS abstract @idsm_probe)
 *  - [AlertQueue]        SQLite 持久队列,APK 被杀也不丢
 *  - [MqttUploader]      MQTT/TLS 上云,证书 pinning + 短时令牌
 *  - [RuleManager]       云端规则包验签、原子切换、回滚
 *
 * native 探针不直接碰网络/云,所有云端交互集中在本服务,便于安全审计。
 */
class IdsmService : Service() {

    private lateinit var queue: AlertQueue
    private lateinit var server: ProbeSocketServer
    private lateinit var uploader: MqttUploader
    private lateinit var rules: RuleManager

    override fun onCreate() {
        super.onCreate()
        queue = AlertQueue(this)
        server = ProbeSocketServer(queue)
        uploader = MqttUploader(this, queue)
        rules = RuleManager(this, uploader)

        server.start()
        uploader.start { topic, payload ->
            // 云端下行:规则包分发
            rules.onCloudMessage(topic, payload)
        }
        rules.start()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIF_ID, buildNotification())
        return START_STICKY
    }

    override fun onDestroy() {
        server.stop()
        uploader.stop()
        queue.close()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun buildNotification(): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        nm?.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "IDSM", NotificationManager.IMPORTANCE_MIN)
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("IDSM Manager")
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .build()
    }

    companion object {
        private const val NOTIF_ID = 0x1D5A
        private const val CHANNEL_ID = "idsm"
    }
}
