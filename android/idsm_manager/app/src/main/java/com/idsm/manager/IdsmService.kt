package com.idsm.manager

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.IBinder

/**
 * IdsmService -- 车规管理核心服务(VSOC 设备接入设计 v1.0 车端落地,
 * 与 linux/idsm_managerd 同协议)。
 *
 * 生命周期: init 拉起(见 vendor .rc 中 APK 由 persistent 属性保证常驻),
 * BOOT_COMPLETED 兜底。持有四个协作组件:
 *  - [ProbeSocketServer] 分通道收探针告警(abstract @idsm_host/eth/can)
 *  - [AlertQueue]        SQLite 持久队列, APK 被杀也不丢
 *  - [MqttUploader]      MQTT 上云: alert 信封/属性心跳/LWT/注册/规则订阅
 *  - [RuleManager]       云端签名规则包验签(v1.0 10.1/10.2)、防回滚、分发
 *  - [ConfigManager]     签名配置包验签落地(10.3, 与 managerd 同协议)
 *  - [LogSnapshotManager] 快照分包上传(11 章, 持久暂存 + nack 补片)
 *
 * native 探针不直接碰网络/云, 所有云端交互集中在本服务, 便于安全审计。
 */
class IdsmService : Service() {

    private lateinit var queue: AlertQueue
    private lateinit var server: ProbeSocketServer
    private lateinit var uploader: MqttUploader
    private lateinit var rules: RuleManager
    private lateinit var configs: ConfigManager
    private lateinit var snapshots: LogSnapshotManager

    override fun onCreate() {
        super.onCreate()
        queue = AlertQueue(this)
        rules = RuleManager(this)
        configs = ConfigManager(this)
        snapshots = LogSnapshotManager(this)
        server = ProbeSocketServer(queue, snapshots)
        uploader = MqttUploader(this, queue, rules, configs, snapshots) { nt ->
            server.peerCount(nt)
        }

        rules.start()
        configs.start()
        server.start()
        /* 探针连接数变化 -> 立即增量属性上报(nodeStatus 真实状态, 8.3) */
        server.onPeerChange = { _, _ -> uploader.reportNow.set(true) }
        uploader.start { payload ->
            // 云端下行: 签名规则包(v1.0 10.2, 单车/车型广播均已按 target 过滤);
            // 配置包走 configListener(见 MqttUploader)
            rules.onCloudMessage(payload)
        }
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
