package com.idsm.manager

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * BootReceiver -- LOCKED_BOOT_COMPLETED / BOOT_COMPLETED 兜底拉起。
 * 系统签名 + persistent 的 APK 正常由 AMS 随系统启动;接收器覆盖
 * 异常路径(崩溃后被清理、direct boot 阶段需要尽早建队)。
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_LOCKED_BOOT_COMPLETED,
            Intent.ACTION_BOOT_COMPLETED -> {
                val svc = Intent(context, IdsmService::class.java)
                context.startForegroundService(svc)
            }
        }
    }
}
