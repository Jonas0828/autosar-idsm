package com.idsm.manager

import android.app.Application
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

/**
 * IdsmApp -- 全局初始化。低版本 Android(< API 31)没有原生 Ed25519,
 * 注册 BouncyCastle 供 [RuleManager] 验签。
 */
class IdsmApp : Application() {
    override fun onCreate() {
        super.onCreate()
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.S) {
            Security.addProvider(BouncyCastleProvider())
        }
    }
}
