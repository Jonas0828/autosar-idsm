/*
 * IdsmManager 构建脚本(参考骨架)。在 AOSP 源码树内用 mm/mma 或
 * standalone Gradle 构建均可;加入 AOSP 时把本模块挂到
 * packages/apps/ 或 vendor/<oem>/apps/ 下并补 Android.bp。
 */
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.idsm.manager"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.idsm.manager"
        minSdk = 28          // Android 9,主流车机平台底线
        targetSdk = 34
    }

    signingConfigs {
        // 量产: 使用平台签名(platform key)签名,使 persistent 生效并进入
        // 独立 sepolicy 域。本地开发可用 debug 签名 + userdebug 镜像。
        create("platform") {
            // storeFile/file/password 由 OEM 构建系统注入
        }
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.getByName("platform")
        }
    }
}

dependencies {
    // MQTT 客户端跑在我们自己的前台服务线程里,不依赖 paho 的 MqttService
    implementation("org.eclipse.paho:org.eclipse.paho.client.mqttv3:1.2.5")
    // Ed25519 规则包验签;Android 12+(API 31)Conscrypt 原生支持后可去掉
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
}
