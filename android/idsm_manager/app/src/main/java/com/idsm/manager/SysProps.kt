package com.idsm.manager

/**
 * SysProps -- android.os.SystemProperties 的反射封装。
 *
 * SystemProperties 是隐藏 API,公共 SDK stub 里没有;平台签名 APK 在
 * AOSP 树内构建时可直接引用,standalone Gradle 构建/本编译检查则不行。
 * 反射一处收口,两种构建方式都可用;读不到属性时回退默认值。
 */
object SysProps {
    private val clazz = try {
        Class.forName("android.os.SystemProperties")
    } catch (e: Exception) {
        null
    }
    private val getMethod = clazz?.getMethod("get", String::class.java, String::class.java)
    private val setMethod = clazz?.getMethod("set", String::class.java, String::class.java)

    fun get(key: String, def: String): String =
        try {
            getMethod?.invoke(null, key, def) as? String ?: def
        } catch (e: Exception) {
            def
        }

    fun set(key: String, value: String) {
        try {
            setMethod?.invoke(null, key, value)
        } catch (e: Exception) {
            // 平台签名缺失时 set 会 SELinux 拒绝; 探针不重载好过崩溃
        }
    }
}
