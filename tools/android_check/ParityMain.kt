/*
 * ParityMain -- JVM 侧冒烟:APK 的 VsocEnvelope 与 C++/python 基线对齐。
 *
 * 用法(在 alientek 构建机上,依赖见 tools/android_check/README.md):
 *   kotlinc -classpath <apk-classes> -d t tools/android_check/ParityMain.kt
 *   java -cp <apk-classes>:t:kotlin-stdlib.jar:<android.jar> ParityMainKt
 *
 * 输出 4 行:eventId / HIDPS 事件名 / NIDPS 事件名 / 完整信封 JSON。
 * eventId 应与 python `hashlib.sha256(b"deadbeef").hexdigest()[:32]`
 * 前缀一致(C++ makeEventId 同算法,已在 test_managerd 覆盖)。
 */
import com.idsm.manager.VsocEnvelope

fun main() {
    println(VsocEnvelope.makeEventId("caic_t99_UNKNOWN_VIN", "HIDPS", "deadbeef"))
    println(VsocEnvelope.eventTypeName("HIDPS", 0x8025))
    println(VsocEnvelope.eventTypeName("NIDPS", 0x8011))
    val line = "{\"event_id\":32805,\"severity\":\"HIGH\"," +
        "\"timestamp_s\":1726640000,\"timestamp_ns\":123456789," +
        "\"ids_message\":\"deadbeef\"}"
    println(VsocEnvelope.buildAlertEnvelope("HIDPS", "0x02", "v0", listOf(line)))
}
