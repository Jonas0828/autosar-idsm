#!/usr/bin/env bash
# Android 信封互操作冒烟:APK 的 VsocEnvelope(JVM 运行)与 C++/python
# 基线对齐检查。返回 0 = PASS。
#
# 依赖(一次性,见 README.md):
#   DEPS=~/work/deps/android-check 下有 kotlin-compiler.jar /
#   kotlin-stdlib.jar / trove4j.jar / annotations.jar / paho.jar /
#   bcprov.jar / json.jar,MZ Android SDK 在 ~/work/code/androidT/rk3588_android_sdk
set -u
DEPS=~/work/deps/android-check
SDK=~/work/code/androidT/rk3588_android_sdk
JDK="$SDK/prebuilts/jdk/jdk11/linux-x86/bin/java"
KC="$DEPS/kotlin-compiler.jar:$DEPS/kotlin-stdlib.jar:$DEPS/trove4j.jar:$DEPS/annotations.jar"
CP_ANDROID="$SDK/prebuilts/sdk/31/public/android.jar"
REPO=~/work/code/autosar-idsm
W=$(mktemp -d /tmp/android_parity.XXXXXX)

"$JDK" -cp "$KC" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler \
    -no-stdlib -no-reflect \
    -classpath "$CP_ANDROID:$DEPS/paho.jar:$DEPS/bcprov.jar:$DEPS/kotlin-stdlib.jar" \
    -d "$W/apk" "$REPO"/android/idsm_manager/app/src/main/java/com/idsm/manager/*.kt
[ $? -ne 0 ] && { echo "FAIL: APK kotlin compile"; exit 1; }

"$JDK" -cp "$KC" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler \
    -no-stdlib -no-reflect \
    -classpath "$W/apk:$DEPS/kotlin-stdlib.jar" \
    -d "$W/t" "$REPO"/tools/android_check/ParityMain.kt
[ $? -ne 0 ] && { echo "FAIL: parity main compile"; exit 1; }

"$JDK" -cp "$W/apk:$W/t:$DEPS/json.jar:$DEPS/kotlin-stdlib.jar:$CP_ANDROID" \
    ParityMainKt > "$W/got.txt" 2>&1 || { echo "FAIL: run"; cat "$W/got.txt"; exit 1; }

EXPECTED_EVENTID="caic_t99_UNKNOWN_VIN-HIDPS-$(python3 -c \
    'import hashlib; print(hashlib.sha256(b"deadbeef").hexdigest()[:32])')"
GOT_EVENTID=$(sed -n '1p' "$W/got.txt")

ok=1
[ "$GOT_EVENTID" = "$EXPECTED_EVENTID" ] || { echo "FAIL eventId: got $GOT_EVENTID want $EXPECTED_EVENTID"; ok=0; }
grep -qx 'DT_FILE_MOD' <(sed -n '2p' "$W/got.txt") || { echo "FAIL eventType HIDPS 0x8025"; ok=0; }
grep -qx 'EVT_8011' <(sed -n '3p' "$W/got.txt") || { echo "FAIL eventType NIDPS 0x8011"; ok=0; }
ENVELOPE=$(sed -n '4p' "$W/got.txt")
echo "$ENVELOPE" | python3 -c '
import json, sys
env = json.loads(sys.stdin.read())
assert env["msg_type"] == "alert_host", env["msg_type"]
assert env["protocol_version"] == "1.0"
e = env["content"][0]
for k in ("eventId","eventType","severity","timestamp","ecuCode","nodeType","ruleVersion","replay","raw"):
    assert k in e, "missing " + k
assert e["severity"] == "HIGH"
assert e["timestamp"] == 1726640000123, e["timestamp"]
assert e["nodeType"] == "HIDPS"
assert e["ruleVersion"] == "v0"
'
[ $? -ne 0 ] && { echo "FAIL envelope"; ok=0; }

# 第 5 行: config canonical base64, 与 gen_rule_vector.py 的 config_canonical
# (seq=7 向量, 常量输入) 逐字节一致; 期望值 = base64(config_canonical)。
EXPECTED_CANON="c2VxPTcKdGVuYW50PWNhaWMKdmVyc2lvbj1jMQpyb2xsYmFjaz0wCnRhcmdldF9lY3U9MHgwMQp0YXJnZXRfbm9kZT1ISURQUwp0YXJnZXRfdm1vZGVsPXQ5OQppc3N1ZWRfYXQ9MTc4OTcxNTc0NQpleHBpcmVzX2F0PTE3OTAzMjA1NDUKY29uZmlnX3R5cGU9MQppdGVtOmFwcF93X2xpc3Q6ZXlKamIyNW1hV2RmYm1GdFpTSTZJbUZ3Y0Y5M1gyeHBjM1FpTENKamIyNW1hV2RmZG1Gc2RXVWlPbHNpTDNWemNpOXpZbWx1TDNOemFHUWlMQ0l2ZFhOeUwySnBiaTlqY205dVpDSmRMQ0pqYjI1bWFXZGZkbVZ5YzJsdmJpSTZJbU14SW4wPQppdGVtOmZ3X2lwX2JfbGlzdDpleUpqYjI1bWFXZGZibUZ0WlNJNkltWjNYMmx3WDJKZmJHbHpkQ0lzSW1OdmJtWnBaMTkyWVd4MVpTSTZXeUl4TUM0d0xqQXVOallpWFN3aVkyOXVabWxuWDNabGNuTnBiMjRpT2lKak1pSjkK"
GOT_CANON=$(sed -n '5p' "$W/got.txt")
[ "$GOT_CANON" = "$EXPECTED_CANON" ] || { echo "FAIL config canonical"; ok=0; }

[ "$ok" = 1 ] && echo "PARITY PASS" || echo "PARITY FAIL"
