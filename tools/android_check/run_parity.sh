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

[ "$ok" = 1 ] && echo "PARITY PASS" || echo "PARITY FAIL"
