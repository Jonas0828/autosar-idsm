# Android APK 编译/信封互操作冒烟检查

不依赖 Android 构建链,用 Kotlin 编译器直接对 API 31 编译 APK 源码,
再在 JVM 上运行 `ParityMain.kt`,校验 `VsocEnvelope` 信封与 C++/python
基线逐字段对齐(eventId、eventType、9 字段 content)。

## 依赖

Android 12 SDK(含 JDK11 与 android.jar):

```
~/work/code/androidT/rk3588_android_sdk
```

Kotlin 编译器及第三方 jar,放到 `~/work/deps/android-check/`:

```bash
DEPS=~/work/deps/android-check
mkdir -p "$DEPS" && cd "$DEPS"
# Kotlin 编译器(含 trove4j / annotations / stdlib)
curl -LO https://repo1.maven.org/maven2/org/jetbrains/kotlin/kotlin-compiler/1.9.24/kotlin-compiler-1.9.24.jar
mv kotlin-compiler-1.9.24.jar kotlin-compiler.jar
unzip -o kotlin-compiler.jar "lib/*" -d /tmp/kc >/dev/null
cp /tmp/kc/lib/kotlin-stdlib.jar /tmp/kc/lib/trove4j.jar /tmp/kc/lib/annotations-13.0.jar .
mv annotations-13.0.jar annotations.jar
# 运行时第三方库
curl -LO https://repo1.maven.org/maven2/org/eclipse/paho/org.eclipse.paho.client.mqttv3/1.2.5/org.eclipse.paho.client.mqttv3-1.2.5.jar
mv org.eclipse.paho.client.mqttv3-1.2.5.jar paho.jar
curl -LO https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.78.1/bcprov-jdk18on-1.78.1.jar
mv bcprov-jdk18on-1.78.1.jar bcprov.jar
# android.jar 里 org.json 是 stub,运行时用真实现替换
curl -LO https://repo1.maven.org/maven2/org/json/json/20240303/json-20240303.jar
mv json-20240303.jar json.jar
```

最终目录需包含:`kotlin-compiler.jar`、`kotlin-stdlib.jar`、`trove4j.jar`、
`annotations.jar`、`paho.jar`、`bcprov.jar`、`json.jar`。

## 用法

```bash
bash tools/android_check/run_parity.sh
# 输出 PARITY PASS = APK 信封与 C++/python 基线对齐
```

## 注意

- `android.os.SystemProperties` 是隐藏 API,公共 SDK android.jar 无此符号,
  APK 侧已收口到反射封装 `SysProps.kt`,编译检查不受影响。
- 该检查只做编译 + 信封冒烟,不替代 APK 真机/模拟器运行验证。
