# vendor 集成模板

把探针和 APK 装进 Android 车机镜像所需的最小文件集。挂法:

```
# OEM 构建配置(如 device/<oem>/<board>/BoardConfig.mk)
BOARD_SEPOLICY_DIRS += <本仓库>/android/vendor/sepolicy
PRODUCT_COPY_FILES += \
    <本仓库>/android/vendor/init/host_probe.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/host_probe.rc \
    <本仓库>/android/vendor/init/eth_probe.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/eth_probe.rc
PRODUCT_PACKAGES += host_probe eth_probe IdsmManager
```

探针二进制建议用本仓库 CMake 交叉编译(Android NDK toolchain 文件,
`-DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-29`)产出
`host_probe` / `eth_probe`,加 Android.bp `cc_prebuilt_binary` 装进
`/vendor/bin/`。

## 文件说明

| 文件 | 作用 |
|---|---|
| `init/host_probe.rc` / `init/eth_probe.rc` | init 拉起:root、重启策略、memcg 兜底、规则热更新属性触发 |
| `sepolicy/host_probe.te` / `eth_probe.te` | 探针域:抓包/.proc/netlink 权限、UDS 上报、规则目录读 |
| `sepolicy/idsm_manager.te` | APK 域:MQTT/TLS、UDS 监听、写 reload 属性 |
| `sepolicy/seapp_contexts` | 平台签名 APK 映射进独立域(安全审计的关键) |
| `sepolicy/property_contexts` | `idsm.reload` 属性白名单 |

## 量产检查单

- [ ] 探针和 APK 均不在 `untrusted_app` 域
- [ ] APK 平台签名 + persistent,`dumpsys activity processes` 可见常驻
- [ ] broker 证书 pinning 指纹已替换,lab token/property 已清除
- [ ] 拔掉网线/断电重启后告警不丢(SQLite 续传验证)
- [ ] 伪造规则包(改一字节)被 Ed25519 验签拒绝
- [ ] 断网期攻击本机,联网后按序补传
