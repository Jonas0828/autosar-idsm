# IdsmManager — IDSM 车规管理 APK

车端云端交互的唯一出口。native 探针(host_probe / eth_probe)不直接碰网络,
告警经 UDS abstract socket 上报到本 APK,由本 APK 持久化并经 MQTT/TLS 上云。

## 组件

| 类 | 职责 |
|---|---|
| `IdsmService` | 前台服务,组装并持有以下组件 |
| `ProbeSocketServer` | 监听 `@idsm_probe`,收 NDJSON 告警行 |
| `AlertQueue` | SQLite 持久队列,至少一次上传语义 |
| `MqttUploader` | MQTT/TLS + 证书 pinning + 短时令牌,QoS1 批量上行 |
| `RuleManager` | 云端规则包 Ed25519 验签、原子切换、出厂基线播种 |
| `BootReceiver` | LOCKED_BOOT_COMPLETED / BOOT_COMPLETED 兜底拉起 |

## 数据流

```
host_probe/eth_probe (root, init 拉起)
    │  NDJSON over UDS abstract "idsm_probe"   ← fire-and-forget
    ▼
IdsmManager APK (平台签名, persistent)
    │  SQLite 落库 → MQTT QoS1 → ack 后 markUploaded
    ▼
云端 broker: ids/alerts/{vin} 上行, ids/rules/{vin} 下行
```

## 集成要点

1. **平台签名**:用 OEM platform key 签名,`persistent` 属性才生效,
   且才能经 `seapp_contexts` 进入独立 sepolicy 域。
2. **替换占位配置**(Config.kt / RuleManager.kt):
   broker 地址与公钥指纹、Ed25519 规则签名公钥、VIN/令牌来源。
3. **首次启动**自动把 `/vendor/etc/idsm/v0` 出厂基线拷为规则 v0。
4. 规则热更新后 APK 置 `idsm.reload` 属性,init 重启探针(见 vendor/init)。

## 构建

standalone: `gradle assembleRelease`(需配置 platform 签名)。
AOSP 内:把本目录挂到 `packages/apps/`,补 Android.bp 后用 `mma` 构建,
随系统镜像预装到 `/system_ext/app/IdsmManager/`。
