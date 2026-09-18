# IdsmManager — IDSM 车规管理 APK(VSOC 设备接入设计 v1.0)

车端云端交互的唯一出口。native 探针(host_probe / eth_probe)不直接碰网络,
告警经 UDS abstract socket(v1.0 按 nodeType 分通道)上报到本 APK,
由本 APK 持久化并经 MQTT/TLS 上云。协议、topic、信封与
linux/idsm_managerd 完全一致,同一套云端(含 tools/vsoc_mock 联调环境)
两侧通用。

## 组件

| 类 | 职责 |
|---|---|
| `IdsmService` | 前台服务,组装并持有以下组件 |
| `DeviceIdentity` | 三段式 device_id / ecuCode / nodeType / topic 体系 |
| `ProbeSocketServer` | 监听 `@idsm_host`/`@idsm_eth`/`@idsm_can`,收 NDJSON 行 |
| `AlertQueue` | SQLite 持久队列(v2,带 node_type/raw),至少一次上传语义 |
| `VsocEnvelope` | 探针 NDJSON -> alert_{host\|eth\|can} 信封(6/9 章) |
| `MqttUploader` | 上行信封/属性心跳/LWT;注册(4 章);规则订阅(10 章) |
| `PropertyReport` | 属性/心跳(8 章,300s±10%)与 LWT 载荷(5.3) |
| `Registration` | 一型一证 init 流程 + 凭据持久化(4 章) |
| `RuleManager` | v1.0 签名规则包验签(10.1 canonical 与 C++/python 逐字节一致)、防回滚、原子切换 |
| `BootReceiver` | LOCKED_BOOT_COMPLETED / BOOT_COMPLETED 兜底拉起 |

## 数据流

```
host_probe/eth_probe (root, init 拉起)
    │  NDJSON over UDS abstract idsm_host / idsm_eth   ← fire-and-forget
    ▼
IdsmManager APK (平台签名, persistent)
    │  SQLite 落库 → MQTT QoS1 → ack 后 markUploaded
    ▼
云端 broker(7 章 topic 体系):
  上行 oc/devices/{device_id}/sys/idps/{host|eth|can}/log   检测日志信封
  上行 oc/devices/{device_id}/sys/property/report           属性/心跳/LWT
  下行 oc/devices/{device_id}/sys/idps/rule/update          签名规则包(单车)
  下行 oc/vmodel/{mfr}_{model}/sys/idps/rule/update         签名规则包(车型广播)
  注册 oc/devices/{device_id}/sys/init/request|response     一型一证
```

## 集成要点

1. **平台签名**:用 OEM platform key 签名,`persistent` 属性才生效,
   且才能经 `seapp_contexts` 进入独立 sepolicy 域。
2. **注入身份属性**(产线 MES 写入):
   `persist.idsm.manufacturer` / `persist.idsm.model_code` / `persist.idsm.vin`
   / `persist.idsm.ecu_code`(默认 0x02 座舱)/ `persist.idsm.nodes`(默认 HIDPS,NIDPS)。
3. **替换占位配置**(Config.kt / RuleManager.kt):
   broker 地址与公钥指纹、Ed25519 规则签名公钥。
4. **注册模式**:`persist.idsm.register=1` 走一型一证 init 流程;
   `persist.idsm.token` 直配短期令牌(车队测试);两者皆无则读本地凭据,
   仍无则匿名(仅 mock/降级环境);`persist.idsm.plain=1` 实验室明文。
5. **首次启动**自动把 `/vendor/etc/idsm/v0` 出厂基线拷为规则 v0。
6. 规则热更新后 APK 置 `idsm.reload={host|eth|can}` 属性,init 重启探针
   (见 vendor/init)。

## 构建

standalone: `gradle assembleRelease`(需配置 platform 签名)。
AOSP 内:把本目录挂到 `packages/apps/`,补 Android.bp 后用 `mma` 构建,
随系统镜像预装到 `/system_ext/app/IdsmManager/`。
