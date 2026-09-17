# Android 量产部署架构

目标形态:GB 44495-2024 / R155 上车运行。实验室的 HTTP 直连 SOC 路径
(`--soc http://...`)只保留给台架;量产车端一律走
**native 探针 → UDS → 系统 APK → MQTT/TLS → 云端**。

## 分层

```
┌────────────────────────────────────────────────────┐
│ 云端: MQTT broker + 规则签名服务 + 告警存储/分析      │
└──────────────▲───────────────────────┬─────────────┘
               │ MQTT/TLS (pinning,    │ ids/rules/{vin}
               │ QoS1, 短时令牌)        │ Ed25519 签名规则包
┌──────────────┴───────────────────────▼─────────────┐
│ IdsmManager APK(平台签名/persistent,独立 sepolicy 域)│
│  ProbeSocketServer ← UDS abstract "idsm_probe"      │
│  AlertQueue(SQLite)  MqttUploader  RuleManager      │
└───────▲─────────────────────────────┬──────────────┘
        │ NDJSON (fire-and-forget)    │ 规则: files/current
┌───────┴──────────┐         ┌────────┴─────────────┐
│ host_probe(root) │         │ eth_probe(root)      │
│ init 拉起,10类    │         │ init 拉起,链路检测    │
│ 主机检测器         │         │                      │
└──────────────────┘         └──────────────────────┘
```

为什么这样切:
- **native 层只做采集**:零外部依赖(无 TLS/MQTT 库),审计面最小,
  崩溃面最小;libcurl 只存在于实验室 HTTP 路径。
- **云端交互收敛到 APK**:证书、令牌、队列、重试只审一处;
  APK 拥有持久队列,探针 fire-and-forget 不背积压逻辑。
- **探针 root 但 SELinux 受限**:init 域独立,只授予抓包//proc/UDS/读规则
  所需权限,拿不到 APK 数据写权限,也上不了网。

## 关键机制

### 告警上报(至少一次)
1. 探针检测合格事件 → IdsRM 双发:HTTP 路径关闭时只走 sink;
2. sink 线程连接 `@idsm_probe` 发 NDJSON 行,断连退避重连,
   队列上限 512,溢出丢弃并计数(探针日志可见);
3. APK 收行即落 SQLite(uploaded=0);
4. MqttUploader 批量取 64 条 → QoS1 publish → broker ack → markUploaded;
5. APK 被杀/断网/断电恢复后从 uploaded=0 续传。

### 规则下发(可信通道)
1. 云端下发规则包 `{version, files{name:b64}, signature}`;
2. APK 验 Ed25519(签名公钥内嵌 APK,换钥必须 OTA);
3. 写 `rules.new/` → fsync → rename `rules/v{version}/` →
   临时软链 + rename 切 `current`(原子,探针永远读到完整一版);
4. 置 `idsm.reload=host/eth` 属性 → init 重启对应探针 → 读新基线;
5. 回滚:重新下发旧 version 的规则包即可,流程完全一致。

### 时间戳(审计合规的坑)
车机断电丢 RTC、冷启动时钟跳变是常态。单一时间源都会对不上云端:
- 探针 JSON 里的 `timestamp_s/ns` 是单调钟+启动纪元换算的墙钟,
  GNSS/NTP 未校准前可能偏;云端排序以 broker 接收时间为主、
  探针时间戳为辅;车端持久化的 `recv_s`(APK 入库时间)供对账;
- 排查时以 `recv_s` 与探针 ts 的差值判断时钟漂移,超阈值告警提示校时异常。

## GB 44495-2024 对照

| 要求 | 落点 |
|---|---|
| 安全事件实时上报 | host/eth 探针检测 → APK → MQTT QoS1;APK 死亡由 init/AMS 拉起补齐 |
| 事件防丢失 | SQLite 持久队列 + 至少一次语义;溢出计数进探针日志 |
| 入侵检测能力覆盖 | host_probe 10 类检测器(见 attack-testing-guide.md)+ eth_probe 链路检测 |
| 安全日志保护 | 探针只写 kmsg/stdout 不存盘;持久数据只在 APK 私有目录,SELinux 隔离 |
| 组件权限最小化 | 独立 sepolicy 域;探针无网络能力,APK 无 root |
| 远端升级/策略更新 | 规则包经签名通道热更新,探针进程重启生效,可回滚 |

## 从实验室到量产的路径

1. 台架/HIL:继续用 `--soc http://<server>:9000` 本地栈,攻击用例见
   `attack-testing-guide.md`;
2. 车机 bring-up:`--sink @idsm_probe` + IdsmManager(debug 签名,
   userdebug 镜像),MQTT broker 先指向内网;
3. 量产:平台签名 APK、替换 broker/pin/签名公钥、sepolicy 合入、
   过 vendor 检查单(`android/vendor/README.md`)。
