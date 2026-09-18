# Linux 车端部署

与 Android 侧同一套车规链路,只是把管理组件从 APK 换成原生守护进程
`idsm_managerd`:

```
host_probe / eth_probe (root, systemd)
    │  NDJSON over UDS (/run/idsm/probe.sock)   ← fire-and-forget
    ▼
idsm_managerd(systemd, 普通用户即可)
    │  JSONL+游标 持久队列 → MQTT/TLS QoS1
    ▼
云端 broker: ids/alerts/{vin} 上行, ids/rules/{vin} 下行
```

线上协议与 Android 完全一致:同一 NDJSON 行格式、同一 topic 规划、
同一规则包格式与 Ed25519 canonical 字节序(两侧都有钉桩测试,见
`tests/test_managerd.cpp` 的 `CanonicalMatchesApkFormat` 与
APK 侧 `RuleManager.canonicalBytes`)。云端不感知车型 OS。

## 组件

| 文件 | 说明 |
|---|---|
| `idsm_managerd/alert_queue.*` | 持久队列: append-only JSONL + 游标断点续传, 零依赖可直接文本审计 |
| `idsm_managerd/socket_server.*` | AF_UNIX 监听, 粘包/拆包/半行处理, 优雅退出 join 全部连接 |
| `idsm_managerd/mqtt_uploader.*` | libmosquitto 真实实现(`-DHAVE_MOSQUITTO`), 无库时 Stub 仅打印; TLS/令牌接口同 APK |
| `idsm_managerd/rule_manager.*` | Ed25519 验签(OpenSSL EVP) + 原子切换 current 软链 + reload-cmd + 出厂基线播种 |
| `idsm_managerd/base64.h` | 标准 Base64, 与 Android `Base64.NO_WRAP` 逐字节一致 |
| `systemd/*.service` | managerd + 两个探针的 unit, 含资源兜底与硬化项 |

## 构建

根 CMake 自动带上(`UNIX AND NOT APPLE`):

```bash
cmake -B build && cmake --build build -j8 --target idsm_managerd
# 真实 MQTT(Ubuntu): sudo apt install libmosquitto-dev 后重新 cmake
```

## 安装

```bash
install -Dm755 build/linux/idsm_managerd/idsm_managerd /usr/lib/idsm/idsm_managerd
install -Dm755 build/host_probe /usr/sbin/idsm/host_probe
install -Dm755 build/eth_probe  /usr/sbin/idsm/eth_probe
install -Dm644 linux/systemd/*.service /etc/systemd/system/
install -Dm644 apps/host_probe/baseline/example_*.txt /etc/idsm/v0/   # 首版基线
# /etc/idsm/managerd.env: IDSMD_BROKER/IDSMD_VIN/IDSMD_PUBKEY_B64/...
systemctl daemon-reload
systemctl enable --now idsm-managerd idsm-host-probe idsm-eth-probe
```

## 验证(无 broker 也可先跑)

```bash
# 单测: 队列断点续传 / 验签切换 / UDS 收包
./build/test_managerd

# 全链路冒烟(stub MQTT 打印即为通过)
idsm_managerd --socket /tmp/idsm.sock --data-dir /tmp/idsm-data \
    --vin TESTVIN --reload-cmd /bin/true &
sudo ./build/host_probe --baseline-exec apps/host_probe/baseline/example_exec.txt \
    --sink /tmp/idsm.sock
```

## 与 Android 侧的对应关系

| 职责 | Android | Linux |
|---|---|---|
| 收探针告警 | `ProbeSocketServer`(abstract `@idsm_probe`) | `SocketServer`(`/run/idsm/probe.sock`) |
| 持久队列 | `AlertQueue`(SQLite) | `AlertQueue`(JSONL+游标) |
| 上云 | `MqttUploader`(paho, TLS pinning) | `MqttUploader`(mosquitto, 同 topic/QoS) |
| 规则下发 | `RuleManager`(Ed25519, BC/Conscrypt) | `RuleManager`(OpenSSL EVP, 同一 canonical) |
| 探针重载 | `idsm.reload` 属性 → init restart | `systemctl restart`(reload-cmd) |
| 出厂基线 | `/vendor/etc/idsm/v0` | `/etc/idsm/v0` |
