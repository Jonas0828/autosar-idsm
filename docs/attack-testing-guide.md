# 攻击测试指南

本文档描述如何测试 eth_probe 的全部 12 类检测器。测试拓扑：

```
[攻击机 .202] ──> [探针 .211 ens37] ──> [server.js :9000] ──> [InfluxDB] ──> [Grafana :3000]
```

## 前置条件

1. **探针运行**（.211 上）：

```bash
sudo ./build/eth_probe -i ens37 \
    --soc http://127.0.0.1:9000/api/idsm-violations \
    --rules apps/eth_probe/rules/example.rules \
    --cidr apps/eth_probe/rules/chnroutes.txt \
    --someip-services 0x1000,0x2000 \
    --trusted 172.16.51.211/32
```

2. **SOC 栈运行**（.211 上）：server.js + InfluxDB + Grafana（见 `tools/soc_dashboard_local/README.md`）。

3. **观察点**：
   - 探针终端：`[PROBE] alert type=N aux=0xXX`
   - server.js 日志：`tail -f /tmp/soc-server.log`
   - Grafana：http://172.16.51.211:3000 → IDSM SOC dashboard

## 检测器测试清单

### 1. PORT_SCAN（端口扫描）

```bash
# 快速扫描(立刻触发)
sudo hping3 -S -p ++1 172.16.51.211 -c 50 --faster

# 慢速扫描(需要探针加大窗口)
# 探针启动时加 --scan-window 60000, 然后:
sudo hping3 -S -p ++1 172.16.51.211 -c 30   # 默认 1包/秒, 30 秒发完
```

**预期**：`type=1 aux=0x14`（aux=唯一端口数）

**注意**：hping3 默认每秒 1 个包，10 秒默认窗口内攒不够 20 个唯一端口。要么 `--faster` 加速，要么探针加 `--scan-window 60000`。

### 2. RATE_FLOOD（洪泛）

```bash
sudo hping3 --flood -p 80 172.16.51.211   # 跑 5 秒 Ctrl+C
```

**预期**：`type=2 aux=<实际pps>`（默认阈值 1000 pps，可用 `--flood-pps` 调整）

### 3. FLAG_ANOMALY（TCP flag 异常）

```bash
sudo hping3 -F -P -U -p 80 172.16.51.211 -c 1   # Xmas (FIN+PSH+URG) → aux=2
sudo hping3 -Y -p 80 172.16.51.211 -c 1         # NULL (无flag)      → aux=1
sudo hping3 -S -F -p 80 172.16.51.211 -c 1      # SYN+FIN            → aux=3
```

### 4. RULE_HIT（规则引擎命中）

需要协议级报文，用 scapy 脚本：

```bash
# .202 上(需 python3-scapy)
sudo python3 tools/attack_tests.py 172.16.51.211 uds    # UDS SecurityAccess → aux=1000001(sid)
sudo python3 tools/attack_tests.py 172.16.51.211 http   # HTTP /admin       → aux=3000001
```

### 5. DOIP（诊断协议异常）

```bash
sudo python3 tools/attack_tests.py 172.16.51.211 doip   # 路由激活请求 → aux=0x5
```

**预期**：`type=5 aux=0x5`（RoutingActivation=非法诊断接入，GB 44496 检测项）

### 6. SOME_IP（车载以太网协议异常）

```bash
sudo python3 tools/attack_tests.py 172.16.51.211 someip  # 非法服务Offer → aux=0x1999
```

**预期**：`type=6 aux=0x1999`（0x1000+service_id 0x999，999 不在白名单）

### 7. REASSEMBLY（重组资源告警）

内部告警，正常测试难以触发（需要打爆重组缓冲区）。跳过。

### 8. CROSS_BORDER（跨境 IP）

```bash
curl http://91.189.91.64    # 或任何非境内 IP
```

**预期**：`type=8 aux=0x0`（目标 IP 在 dst_ip 字段）

**注意**：管理机/服务器自己的出网流量会误报，用 `--trusted` 加白名单。

### 9. TLS（加密流量元数据）

```bash
sudo python3 tools/attack_tests.py 172.16.51.211 tls    # TLS 1.0 ClientHello → aux=0x9002
```

**预期**：`type=9 aux=0x9001`（车内出现 TLS）或 `aux=0x9002`（版本<1.2）

### 10. HTTP（HTTP 异常）

```bash
# 需要 .211 上有 HTTP 服务(80 端口开放)
curl http://172.16.51.211/admin
```

无 HTTP 服务时可用规则命中代替（见 type=4 的 http 测试）。

### 11. DNS（DNS 异常）

```bash
# 需要 .211 上有 DNS 服务
dig @172.16.51.211 example.com ANY   # ANY 查询 → aux=0xB0FF
```

### 12. ARP_SPOOF（ARP 欺骗）

**警告**：会干扰网络，测试后 Ctrl+C 停止并等 ARP 缓存恢复。

```bash
sudo apt install -y dsniff
sudo arpspoof -i ens37 -t 172.16.51.211 172.16.51.1   # 让 .211 以为你是网关
```

**预期**：`type=12 aux=1`（IP→MAC 绑定突变）

## 一键全测

```bash
# .202 上(覆盖 4/5/6/9 + 规则命中的 HTTP)
sudo python3 tools/attack_tests.py 172.16.51.211 all
```

## 常见问题

### nmap -sS 不发包

`nmap -sS` 默认先做 host discovery，判定主机 down 就跳过扫描。**加 `-Pn`**：

```bash
sudo nmap -Pn -sS -p 1-100 172.16.51.211
```

### 探针打印了告警但页面没有

1. **探针二进制是不是最新**：改了代码后必须 `cmake --build build` 并**重启探针进程**（旧进程跑的是旧代码）。
2. **SOC 端口对不对**：`--soc` 应该指向 **9000**（server.js），不是 8080（mock_soc_server）。
3. **时间窗口**：Grafana 右上角时间范围选 "Last 1 hour"，攻击发生在窗口内才显示。

### 清空历史告警重新测试

```bash
curl -X POST http://172.16.51.211:9000/api/clear
```

Grafana 10 秒内自动刷新归零。

## 告警类型速查

| type | SEv ext ID | 名称 | aux 含义 |
|---|---|---|---|
| 1 | 0x8003 | PORT_SCAN | 唯一端口数 |
| 2 | 0x8004 | RATE_FLOOD | 实测 pps |
| 3 | 0x8005 | FLAG_ANOMALY | 1=NULL 2=Xmas 3=SYN+FIN |
| 4 | 0x8006 | RULE_HIT | 规则 sid |
| 5 | 0x8007 | DOIP | payload_type 或错误码 |
| 6 | 0x8008 | SOME_IP | 0x1000+service_id / 0x2000(session回绕) |
| 7 | 0x8009 | REASSEMBLY | 1=defrag淘汰 2=流淘汰 |
| 8 | 0x800A | CROSS_BORDER | 0（目标在 dst_ip） |
| 9 | 0x800B | TLS | 0x9001=车内出现 / 0x9002=版本<1.2 |
| 10 | 0x800C | HTTP | 错误码 |
| 11 | 0x800D | DNS | 0xB001=非法域名 / 0xB000+qtype |
| 12 | 0x800E | ARP_SPOOF | 1=绑定突变 / 2=无偿洪泛 |
| 100 | 0x8010 | SURICATA（eve_bridge） | signature_id |
