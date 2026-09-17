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

### CAN 探针 (can_probe)

| type | SEv ext ID | 名称 | aux 含义 |
|---|---|---|---|
| 1 | 0x8011 | CAN_UNKNOWN_ID | 0（白名单外的帧 ID） |
| 2 | 0x8012 | CAN_ID_FLOOD | 实测 fps |
| 3 | 0x8013 | CAN_BUS_FLOOD | 实测 fps |
| 4 | 0x8014 | CAN_ERROR_BURST | 窗口内错误帧数 |
| 5 | 0x8015 | CAN_DLC_ANOMALY | 1=classic DLC>8 / 2=FD len>64 |
| 6 | 0x8016 | CAN_REMOTE_FRAME | 0 |
| 7 | 0x8017 | CAN_UDS_SEC_ACCESS | 1=SEED_FLOOD / 2=KEY_GUESS |
| 8 | 0x8018 | CAN_UDS_SVC_SCAN | 不同 SID 数 |
| 9 | 0x8019 | CAN_DIAG_FLOOD | 实测 fps |
| 10 | 0x801A | CAN_CYCLE_ANOMALY | 实测间隔 ms |

CAN 上下文为 16 字节布局 v1：`detector_type(1) | flags(1) | can_id(4) | reserved(2) |
count(4) | aux(4)`，大端。flags: E=扩展帧 R=远程帧 F=FD X=错误帧。

**实时攻击测试**（需要 can-utils，无真实 CAN 卡时用虚拟总线）：

```bash
sudo modprobe vcan && sudo ip link add dev can0 type vcan && sudo ip link set can0 up
sudo ./build/can_probe -i can0 --ids apps/can_probe/whitelist/example_ids.txt \
    --soc http://localhost:9000/api/idsm-violations
# 另一个终端发攻击帧：
cansend can0 321#DEADBEEF        # 未知 ID 注入 -> 0x8011
for i in $(seq 6); do cansend can0 7E0#2701; done   # UDS SecurityAccess 爆破 -> 0x8017
for i in $(seq 60); do cansend can0 7DF#3E00; done  # 诊断洪泛 -> 0x8019
for i in $(seq 120); do cansend can0 123#01020304; done  # 单 ID 洪泛 -> 0x8012
```

**离线回放**（pcap 需为 LINKTYPE_CAN_SOCKETCAN=227，可用 `candump -L` 或 scapy 生成）：

```bash
./build/can_probe --pcap capture.pcap --ids apps/can_probe/whitelist/example_ids.txt \
    --soc http://localhost:9000/api/idsm-violations
```
## 主机探针 (host_probe)

面向 Linux / Android 主机的 HIDS 探针（`apps/host_probe/`），告警 ext
`0x8021`-`0x802A`。两种实时源：netlink `PROC_CONNECTOR`（exec 事件实时，
需 root）和 `/proc` 轮询（无需 root，`--no-netlink`）；另支持 `--events`
离线回放。ext 事件 ID 与 SOC 面板 `detector` 标签（HOST_* 名）一一对应。

**前置**（.211 上）：

```bash
# 生成被监控文件 / 内核模块基线（示例）
sha256sum /etc/hostname /etc/passwd > /tmp/hp_files.txt
awk '{print $1}' /proc/modules | sort > /tmp/hp_mods.txt
# 探针 A：netlink 实时（root）
sudo ./build/host_probe --baseline-exec apps/host_probe/baseline/example_exec.txt \
    --baseline-files /tmp/hp_files.txt --baseline-mods /tmp/hp_mods.txt \
    --soc http://localhost:9000/api/idsm-violations
# 探针 B：/proc 轮询（普通用户，exec 检测有 scan-ms 级延迟）
./build/host_probe --no-netlink --scan-ms 1000 \
    --baseline-exec apps/host_probe/baseline/example_exec.txt \
    --baseline-files /tmp/hp_files.txt --baseline-mods /tmp/hp_mods.txt \
    --soc http://localhost:9000/api/idsm-violations
```

### 1. UNKNOWN_EXEC（未知程序执行，0x8021）

```bash
cp /bin/sleep /tmp/.evil_malware && /tmp/.evil_malware 60
# 期望: 0x8021, proc=.evil_malware（白名单外的可执行文件）
```

### 2. PRIV_ESC（提权，0x8022）

```bash
passwd   # 非 root 用户执行任何 setuid-root 程序都会命中
# 期望: 0x8022, flags 含 SETUID（context[1] bit0）
```

### 3. FORK_FLOOD（fork 风暴，0x8023）

```bash
# 探针加 --fork-rate 50 降低阈值（默认 200）
# 注意: 必须让子进程立即退出（if pid == 0 分支），父进程独自继续循环；
# 裸写 os.fork() 循环是 2^80 的指数 fork 炸弹，会耗尽 PID/内存搞挂机器
python3 -c 'import os,time
for _ in range(80):
    pid = os.fork()
    if pid == 0:
        time.sleep(30)   # 子进程活着，保证轮询模式也能扫到
        os._exit(0)
time.sleep(35)
for _ in range(80): os.waitpid(-1, 0)'
# 期望: 0x8023, aux=窗口内进程数
# 注意: 轮询模式把新 pid 视为 exec，netlink 模式只统计真实 exec
```

### 4. REV_SHELL（反弹 shell，0x8024）

检测条件：shell 的父进程 comm 属于网络守护进程集（adbd/sshd/netd...）。
注意 comm 取自被执行文件名而非 argv[0]，所以 `exec -a netd bash` 这类
手法无效；要用 prctl(PR_SET_NAME) 把父进程 comm 改成 netd 再派生 shell：

```bash
python3 - <<'EOF'
import ctypes, os, time
libc = ctypes.CDLL(None)
libc.prctl(15, b"netd", 0, 0, 0)                 # PR_SET_NAME: 本进程 comm -> netd
pid = os.fork()
if pid == 0:
    # 注意: 不能用 "-c sleep 2"，bash 对单命令会 exec 优化直接变成 sleep；
    # 命令列表可阻止优化，保持 comm=bash 的 shell 进程
    os.execlp("bash", "bash", "-c", "sleep 2; echo done")
time.sleep(3)
os.waitpid(pid, 0)
EOF
# 期望: 0x8024, aux=父进程 pid（netd 在默认网络守护进程集内）
# 已实测验证（2026-09, Ubuntu 20.04 轮询模式）
```

### 5. FILE_MOD（文件完整性，0x8025）

```bash
echo tampered | sudo tee -a /etc/hostname      # 摘要变化
sudo mv /etc/hostname /etc/hostname.bak        # 文件消失 -> HF_MISSING
# 期望: 0x8025, aux=1(摘要不符) / 2(文件消失, flags 含 MISSING)
sudo mv /etc/hostname.bak /etc/hostname
```

> 切勿拿 /etc/passwd 做"文件消失"测试：移走后 sudo 立即失效
> （`you do not exist in the passwd database`），sshd 也无法建立新连接，
> 只能用 Docker 或进 recovery 模式恢复。hostname 文件随意折腾，无风险。

### 6. NEW_SETUID（新增 setuid-root 文件，0x8026）

```bash
sudo cp /bin/dash /tmp/.suid_dash && sudo chmod 4755 /tmp/.suid_dash
# /tmp/.suid_dash 不在文件基线路径集里 -> 期望: 0x8026
sudo rm -f /tmp/.suid_dash
```

### 7. KMOD_LOAD（内核模块加载，0x8027）

```bash
sudo modprobe dummy      # 选一个不在 /tmp/hp_mods.txt 里的模块
# 期望: 0x8027, proc=dummy
sudo rmmod dummy
```

### 8. ZOMBIE_STORM（僵尸风暴，0x8028）

```bash
# 探针加 --zombie-max 50（默认 100）
python3 -c 'import os,time
for _ in range(80): os.fork() or os._exit(0)
time.sleep(30)'          # 子进程退出后父进程不回收 -> 80 个僵尸
# 期望: 0x8028, aux=峰值僵尸数
```

### 9. RES_EXHAUST（资源耗尽，0x8029）

```bash
yes > /dev/null &        # CPU 打满单核 -> aux=1(CPU)
python3 -c 'import time; x=bytearray(600*1024*1024); time.sleep(30)'
# 探针加 --rss-kb 524288 时 600MB -> aux=2(MEM)
kill %1
```

### 10. ROOT_SHELL（root shell，0x802A）

```bash
sudo bash                # uid=0 shell, parent=sudo -> aux=1(TTY)
ssh root@localhost       # -> aux=2(NET)
# 期望: 0x802A
```

**离线回放**（无 root、无风险复现多类告警）：

```bash
cat > /tmp/host_attack.events <<'EOF'
exec 1000 501 500 1000 0 1000 0 sh adbd /system/bin/sh
exec 2000 502 1 0 0 0 0 bash init /bin/bash
exec 2001 503 500 1000 0 1000 0 evil_tool sh /usr/bin/evil_tool
file 3000 /etc/hostname 1 0644 0 cc00000000000000000000000000000000000000000000000000000000000000
file 3100 /etc/passwd 0 0 0 -
module 4001 evil_rootkit
snap 5000 150 900 0 950 hog 901 0 2097152 fat
EOF
./build/host_probe --events /tmp/host_attack.events \
    --baseline-exec apps/host_probe/baseline/example_exec.txt \
    --baseline-files /tmp/hp_files.txt --baseline-mods /tmp/hp_mods.txt \
    --soc http://localhost:9000/api/idsm-violations
```

**注意**：

- 轮询模式 `--scan-ms` 决定快照/模块/文件检测粒度；netlink 模式下 exec
  事件实时，但快照/模块/文件仍按 `--scan-ms` 周期
- 文件完整性基线在探针启动时加载一次，改基线需重启探针
- 首次启动时系统现存进程与模块视为基线，不会产生告警
- 各检测器有默认静音期（同 key 冷却），重复触发同一攻击不会刷屏

### 主机探针速查表

| type | SEv ext ID | 名称 | aux 含义 |
|---|---|---|---|
| 1 | 0x8021 | HOST_UNKNOWN_EXEC | 0 |
| 2 | 0x8022 | HOST_PRIV_ESC | 0（flags: SETUID/SETGID） |
| 3 | 0x8023 | HOST_FORK_FLOOD | 窗口内进程数 |
| 4 | 0x8024 | HOST_REV_SHELL | 父进程 pid |
| 5 | 0x8025 | HOST_FILE_MOD | 1=摘要不符 / 2=文件消失 |
| 6 | 0x8026 | HOST_NEW_SETUID | 0 |
| 7 | 0x8027 | HOST_KMOD_LOAD | 0 |
| 8 | 0x8028 | HOST_ZOMBIE_STORM | 峰值僵尸数 |
| 9 | 0x8029 | HOST_RES_EXHAUST | 1=CPU / 2=内存 |
| 10 | 0x802A | HOST_ROOT_SHELL | 1=TTY / 2=ssh/adb |

主机上下文为 32 字节布局 v1：`detector_type(1) | flags(1) | pid(4) |
uid/mode(4) | count(4) | aux(4) | name(12) | reserved(2)`，大端。
