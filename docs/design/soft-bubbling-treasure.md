# Ethernet 探针双轨方案：eth_probe（嵌入式）+ Suricata 全量检测工具（台架/网关）

## Context

当前仓库只有 IDSM 管理器 + IDSRM 上报模块，sensor 侧靠 CLI/测试模拟，没有真实检测能力。用户最终确认的需求是**双轨**：

- **轨 A（嵌入式板）**：自研轻量探针 `eth_probe`——纯 C++17（仅 pcre2 一个可选外部依赖），跟随现有 CMake，交叉编译无负担。
- **轨 B（HIL 台架/网关级平台）**：**全量功能检测工具 = 官方构建的 Suricata 8.0.6**（IPS/NFQUEUE、300+ 关键字、HTTP/DNS、TLS 元数据全部现成且经过验证）+ 自研 `eve_bridge`（读 EVE JSON 告警 → `IdsM_ReportSecurityEvent()`）。

两条轨的告警统一进入 IDSM/IDSRM 管线，SOC 侧收到同一套 IDS Message 格式。不移植 Suricata 进 CMake（重写实测为多人力年级且无意义），不重复造它已有的轮子。

**TLS 内容解密**：被动监听下密码学不可能（ECDHE 前向保密），两轨都不做；轨 B 的 HIL 场景如需解密验证，用外部工具（mitmproxy + SSLKEYLOGFILE）离线分析，不进探针。

---

# 轨 A：eth_probe（嵌入式轻量探针）

## 范围（用户确认）

1. 包级异常：端口扫描 / 洪泛 / TCP flag 异常
2. 规则文件引擎：Suricata/Snort 语法**子集** + pcre（pcre2）——后续按用户点名扩充关键字，不追"完整集"
3. TCP 流重组（跨包 content/pcre 匹配）
4. IP 分片重组（UDP 大报文如 SOME/IP 跨分片还原）
5. 车载协议：DoIP (ISO 13400) + SOME/IP（含 SD 状态机）
6. **HTTP/1.1 + DNS 应用层解析**（车载网关有 OTA/诊断上传场景）+ 对应规则关键字族 `http_method`/`http_uri`/`http_header`/`dns_query`
7. TLS 握手元数据（SNI/版本/JA3），不解密
8. 跨境 IP 分析（CIDR 前缀库，出向非境内 IP 告警——数据出境合规）
9. ~~IPS inline 阻断~~ → 由轨 B 的 Suricata NFQUEUE 承担，eth_probe 保持旁路

## 模块结构（全部新增）

```
apps/eth_probe/
  main.cpp         # 入口：参数解析、规则/GeoIP 库加载、IDSM/IDSRM 初始化、抓包线程、信号退出
  packet.h/.cpp    # L2-L4 解析：Ethernet/VLAN/IPv4/IPv6(含分片头)/TCP/UDP/ICMP → ParsedPacket
  ip_defrag.h/.cpp # IPv4/IPv6 分片重组：按 (src,dst,id,proto) 缓存分片，超时/内存上限
  stream_tcp.h/.cpp# TCP 流重组：流表 + 乱序缓存 + 按序字节流交付
  rules.h/.cpp     # Suricata 语法子集解析 + 匹配引擎（单包 / 重组流 / HTTP / DNS 缓冲）
  proto_doip.h/.cpp   # DoIP 头部解析校验 + 诊断接入检测
  proto_someip.h/.cpp # SOME/IP 解析 + SOME/IP-SD 状态机跟踪
  proto_tls.h/.cpp    # TLS record/ClientHello 解析：SNI、版本、密码套件、JA3 指纹
  proto_http.h/.cpp   # HTTP/1.1 请求行/状态行/头部解析（基于重组流）
  proto_dns.h/.cpp    # DNS 查询/应答解析（UDP/TCP 53，含 TCP 2 字节长度前缀）
  geoip.h/.cpp        # CIDR 文本库加载 + 最长前缀匹配（前缀树），跨境判定
  detectors.h/.cpp    # 端口扫描 / 洪泛 / flag 异常（包级）
  capture.h/.cpp      # AF_PACKET 抓包线程；手写 pcap 回放读取器
  rules/example.rules # 示例规则（Suricata 语法子集）
  rules/chnroutes.txt # 境内 CIDR 库（示例裁剪版，部署时换全量）
apps/eve_bridge/
  main.cpp         # 轨 B：unix socket 读 Suricata EVE JSON → 字段提取 → IdsM_ReportSecurityEvent()
tests/test_eth_probe.cpp  # gtest 全覆盖（仿 test_idsm.cpp 模式）
tests/test_eve_bridge.cpp # EVE 解析与 SEv 映射单测
```

## 各模块设计

### 规则引擎（rules.cpp）—— Suricata 语法子集

规则格式（与 Suricata/Snort 兼容的子集）：
```
alert tcp any any -> any 13400 (msg:"UDS SecurityAccess"; sid:1000001; rev:1; content:"|27 01|";)
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"TLS to foreign"; sid:1000002; pcre:"/^\x16\x03[\x00-\x03]/";)
```
- **头部**：action 仅支持 `alert`（IDS 非 IPS，drop/pass 报解析警告并跳过）；proto: tcp/udp/icmp/ip；地址：IPv4/IPv6 字面量、CIDR、`any`、`!` 取反、`$VAR` 变量（yaml 风格 vars 段或命令行 `--var HOME_NET=10.0.0.0/8`）；端口：any/单值/`a:b` 范围/取反。方向仅 `->`。
- **option 支持集**：`msg`、`sid`、`rev`、`content`（可多个，按序匹配；支持 `"|hex|"` 与字符串混合）、`nocase`、`offset`/`depth`/`distance`/`within`、`pcre`（pcre2 实现）、`http_method`/`http_uri`/`http_header`（sticky buffer，作用于 HTTP 解析缓冲）、`dns_query`（作用于 DNS 查询名缓冲）、`classtype`/`metadata`（存字段不影响匹配）。其余关键字后续按需扩充。
- **未知 option**：打印警告并跳过该条规则（不杀进程）；加载结束报告 N 条规则、M 条跳过。
- **匹配路径**：TCP → ip_defrag（如需）→ stream_tcp 重组 → 对按序字节流匹配（跨交付边界保留 max_pattern_len-1 尾部）；UDP/ICMP → 单包匹配。无 payload option 的纯头规则包级直接匹配。
- **算法**：规则按 (proto, dst_port) 分桶减少候选集；桶内逐规则匹配，content 用 memmem，pcre 用 pcre2_match。规则规模按几十~几百条设计，不上 AC 自动机。
- **pcre2 依赖**：CMake `find_package(PkgConfig) → pkg_check_modules(PCRE2 libpcre2-8)`，找不到则 `ETH_PROBE_WITH_PCRE2=OFF` 降级：含 pcre 的规则加载时警告跳过。嵌入式交叉编译时 pcre2 可静态链。

### TCP 流重组（stream_tcp.cpp）

- 流表：5 元组双向归一 hash map，容量上限（默认 1024，LRU 淘汰）。
- 每方向：期望 seq + 连续缓冲 + 乱序段缓存（每方向 ≤64KB）；重传/重叠 first-seen wins；缺口超时（默认 5s）跳过；FIN/RST 关闭。
- **资源硬上限**：全局重组内存封顶（默认 4MB），超限淘汰并上报 detector_type=7 资源告警（防对探针自身的洪泛攻击）。

### IP 分片重组（ip_defrag.cpp）

- key=(src,dst,identification,proto) 分片缓冲 + hole 链表，超时 10s，全局内存上限（默认 2MB）。
- IPv6 走 Fragment Header(44) 链。重组完成的报文重新进入 L4 解析管线；UDP/SOME-IP 大报文经此完整还原。

### 车载协议解析

**DoIP（proto_doip.cpp，TCP/UDP 13400，detector_type=5）**
- 8 字节头解析：version/inverse 校验、payload_type、length 一致性。
- 告警：畸形头（version 反码不符/长度越界）、RoutingActivation(0x0005) 请求（非法诊断接入）、保留/未知 payload_type。aux=payload_type 或错误码。

**SOME/IP + SD（proto_someip.cpp，默认 30490 可配，detector_type=6）**
- 16 字节头校验：length(≥8 且一致)、proto_ver=0x01、msg_type/return_code 合法值。
- **SD 状态机**：跟踪每 (service_id,instance_id) 的 Offer/Find/Subscribe 状态与 TTL 到期；告警：非白名单 service 的 Offer（`--someip-services` 白名单）、SD 消息速率洪泛、session-id 回绕（节点重启检测）、TTL 异常。
- aux=service_id 或错误码。

**TLS（proto_tls.cpp，基于重组流，detector_type=9）**
- record 层 + ClientHello/ServerHello 解析：SNI、TLS 版本、密码套件列表、扩展列表 → **JA3 指纹**（md5，自实现 ~100 行免依赖）。
- 告警：车内网段出现 TLS（车载以太网通常明文 SOME/IP/DoIP，TLS 出现即异常——可配白名单 SNI）、TLS 版本 <1.2、SNI 命中跨境 IP 分析标记的连接。aux=版本号/错误码。

### HTTP / DNS 解析

**HTTP/1.1（proto_http.cpp，基于重组流，detector_type=10）**
- 解析请求行（method/uri/version）、状态行、头部块（`\r\n\r\n` 终止，每流头部缓冲上限 8KB）。
- 产出 sticky buffer 供规则引擎 `http_method`/`http_uri`/`http_header` 匹配。
- 异常告警：非 HTTP 流量命中 80/8080 端口（协议异常）、畸形请求行、超长 URI（>2KB，缓冲区扫描特征）。aux=错误码。

**DNS（proto_dns.cpp，UDP/TCP 53，TCP 走重组流，detector_type=11）**
- 解析 header + question 段：查询名（含标签指针压缩）、qtype/qclass；应答仅计数不展开。
- 产出 `dns_query` sticky buffer。
- 异常告警：查询名超长/非法字符（DNS tunnel 特征）、NULL/ANY 等罕见 qtype、NXDOMAIN 率高（隧道/DGA 迹象，滑窗统计）。aux=qtype/错误码。

### 跨境 IP 分析（geoip.cpp，detector_type=8）

- 加载 CIDR 文本库（chnroutes 格式，每行 `x.x.x.0/24`；示例文件裁剪版，部署换全量 ~8k 条）；前缀树最长前缀匹配，查询 O(32)。
- 判定逻辑：车内网段（`--home-net`，默认 RFC1918+链路本地）之外的出向连接，目的 IP **不在境内库** → 告警（潜在数据出境）。境内库未加载时该检测器关闭。
- IPv6 同格式支持。与 TLS 检测联动：TLS 连接目的 IP 跨境时告警升级（severity 由 IDSM SEv 配置统一控制，初版不分级）。

### 包级异常检测器（detectors.cpp）

| detector_type | 检测器 |
|---|---|
| 1 | PortScanDetector：每源 IP 滑窗唯一目的端口 > N(默认20)/T(默认10s) |
| 2 | RateFloodDetector：每源 IP pps > 阈值(默认1000，窗口1s)，count 预聚合 |
| 3 | FlagAnomalyDetector：NULL / Xmas(FIN+PSH+URG) / SYN+FIN |
| 4 | 规则引擎命中（aux=rule sid） |
| 5 | DoIP（aux=payload_type/错误码） |
| 6 | SOME/IP + SD（aux=service_id/错误码） |
| 7 | 重组资源告警（aux=触发原因） |
| 8 | 跨境 IP（aux=0，dst_ip 即目标） |
| 9 | TLS 异常（aux=版本/错误码） |
| 10 | HTTP 异常（aux=错误码） |
| 11 | DNS 异常（aux=qtype/错误码） |
| 12 | ARP 欺骗：跟踪 IP→MAC 绑定表，绑定突变/无偿 ARP 洪泛告警（GB 44495 网络欺骗检测项） |

## 法规符合性映射（GB 44495-2024 / GB 44496-2024）

| 法规要求 | 覆盖模块 |
|---|---|
| GB 44495 端口扫描检测 | detector_type 1 |
| GB 44495 拒绝服务攻击检测 | detector_type 2（慢速应用层 DoS 除外） |
| GB 44495 恶意/畸形数据识别 | detector_type 3/5/6 |
| GB 44495 已知攻击特征 | rules 引擎（type 4）；轨 B 用 ET Open 全集 |
| GB 44495 非法访问/未授权诊断接入 | DoIP RoutingActivation + UDS 服务规则（type 4/5） |
| GB 44495 网络欺骗（ARP） | detector_type 12 |
| GB 44495 数据出境监测 | detector_type 8 跨境 IP 分析 |
| GB 44495 安全事件记录与上报 | IDSM/IDSRM → SOC（本项目核心） |
| GB 44496 非授权软件升级防护（检测面） | DoIP 刷写会话检测（UDS 0x27/0x2E/0x34-0x37 示例规则入 example.rules）、升级服务器异常连接规则 |
| 不覆盖项 | CAN 总线侧检测（需另设 CAN sensor，走同一 IDSM API）；慢速 DoS；加密流量内容（不可行） |

> 合规声明以标准原文逐条核对为准（实施时附录列出条款号映射表，供认证测试用）。

## IDSM 集成（关键约束，来自探索结论）

- **SEv 注册**：main.cpp 仿 [apps/idsm_cli/main.cpp:59-108](apps/idsm_cli/main.cpp#L59-L108)，注册单个 SEv：**ext ID 0x8003，sensor instance 0，DETAILED，sink_to_idsr=true**；配 aggregation 窗口（如 1000ms，须为 main_function_period_ms 整数倍）防告警风暴。
- **统一 context 布局 v1（32B 大端，<127B 短格式编码）**，所有 detector_type 共用（满足"不同布局必须不同 external ID"约束）：
  ```c
  struct EthProbeContext {  // contextDataVersion = 1
      uint8_t  detector_type;  // 1-12 见上表（轨 B Suricata 告警用 100）
      uint8_t  proto;          // 6=TCP 17=UDP 1=ICMP
      uint16_t src_port, dst_port;
      uint8_t  src_ip[16];     // IPv4 放前 4 字节
      uint8_t  dst_ip[16];
      uint32_t count;          // 预聚合次数
      uint32_t aux;            // 随 detector_type 变化（rule sid / payload_type / service_id ...）
  };
  ```
- 上报：`IdsM_ReportSecurityEvent(0, ctx, sizeof(ctx), 1, count, nullptr)`，非阻塞深拷贝（[include/IdsM.h:23-28](include/IdsM.h#L23-L28)）。
- 关闭顺序：`IdsRm_DeInit()` → `IdsM_DeInit()`。
- 命令行：`eth_probe -i eth0 [--pcap f.pcap] [--soc URL] [--rules f.rules] [--cidr f.txt] [--home-net CIDR,...] [--var K=V]... [--someip-port N] [--someip-services ids] [--scan-ports N] [--flood-pps N] [--max-flows N] [--max-reassembly-mem MB]`

## CMake 改动（[CMakeLists.txt](CMakeLists.txt)，沿用顶层平铺模式）

- `add_executable(eth_probe ...)`，`target_link_libraries(eth_probe PRIVATE idsm_core idsrm_core)`，条件链接 pcre2；`if(NOT UNIX OR APPLE)` FATAL_ERROR 守卫（AF_PACKET Linux-only）。
- `test_eth_probe` 入 tests 段（`idsm_core GTest::gtest_main` + `gtest_discover_tests`）；测试不依赖 pcre2（条件编译跳过 pcre 用例）。
- 保持 `-Wall -Wextra -Wpedantic` 零告警。

## 测试（tests/test_eth_probe.cpp）

- packet：Ethernet/VLAN/IPv4/IPv6/TCP/UDP/ICMP 解析、截断/畸形不崩。
- ip_defrag：乱序分片、hole 填补、重叠 first-wins、超时、内存上限；IPv6 fragment header 链。
- stream_tcp：按序/乱序/重传/重叠/缺口超时跳过/FIN-RST/内存淘汰。
- rules：语法子集解析（含坏规则跳过）、content+offset/depth/nocase/distance/within、多 content 按序、pcre（有条件时）、**跨包特征经重组命中**（关键用例）、变量替换、端口范围/取反。
- proto_*：DoIP version 反码错误/长度越界；SOME/IP 各字段非法、SD 状态机（Offer 白名单、session 回绕、TTL）；TLS ClientHello SNI/JA3 提取、版本判定。
- geoip：CIDR 加载、最长前缀匹配边界、境内外判定。
- detectors：滑窗边界、flood 阈值、flag 异常三类、ARP 绑定突变/无偿 ARP 洪泛。
- 端到端：IdsM_Init + Dem sink 回调 + 喂包 → wait_until 确认 QSEv（复用 test_idsm.cpp 模式）。

## 实施顺序（按依赖与风险排序）

1. `packet` + 单测
2. `ip_defrag` + 单测
3. `stream_tcp` + 单测（技术风险最高，优先攻下）
4. `rules` 引擎（语法解析 → 单包匹配 → 流匹配；pcre2 最后接）+ 单测
5. `proto_doip` / `proto_someip`(含SD) / `proto_tls` / `proto_http` / `proto_dns` + 单测
6. `geoip` + 单测
7. `detectors` + 单测
8. `capture` + `main.cpp` 接线 + example.rules + 裁剪版 chnroutes.txt
9. **轨 B：Suricata 官方构建 + eve_bridge**（见下节）
10. 服务器 E2E 验证（两轨各验）
11. 更新 README.md / CLAUDE.md

---

# 轨 B：Suricata 全量检测工具 + eve_bridge

## 定位

HIL 台架 / 网关级平台上的**全量功能检测工具**：直接用官方 autotools 构建 third_party/suricata/suricata-8.0.6（不重写构建体系），获得完整的 300+ 规则关键字、HTTP/DNS/SMB 等全协议解析、NFQUEUE IPS、ET Open 规则集兼容。告警经 `eve_bridge` 接入 IDSM → SOC，与轨 A 格式统一。

## 构建（官方路径，服务器上）

```bash
# 依赖：libpcap-dev libyaml-dev libjansson-dev libpcre2-dev zlib1g-dev + Rust(MSRV 1.75，用 rustup，Ubuntu 20.04 apt 版太旧)
cd third_party/suricata/suricata-8.0.6
./configure --prefix=/opt/suricata --disable-nfqueue --disable-nflog \
            --disable-suricata-update --disable-python --disable-af-xdp
make -j$(nproc) && sudo make install
```
- rust/vendor 已随源码包提供（215 crate），cargo 离线构建，服务器 GitHub 慢不影响。
- IPS 场景另开 `--enable-nfqueue` 构建变体 + iptables 规则，部署评审单独做（fail-open/时延/误阻断风险）。

## suricata.yaml 关键配置

- `af-packet: - interface: <网口>`；`outputs: - eve-log: enabled, filetype: unix_stream, filename: /tmp/suricata-eve.sock, types: [alert]`（桥接只需要 alert；anomaly/dns/tls 日志可选开）。
- 规则：ET Open 或自写规则放 /opt/suricata/rules/。

## eve_bridge（apps/eve_bridge/main.cpp，~300 行，入项目 CMake）

- 监听 unix socket（`/tmp/suricata-eve.sock`，Suricata unix_stream 模式为主动连接方，bridge 做 listen 端，支持断线重连接受）。
- 按行读 EVE JSON，提取字段：`src_ip/src_port/dest_ip/dest_port/proto/alert.signature_id/alert.severity`。JSON 解析用 **jansson**（轨 B 机器上构建 Suricata 必装，CMake `find_library(jansson)`；不做手写 JSON 解析）。
- **SEv 映射**：独立 SEv——**ext ID 0x8006，sensor instance 1**（不同 context 布局必须不同 external ID，设计文档约束），contextDataVersion=1，32B 布局同构（detector_type=100 表示 Suricata 告警，aux=signature_id）。
- IDSM/IDSRM 初始化与关闭顺序同 eth_probe；soc_url 命令行可配。
- `test_eve_bridge`：EVE 样例 JSON 解析、字段缺失容错、SEv 映射、端到端（内存 socketpair 喂 JSON → Dem 回调断言）。

## 轨 A 验证（远程 Linux 服务器）

```bash
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DFETCHCONTENT_SOURCE_DIR_GOOGLETEST=$HOME/work/deps/googletest-1.14.0
cmake --build build && ctest --test-dir build --output-on-failure

python3 tests/mock_soc_server.py 8080 &
sudo ./build/eth_probe -i lo --rules apps/eth_probe/rules/example.rules --cidr apps/eth_probe/rules/chnroutes.txt &
nmap -sS -p 1-100 127.0.0.1                    # 触发端口扫描
# 另用 python/scapy 构造: DoIP routing activation、SOME/IP-SD offer、TLS ClientHello(SNI)、
#   HTTP 请求、DNS 查询、跨境目的 IP、分片 UDP、跨包 TCP 特征
./build/eth_probe --pcap sample.pcap --rules ... --cidr ...   # 无 root 回放验证
```

轨 A 验收标准：mock SOC 收到 IDS Message（protocol v2，ext 0x8003），context 布局与文档一致；跨包 TCP 特征命中；DoIP/SOME-IP 畸形与状态异常触发 type 5/6；跨境目的 IP 触发 type 8；TLS ClientHello 触发 type 9；HTTP/DNS 异常触发 type 10/11；全部单测通过、编译零告警。

## 轨 B 验证

```bash
sudo /opt/suricata/bin/suricata -c /opt/suricata/etc/suricata.yaml -i <网口> &
./build/eve_bridge --sock /tmp/suricata-eve.sock --soc http://localhost:8080/api/idsm-violations &
nmap -sS <目标>   # 触发 ET 规则 → mock SOC 收到 ext 0x8006 / sensor 1 的 QSEv
```

## 不做的事（两轨共同的剩余边界）

- 不把 Suricata 移植进 CMake；不重复实现它已有的能力（完整关键字集/IPS 交给轨 B）。
- 不做加密流量内容解密（被动监听密码学不可行；HIL 需要时用 mitmproxy+SSLKEYLOGFILE 离线分析）。
- 轨 A 不支持 Suricata 完整关键字集（子集 + 按需扩充；未知 option 警告跳过该规则）。
- 轨 A 不做 HTTP/2、 chunked body 重组；DNS 不展开应答记录（仅 question 级解析 + 统计特征）。
- 轨 A 单线程抓包（不上 PACKET_FANOUT 多核分流，性能不够时再加）。

## 规模预估

- 轨 A：新增 ~8-10k 行（含测试），二进制预计 2-4MB（+pcre2）。各模块独立可裁剪：裁剪任意 proto_*/geoip 只需从 CMake 源清单移除并在 main.cpp 去掉对应初始化调用。
- 轨 B：eve_bridge ~300 行 + 单测；Suricata 本体官方构建，零代码改动。
