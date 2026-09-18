# VSOC 设备接入详细设计 v1.0(量产落地版)

> 本文基于《VSOC 设备接入详细设计 v0.7》评审修订,目标是**可直接进入开发**
> 的设备接入规范。v0.7 中全部"待定/TODO"项已在本文定稿,协议不一致处已统一,
> 并补充:策略签名与防回滚、设备在线状态机、断网补传、ECU 更换流程、
> Topic ACL 矩阵、JSON Schema 附录。

## 修订记录

| 日期 | 版本 | 说明 |
|---|---|---|
| 2023/11/03 | V0.7 | 完善附录中消息格式(史贵振) |
| 2026/09/18 | V1.0 | 量产化修订:定稿待定项、统一协议、补充安全与可靠性设计 |

V1.0 相对 V0.7 的主要变更:

| # | 变更 | 对应 v0.7 问题 |
|---|---|---|
| 1 | 砍掉 RK/SK 自研密钥握手,传输安全统一为 TLS 1.3 双向认证 | 2.2.4 自定义握手"待定",自研加密风险高 |
| 2 | 策略/配置包增加 Ed25519 签名 + 单调 seq + 防回滚 | 4.1.6 下发无完整性保护,云端被攻破可静默关闭检测 |
| 3 | 设备在线状态机定稿(keepalive + LWT + 属性上报) | 接入状态表"在线(如何实现)"为 TODO |
| 4 | 增加断网缓存补传与 event_id 幂等协议 | 全文缺失,违反 GB 44495 事件记录要求 |
| 5 | 增加 ECU/零部件更换与证书吊销流程 | 全文缺失,量产必经路径 |
| 6 | 统一 rc 语义(0=成功)、timestamp 必选、修正全部非法 JSON 示例 | rc 200/0 打架、示例带尾逗号 |
| 7 | 增加 Topic ACL 矩阵、孪生/重放数据隔离命名空间 | 授权模型未定义,attacker 数据可与真实车辆混流 |
| 8 | 附录提供机器可校验 JSON Schema,示例由 schema 派生 | 字段类型前后不一致 |
| 9 | 凭据管理从正文移除,改密管下发;clientId 生命周期定稿 | 明文凭据表写死在文档 |

---

## 1 概述

### 1.1 范围

本文对 VSOC 平台设备接入进行详细设计,覆盖:

- 设备身份模型与认证授权(3~5 章)
- 车云消息协议:属性、检测日志、策略/配置、日志快照(6~11 章)
- 可靠性与安全要求:断网补传、签名防回滚、审计(9、10、14 章)
- 云端数据定义与 GB 标准对照(13、15 章)

### 1.2 术语

| 术语 | 定义 |
|---|---|
| VSOC | 汽车安全运营平台,本文中设备接入的"云服务器" |
| 设备端 / IDPS 节点 | 车辆侧入侵检测探针及管理组件,MQTT 客户端 |
| 设备树 | 车型(model)→ 车辆(VIN)→ 零部件/ECU 的三层资产结构 |
| 管理组件 | 车端汇聚组件:Linux 为 `idsm_managerd`,Android 为 IdsmManager APK,探针不直接连云端 |
| broker | MQTT 代理(EMQX),负责接入认证与 topic 转发 |
| nodeType | 探针类型:HIDPS(主机)/NIDPS(网络)/CIDS(CAN),对应 host/eth/can 三探针 |

### 1.3 设计原则

1. **不自研密码学**:加密、密钥协商、签名一律使用标准算法与库(TLS 1.3、Ed25519、SHA-256)。
2. **零信任下发**:云端→车端的一切可执行内容(规则/配置/使能开关)必须签名,seq 单调防回滚。
3. **最小权限**:每个客户端证书/账号只能访问其角色所需的 topic(见 3.5 ACL 矩阵)。
4. **至少一次 + 幂等**:告警与日志允许重传,云端按幂等键去重;车端断电不丢事件。
5. **标准优先**:消息格式可 JSON Schema 校验;时间戳统一 Unix 毫秒;日期 ISO 8601。

---

## 2 总体架构

### 2.1 部署形态

```
┌──────────────────────────────────────────────────────────┐
│ VSOC 云端: EMQX broker + 接入微服务 + 信任中心 PKI        │
│   注册服务 / 规则签名服务 / 告警存储 / 工单审核(可选)      │
└───────▲──────────────────────────────┬───────────────────┘
        │ MQTT over TLS 1.3 (双向证书)  │ 策略/配置下发(签名)
┌───────┴──────────────────────────────▼───────────────────┐
│ 车辆: 管理组件(每 OS 一个)                                │
│  Android: IdsmManager APK  Linux: idsm_managerd           │
│   UDS 汇聚 / 持久队列 / 注册状态机 / 验签切换              │
└───▲──────────▲──────────▲────────────────────────────────┘
    │ UDS sink │ UDS sink │ UDS sink
┌───┴───┐  ┌───┴───┐  ┌───┴───┐
│HIDPS  │  │NIDPS  │  │CIDS   │   host_probe / eth_probe / can_probe
│主机探针│  │网络探针│  │CAN探针│   (root, systemd/init 拉起, 零云依赖)
└───────┘  └───────┘  └───────┘
```

探针只负责检测并通过 UDS 上报(NDJSON),不持有云凭据、不实现 MQTT;
所有云端交互(注册、心跳、上报、验签、下发)集中在管理组件,审计面最小。

### 2.2 设备树与消息路由

- 车辆是资产与计费主体;一辆车的多个 ECU 探针(HIDPS/NIDPS/CIDS)可能分布在
  不同控制器上(如 HIDPS 在车机 0x02,NIDPS 在 GW 0x01)。
- MQTT 连接以**车辆**为单位(通常由 T-box 0x00 或 GW 0x01 上的管理组件建立),
  消息内部用 `ecuCode + nodeType` 定位探针(见第 8 章)。
- 单 ECU 直连云(如 T-box 自带 IDPS)是同一协议的退化形态,不做特殊设计。

---

## 3 身份与认证

### 3.1 device_id 与 clientId

**device_id**(设备编号,= 业务证书 CN):

```
device_id = {manufacturer}_{model_code}_{vin}
```

| 段 | 来源 | 说明 |
|---|---|---|
| manufacturer | 数据字典 | 厂商/租户标识,小写字母数字 |
| model_code | vsoc_vehicle_model | 车型编码 |
| vin | 车辆铭牌 | 17 位车架号,大写 |

**clientId**(MQTT 接入标识,三段式):

```
vehicle_{model_code}_{suffix}        # 量产车端
sim_{model_code}_{suffix}            # 数字孪生体
attacker_{model_code}_{suffix}       # 攻击重放数据源
app_{模块}_{suffix}                  # 云端服务(见 ACL 矩阵)
```

- `suffix` = 16 字节随机数 base64url(22 字符),**注册时生成并持久化**,
  设备生命周期内不变;更换业务证书不改变 clientId。
- clientId 与 device_id 的绑定关系由注册服务登记,broker 按 3.5 ACL 校验。

### 3.2 认证方案(收敛)

v0.7 列四种方案,量产收敛为两种,其余标记废弃:

| 方案 | 状态 | 适用 |
|---|---|---|
| 一机一证 | **量产主方案** | 每台车烧录唯一设备证书,安全等级最高 |
| 一型一证 + 动态注册 | **量产辅助** | 产线不便一一烧录的车型;注册拿到 clientId+token 后按 4.2 换发业务证书 |
| 一型一证免预注册(长期 token) | 废弃 | 长期 token 等价于静态密钥,泄露面大 |
| 子设备动态注册 | 保留(网关场景) | 主设备上线后子 ECU 申请凭据,由主设备代理托管 |

认证强度:MQTT CONNECT 必须 TLS 1.3 + 业务证书(双向);仅孪生/实验室环境
允许用户名密码降级,凭据由密管系统按环境下发,**禁止写入设计文档或代码仓库**。

### 3.3 证书生命周期

| 阶段 | 流程 | 说明 |
|---|---|---|
| 预置 | 产线向 PKI 申请"预置证书"注入安全存储(SE/TEE/HSM) | 预置证书**只能**调用证书申请接口,其他操作返回 403 |
| 换发 | 设备用预置证书走 4.2 申请业务证书,成功后**就地销毁预置证书私钥** | 业务证书 CN=device_id |
| 续期 | 业务证书剩余有效期 < 1/3 时自动重新申请,新旧证书重叠期 ≤ 7 天 | 云端按证书序列号做短期双认 |
| 吊销 | 见 4.4(ECU 更换/退役/疑似泄露) | CRL 下发到 broker,连接层与订阅层双重校验 |
| 无 RTC 设备 | 设备不校验证书有效期,仅校验链与吊销状态;有效期 enforcement 在云端 | 车端时钟不可信,见 6.3 |

### 3.4 凭据与密钥存储

- 设备私钥不出安全硬件;签名操作(SE/TEE 内)对应用只暴露接口。
- 车端管理组件持有的 token/缓存凭据存放 `/var/lib/idsm` 或 APK device-protected
  目录,文件权限 0600,SELinux/文件系统隔离(见第 16 章实现映射)。

### 3.5 Topic ACL 矩阵(broker 强制执行)

| 客户端角色(CN 前缀) | 可 publish | 可 subscribe |
|---|---|---|
| 业务证书 `device_id`(车端) | `oc/devices/{own}/sys/init/request/*`、`oc/devices/{own}/sys/cert/request/*`、`oc/devices/{own}/sys/property/report`、`oc/devices/{own}/sys/idps/host/log`、`oc/devices/{own}/sys/idps/eth/log`、`oc/devices/{own}/sys/idps/can/log`、`oc/devices/{own}/sys/log/report`、`oc/devices/{own}/sys/events/up` | `oc/devices/{own}/sys/init/response/*`、`oc/devices/{own}/sys/cert/response/*`、`oc/devices/{own}/sys/idps/rule/update`、`oc/devices/{own}/sys/idps/config/update`、`oc/devices/{own}/sys/events/down` |
| 预置证书 `DemoCert` | 仅 `oc/devices/+/sys/cert/request` | 仅 `oc/devices/+/sys/cert/response` |
| 规则签名服务(平台内) | 单车/广播 `sys/idps/rule/update`、`sys/idps/config/update` | — |
| `sim_*` / `attacker_*` | `sim/devices/+/idps/candata` | `sim/devices/+/sys/idps/rule/update` |
| `app_ssdb_*`(双安库网关) | `oc/devices/+/idps/rulelog` | `oc/devices/+/idps/can/log` |
| `app_vsoc_*` / `app_ai_*` / `app_webpage_*` | `oc/devices/+/sys/events/down` | `oc/devices/+/sys/idps/host/log`、`oc/devices/+/sys/idps/eth/log`、`oc/devices/+/sys/idps/can/log`、`oc/devices/+/sys/property/report`、`oc/devices/+/sys/events/up`、`oc/devices/+/sys/log/report` |

要点:

- 车端证书**只能**发布/订阅 own device_id 下的 topic,`+` 通配仅平台服务可用。
- 孪生/重放数据走独立根 `sim/devices/`,物理上无法混入真实车辆 topic。
- broker 开启"订阅时校验 ACL"(`check_subscribe_acl`),防止订阅嗅探。

---

## 4 设备注册(定稿)

### 4.1 接入状态机

资产从 ERP/资产系统录入后进入状态机(云端持久化,见 13 章):

```
未注册(0) --注册成功--> 离线(1) --首次上线--> 在线(2)
   ↑                                        |
   |---- 连续 3 个 keepalive 未收到 ---------+--> 离线(1)
   |---- 吊销/更换流程 ---------------------> 未注册(0)
```

状态迁移由 broker 在线事件 + LWT 遗嘱驱动(见 5.3),资产管理页只读展示。

### 4.2 注册流程(一型一证动态注册)

```
设备(预置证书)              注册服务               信任中心 PKI
   |-- POST .../sys/init/request ------------------->|
   |   (rid=UUID, content{vin, modelId, ...})        |
   |                        | 逻辑校验+资产比对       |
   |                        | (自动审核或工单审核)    |
   |<-- .../sys/init/response: clientId, token ------|
   |                                                   |
   |-- POST .../sys/cert/request (csr_pem) ----------->|-- 签发业务证书
   |<-- .../sys/cert/response: cert_pem, chain -------|
   |  销毁预置证书私钥, 用业务证书重连 MQTT              |
```

**一机一证**车型跳过 init,凭产线烧录的设备证书直接走第三步换发业务证书;
`sys/cert/request` 通道两种方案共用。

审核策略(2.2.2 定稿):

- **自动审核**:资产库已有该 VIN 且字段匹配(model_code、manufacturer、ecuList
  拓扑完整)直接放行;新 VIN 走工单。
- **工单审核**:对接 OA;工单接口规范由集成方提供,本文只约束出参
  `{approved: bool, reason: string, ticket_id: string}`。

### 4.3 消息定义

**注册请求** `oc/devices/{device_id}/sys/init/request/rid={request_id}`

| 字段 | 必选 | 类型 | 说明 |
|---|---|---|---|
| request_id | 必 | string(UUID) | 请求标识,响应 topic 原样带回;TTL 5 分钟,重复 request_id 按幂等返回首个结果 |
| timestamp | 必 | int | Unix 毫秒(UTC) |
| manufacturer | 必 | string | 与 device_id 第一段一致,租户路由 |
| type | 必 | int | 固定 1(注册) |
| content | 必 | object | 见下 |

content:`{vin(必), modelId(必), engineNumber(可), color(可), productionDate(可,yyyy-MM-dd), ecuList(可,array<ecuCode> 预声明本车 ECU 拓扑), remark(可)}`

**注册响应** `oc/devices/{device_id}/sys/init/response/rid={request_id}`

```json
{
  "rc": 0,
  "rn": "register_response",
  "request_id": "b7d2f1a0-3c4e-4a2b-9d1f-2e8a6b0c4d5f",
  "timestamp": 1726640000000,
  "paras": {
    "msg": "注册成功",
    "client_id": "vehicle_t99_AbCdEf1234567890",
    "token": "eyJhbGciOiJFZERTQSJ9.example-short-lived-jwt",
    "token_expire": 1726647200
  }
}
```

**证书申请请求** `oc/devices/{device_id}/sys/cert/request/rid={request_id}`

content:`{csr_pem(必,PKCS#10), cert_type(必,"business"), renew(可,bool 续期标志)}`

**证书申请响应** `oc/devices/{device_id}/sys/cert/response/rid={request_id}`

paras:`{msg, cert_pem, chain_pem, serial_number, expire_at}`;
rc≠0 时 paras 只含 `{msg}`,原因码对终端模糊化(见 6.5)。

### 4.4 重复注册与 ECU 更换(新增,量产必走)

| 场景 | 处理 |
|---|---|
| 同 VIN 重复 init | 凭据未泄露:校验资产一致后返回已有 clientId 并**轮换 token**;`force_rotate=true` 时另发新 clientId 并吊销旧绑定 |
| 整车换 T-box/GW(同 VIN 新硬件) | init 带 `replacement: {old_serial}`;云端吊销旧证书序列号 → 状态回 0 → 重新注册;旧证书进 CRL |
| ECU 更换(探针所在控制器) | 不影响设备证书;零部件解绑/重绑走资产管理流程,`ecuList` 拓扑变更经属性上报同步(8 章) |
| 车辆退役/报废 | 吊销证书,资产状态置退役,topic 绑定解绑 |
| 疑似泄露 | 云端一键吊销 + CRL 下发;车端连接失败进入重注册流程 |

---

## 5 设备接入与在线状态(定稿)

### 5.1 连接建立

1. 设备以业务证书 + clientId 建立 MQTT over TLS 1.3 连接;
2. username = clientId;password 仅降级环境使用(3.2);
3. broker 校验:证书链/吊销状态、CN-device_id 一致性、CN-topic 前缀一致性
   (CN 与 topic 中 device_id 不符直接断开,错误码见 6.5);
4. CONNECT 成功后 broker 通知注册服务置"在线"。

v0.7 的 `sys/conn/request`(RK/SK 会话密钥协商)**废弃**:应用层再加密一次
对 TLS 1.3 双向认证无增益,且自研握手无法审计。如监管明确要求应用层保护,
按 10.1 的签名机制覆盖关键下行消息即可,不引入对称密钥协商。

### 5.2 心跳参数

| 参数 | 值 | 说明 |
|---|---|---|
| keepalive | 60 s | CONNECT 声明;蜂窝弱网可配,不得 > 300 s |
| 离线判定 | 3 × keepalive 未收到任何报文 | broker 触发,注册服务落库 |
| 属性上报周期 | 300 s ± 10% 随机抖动 | 防止车队同时上报雪崩 |
| 属性变更即时上报 | 节点上下线、ruleVersion 变化 | 事件触发,不计入周期 |

### 5.3 LWT 遗嘱(在线状态的实现,定稿)

CONNECT 时携带 Will:

- topic:`oc/devices/{device_id}/sys/property/report`(与属性上报同通道)
- payload:`{"nodeStatus": 0, "offline_reason": "lwt", "timestamp": <broker 打点>}`
- qos 1, retain false;broker 代发,云端据此置离线并记录 `last_seen`

结合 5.2 超时判定与周期属性上报,"在线/离线"语义闭环,
v0.7 附录"在线(如何实现)"就此定稿。

---

## 6 消息通用规范

### 6.1 信封

所有应用层消息统一外层字段:

| 字段 | 必选 | 类型 | 说明 |
|---|---|---|---|
| msg_type | 必 | string | `register` / `cert_apply` / `property` / `alert_host` / `alert_eth` / `alert_can` / `rule_update` / `config_update` / `log_snapshot` / `event` |
| protocol_version | 必 | string | 固定 `1.0`;不兼容变更升 major |
| timestamp | 必 | int | Unix 毫秒(设备本地时钟,见 6.3) |
| manufacturer | 必 | string | 租户路由 |
| content | 必 | object/array/string | 按 msg_type 约束 |

**响应信封**(request/response 型消息):

| 字段 | 必选 | 类型 | 说明 |
|---|---|---|---|
| rc | 必 | int | **0=成功,非 0=失败**(全文档统一,v0.7 的 200 语义废除) |
| rn | 必 | string | `{msg_type}_response` |
| request_id | 必 | string | 请求标识 |
| timestamp | 必 | int | 服务端打点 |
| paras | 条件 | object | 成功/失败参数或对外模糊原因 |

### 6.2 QoS 与 retain 策略

| 消息 | QoS | retain | 说明 |
|---|---|---|---|
| 注册/证书申请请求响应 | 1 | false | request_id 关联 |
| 属性上报 / LWT | 1 | false | |
| 检测日志(host/eth/can) | 1 | false | 批量,见 9 章 |
| 策略/配置下发(单车) | 1 | **true** | 新上线设备立即拿到当前版本,见 10.5 |
| 策略/配置下发(广播) | 1 | true | vmodel/ecu 过滤在消费端做 |
| 平台事件下发 | 1 | false | |
| 日志快照分片 | 1 | false | transfer_id 关联,见 11 章 |
| 孪生数据重放 | 0 | false | 允许丢 |

单消息 ≤ 256 KB;超过走快照分包通道(11 章)。broker 单连接 inflight ≥ 64。

### 6.3 时钟规则

- 设备时钟可能断电丢失:事件排序以**云端 broker 接收时间为准**,
  设备 timestamp 作展示与对账参考;偏差 > 24 h 时云端生成
  `clock_drift` 审计事件并触发车端校时(GNSS/NTP)。
- 快照/日志文件内时间字段(log_time)用 ISO 8601 带时区。

### 6.4 协议演进

- 字段只增不删;弃用字段保留至少一个大版本并标注 deprecated。
- 附录 A 的 JSON Schema 为唯一权威定义,正文示例由 schema 生成;
  CI 中对示例做 schema 校验,杜绝"示例是非法 JSON"。

### 6.5 错误码(模糊化规则定稿)

终端只收通用码 + request_id;详细原因落云端审计日志,两者经 request_id 关联。

| 对外码 | 含义 | 云端详细原因(内部) |
|---|---|---|
| 0 | 成功 | — |
| 1001 | 参数错误 | schema 校验失败详情 |
| 1002 | 未注册/凭据无效 | 资产缺失、token 过期、证书吊销 |
| 1003 | 无权限 | CN 与 topic 不匹配、预置证书越权 |
| 1004 | 服务端繁忙 | 限流、PKI 超时 |
| 1005 | 版本冲突 | seq 回滚拒绝、protocol_version 不支持 |
| 1006 | 签名校验失败 | 规则/配置包验签详情 |

---

## 7 Topic 体系(全量)

| 分类 | topic | 发布者 | 订阅者 | 用途 |
|---|---|---|---|---|
| 注册 | `oc/devices/{device_id}/sys/init/request/rid={request_id}` | 设备 | 平台 | 设备注册 |
| 注册 | `oc/devices/{device_id}/sys/init/response/rid={request_id}` | 平台 | 设备 | 注册响应 |
| 证书 | `oc/devices/{device_id}/sys/cert/request/rid={request_id}` | 设备 | 平台 | 业务证书申请/续期 |
| 证书 | `oc/devices/{device_id}/sys/cert/response/rid={request_id}` | 平台 | 设备 | 证书响应 |
| 属性 | `oc/devices/{device_id}/sys/property/report` | 设备 | 平台 | 属性/心跳/LWT(5.3) |
| 主机检测 | `oc/devices/{device_id}/sys/idps/host/log` | 设备 | 平台 | HIDPS 告警日志(9 章) |
| 以太网检测 | `oc/devices/{device_id}/sys/idps/eth/log` | 设备 | 平台 | NIDPS 告警日志 |
| CAN 检测 | `oc/devices/{device_id}/sys/idps/can/log` | 设备 | 平台 | CIDS 告警日志 |
| 策略 | `oc/devices/{device_id}/sys/idps/rule/update` | 平台 | 设备 | 单车策略下发(签名,10 章) |
| 策略 | `oc/devices/sys/idps/rule/update` | 平台 | 设备 | 广播下发 |
| 配置 | `oc/devices/{device_id}/sys/idps/config/update` | 平台 | 设备 | 单车配置下发(签名) |
| 配置 | `oc/devices/sys/idps/config/update` | 平台 | 设备 | 广播配置下发 |
| 事件 | `oc/devices/{device_id}/sys/events/up` | 设备 | 平台 | OTA 查询等上行事件 |
| 事件 | `oc/devices/{device_id}/sys/events/down` | 平台 | 设备 | OTA 通知等下行事件 |
| 快照 | `oc/devices/{device_id}/sys/log/report` | 设备 | 平台 | 日志快照上传(11 章) |
| 双安库 | `oc/devices/{device_id}/idps/rulelog` | 双安库网关 | 消费服务 | 规则检测结果通道 |
| 孪生 CAN | `sim/devices/{device_id}/idps/candata` | sim/attacker | 检测引擎 | 数采/攻击注入报文 |

订阅通配规则:车端订阅 own 前缀用具体 topic;平台服务可用 `+`;
`{request_id}` 段订阅必须用 `rid=+` 单段通配,**禁止 `#` 全局通配**。
(v0.7 的 `request_id=` 段名由兼容层保留一年,新实现一律 `rid=`)

---

## 8 设备属性与心跳上报

topic:`oc/devices/{device_id}/sys/property/report`,QoS 1。

### 8.1 消息格式

content 为探针节点数组,一次上报覆盖本车全部 IDPS 节点:

| 字段 | 必选 | 类型 | 说明 |
|---|---|---|---|
| ecuCode | 必 | string | 零部件编码(见 8.2) |
| ecuName | 可 | string | 零部件名称 |
| ecuOs | 必 | string | `Linux` / `Android` / `QNX` / `AUTOSAR` |
| nodeType | 必 | string | `HIDPS` / `NIDPS` / `CIDS` |
| nodeVersion | 必 | string | 探针软件版本,如 `1.3.0+git.a1b2c3d` |
| nodeStatus | 必 | int | 0 离线 / 1 在线 / -1 异常(异常须附 remark) |
| ruleVersion | 必 | string | 当前生效策略版本(管理组件 current 指向,见 10.4) |
| lastAlertSeq | 可 | int | 已产生的最大告警序号(云端对账,见 9.3) |
| remark | 可 | string | 备注/异常原因 |

唯一性:`{device_id, ecuCode, nodeType}` 三元组定位一个探针节点。

### 8.2 零部件编码表(ecuCode)

| 编码 | 零部件 | 计算单元 |
|---|---|---|
| 0x00 | T-box | MPU |
| 0x01 | GW(网关) | MPU |
| 0x02 | 车机(座舱主机) | MPU |
| 0x10 | OIB1 | MPU |
| 0x11 | OIB2 | MPU |
| 0x20 | 底盘域控 | MCU |
| 0x21 | 灯光域控 | MCU |
| 0x22 | 车身域控 | MCU |
| 0x23 | 悬架域控 | MCU |
| 0x99 | 云端 | APP |

新增编码向数据字典申请,不允许车端自定。

### 8.3 上报时机

| 时机 | 内容 |
|---|---|
| 周期 | 全量节点数组,300 s ± 10% 抖动 |
| 节点上线/下线 | 单节点增量,立即上报 |
| 策略版本切换成功 | 单节点增量,ruleVersion 更新(10.4 步骤 6) |
| MQTT CONNECT | 连接建立后 5 s 内上报一次全量(配合 LWT 构成在线判定的完整语义) |

---

## 9 安全事件与检测日志上报

topic(按探针类型分管道):

| nodeType | topic |
|---|---|
| HIDPS | `oc/devices/{device_id}/sys/idps/host/log` |
| NIDPS | `oc/devices/{device_id}/sys/idps/eth/log` |
| CIDS | `oc/devices/{device_id}/sys/idps/can/log` |

### 9.1 消息格式

批量上报,content 为事件数组,单批 ≤ 64 条:

| 字段 | 必选 | 类型 | 说明 |
|---|---|---|---|
| eventId | 必 | string | 全局唯一:`{device_id}-{nodeType}-{32位hex}` |
| eventType | 必 | string | 检测类型枚举(由各探针定义,如 `DT_UNKNOWN_EXEC`) |
| severity | 必 | string | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| timestamp | 必 | int | 探针检测时刻,Unix 毫秒(参考,排序以云端接收为准) |
| ecuCode | 必 | string | 探针所在 ECU(8.2) |
| nodeType | 必 | string | 探针类型 |
| ruleVersion | 必 | string | 检测所用策略版本 |
| replay | 必 | bool | true=断网补传,false=实时 |
| raw | 必 | object | 原始检测上下文(探针自定义 schema,见附录 A.6) |

raw 的权威结构由各探针 schema 定义;HIDPS/NIDPS/CIDS 公共字段
(进程名/pid、五元组、CAN ID 等)录数据字典统一管理。

### 9.2 严重级别与响应时限

| severity | 云端处理 | 车端本地动作 |
|---|---|---|
| CRITICAL | 实时推送 VSOC 值班 + 短信 | 可选联动(记录审计日志,联动策略由配置下发) |
| HIGH | 实时入告警库 | 记录 |
| MEDIUM/LOW | 批量入库 | 记录 |

### 9.3 断网缓存补传(新增,GB 44495 要求)

```
探针事件 → 管理组件持久队列(落盘, 断电不丢)
    │ 在线: 实时上报, replay=false
    │ 断网: 积压; 恢复后按序补传, replay=true
    ▼
云端按 eventId 幂等去重(唯一键 eventId, 保留 72 h 去重窗口)
```

- 管理组件持久队列容量上限可配(默认 10 万条/车);写满后**丢弃最旧并计数**,
  溢出计数经属性上报 `lastAlertSeq` 缺口由云端审计发现。
- 补传速率 ≤ 实时速率的 2 倍,避免恢复瞬间打爆 broker;
  补传优先级低于实时事件。
- 云端收到 `replay=true` 的事件不做实时告警推送,只入库对账。

---

## 10 策略与配置下发(可信通道,核心增强)

### 10.1 签名与防回滚

v0.7 的下发消息无完整性保护:云端账号被攻破即可下发"关闭全部检测"。
V1.0 定稿:所有可改变车端行为的消息(策略、配置、使能开关)必须
由**规则签名服务**签名后下发。

**签名算法**:Ed25519(SPKI 公钥,sha256 指纹标识版本)。

**canonical 字节序列**(参与签名的内容,UTF-8):

```
seq={seq}\n
version={version}\n
rollback={0|1}\n
target_ecu={ecu 或 all}\n
target_node={nodeType 或 all}\n
target_vmodel={model_code 或 all}\n
issued_at={unix秒}\n
expires_at={unix秒}\n
upgrade_type={1|2}\n
{payload 行按名称排序}\n
```

payload 行:

- `upgrade_type=1`(规则内容内联):每行 `rule:{rule_id}:{base64(规则文本)}`
- `upgrade_type=2`(规则包 URL):`uri:{download_uri}`
- 配置消息:`config:{config_name}:{base64(sha256(规范化JSON))}`

**防回滚**:`seq` 为平台级单调递增序号(与 version 解耦)。
车端记录已应用的最大 seq,收到 `seq <= max_seq` 的包拒绝(错误码 1005)。
`rollback=1` 的包表示**授权回滚**(seq 仍递增,version 回退),车端允许。

**时效**:`expires_at - issued_at ≤ 7 天`;过期包拒绝。

### 10.2 策略下发格式

topic:`oc/devices/{device_id}/sys/idps/rule/update`(单车)/
`oc/devices/sys/idps/rule/update`(广播)。QoS 1 + retain。

| 字段 | 必选 | 类型 | 说明 |
|---|---|---|---|
| seq | 必 | int | 平台单调序号(10.1) |
| version | 必 | string | 策略版本号,车端属性上报回读 |
| rollback | 必 | bool | 是否授权回滚 |
| target | 必 | object | `{ecu: "0x01|all", nodeType: "NIDPS|all", vmodel: "t99|all"}` |
| upgrade_type | 必 | int | 1 单条/多条内联;2 批量包 URL |
| rules | 条件 | array | upgrade_type=1 时必:规则内容数组 |
| download_uri | 条件 | string | upgrade_type=2 时必:HTTPS 下载地址(车端下载后再验整体 sha256,见 canonical) |
| sha256 | 条件 | string | upgrade_type=2 时必:规则包整体摘要 |
| issued_at / expires_at | 必 | int | 签发/过期 Unix 秒 |
| sig_alg | 必 | string | 固定 `Ed25519` |
| pubkey_id | 必 | string | 签名公钥 sha256 指纹前 16 hex,车端据此选公钥 |
| signature | 必 | string | base64(Ed25519 签名(canonical 字节)) |

### 10.3 配置下发格式

topic:`sys/idps/config/update`(单车/广播同上)。同样签名。

| 字段 | 必选 | 类型 | 说明 |
|---|---|---|---|
| seq / rollback / target / issued_at / expires_at / sig_alg / pubkey_id / signature | 必 | — | 同 10.2 |
| config_type | 必 | int | 1 黑白名单;2 策略使能配置 |
| items | 必 | array | 配置项数组,见下 |

config_type=1(黑白名单)items:

| 字段 | 必选 | 类型 | 说明 |
|---|---|---|---|
| config_name | 必 | string | `app_w_list` / `process_w_list` / `fw_ip_w_list` / `fw_ip_b_list` / `fw_port_w_list` / `fw_port_b_list` |
| config_value | 必 | array<string> | 名单内容 |
| config_version | 必 | string | 该名单版本 |

config_type=2(策略使能)items:

| 字段 | 必选 | 类型 | 说明 |
|---|---|---|---|
| config_name | 必 | string | `rule_enable` |
| config_value | 必 | object | `{rule_id: 1\|0}` 显式开关;探针默认遵循,管理组件审计日志留痕 |

注意:`config_value` 中 `rule_enable` 全 0 的包是**高危操作**,云端审批流
必须双人复核,签名服务记录操作人(审计,14 章)。

### 10.4 车端原子切换与回滚

```
1. 收包 → 2. 校验 sig_alg/pubkey_id/时效 → 3. Ed25519 验签
→ 4. 防回滚(seq > max_seq 或 rollback=1)
→ 5. 写入 rules.new/ → fsync → rename rules/v{version}/
→ 6. 临时软链 + rename 切 current(原子, 探针永远读到完整一版)
→ 7. 重启探针(systemctl restart / init property)
→ 8. 属性上报 ruleVersion, 闭环
```

- 任一步失败即整体拒绝,不留半切换状态;当前版本不受影响。
- 回滚 = 重新签发 `rollback=1` 指向旧 version 的包,seq 递增,流程一致。
- 探针重启失败(systemd Restart= 兜底)仍持有旧 current,人工介入。

### 10.5 retained 与新设备上线

单车策略/配置消息 retain=true:设备(重)上线订阅后立即收到当前版本,
以 retained 包为基线再应用后续增量。广播 topic 的 retained 消息为
最近一次广播版本,车端按 `target` 过滤与 `seq` 去重。

---

## 11 日志快照上传(分包协议定稿)

topic:`oc/devices/{device_id}/sys/log/report`,QoS 1。

快照(二进制取证文件,如 pcap/核心转储)超过 256 KB 必须分包:

### 11.1 元消息

```json
{
  "msg_type": "log_snapshot",
  "transfer_id": "8f1c2a-...",
  "filename": "attack_20260918.pcap",
  "total_size": 5242880,
  "total_chunks": 20,
  "sha256": "整体文件 sha256",
  "log_time": "2026-09-18T10:20:30+08:00",
  "event_id": "关联告警 eventId",
  "ecuCode": "0x01",
  "remark": "端口扫描取证"
}
```

### 11.2 分片

每片 ≤ 128 KB,字段:`{transfer_id, chunk_index, chunk_sha256, data(base64)}`。
全部到达后云端校验整体 sha256,失败按缺失 index 走
`sys/log/report/negative-ack`(补片请求,重发仅限 24 h 内)。

### 11.3 规则

- transfer 有效期 24 h,过期碎片清理;
- 同一 transfer_id 重复分片按 chunk_index 幂等覆盖;
- 断网期间快照与告警一样入持久队列,恢复后补传(`replay=true`);
- HTTP multipart 备用通道保留(v0.7 语义),量产以 MQTT 分包为主。

---

## 12 数字孪生与攻击重放隔离

| 项 | 规则 |
|---|---|
| 命名空间 | 孪生/重放设备使用 `sim_`/`attacker_` clientId 前缀与 `sim/devices/` topic 根,与生产完全隔离 |
| 数据流向 | sim 只能 pub `sim/devices/+/idps/candata`;消费侧(检测引擎)订阅同名 topic |
| 有效期 | sim 凭据有效期 ≤ 7 天,按实验申请,过期自动吊销 |
| 防污染 | broker ACL 物理阻断 sim 证书访问 `oc/` 前缀;云端对账报表按命名空间过滤 |
| 重放审计 | attacker 数据源须登记实验工单号,消息头 `experiment_id` 留痕 |

---

## 13 数据库定义

### 13.1 设备注册表 vsoc_device(核心)

| 列 | 类型 | 说明 |
|---|---|---|
| id | bigint PK | 自增 |
| device_id | varchar(64) UK | manufacturer_modelCode_vin |
| vin | varchar(17) | 车架号,索引 |
| model_code | varchar(32) | 车型编码 |
| manufacturer | varchar(32) | 厂商/租户 |
| client_id | varchar(64) UK | 三段式接入标识 |
| access_status | tinyint | 0 未注册 / 1 离线 / 2 在线 / 3 退役 |
| cert_serial | varchar(64) | 当前业务证书序列号 |
| rule_seq_max | bigint | 已应用的最大签名 seq(防回滚基准) |
| rule_version | varchar(32) | 当前生效策略版本 |
| ecu_list | json | 最近一次属性上报的 ECU 拓扑 |
| last_seen | timestamp | 最近在线时间 |
| created_at / updated_at | timestamp | — |

### 13.2 设备证书登记表 vsoc_device_cert

| 列 | 类型 | 说明 |
|---|---|---|
| id | bigint PK | — |
| device_id | varchar(64) | 索引 |
| serial_number | varchar(64) UK | 证书序列号 |
| cert_pem | text | 业务证书 |
| status | tinyint | 0 有效 / 1 已吊销 / 2 已过期 |
| revoked_at / revoke_reason | timestamp / varchar | 吊销审计 |

### 13.3 策略版本表 vsoc_rule_release

| 列 | 类型 | 说明 |
|---|---|---|
| seq | bigint UK | 平台单调序号 |
| version | varchar(32) | 策略版本 |
| target_json | json | 目标过滤条件 |
| payload_uri | varchar(512) | 规则包存储地址 |
| sha256 | varchar(64) | 包摘要 |
| signature / pubkey_id | varchar | 签名留痕 |
| operator | varchar(32) | 签发操作人(审计) |
| approved_by | varchar(32) | 双人复核人(高危配置必填) |
| created_at | timestamp | — |

车型/零部件管理表沿用 v0.7,在资产表增加 `access_status` 字段(只读,
来源 13.1,不允许人工改)。

---

## 14 安全与审计要求

| 项 | 要求 |
|---|---|
| 下发审计 | 每次策略/配置签发记录操作人、复核人、canonical 摘要、目标车辆范围,留存 ≥ 3 年 |
| 车端审计 | 管理组件记录每次下发包的验签结果、切换前后 version,本地留存 ≥ 90 天 |
| 连接审计 | broker 记录 CONNECT/DISCONNECT、ACL 拒绝事件,request_id 关联全链路 |
| 模糊化 | 终端错误码按 6.5,详细原因仅服务端日志 |
| 密钥 | 签名私钥放 KMS/HSM,pubkey_id 轮换随车端 OTA;车端内嵌公钥 ≥ 2 个(当前+下一个) |
| 渗透 | 上线前对 broker ACL、签名验签、重放/回滚拒绝做渗透测试用例(见 attack-testing-guide.md) |

---

## 15 GB 标准对照

| 要求 | 本文落点 |
|---|---|
| GB 44495-2024 安全事件记录与防丢 | 9.3 断网补传 + eventId 幂等;8.3 lastAlertSeq 对账 |
| GB 44495-2024 入侵检测能力 | host/eth/can 三探针分管道上报(第 9 章) |
| GB 44495-2024 组件权限最小化 | 3.5 ACL 矩阵;探针零云依赖(2.1) |
| GB 44495-2024 策略更新可信 | 10.1 签名 + 防回滚 + 原子切换 |
| GB/T 32960.3 通信协议参照 | 保留 v0.7 参照关系;时间戳/校时按 6.3 执行 |
| R155 CSMS 审计 | 14 章审计留存;13.3 双人复核 |

---

## 16 落地实现映射(本仓库)

| 本文档 | 仓库实现 | 状态 |
|---|---|---|
| 管理组件(2.1) | `linux/idsm_managerd/`、`android/idsm_manager/` | 已有,待按本文 topic/信封适配 |
| 三探针(9 章) | `apps/host_probe`(HIDPS)、`apps/eth_probe`(NIDPS)、`apps/can_probe`(CIDS) | 已有,UDS sink 就绪 |
| 持久队列(9.3) | JSONL+游标(Linux)/ SQLite(APK) | 已有 |
| 规则验签切换(10.4) | `rule_manager`(OpenSSL EVP/BC Ed25519,canonical 与 10.1 一致) | 已有,需扩展 seq/rollback/target 字段 |
| 注册状态机(4 章) | managerd/APK 尚无,**待开发** | 缺口 |
| 属性/心跳上报(8 章) | 尚无,**待开发**(探针定期输出状态经管理组件上报) | 缺口 |
| ACL 矩阵(3.5) | EMQX 配置,平台侧 | 待部署 |
| 快照分包(11 章) | 尚无 | 缺口,低优先 |

适配优先级:P0 = topic 映射 + device_id 三段式 + 信封统一;P1 = 属性上报、
注册状态机、策略包 seq/防回滚扩展;P2 = 快照分包、孪生隔离。

---

## 附录 A 消息 JSON Schema(权威定义)

Schema 为唯一权威;正文与示例由 schema 派生,CI 校验。

### A.1 通用信封

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "vsoc_envelope",
  "type": "object",
  "required": ["msg_type", "protocol_version", "timestamp", "manufacturer", "content"],
  "additionalProperties": false,
  "properties": {
    "msg_type": {
      "type": "string",
      "enum": ["register", "cert_apply", "property", "alert_host", "alert_eth",
               "alert_can", "rule_update", "config_update", "log_snapshot", "event"]
    },
    "protocol_version": {"type": "string", "const": "1.0"},
    "timestamp": {"type": "integer", "minimum": 0},
    "manufacturer": {"type": "string", "pattern": "^[a-z0-9]{2,32}$"},
    "request_id": {"type": "string", "format": "uuid"},
    "content": true
  }
}
```

### A.2 响应信封

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "vsoc_response",
  "type": "object",
  "required": ["rc", "rn", "request_id", "timestamp"],
  "additionalProperties": false,
  "properties": {
    "rc": {"type": "integer"},
    "rn": {"type": "string"},
    "request_id": {"type": "string", "format": "uuid"},
    "timestamp": {"type": "integer"},
    "paras": {"type": "object"}
  }
}
```

### A.3 注册请求 content

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "register_request_content",
  "type": "object",
  "required": ["vin", "modelId"],
  "additionalProperties": false,
  "properties": {
    "vin": {"type": "string", "pattern": "^[A-HJ-NPR-Z0-9]{17}$"},
    "modelId": {"type": "string", "minLength": 1, "maxLength": 32},
    "engineNumber": {"type": "string", "maxLength": 64},
    "color": {"type": "string", "maxLength": 32},
    "productionDate": {"type": "string", "pattern": "^\\d{4}-\\d{2}-\\d{2}$"},
    "ecuList": {"type": "array", "items": {"type": "string", "pattern": "^0x[0-9a-f]{2}$"}},
    "remark": {"type": "string", "maxLength": 256}
  }
}
```

### A.4 属性上报 content(节点数组)

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "property_report_content",
  "type": "array",
  "minItems": 1,
  "maxItems": 64,
  "items": {
    "type": "object",
    "required": ["ecuCode", "ecuOs", "nodeType", "nodeVersion", "nodeStatus", "ruleVersion"],
    "additionalProperties": false,
    "properties": {
      "ecuCode": {"type": "string", "pattern": "^0x[0-9a-f]{2}$"},
      "ecuName": {"type": "string", "maxLength": 64},
      "ecuOs": {"type": "string", "enum": ["Linux", "Android", "QNX", "AUTOSAR"]},
      "nodeType": {"type": "string", "enum": ["HIDPS", "NIDPS", "CIDS"]},
      "nodeVersion": {"type": "string", "maxLength": 64},
      "nodeStatus": {"type": "integer", "enum": [-1, 0, 1]},
      "ruleVersion": {"type": "string", "maxLength": 32},
      "lastAlertSeq": {"type": "integer", "minimum": 0},
      "remark": {"type": "string", "maxLength": 256}
    }
  }
}
```

### A.5 检测日志上报 content

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "alert_log_content",
  "type": "array",
  "minItems": 1,
  "maxItems": 64,
  "items": {
    "type": "object",
    "required": ["eventId", "eventType", "severity", "timestamp",
                 "ecuCode", "nodeType", "ruleVersion", "replay", "raw"],
    "additionalProperties": false,
    "properties": {
      "eventId": {"type": "string", "maxLength": 128},
      "eventType": {"type": "string", "maxLength": 64},
      "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
      "timestamp": {"type": "integer", "minimum": 0},
      "ecuCode": {"type": "string", "pattern": "^0x[0-9a-f]{2}$"},
      "nodeType": {"type": "string", "enum": ["HIDPS", "NIDPS", "CIDS"]},
      "ruleVersion": {"type": "string", "maxLength": 32},
      "replay": {"type": "boolean"},
      "raw": {"type": "object"}
    }
  }
}
```

### A.6 策略下发(签名包)

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "rule_update",
  "type": "object",
  "required": ["msg_type", "protocol_version", "timestamp", "manufacturer",
               "seq", "version", "rollback", "target", "upgrade_type",
               "issued_at", "expires_at", "sig_alg", "pubkey_id", "signature"],
  "additionalProperties": false,
  "properties": {
    "msg_type": {"type": "string", "const": "rule_update"},
    "protocol_version": {"type": "string", "const": "1.0"},
    "timestamp": {"type": "integer"},
    "manufacturer": {"type": "string"},
    "seq": {"type": "integer", "minimum": 1},
    "version": {"type": "string", "maxLength": 32},
    "rollback": {"type": "boolean"},
    "target": {
      "type": "object",
      "required": ["ecu", "nodeType", "vmodel"],
      "properties": {
        "ecu": {"type": "string"},
        "nodeType": {"type": "string", "enum": ["HIDPS", "NIDPS", "CIDS", "all"]},
        "vmodel": {"type": "string"}
      }
    },
    "upgrade_type": {"type": "integer", "enum": [1, 2]},
    "rules": {"type": "array", "items": {"type": "string"}},
    "download_uri": {"type": "string", "format": "uri"},
    "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "issued_at": {"type": "integer"},
    "expires_at": {"type": "integer"},
    "sig_alg": {"type": "string", "const": "Ed25519"},
    "pubkey_id": {"type": "string", "pattern": "^[0-9a-f]{16}$"},
    "signature": {"type": "string"}
  }
}
```

(配置下发 schema 结构相同,`msg_type=config_update`,以 `config_type`+`items`
替换 `upgrade_type`/`rules`/`download_uri`,定义见 10.3。)

### A.7 日志快照元消息

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "log_snapshot_meta",
  "type": "object",
  "required": ["msg_type", "protocol_version", "timestamp", "manufacturer",
               "transfer_id", "filename", "total_size", "total_chunks",
               "sha256", "log_time", "ecuCode"],
  "additionalProperties": false,
  "properties": {
    "msg_type": {"type": "string", "const": "log_snapshot"},
    "protocol_version": {"type": "string", "const": "1.0"},
    "timestamp": {"type": "integer"},
    "manufacturer": {"type": "string"},
    "transfer_id": {"type": "string", "maxLength": 64},
    "filename": {"type": "string", "maxLength": 256},
    "total_size": {"type": "integer", "minimum": 1},
    "total_chunks": {"type": "integer", "minimum": 1, "maximum": 10000},
    "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "log_time": {"type": "string", "format": "date-time"},
    "event_id": {"type": "string", "maxLength": 128},
    "ecuCode": {"type": "string", "pattern": "^0x[0-9a-f]{2}$"},
    "replay": {"type": "boolean"},
    "remark": {"type": "string", "maxLength": 256}
  }
}
```

## 附录 B 关键示例(已由 schema 校验)

属性上报:

```json
{
  "msg_type": "property",
  "protocol_version": "1.0",
  "timestamp": 1726640000123,
  "manufacturer": "caic",
  "content": [
    {
      "ecuCode": "0x02",
      "ecuName": "车机",
      "ecuOs": "Android",
      "nodeType": "HIDPS",
      "nodeVersion": "1.3.0+git.a1b2c3d",
      "nodeStatus": 1,
      "ruleVersion": "v7",
      "lastAlertSeq": 1024
    },
    {
      "ecuCode": "0x01",
      "ecuName": "GW",
      "ecuOs": "Linux",
      "nodeType": "NIDPS",
      "nodeVersion": "1.3.0+git.a1b2c3d",
      "nodeStatus": 1,
      "ruleVersion": "v7",
      "lastAlertSeq": 2048
    }
  ]
}
```

检测日志上报(主机告警,补传):

```json
{
  "msg_type": "alert_host",
  "protocol_version": "1.0",
  "timestamp": 1726640000456,
  "manufacturer": "caic",
  "content": [
    {
      "eventId": "caic_t99_LXXXXXXX202000001-HIDPS-3fa85f64c5b34f2c9e2f4a8b1d2c3e4f",
      "eventType": "DT_UNKNOWN_EXEC",
      "severity": "MEDIUM",
      "timestamp": 1726639999000,
      "ecuCode": "0x02",
      "nodeType": "HIDPS",
      "ruleVersion": "v7",
      "replay": true,
      "raw": {
        "exe": "/tmp/.suid_dash",
        "pid": 4321,
        "uid": 0
      }
    }
  ]
}
```

策略下发(单车内联,已签名):

```json
{
  "msg_type": "rule_update",
  "protocol_version": "1.0",
  "timestamp": 1726640000000,
  "manufacturer": "caic",
  "seq": 1025,
  "version": "v8",
  "rollback": false,
  "target": {"ecu": "all", "nodeType": "all", "vmodel": "t99"},
  "upgrade_type": 1,
  "rules": ["alert tcp any any -> any 3389 (msg:\"RDP access\"; sid:10001;)"],
  "issued_at": 1726639200,
  "expires_at": 1727244000,
  "sig_alg": "Ed25519",
  "pubkey_id": "9f2c4a1db8e67305",
  "signature": "base64-ed25519-signature-over-canonical-bytes"
}
```
