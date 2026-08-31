# IDSM 过滤器链与 QSEv 设计文档

> 依据规范(docs/AutoSar/R24-11/):
> - **CP SWS IdsM**(AUTOSAR_CP_SWS_IntrusionDetectionSystemManager.pdf, Doc ID 977)§7.3–7.8、§8.3
> - **FO PRS IDS Protocol**(AUTOSAR_FO_PRS_IntrusionDetectionSystem.pdf, Doc ID 981)§5
> - **FO RS IDS**(AUTOSAR_FO_RS_IntrusionDetectionSystem.pdf, Doc ID 976)§4
> - **CP SWS Firewall**(AUTOSAR_CP_SWS_Firewall.pdf, Doc ID 1084)§7.6(传感器侧契约)
>
> 状态：设计评审稿 v2 | 日期：2026-08-25
> v2 变更：采纳方案 A(删除操作模式);QSEv 对齐 PRS IDS Event Frame 线格式；
> 补充 Firewall 传感器契约；补充 RS 需求追踪表

---

## 1. 目标与范围

将现有 IDSM 实现从"monitor + 单一防洪窗口"模型升级为 R24-11 规范的
**SEv → 过滤器链 → QSEv** 模型。本设计覆盖 P0 范围:

1. 新上报 API `IdsM_ReportSecurityEvent`(CP §8.3.4)
2. 报告模式过滤器(Reporting Mode,CP §7.6.1.1 / RS_Ids_00310)
3. 过滤器链框架 + 5 种事件级过滤器(CP §7.6)
4. QSEv 数据结构 + **IDS Event Frame 线格式序列化**(PRS §5.1.4)
5. 2 种实例级限速过滤器(CP §7.6.4 / RS_Ids_00511)

**架构决策(不变)**:现有"非阻塞入队 + 后台工作线程异步处理"模型恰好符合
[SWS_IdsM_00901](事件入 Event Buffer，在 MainFunction 中异步 qualify)。
工作线程即 MainFunction 等价物，过滤器链全部在工作线程上执行,
`IdsM_ReportSecurityEvent()` 保持 <1µs 纯入队。

**IdsRm 定位**:改造为 QSEv 消费者(sink 角色，对应 IdsR)。HTTP 转发功能保留,
JSON 中携带按 PRS 序列化的 IDS Message hex 及解码后的字段。

**方案 A(已确认)**:**删除 PRE_RUN/RUN/POST_RUN 操作模式**——规范中无此
概念。生命周期语义由两个规范机制取代:
- 每 SEv 的 **Reporting Mode**(默认来自配置，运行时可改)
- **Block State Filter** 的状态由 `IdsM_BswM_StateChanged()` 注入(仿真
  BswM);不需要状态阻塞的 SEv 配空阻塞表即可

---

## 2. 数据模型

### 2.1 安全事件标识(CP §7.3.2 / PRS §5.1.4.3)

```
SEv 标识 = ( IdsMExternalEventId ,  IdsMSensorInstanceId )
                ↓ 配置时映射
        IdsMInternalEventId (内部索引, 0..N-1)
                ↓ 传感器使用
        符号名常量 (SymbolicNameValue)  —— 模拟生成代码的 #define
```

- **外部事件 ID**(Event Definition ID):全局唯一事件类型 ID。取值范围
  [PRS_Ids_00017]:
  - `0x0000–0x7FFF`:AUTOSAR 内部 ID(如 Firewall 的 50–77)
  - `0x8000–0xFFFE`:OEM/用户自定义 ID(本项目传感器事件用此段)
  - `0xFFFF`:无效 [SWS_IdsM_00604]
- **传感器实例 ID**:6 bit(0–63)[PRS_Ids_00014],同类传感器多实例区分号,
  单实例配 0
- **IdsM 实例 ID**:10 bit(0–1023)[PRS_Ids_00013],标识本 ECU;单实例配 0 或 1

```c
/* IdsM_Types.h */
typedef uint16_t IdsM_SecurityEventIdType;          /* CP §8.2.2 内部 ID */
typedef uint16_t IdsM_ExternalSecurityEventIdType;  /* CP §8.2.7 外部 ID */
typedef uint8_t  IdsM_SensorInstanceIdType;         /* 0..63 */
#define IDSM_EXTERNAL_EVENT_ID_INVALID  ((IdsM_ExternalSecurityEventIdType)0xFFFFu)
```

应用侧符号常量(模拟配置生成器输出):

```c
#define IDSM_SEV_CAN_IDS_FLOOD          ((IdsM_SecurityEventIdType)0)
#define IDSM_SEV_SECOC_AUTH_FAIL        ((IdsM_SecurityEventIdType)1)
#define IDSM_SEV_ETH_PORT_SCAN          ((IdsM_SecurityEventIdType)2)
/* Firewall 集成时直接使用 AUTOSAR 标准 ID(§7.1):SEV_FW_PACKET_BLOCKED_IPV4_MISMATCH=51 等 */
```

**迁移映射**(现有 5 个 monitor → SEv，外部 ID 用 OEM 段 0x8000 起):

| 现 monitor_id | 外部事件 ID | 传感器实例 | 说明 |
|---|---|---|---|
| 0x001 CAN-IDS | 0x8001 | 0 | CAN 总线入侵检测 |
| 0x002 SecOC | 0x8002 | 0 | SecOC 认证失败 |
| 0x003 Ethernet | 0x8003 | 0 | 以太网 IDS |
| 0x004 OBD-II | 0x8004 | 0 | OBD-II 扫描 |
| 0x005 FW-Integrity | 0x8005 | 0 | 固件完整性 |

### 2.2 上报 API(CP §8.3.4)

```c
/* IdsM.h — 替代现有 IdsM_ReportEvent */
void IdsM_ReportSecurityEvent(
    IdsM_SecurityEventIdType        securityEventId,    /* 符号名常量 */
    const uint8_t*                  contextData,        /* NULL = 无上下文 */
    uint16_t                        contextDataSize,    /* 无上下文填 0 */
    uint16_t                        contextDataVersion, /* 无上下文填 1 (R24-11 新增) */
    uint16_t                        count,              /* 传感器侧已聚合次数, [1, 65535] */
    const IdsM_TimestampDataType*   timestamp           /* NULL = IdsM 内部取时 */
);
```

与现状的差异:

- **severity 移出上报参数**——规范中 severity 是 SEv 的配置属性(R23-11 引入),
  CLI 的 `sev=` 参数改为配置项
- **count** 支持智能传感器预聚合(CP §7.3.1.1);下游过滤器按 count 累加,
  最终 QSEv 的 count = 传感器预设值 + IdsM 聚合结果[PRS_Ids_00018]
- **timestamp**:传感器可自带 StbM 同步时间;NULL 时 IdsM 用内部
  `steady_clock` 取时(后续可换 StbM 适配层)
- 旧 `IdsM_SetSecurityEvent*` 六变体规范已标 obsolete,**不实现**;
  现有 `IdsM_ReportEvent()` 保留一个版本作兼容包装(count=1, version=1)

### 2.3 时间戳(PRS §5.1.5)

对齐 PRS 线格式:`{source(1bit) + reserved + nanoseconds(30bit) + seconds(32bit)}`
共 8 字节。内部表示:

```c
typedef enum {
    IDSM_TIMESTAMP_SOURCE_AUTOSAR = 0,  /* StbM(仿真:steady_clock) */
    IDSM_TIMESTAMP_SOURCE_OEM     = 1   /* 传感器/应用自定义 */
} IdsM_TimestampSourceType;

typedef struct {
    uint32_t seconds;       /* 32 bit,~127 年 [PRS_Ids_00407] */
    uint32_t nanoseconds;   /* 有效 30 bit,0..999999999 [PRS_Ids_00406] */
    IdsM_TimestampSourceType source;
} IdsM_TimestampDataType;
```

### 2.4 QSEv 结构(CP §7.8.1 + PRS §5.1)

QSEv 的内存结构独立于 sink[SWS_IdsM_01200];其线格式即 IDS Message:

```
┌────────────────────────── IDS Message ───────────────────────────┐
│ Event Frame (8B, 必含)                                            │
│   Byte0:    ProtocolVersion(4bit)|ProtocolHeader(4bit)           │
│             Header bit0=含ContextData bit1=含Timestamp bit2=含签名 │
│   Byte1-2:  IdsM Instance ID(10bit)|Sensor Instance ID(6bit)     │
│   Byte3-4:  Event Definition ID(16bit)                           │
│   Byte5-6:  Count(16bit)                                         │
│   Byte7:    Reserved(=0)                                         │
│ Timestamp (8B, 可选)                                              │
│ Context Data Frame (可选): Version(2B) + Length(1或4B) + blob     │
│   Version Byte0 bit7: 0=传感器原始数据 1=经 Callout 修改            │
│   Length Byte0 bit7=0: 7bit 编码(1..127B);bit7=1: 31bit(4B)     │
│ Signature Frame (可选): Length(2B) + blob —— P2 实现              │
└───────────────────────────────────────────────────────────────────┘
字节序:大端(网络序)[PRS_Ids_00004]
```

- **Protocol Version = 2**(含 Context Data Version)[PRS_Ids_00008]
- **Protocol Header 的 3 个标志位**反映本 QSEv 实际携带哪些可选字段
  [PRS_Ids_00010]——BRIEF 报告模式清掉 context data 后 bit0 必须置 0

```c
/* IdsM_Types.h — 内存表示 */
typedef struct {
    uint8_t                            idsm_instance_id;    /* 10 bit 有效 */
    IdsM_ExternalSecurityEventIdType   external_event_id;
    IdsM_SensorInstanceIdType          sensor_instance_id;  /* 6 bit 有效 */
    IdsM_EventSeverityType             severity;            /* 取自 SEv 配置(项目扩展,不上线) */
    uint16_t                           count;               /* 创建时=1 [PRS_Ids_00018] */
    boolean                            has_timestamp;       /* → Header bit1 */
    IdsM_TimestampDataType             timestamp;
    /* context data 本体在 C++ 侧为 std::vector<uint8_t>(OwnedQSEv);空 → Header bit0=0 */
    uint16_t                           context_data_version;
    const uint8_t*                     context_data;
    uint16_t                           context_data_size;
} IdsM_QualifiedSecurityEventType;
```

C++ 内部使用 `IdsM_OwnedQSEv`(深拷贝 context data),与现有
`IdsM_OwnedEvent` 同一模式，保证跨队列边界的所有权安全。

**序列化**新增模块 `IdsM_Protocol.c`:
`IdsM_Protocol_SerializeQSEv(const IdsM_QualifiedSecurityEventType*, uint8_t* buf, uint16_t* len)`
按 PRS §5.1.4–5.1.6 输出大端 IDS Message。IdsRm 转发前调用,
JSON 中同时携带 hex 与解码字段(§6)。二进制序列化器同时是 P1 对接真实
IdsR(PduR/以太网）时的复用件。

### 2.5 报告模式(CP §7.6.1.1 / RS_Ids_00310)

每个 SEv 一个报告模式，过滤器链之前的必经判定[SWS_IdsM_01010/01011]:

```c
typedef enum {
    IDSM_REPORTING_OFF                        = 0, /* 直接丢弃,不做任何处理 */
    IDSM_REPORTING_BRIEF                      = 1, /* 丢弃 context data 后进过滤器链 */
    IDSM_REPORTING_DETAILED                   = 2, /* 保留 context data 进过滤器链 */
    IDSM_REPORTING_BRIEF_BYPASSING_FILTERS    = 3, /* 丢弃 context,跳链,直接成 QSEv */
    IDSM_REPORTING_DETAILED_BYPASSING_FILTERS = 4  /* 保留 context,跳链,直接成 QSEv */
} IdsM_Filters_ReportingModeType;  /* CP §8.2.4 */
```

- 默认值来自配置;运行时经 `IdsM_SetReportingMode(sevId, mode)` 修改
  (RS_Ids_00700;为 P1 的 DCM 诊断、NvM 持久化预留)
- **方案 A 落地**:`IdsM_SetOperatingMode`/`IdsM_GetOperatingMode`/
  `enabled_in_pre_run/run/post_run` 全部删除;CLI `mode` 命令替换为
  `rptmode <sevId> <off|brief|detailed|bbypass|dbypass>`

---

## 3. 过滤器链

### 3.1 总体结构([SWS_IdsM_01001–01005])

```
上报入队(纯拷贝, <1µs)
     │
     ▼  工作线程(MainFunction 等价物)逐个取出 SEv
┌─────────────────────────────────────────────────┐
│ 0. Reporting Mode 判定(每个 SEv 强制,不在链内)  │
│    OFF → 丢弃 | BYPASSING → 直接成 QSEv 送 sink  │
└─────────────────────────────────────────────────┘
     │ (BRIEF / DETAILED)
     ▼
┌─── 事件级过滤器链(按 SEv 配置,严格按序)─────────┐
│ 1. Block State Filter      当前状态在阻塞表 → 丢弃 │
│ 2. Forward Every Nth       采样,每 n 个放 1 个    │
│ 3. Event Aggregation       时间窗内聚合成 1 个     │
│ 4. Event Threshold         窗内未达阈值 → 丢弃     │
└──────────────────────────────────────────────────┘
     │ 全部通过 → SEv 成为 QSEv
     ▼
┌─── 实例级过滤器(送 IdsR sink 前,全实例共享)────┐
│ 5. Event Rate Limitation   窗内超最大事件数 → 丢弃 │
│ 6. Traffic Limitation      窗内超最大字节数 → 丢弃 │
└──────────────────────────────────────────────────┘
     ▼
  sink 分发(Dem 存储 / IdsRm HTTP 转发)
```

关键规则:

- **短路**:任一过滤器丢弃,后续不再评估[SWS_IdsM_01005]
- **顺序固定**:BlockState → ForwardNth → Aggregation → Threshold
  [SWS_IdsM_01004],不可配置
- **链可选**:SEv 可以不配过滤器链(报告模式非 OFF 即直通)
- **多链共存**:多个 SEv 可引用不同过滤器链(RS_Ids_00301);
  本实现中链以内联配置表达(每 SEv 一组过滤器参数),共享同一套过滤器代码
- **事件级 vs 实例级**:1–4 按 SEv 独立维护状态;5–6 整个 IdsM 实例共享
  计数器(CP §7.6.4),只在发往 IdsR(本项目=IdsRm)前应用,**不影响 Dem 存储**

### 3.2 各过滤器设计

#### 3.2.1 Reporting Mode Filter
见 §2.5。事件出队后、链评估前判定[SWS_IdsM_01002]。
BRIEF 在此清空 context data(后续所有环节不可见,序列化时 Header bit0=0)。

#### 3.2.2 Block State Filter(CP §7.6.1.2 / RS_Ids_00320)

```c
typedef uint8_t IdsM_BlockStateIdType;   /* 状态符号名,BswM 域 */

typedef struct {
    IdsM_BlockStateIdType blocked_states[8];  /* IdsMBlockState 列表 */
    uint8_t               num_blocked_states; /* 0 = 恒放行 */
} IdsM_BlockStateFilterConfigType;
```

- 当前状态由 `IdsM_BswM_StateChanged(stateId)` 注入[SWS_IdsM_01022]。
  **方案 A 下它是独立公共 API**(不再由 SetOperatingMode 转调),仿真
  环境由 CLI 的 `blockstate <id>` 命令驱动;接入真实 BSW 时由 BswM 调用
- 判定在工作线程异步执行:当前状态 ∈ 阻塞表 → 丢弃
- 旧"某模式下监控器禁用"语义的等价配置:`enabled_in_post_run=false` →
  阻塞表含 POST_RUN 对应的状态 ID。默认配置不再预置任何状态/阻塞关系

#### 3.2.3 Forward Every Nth(CP §7.6.2.1 / RS_Ids_00330)

```c
typedef struct {
    uint16_t n;          /* IdsMNthParameter */
    uint16_t counter;    /* 运行时状态 */
} IdsM_ForwardEveryNthFilterType;
```

- 放行第 1、n+1、2n+1… 个 SEv;`counter == n` 放行并清零
  [SWS_IdsM_01031/01032]
- **不修改 SEv 数据**[SWS_IdsM_01033]:count 原值透传
- count>1 的 SEv 到达时计数器按 count 累加,可超过 n,仍放行且聚合 count
  原样带出[SWS_IdsM_01034]

#### 3.2.4 Event Aggregation Filter(CP §7.6.3.1 / RS_Ids_00340)

```c
typedef struct {
    uint32_t interval_ms;     /* IdsMEventAggregationTimeInterval,
                                 MainFunction 周期整数倍 */
    bool     has_pending;     /* 运行时:窗内已有暂存事件 */
    IdsM_OwnedQSEv* pending;  /* 暂存的聚合事件(C++ 侧) */
    uint32_t window_start_ms;
} IdsM_AggregationFilterType;
```

- 窗内首个 SEv 暂存;后续同 ID SEv → `pending->count += sev.count`,
  **只保留首个事件的 context data**(CP §7.6.1 及 Firewall §7.6.1 均明确此
  语义;这也是 Firewall 把 SEv ID 按协议细分的原因,见 §7.2)
- 窗口到期(工作线程 tick)→ pending 作为单个 SEv 交下游过滤器
- 唯一会延迟事件的过滤器,依赖周期 tick(§4.2)

#### 3.2.5 Event Threshold Filter(CP §7.6.3.2 / RS_Ids_00350)

```c
typedef struct {
    uint16_t threshold;       /* IdsMEventThresholdNumber */
    uint32_t interval_ms;     /* MainFunction 周期整数倍 [SWS_IdsM_01064] */
    uint32_t accumulated;     /* 运行时:窗内 count 累加值 */
    uint32_t window_start_ms;
} IdsM_ThresholdFilterType;
```

- 窗内 `accumulated < threshold` → 丢弃并累加;达到后本窗内后续 SEv
  **立即原样放行**[SWS_IdsM_01061/01062]
- 窗口到期清零[SWS_IdsM_01063];计时自 MainFunction 首次调用起
  [SWS_IdsM_01065]

#### 3.2.6 Event Rate Limitation(CP §7.6.4.1,实例级)

```c
typedef struct {
    uint32_t max_events;      /* IdsMRateLimitationMaximumEvents */
    uint32_t interval_ms;     /* 周期整数倍 [SWS_IdsM_01082] */
    uint32_t sent_in_window;  /* 运行时 */
    uint32_t window_start_ms;
} IdsM_RateLimitationFilterType;
```

发送将使窗内计数超 max_events → 丢弃[SWS_IdsM_01081]。
现有 `flood_protection_ms` 由此取代并删除。

#### 3.2.7 Traffic Limitation(CP §7.6.4.2,实例级)

同上,按 **IDS Message 序列化字节数**计[SWS_IdsM_01091](与 §2.4 的
序列化器配合,先算长度再判定);超限且配置了内部事件时上报
`IDSM_INTERNAL_EVENT_TRAFFIC_LIMITATION_EXCEEDED`[SWS_IdsM_01094]
——内部 SEv 机制的第一个实例(CP §7.4,其余 P2 补全)。

### 3.3 配置结构(CP §8.2.1,替代 IdsM_MonitorConfigType)

```c
typedef struct {
    IdsM_ExternalSecurityEventIdType    external_event_id;      /* 0x8000 段(OEM) */
    IdsM_SensorInstanceIdType           sensor_instance_id;     /* 0..63 */
    IdsM_EventSeverityType              severity;               /* 配置属性(项目扩展) */
    IdsM_Filters_ReportingModeType      default_reporting_mode;
    /* 过滤器链:0/NULL = 未配置该过滤器 */
    const IdsM_BlockStateFilterConfigType*  block_state;
    uint16_t                            forward_every_nth;        /* 0=禁用 */
    uint32_t                            aggregation_interval_ms;  /* 0=禁用 */
    struct { uint16_t threshold; uint32_t interval_ms; } event_threshold; /* threshold=0=禁用 */
    /* sink 列表 [SWS_IdsM_01201] */
    boolean                             sink_to_dem;
    boolean                             sink_to_idsr;   /* 本项目 = IdsRm */
} IdsM_SecurityEventConfigType;

typedef struct {
    uint8_t                             idsm_instance_id;         /* 10 bit 有效 */
    uint32_t                            main_function_period_ms;  /* 工作线程 tick */
    struct { uint32_t max_events; uint32_t interval_ms; } rate_limitation;    /* max_events=0=禁用 */
    struct { uint32_t max_bytes;  uint32_t interval_ms; } traffic_limitation; /* max_bytes=0=禁用 */
    const IdsM_SecurityEventConfigType* sev_configs;
    uint16_t                            sev_count;
    uint32_t                            event_buffer_size;
} IdsM_ConfigType;   /* CP §8.2.1 */

STD_RETURN_TYPE IdsM_Init(const IdsM_ConfigType* config);  /* 签名变更 */
```

---

## 4. 与现有异步架构的融合

### 4.1 线程模型(不变)

```
传感器线程                IDSM 工作线程                    IDSRM 工作线程
     │                        │                                │
ReportSecurityEvent()    出队 → Reporting Mode            出队 → PRS 序列化
  深拷贝 → 入队  ──►      → 过滤器链(事件级)      ──►    → HTTP POST
  <1µs 返回               → QSEv → 实例级限速
                          → sink 分发(Dem / IdsRm 入队)
```

### 4.2 工作线程 tick 改造

Aggregation/Threshold/Rate/Traffic 基于时间窗,需要周期唤醒:

```cpp
// IdsM_Manager.cpp 工作线程主循环
while (running) {
    // 1. 处理队列中所有待办事件(过滤器链)
    // 2. 检查各时间窗到期:
    //    - aggregation pending 到窗 → 送链下游
    //    - threshold 窗到期 → 清零
    //    - rate/traffic 窗到期 → 清零
    // 3. 取最早到期时间 condition_variable::wait_until
}
```

`main_function_period_ms`(默认 10ms)为 tick 粒度上限;窗口配置必须是其
整数倍[SWS_IdsM_01064/01082/01092],Init 时校验,不满足返回 `E_NOT_OK`
(P2 接 DET 错误码)。

### 4.3 缓冲区

保留单一共享入队队列(所有 SEv 共用),容量 `event_buffer_size`,溢出丢最旧。
CP §7.3.3 允许每 SEv 独立 buffer,本项目规模下共享队列足够;溢出时上报内部
SEv(P2)。

---

## 5. RS 需求追踪(FO RS → 本设计)

| 需求 | 内容 | 本设计落点 |
|---|---|---|
| RS_Ids_00100 | 初始化 | `IdsM_Init(Idsm_ConfigType)` §3.3 |
| RS_Ids_00200 | SEv 上报接口 | `IdsM_ReportSecurityEvent` §2.2 |
| RS_Ids_00210 | 为调用方缓冲 SEv | 共享入队队列 §4.3 |
| RS_Ids_00310 | 每事件报告模式 | §2.5 |
| RS_Ids_00300/00301 | 可配置/多重过滤器链 | §3.1(每 SEv 内联链配置) |
| RS_Ids_00320 | 状态(阻塞)过滤器 | §3.2.2 |
| RS_Ids_00330 | 采样过滤器 | §3.2.3 |
| RS_Ids_00340 | 聚合过滤器 | §3.2.4 |
| RS_Ids_00350 | 阈值过滤器 | §3.2.5 |
| RS_Ids_00502/00503 | 时间戳及来源 | §2.3 |
| RS_Ids_00510 | QSEv 传输到 IdsR | PRS 序列化 §2.4 + IdsRm §6 |
| RS_Ids_00511 | 速率/流量限制 | §3.2.6/3.2.7 |
| RS_Ids_00600/00610 | SEv/过滤器配置模型 | §3.3 |
| RS_Ids_00700 | 运行时再配置 | `IdsM_SetReportingMode`(P1 扩展) |
| RS_Ids_00400/00620 | QSEv 持久化 | Dem sink(P1,桩已留) |
| RS_Ids_00505 | QSEv 签名真实性 | Signature Frame(P2) |
| RS_Ids_00820 | IdsM 内部 SEv | Traffic 超限事件起步(P2 补全) |
| RS_Ids_00430/00710/00810 | 防篡改/整链替换/BSW 事件 | 不在本期范围 |

---

## 6. IdsRm 改造(sink 化)

```
现状:IdsRm_Init() → IdsM_SetDemReportCallback(收原始事件)
改为:IdsRm_Init() → IdsM_RegisterIdsrSink(callback)(收 QSEv)
```

- 回调签名:`void (*IdsM_IdsrSinkCallbackType)(const IdsM_QualifiedSecurityEventType*)`
- IdsRm 工作线程先调 `IdsM_Protocol_SerializeQSEv()` 得到 IDS Message,
  JSON 同时携带线格式 hex 与解码字段:

```json
{
    "ids_message": "200101018001000300",
    "protocol_version": 2,
    "has_context_data": true,
    "has_timestamp": true,
    "idsm_instance_id": 1,
    "sensor_instance_id": 0,
    "event_id": 32769,
    "count": 3,
    "severity": "HIGH",
    "timestamp_s": 42, "timestamp_ns": 0,
    "context_data_version": 1,
    "payload": "00000123080102030405060708",
    "payload_len": 13
}
```

- 实例级 Rate/Traffic Limitation 在 IDSM 侧已过滤,IdsRm 无需感知
- Grafana dashboard 的 monitor 维度改用 `event_id`

---

## 7. Firewall 传感器契约(CP SWS Firewall §7.6)

Firewall 规范与 IDSM 的关联点:Firewall 是规范的 **IDS 传感器**,以
`IdsM_ReportSecurityEvent` 向 IdsM 上报 SEv。本期不实现 Firewall 本体,
但设计须兼容其契约，后续接入传感器(含自研 CAN-IDS 适配器)时遵循同样约定:

1. **标准 SEv ID 表**(Firewall §7.6.1,DRAFT):数据链路层=50、IPv4=51、
   IPv6=52、ICMP=53、TCP=54、UDP=55、SOMEIP=56、SOMEIPSD=57、DDS=58、
   DoIP=59、通用=60、TCP 连接数=61、TCP 超时=62、限速=63、流过滤=77 等,
   全部在 AUTOSAR 内部段(0–0x7FFF)。集成 Firewall 时直接按此表配置,
   与 §2.1 的 OEM 段(0x8000+)并存
2. **Context data 布局**:Firewall 的 context data 为结构化二进制
   (如 `FirewallRuleId uint16 + CompleteIPv4Header uint8[24]`,
   Context Data Version=1)。IDSM 侧保持不透明透传即可;**SOC 侧解析**
   需要 version 字段区分布局——印证 R24-11 引入 contextDataVersion 的动机
3. **聚合信息损失**(Firewall §7.6.1 明确警示):Aggregation 只保留首事件
   context data,故 SEv ID 要足够细粒度(Firewall 按协议细分)。
   **本项目 SEv 设计准则**:context data 布局不同的事件必须分配不同的外部
   事件 ID,不能共用一个 ID 靠 context 区分
4. **count 预聚合**:Firewall 的 per-stream filtering 会以 count>1 上报——
   过滤器链按 count 累加的处理(§3.2.3/3.2.5)已覆盖此场景

---

## 8. 兼容与迁移

| 旧 API/配置 | 处置(方案 A) |
|---|---|
| `IdsM_ReportEvent()` | 保留一个迭代,转调新 API(count=1, ver=1),注释标 deprecated |
| `IdsM_SetOperatingMode()/IdsM_GetOperatingMode()` | **删除**;相关枚举、`enabled_in_*` 配置字段一并删除 |
| CLI `mode` 命令 | **删除**,替换为 `rptmode <sev> <mode>` 与 `blockstate <id>` |
| `IdsM_GetDetectionStatus()` | 保留(项目自定义功能),语义不变 |
| `flood_protection_ms` | 删除,由 Rate Limitation 取代 |
| `IdsM_MonitorConfigType` | 删除,由 `IdsM_ConfigType`/`IdsM_SecurityEventConfigType` 取代 |

## 9. 测试计划(Google Test)

每个过滤器独立单测 + 链集成测试,模式:"上报 → 推进 tick → 检查 sink 收到的
QSEv / 序列化字节":

| 测试组 | 用例要点 |
|---|---|
| ReportingModeTest | OFF 丢弃;BRIEF 清 context;DETAILED 保留;两种 BYPASSING 跳链 |
| BlockStateTest | `IdsM_BswM_StateChanged` 切状态后同事件从放行变丢弃;空表恒放行 |
| ForwardNthTest | n=3 放行第 1/4/7 个;count>1 累加越界仍放行(01034) |
| AggregationTest | 窗内 3 事件合 1、count=3、保留首 context;跨窗不合并 |
| ThresholdTest | p=3 时前 2 丢弃第 3 起放行;窗过期清零 |
| RateLimitTest | 超 max_events 丢弃;多 SEv 共享计数器(实例级) |
| TrafficLimitTest | 按序列化字节超限丢弃;触发内部 SEv |
| ChainOrderTest | 构造链验证短路:前级丢弃后级计数器不动(01005) |
| ProtocolTest | 序列化:8B Event Frame 位布局、大端序、Header 标志位、7/31bit 长度编码、时间戳 30/32bit 拆分 |
| QsevStructTest | QSEv 字段正确填充,version=2,count 初值=1 |
| CompatTest | 旧 `IdsM_ReportEvent` 转调路径等价 |
| IdsRmSinkTest | JSON 含 ids_message hex 与解码字段;限速后数量正确 |
| NoOperatingModeTest | 操作模式 API 已删除后,等价语义经 rptmode/blockstate 达成 |

## 10. 实施阶段

| 阶段 | 内容 | 验收 |
|---|---|---|
| 1 ✅ (2026-08-25) | 数据模型(§2.1–2.3)+ 新 API + Reporting Mode + QSEv + **PRS 序列化器** + IdsRm sink 化;删除操作模式(方案 A) | 56/56 测试通过 + CLI 端到端冒烟通过 |
| 2 ✅ (2026-08-25) | BlockState(`IdsM_BswM_StateChanged`)+ ForwardNth | 对应测试组通过 |
| 3 | Aggregation + Threshold(工作线程 tick 改造) | 对应测试组通过 |
| 4 | Rate/Traffic Limitation + 内部 SEv 机制落地第一个事件 | 对应测试组通过 |
| 5 | 兼容层删除、CLI/README/CLAUDE.md 更新 | 全量 ctest 通过 |

阶段 1 是数据结构大改;2–4 纯增量、互不阻塞。

## 11. 暂不实现(明确排除)

- `IdsM_SetSecurityEvent*` 六变体(规范 obsolete)
- PduR `IdsM_CopyTxData`/`TxConfirmation`、Csm 签名、StbM 真实接入、
  Firewall 模块本体——留接口位置(字段/回调类型/序列化器),仿真环境用桩
- DCM 诊断、NvM 持久化、DET 错误码表——P1/P2 迭代
