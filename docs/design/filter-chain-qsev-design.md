# IDSM 过滤器链与 QSEv 设计文档

> 依据:`docs/AutoSar/R24-11/CP/AUTOSAR_CP_SWS_IntrusionDetectionSystemManager.pdf`
> (AUTOSAR CP R24-11, Document ID 977) §7.3–7.8、§8.3
> 状态：设计评审稿 | 日期：2026-08-25

---

## 1. 目标与范围

将现有 IDSM 实现从"monitor + 单一防洪窗口"模型升级为 R24-11 规范的
**SEv → 过滤器链 → QSEv** 模型。本设计覆盖 P0 范围:

1. 新上报 API `IdsM_ReportSecurityEvent`(§8.3.4)
2. 报告模式过滤器(Reporting Mode,§7.6.1.1)
3. 过滤器链框架 + 5 种事件级过滤器(§7.6)
4. QSEv 数据结构(§7.8.1)
5. 2 种实例级限速过滤器(§7.6.4)

**保持不变的架构决策**:现有的"非阻塞入队 + 后台工作线程异步处理"模型恰好
符合规范 [SWS_IdsM_00901](事件存入 Event Buffer，在 MainFunction 中异步
qualify)——工作线程即 MainFunction 的等价物，过滤器链全部在工作线程上
执行，`IdsM_ReportSecurityEvent()` 保持 <1µs 纯入队。

**IdsRm 的定位**:IdsRm 改造为 QSEv 的消费者(sink 角色，对应规范的 IdsR),
挂在过滤器链输出之后。现有 HTTP 转发功能保留。

---

## 2. 数据模型

### 2.1 安全事件标识(§7.3.2)

规范中事件的唯一标识是三元组，而非现有的 (monitor_id, event_id):

```
SEv 标识 = ( IdsMExternalEventId ,  IdsMSensorInstanceId )
                ↓ 配置时映射
        IdsMInternalEventId (内部索引, 0..N-1)
                ↓ 传感器使用
        符号名常量 (SymbolicNameValue)  —— 生成代码中的 #define
```

- **外部事件 ID**:全局唯一的事件类型 ID(SecXT 模型中定义),`0xFFFF` 为无效值
  [SWS_IdsM_00604]
- **传感器实例 ID**:同一 ECU 内多个同类传感器上报告同类事件时的区分号,
  单实例时配 0
- **内部事件 ID**:由 IdsM 在 Init 时按配置数组下标分配，传感器不感知
  [SWS_IdsM_00601/00602]

```c
/* IdsM_Types.h */
typedef uint16_t IdsM_SecurityEventIdType;          /* §8.2.2 内部 ID */
typedef uint16_t IdsM_ExternalSecurityEventIdType;  /* §8.2.7 外部 ID,0xFFFF 无效 */
typedef uint8_t  IdsM_SensorInstanceIdType;
```

应用侧使用符号常量，手工配置期用宏模拟生成代码:

```c
/* 应用配置示例(模拟配置生成器输出) */
#define IDSM_SEV_CAN_IDS_FLOOD          ((IdsM_SecurityEventIdType)0)
#define IDSM_SEV_SECOC_AUTH_FAIL        ((IdsM_SecurityEventIdType)1)
#define IDSM_SEV_ETH_PORT_SCAN          ((IdsM_SecurityEventIdType)2)
```

**迁移映射**(现有 5 个 monitor → SEv 定义):

| 现 monitor_id | 外部事件 ID | 传感器实例 ID | 说明 |
|---|---|---|---|
| 0x001 CAN-IDS | 0x0001 | 0 | CAN 总线入侵检测 |
| 0x002 SecOC | 0x0002 | 0 | SecOC 认证失败 |
| 0x003 Ethernet | 0x0003 | 0 | 以太网 IDS |
| 0x004 OBD-II | 0x0004 | 0 | OBD-II 扫描 |
| 0x005 FW-Integrity | 0x0005 | 0 | 固件完整性 |

### 2.2 上报 API(§8.3.4)

```c
/* IdsM.h — 替代现有 IdsM_ReportEvent */
void IdsM_ReportSecurityEvent(
    IdsM_SecurityEventIdType        securityEventId,    /* 符号名常量 */
    const uint8_t*                  contextData,        /* NULL = 无上下文 */
    uint16_t                        contextDataSize,    /* 无上下文填 0 */
    uint16_t                        contextDataVersion, /* 无上下文填 1 (R24-11 新增) */
    uint16_t                        count,              /* 传感器侧已聚合次数, [1, 65535] */
    const IdsM_TimestampDataType*   timestamp           /* NULL = 由 IdsM 内部取时 */
);
```

与现状的差异:

- **severity 移出上报参数**——规范中 severity 是 SEv 的配置属性(R23-11 引入),
  不是上报时的变量。CLI 的 `sev=` 参数改为配置项
- **count** 支持"智能传感器"侧预聚合(§7.3.1.1):传感器自己数了 N 次才上报一次,
  下游过滤器必须按 count 累加而非按次数累加
- **timestamp** 允许传感器自带时间戳(StbM 同步时间);NULL 时由 IdsM 用内部
  `steady_clock` 取时(后续可换 StbM 适配层)
- 旧 `IdsM_SetSecurityEvent*` 六变体规范已标 obsolete,**不实现**;
  现有 `IdsM_ReportEvent()` 保留一个版本作为兼容包装(内部转调新 API,
  count=1, version=1),下个迭代删除

### 2.3 QSEv 结构(§7.8.1)

过滤器链全部通过后的产出物。结构独立于 sink[SWS_IdsM_01200]:

```c
/* IdsM_Types.h */
typedef struct {
    /* --- 协议头(对应 IDS Protocol v2 字段,暂以平铺字段表示) --- */
    uint8_t                            protocol_version;  /* IDS 协议版本,新 API=2 */
    uint8_t                            idsm_instance_id;  /* 本 ECU 的 IdsM 实例 ID,配置项 */
    /* --- 事件身份 --- */
    IdsM_ExternalSecurityEventIdType   external_event_id;
    IdsM_SensorInstanceIdType          sensor_instance_id;
    /* --- 事件内容 --- */
    IdsM_EventSeverityType             severity;          /* 取自 SEv 配置 */
    uint16_t                           count;             /* 聚合后的次数,创建时=1 */
    uint16_t                           context_data_version;
    IdsM_TimestampDataType             timestamp;
    /* context data 本体在 C++ 侧为 std::vector<uint8_t>(OwnedQSEv) */
    const uint8_t*                     context_data;
    uint16_t                           context_data_size;
} IdsM_QualifiedSecurityEventType;
```

C++ 内部使用 `IdsM_OwnedQSEv`(深拷贝 context data),与现有
`IdsM_OwnedEvent` 同一模式,保证跨队列边界的所有权安全。

### 2.4 报告模式(§7.6.1.1)

**取代现有 PRE_RUN/RUN/POST_RUN 操作模式**。每个 SEv 一个报告模式,
是过滤器链之前的必经判定(规范强制,[SWS_IdsM_01010/01011]):

```c
typedef enum {
    IDSM_REPORTING_OFF                        = 0, /* 直接丢弃,不做任何处理 */
    IDSM_REPORTING_BRIEF                      = 1, /* 丢弃 context data 后进过滤器链 */
    IDSM_REPORTING_DETAILED                   = 2, /* 保留 context data 进过滤器链 */
    IDSM_REPORTING_BRIEF_BYPASSING_FILTERS    = 3, /* 丢弃 context data,跳过过滤器链,直接成 QSEv */
    IDSM_REPORTING_DETAILED_BYPASSING_FILTERS = 4  /* 保留 context data,跳过过滤器链,直接成 QSEv */
} IdsM_Filters_ReportingModeType;  /* §8.2.4 */
```

运行时可通过 `IdsM_SetReportingMode(sevId, mode)` 修改(为 P1 的 DCM
诊断接口预留;该接口也是 NvM 持久化的对象,§7.9)。

**现有操作模式的迁移**:`IdsM_SetOperatingMode(PRE_RUN/RUN/POST_RUN)`
在规范中没有对应物。两个选择:

- **方案 A(推荐)**:删除操作模式。CLI 的 `mode` 命令改为批量设置报告模式
- **方案 B**:把操作模式保留为 Block State Filter 的状态源(见 §3.2)——
  PRE_RUN/RUN/POST_RUN 作为 3 个 IdsMBlockState,由
  `IdsM_BswM_StateChanged` 等价 API 通知

本设计采用**方案 B**:既符合规范,又不破坏现有 CLI 体验和测试惯性。

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

- **短路**:任一过滤器丢弃,后续过滤器不再评估[SWS_IdsM_01005]
- **顺序固定**:BlockState → ForwardNth → Aggregation → Threshold
  [SWS_IdsM_01004],不可配置
- **链可选**:SEv 可以不配过滤器链(裸事件,报告模式非 OFF 即直通)
- **事件级 vs 实例级**:1–4 按 SEv 独立维护状态;5–6 是整个 IdsM 实例共享
  一个计数器(§7.6.4 注),只在发往 IdsR(本项目中=IdsRm)前应用,
  **不影响 Dem 存储 sink**

### 3.2 各过滤器设计

#### 3.2.1 Reporting Mode Filter
见 §2.4。在事件出队后、链评估前判定[SWS_IdsM_01002]。
BRIEF 模式在此处清空 context data(后续所有环节都看不到)。

#### 3.2.2 Block State Filter(§7.6.1.2)

```c
typedef uint8_t IdsM_BlockStateIdType;   /* 状态符号名,BswM 域 */

/* 配置:该 SEv 在哪些状态下被阻塞 */
typedef struct {
    IdsM_BlockStateIdType blocked_states[8];  /* IdsMBlockState 列表 */
    uint8_t               num_blocked_states;
} IdsM_BlockStateFilterConfigType;
```

- 当前状态由 `IdsM_BswM_StateChanged(stateId)` 回调更新
  [SWS_IdsM_01022];在本仿真项目中,`IdsM_SetOperatingMode()` 内部
  转调它,把 PRE_RUN=1 / RUN=2 / POST_RUN=3 注册为三个状态
- 判定在工作线程异步执行[SWS_IdsM_01022]:当前状态 ∈ 阻塞表 → 丢弃
- 这就完整复刻了现有"某模式下监控器禁用"的语义:CLI 配置里
  `enabled_in_post_run=false` 等价于"阻塞状态表含 POST_RUN"

#### 3.2.3 Forward Every Nth(§7.6.2.1)

```c
typedef struct {
    uint16_t n;          /* IdsMNthParameter */
    uint16_t counter;    /* 运行时状态 */
} IdsM_ForwardEveryNthFilterType;
```

- 放行第 1、n+1、2n+1… 个 SEv;`counter == n` 时放行并清零
  [SWS_IdsM_01031/01032]
- **不修改 SEv 数据**[SWS_IdsM_01033]:count 保持原值透传
- count>1 的 SEv 到达时计数器按 count 累加,可超过 n,此时仍放行
  且聚合 count 原样带出[SWS_IdsM_01034]

#### 3.2.4 Event Aggregation Filter(§7.6.3.1)

时间窗内同 SEv ID 的事件合并为一个,count 累加:

```c
typedef struct {
    uint32_t interval_ms;     /* IdsMEventAggregationTimeInterval,
                                 必须是 MainFunction 周期的整数倍 */
    /* 运行时状态 */
    bool     has_pending;     /* 窗内已有暂存事件 */
    IdsM_OwnedQSEv* pending;  /* 暂存的聚合事件(C++ 侧) */
    uint32_t window_start_ms;
} IdsM_AggregationFilterType;
```

- 窗内首个 SEv 暂存;后续同 ID SEv 到来 → `pending->count += sev.count`,
  context data 保留**首个**事件的(规范:聚合保留首事件数据)
- 窗口到期(工作线程 tick 检查)→ 把 pending 作为单个 SEv 交给下一个过滤器
- 这是**唯一会延迟事件**的过滤器,需要工作线程周期 tick(见 §4.2)

#### 3.2.5 Event Threshold Filter(§7.6.3.2)

```c
typedef struct {
    uint16_t threshold;       /* IdsMEventThresholdNumber */
    uint32_t interval_ms;     /* IdsMEventThresholdTimeInterval,
                                 MainFunction 周期整数倍 [SWS_IdsM_01064] */
    /* 运行时状态 */
    uint32_t accumulated;     /* 当前窗内 count 累加值 */
    uint32_t window_start_ms;
} IdsM_ThresholdFilterType;
```

- 窗内 `accumulated < threshold` → 丢弃并累加;`accumulated >= threshold`
  → 该 SEv 及本窗内后续 SEv **立即放行**,不做修改[SWS_IdsM_01061/01062]
- 窗口到期计数器清零[SWS_IdsM_01063],计时从 MainFunction 首次调用开始
  [SWS_IdsM_01065]

#### 3.2.6 Event Rate Limitation(§7.6.4.1,实例级)

```c
typedef struct {
    uint32_t max_events;      /* IdsMRateLimitationMaximumEvents */
    uint32_t interval_ms;     /* IdsMRateLimitationTimeInterval */
    /* 运行时 */
    uint32_t sent_in_window;
    uint32_t window_start_ms;
} IdsM_RateLimitationFilterType;
```

发送 QSEv 将使窗内发送数超 max_events → 丢弃[SWS_IdsM_01081]。
现有的 `flood_protection_ms` 由此取代并删除。

#### 3.2.7 Traffic Limitation(§7.6.4.2,实例级)

同上,但按 QSEv 序列化**字节数**计[SWS_IdsM_01091];超限且配置了内部
事件时,上报 `IDSM_INTERNAL_EVENT_TRAFFIC_LIMITATION_EXCEEDED`
[SWS_IdsM_01094]——作为内部 SEv 机制的第一个实例(§7.4,P2 再补全)。

### 3.3 配置结构(替代 IdsM_MonitorConfigType)

```c
/* 单个 SEv 的配置 */
typedef struct {
    IdsM_ExternalSecurityEventIdType    external_event_id;
    IdsM_SensorInstanceIdType           sensor_instance_id;
    IdsM_EventSeverityType              severity;            /* 配置属性,不再上报时传 */
    IdsM_Filters_ReportingModeType      default_reporting_mode;
    /* 过滤器链:NULL/0 = 未配置该过滤器 */
    const IdsM_BlockStateFilterConfigType*    block_state;
    uint16_t                                 forward_every_nth;   /* 0=禁用 */
    uint32_t                                 aggregation_interval_ms; /* 0=禁用 */
    struct { uint16_t threshold; uint32_t interval_ms; } event_threshold; /* threshold=0=禁用 */
    /* sink 列表 [SWS_IdsM_01201] */
    boolean                                  sink_to_dem;
    boolean                                  sink_to_idsr;   /* 本项目 = IdsRm */
} IdsM_SecurityEventConfigType;

/* 实例级配置 */
typedef struct {
    uint8_t                             idsm_instance_id;
    uint32_t                            main_function_period_ms;  /* 工作线程 tick 周期 */
    struct { uint32_t max_events; uint32_t interval_ms; } rate_limitation;    /* max_events=0=禁用 */
    struct { uint32_t max_bytes;  uint32_t interval_ms; } traffic_limitation; /* max_bytes=0=禁用 */
    const IdsM_SecurityEventConfigType* sev_configs;
    uint16_t                            sev_count;
    uint32_t                            event_buffer_size;   /* 入队队列容量 */
} IdsM_ConfigType;   /* §8.2.1 */

STD_RETURN_TYPE IdsM_Init(const IdsM_ConfigType* config);  /* 签名变更 */
```

---

## 4. 与现有异步架构的融合

### 4.1 线程模型(不变)

```
传感器线程                IDSM 工作线程                    IDSRM 工作线程
     │                        │                                │
ReportSecurityEvent()    出队 → Reporting Mode            出队 → HTTP POST
  深拷贝 → 入队  ──►      → 过滤器链(事件级)      ──►    (实例级限速已在
  <1µs 返回               → QSEv → 实例级限速             IDSM 侧完成)
                          → sink 分发(Dem / IdsRm 入队)
```

### 4.2 工作线程 tick 改造

Aggregation/Threshold/Rate/Traffic 都基于时间窗,需要周期唤醒。现有工作线程
是事件驱动(条件变量),改造为:

```cpp
// IdsM_Manager.cpp 工作线程主循环
while (running) {
    // 1. 处理队列中所有待办事件(过滤器链)
    // 2. 检查各时间窗是否到期:
    //    - aggregation pending 到窗 → 送入链下游
    //    - threshold 窗到期 → 清零
    //    - rate/traffic 窗到期 → 清零
    // 3. 计算下次最早到期时间,condition_variable::wait_until
}
```

`main_function_period_ms`(默认 10ms)是 tick 粒度上限,窗口配置必须是
其整数倍[SWS_IdsM_01064/01082/01092]——Init 时校验,不满足返回
`E_NOT_OK`(后续接 DET 错误码)。

### 4.3 缓冲区

保留现有单一入队队列(所有 SEv 共享),容量由 `event_buffer_size` 配置。
规范 §7.3.3 允许每 SEv 独立 buffer,但共享队列对本项目规模足够,且保留
现有"溢出丢最旧"语义;溢出时上报内部 SEv(P2)。

---

## 5. IdsRm 改造(sink 化)

```
现状:IdsRm_Init() → IdsM_SetDemReportCallback(收原始事件)
改为:IdsRm_Init() → IdsM_RegisterIdsrSink(callback)(收 QSEv)
```

- 回调签名改为 `void (*IdsM_IdsrSinkCallbackType)(const IdsM_QualifiedSecurityEventType*)`
- JSON 报文扩展(向后兼容地加字段):

```json
{
    "protocol_version": 2,
    "idsm_instance_id": 1,
    "external_event_id": 1,
    "sensor_instance_id": 0,
    "severity": "HIGH",
    "count": 3,
    "timestamp_ms": 42000,
    "context_data_version": 1,
    "payload": "00000123080102030405060708",
    "payload_len": 13
}
```

- 实例级 Rate/Traffic Limitation 在 IDSM 侧已过滤,IdsRm 无需感知
- Grafana dashboard 的 monitor 维度改用 `external_event_id`

## 6. 兼容与迁移

| 旧 API | 处置 |
|---|---|
| `IdsM_ReportEvent()` | 保留一个迭代,内部转调新 API(count=1, ver=1),标 `[[deprecated]]` 注释 |
| `IdsM_SetOperatingMode()` | 保留,内部转调 Block State 状态更新(方案 B) |
| `IdsM_GetDetectionStatus()` | 保留(项目自定义功能,规范外),语义不变 |
| `flood_protection_ms` 配置字段 | 删除,由 Rate Limitation 取代 |
| `IdsM_MonitorConfigType` | 删除,由 `IdsM_ConfigType`/`IdsM_SecurityEventConfigType` 取代 |

## 7. 测试计划(Google Test)

每个过滤器独立单测 + 链集成测试,均用"上报 → 手动推进 tick → 检查 sink 收到
的 QSEv"模式:

| 测试组 | 用例要点 |
|---|---|
| ReportingModeTest | OFF 丢弃;BRIEF 清 context;DETAILED 保留;两种 BYPASSING 跳链 |
| BlockStateTest | 状态切换后同事件从放行变丢弃;阻塞表为空恒放行 |
| ForwardNthTest | n=3 放行第 1/4/7 个;count>1 累加越界仍放行(01034) |
| AggregationTest | 窗内 3 事件合 1、count=3、保留首 context;跨窗不合并 |
| ThresholdTest | p=3 时前 2 丢弃第 3 起放行;窗过期计数清零 |
| RateLimitTest | 超 max_events 丢弃;多 SEv 共享计数器(实例级) |
| TrafficLimitTest | 按字节超限丢弃;触发内部 SEv |
| ChainOrderTest | 构造链验证短路:前级丢弃后级计数器不动(01005) |
| QsevStructTest | QSEv 各字段正确填充,version=2,count 初值=1 |
| CompatTest | 旧 `IdsM_ReportEvent` 转调路径等价 |
| IdsRmSinkTest | 改造后 JSON 字段齐全;限速后 IdsRm 收到的事件数正确 |

## 8. 实施阶段

| 阶段 | 内容 | 验收 |
|---|---|---|
| 1 | 数据模型 + `IdsM_ReportSecurityEvent` + Reporting Mode + QSEv 结构,IdsRm sink 化 | 现有 39 测试迁移通过 + ReportingMode/QsevStruct 测试 |
| 2 | BlockState(含操作模式桥接)+ ForwardNth | 对应测试组通过 |
| 3 | Aggregation + Threshold(工作线程 tick 改造) | 对应测试组通过 |
| 4 | Rate/Traffic Limitation + 内部 SEv 机制落地第一个事件 | 对应测试组通过 |
| 5 | 兼容层删除、CLI/README 更新 | 全量 ctest 通过 |

阶段 1 是数据结构大改,后续阶段纯增量、互不阻塞。

## 9. 暂不实现(明确排除)

- `IdsM_SetSecurityEvent*` 六变体(规范 obsolete)
- PduR `IdsM_CopyTxData`/`TxConfirmation`、Csm 签名、StbM 真实接入——
  留接口位置(结构体字段、回调类型),仿真环境用桩
- DCM 诊断、NvM 持久化、DET 错误码表——P1/P2 迭代
- IDS Protocol 报文二进制序列化([4] IDS Protocol 规范)——QSEv 先以
  结构化形式在 ECU 内流转,序列化在真正对接 IdsR 协议时再做
