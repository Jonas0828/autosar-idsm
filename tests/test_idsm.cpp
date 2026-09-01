#include <gtest/gtest.h>
#include <atomic>
#include <thread>
#include <chrono>
#include <functional>
#include <cstring>
#include "IdsM.h"
#include "IdsM_Protocol.h"

/* ── Helpers ──────────────────────────────────────────────────────────────── */

/* Polls condition every 10ms up to max_ms. Returns true if condition met. */
static bool wait_until(std::function<bool()> cond, int max_ms = 1000) {
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(max_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (cond()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return cond(); /* final check */
}

static IdsM_SecurityEventConfigType make_sev(
    IdsM_ExternalSecurityEventIdType ext_id = 0x8001,
    IdsM_Filters_ReportingModeType mode = IDSM_REPORTING_DETAILED,
    IdsM_EventSeverityType severity = IDSM_SEVERITY_HIGH)
{
    IdsM_SecurityEventConfigType s{};
    s.external_event_id      = ext_id;
    s.sensor_instance_id     = 0;
    s.severity               = severity;
    s.default_reporting_mode = mode;
    s.block_state            = nullptr;
    s.forward_every_nth      = 0;
    s.aggregation_interval_ms = 0;
    s.event_threshold        = {0, 0};
    s.sink_to_dem            = true;
    s.sink_to_idsr           = true;
    return s;
}

static IdsM_ConfigType make_config(const IdsM_SecurityEventConfigType* sevs, uint16_t n) {
    IdsM_ConfigType c{};
    c.idsm_instance_id        = 1;
    c.main_function_period_ms = 10;
    c.rate_limitation         = {0, 0};
    c.traffic_limitation      = {0, 0};
    c.sev_configs             = sevs;
    c.sev_count               = n;
    c.event_buffer_size       = 128;
    return c;
}

/* Persistent payload buffer — ReportSecurityEvent deep-copies, safe as static. */
static uint8_t g_test_payload[4] = {0xDE, 0xAD, 0xBE, 0xEF};

/* ── Shared sink capture state ────────────────────────────────────────────── */

static std::atomic<int>      g_dem_count{0};
static std::atomic<uint16_t> g_last_ext_id{0};
static std::atomic<uint16_t> g_last_count{0};
static std::atomic<uint16_t> g_last_ctx_version{0};
static std::atomic<size_t>   g_last_ctx_size{0};
static IdsM_EventSeverityType g_last_severity = IDSM_SEVERITY_LOW;
static bool                  g_last_has_ts = false;

static void dem_cb(const IdsM_QualifiedSecurityEventType* q) {
    g_dem_count++;
    g_last_ext_id.store(q->external_event_id);
    g_last_count.store(q->count);
    g_last_ctx_version.store(q->context_data_version);
    g_last_ctx_size.store(q->context_data_size);
    g_last_severity  = q->severity;
    g_last_has_ts    = q->has_timestamp;
}

/* ── Fixture ──────────────────────────────────────────────────────────────── */

class IdsMTest : public ::testing::Test {
protected:
    void SetUp() override {
        g_dem_count.store(0);
        g_last_ext_id.store(0);
        g_last_count.store(0);
        g_last_ctx_version.store(0);
        g_last_ctx_size.store(0);
    }

    void TearDown() override {
        IdsM_DeInit();
    }

    void init_default(IdsM_Filters_ReportingModeType mode = IDSM_REPORTING_DETAILED) {
        auto sev = make_sev(0x8001, mode);
        init_with_sev(sev);
    }

    void init_with_sev(const IdsM_SecurityEventConfigType& sev) {
        auto cfg = make_config(&sev, 1);
        ASSERT_EQ(E_OK, IdsM_Init(&cfg));
        IdsM_SetDemReportCallback(dem_cb);
        /* Give the worker thread a moment to start and enter wait */
        std::this_thread::sleep_for(std::chrono::milliseconds(15));
    }

    void report_default(uint16_t count = 1) {
        IdsM_ReportSecurityEvent(0, g_test_payload, sizeof(g_test_payload),
                                 1 /*version*/, count, nullptr);
    }

    /* Report n events (count=1 each) */
    void report_n(int n) {
        for (int i = 0; i < n; ++i) report_default();
    }
};

/* ═══════════════════════════════════════════════════════════════════════════
   Lifecycle
   ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(IdsMTest, InitDeInit) {
    auto sev = make_sev();
    auto cfg = make_config(&sev, 1);
    EXPECT_EQ(E_OK, IdsM_Init(&cfg));
    EXPECT_EQ(E_OK, IdsM_DeInit());
}

TEST_F(IdsMTest, InitNullConfig) {
    EXPECT_EQ(E_PARAM_POINTER, IdsM_Init(nullptr));
}

TEST_F(IdsMTest, InitNullSevArrayNonZeroCount) {
    IdsM_ConfigType cfg = make_config(nullptr, 3);
    EXPECT_EQ(E_PARAM_POINTER, IdsM_Init(&cfg));
}

TEST_F(IdsMTest, InitRejectsInvalidExternalEventId) {
    auto sev = make_sev(IDSM_EXTERNAL_EVENT_ID_INVALID);
    auto cfg = make_config(&sev, 1);
    EXPECT_EQ(E_PARAM_CONFIG, IdsM_Init(&cfg));
}

TEST_F(IdsMTest, InitRejectsSensorInstanceIdAbove63) {
    auto sev = make_sev();
    sev.sensor_instance_id = 64;
    auto cfg = make_config(&sev, 1);
    EXPECT_EQ(E_PARAM_CONFIG, IdsM_Init(&cfg));
}

/* ═══════════════════════════════════════════════════════════════════════════
   Reporting Mode Filter (CP §7.6.1.1)
   ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(IdsMTest, ReportingModeOffDiscardsEvent) {
    init_default(IDSM_REPORTING_OFF);
    report_default();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(0, g_dem_count.load());
    /* Dropped before acceptance — detection status untouched */
    EXPECT_EQ(IDSM_STATUS_UNINITIALIZED, IdsM_GetDetectionStatus(0));
}

TEST_F(IdsMTest, ReportingModeBriefDropsContextData) {
    init_default(IDSM_REPORTING_BRIEF);
    report_default();
    ASSERT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }));
    EXPECT_EQ(0u, g_last_ctx_size.load());   /* context stripped */
}

TEST_F(IdsMTest, ReportingModeDetailedKeepsContextData) {
    init_default(IDSM_REPORTING_DETAILED);
    report_default();
    ASSERT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }));
    EXPECT_EQ(sizeof(g_test_payload), g_last_ctx_size.load());
}

TEST_F(IdsMTest, ReportingModeBriefBypassingQualifiesImmediately) {
    init_default(IDSM_REPORTING_BRIEF_BYPASSING_FILTERS);
    report_default();
    ASSERT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }));
    EXPECT_EQ(0u, g_last_ctx_size.load());
}

TEST_F(IdsMTest, ReportingModeDetailedBypassingKeepsContext) {
    init_default(IDSM_REPORTING_DETAILED_BYPASSING_FILTERS);
    report_default();
    ASSERT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }));
    EXPECT_EQ(sizeof(g_test_payload), g_last_ctx_size.load());
}

TEST_F(IdsMTest, SetReportingModeAtRuntime) {
    init_default(IDSM_REPORTING_DETAILED);
    EXPECT_EQ(IDSM_REPORTING_DETAILED, IdsM_GetReportingMode(0));

    ASSERT_EQ(E_OK, IdsM_SetReportingMode(0, IDSM_REPORTING_OFF));
    EXPECT_EQ(IDSM_REPORTING_OFF, IdsM_GetReportingMode(0));

    report_default();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(0, g_dem_count.load());

    ASSERT_EQ(E_OK, IdsM_SetReportingMode(0, IDSM_REPORTING_DETAILED));
    report_default();
    EXPECT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }));
}

TEST_F(IdsMTest, SetReportingModeRejectsInvalidSevAndMode) {
    init_default();
    EXPECT_EQ(E_PARAM_CONFIG, IdsM_SetReportingMode(0x99, IDSM_REPORTING_DETAILED));
    EXPECT_EQ(E_PARAM_CONFIG,
              IdsM_SetReportingMode(0, static_cast<IdsM_Filters_ReportingModeType>(99)));
}

/* ═══════════════════════════════════════════════════════════════════════════
   Block State Filter (CP §7.6.1.2)
   ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(IdsMTest, BlockStateDropsEventsInBlockedState) {
    static const IdsM_BlockStateFilterConfigType block_cfg = {{5}, 1};
    auto sev = make_sev(0x8001);
    sev.block_state = &block_cfg;
    init_with_sev(sev);

    /* Current state 0 (not blocked) -> flows */
    report_default();
    ASSERT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }));

    /* Enter blocked state 5 -> dropped */
    IdsM_BswM_StateChanged(5);
    report_default();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(1, g_dem_count.load());

    /* Back to a non-blocked state -> flows again */
    IdsM_BswM_StateChanged(0);
    report_default();
    EXPECT_TRUE(wait_until([&]{ return g_dem_count.load() >= 2; }));
}

TEST_F(IdsMTest, BlockStateNullConfigAlwaysPasses) {
    init_default();   /* block_state = nullptr */
    IdsM_BswM_StateChanged(7);
    report_default();
    EXPECT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }));
}

TEST_F(IdsMTest, BlockStateSkippedInBypassingMode) {
    static const IdsM_BlockStateFilterConfigType block_cfg = {{5}, 1};
    auto sev = make_sev(0x8001, IDSM_REPORTING_DETAILED_BYPASSING_FILTERS);
    sev.block_state = &block_cfg;
    init_with_sev(sev);

    IdsM_BswM_StateChanged(5);   /* blocked, but BYPASSING mode skips the chain */
    report_default();
    EXPECT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }));
}

/* ═══════════════════════════════════════════════════════════════════════════
   Forward Every Nth Filter (CP §7.6.2.1)
   ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(IdsMTest, ForwardNthPassesFirstAndEveryThird) {
    /* n=3 -> forwards SEvs 1, 4, 7 [SWS_IdsM_01031 example] */
    auto sev = make_sev(0x8001);
    sev.forward_every_nth = 3;
    init_with_sev(sev);

    report_n(7);
    EXPECT_TRUE(wait_until([&]{ return g_dem_count.load() >= 3; }, 2000));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(3, g_dem_count.load());
}

TEST_F(IdsMTest, ForwardNthResetsCounterAfterForwarding) {
    /* n=2 -> forwards 1, 3, 5: counter restarts after each pass */
    auto sev = make_sev(0x8001);
    sev.forward_every_nth = 2;
    init_with_sev(sev);

    report_n(5);
    EXPECT_TRUE(wait_until([&]{ return g_dem_count.load() >= 3; }, 2000));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(3, g_dem_count.load());
}

TEST_F(IdsMTest, ForwardNthAccumulatesSensorCount) {
    /* [SWS_IdsM_01034]: count>1 accumulates in the counter, may exceed n.
       n=3; events with count=2: e1 (counter 3+2>=3 -> fwd), e2 (2 < 3 -> drop),
       e3 (2+2>=3 -> fwd) */
    auto sev = make_sev(0x8001);
    sev.forward_every_nth = 3;
    init_with_sev(sev);

    report_default(2);
    report_default(2);
    report_default(2);
    EXPECT_TRUE(wait_until([&]{ return g_dem_count.load() >= 2; }, 2000));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(2, g_dem_count.load());
    /* Forwarded SEv keeps its original count unmodified [SWS_IdsM_01033] */
    EXPECT_EQ(2, g_last_count.load());
}

TEST_F(IdsMTest, ForwardNthDisabledWhenZero) {
    auto sev = make_sev(0x8001);
    sev.forward_every_nth = 0;
    init_with_sev(sev);

    report_n(4);
    EXPECT_TRUE(wait_until([&]{ return g_dem_count.load() >= 4; }, 2000));
}

TEST_F(IdsMTest, ForwardNthIsPerSevIndependent) {
    /* Two SEvs with different n: counters independent */
    IdsM_SecurityEventConfigType sevs[2] = {
        make_sev(0x8001), make_sev(0x8002)
    };
    sevs[0].forward_every_nth = 3;   /* 1 of 3 passes */
    sevs[1].forward_every_nth = 0;   /* all pass */
    auto cfg = make_config(sevs, 2);
    ASSERT_EQ(E_OK, IdsM_Init(&cfg));
    IdsM_SetDemReportCallback(dem_cb);
    std::this_thread::sleep_for(std::chrono::milliseconds(15));

    for (int i = 0; i < 6; ++i) IdsM_ReportSecurityEvent(0, nullptr, 0, 1, 1, nullptr);
    for (int i = 0; i < 6; ++i) IdsM_ReportSecurityEvent(1, nullptr, 0, 1, 1, nullptr);

    /* sev0: 2 pass (1st, 4th); sev1: 6 pass -> total 8 */
    EXPECT_TRUE(wait_until([&]{ return g_dem_count.load() >= 8; }, 2000));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(8, g_dem_count.load());
}

/* ═══════════════════════════════════════════════════════════════════════════
   Event Aggregation Filter (CP §7.6.3.1)
   ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(IdsMTest, AggregationMergesWindowIntoSingleQsev) {
    auto sev = make_sev(0x8001);
    sev.aggregation_interval_ms = 200;   /* multiple of period 10 */
    init_with_sev(sev);

    report_n(3);   /* three SEvs within the window */
    /* None qualified while the window is open */
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_EQ(0, g_dem_count.load());

    /* After the window expires: one aggregate with the accumulated count */
    ASSERT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }, 2000));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(1, g_dem_count.load());
    EXPECT_EQ(3, g_last_count.load());                    /* merged count */
    EXPECT_EQ(sizeof(g_test_payload), g_last_ctx_size.load()); /* first ctx kept */
}

TEST_F(IdsMTest, AggregationKeepsFirstContextOnly) {
    auto sev = make_sev(0x8001);
    sev.aggregation_interval_ms = 150;
    init_with_sev(sev);

    report_default();                    /* first: carries g_test_payload */
    report_default();                    /* second: same payload anyway */
    ASSERT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }, 2000));
    EXPECT_EQ(sizeof(g_test_payload), g_last_ctx_size.load());
}

TEST_F(IdsMTest, AggregationAddsSensorCount) {
    /* count pre-aggregation adds up: 2 + 3 = 5 [PRS_Ids_00018] */
    auto sev = make_sev(0x8001);
    sev.aggregation_interval_ms = 150;
    init_with_sev(sev);

    report_default(2);
    report_default(3);
    ASSERT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }, 2000));
    EXPECT_EQ(5, g_last_count.load());
}

TEST_F(IdsMTest, AggregationAcrossWindowsDoesNotMerge) {
    auto sev = make_sev(0x8001);
    sev.aggregation_interval_ms = 100;
    init_with_sev(sev);

    report_n(2);                                  /* window 1 */
    std::this_thread::sleep_for(std::chrono::milliseconds(300)); /* expire */
    report_n(2);                                  /* window 2 */

    ASSERT_TRUE(wait_until([&]{ return g_dem_count.load() >= 2; }, 2000));
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    EXPECT_EQ(2, g_dem_count.load());             /* two separate aggregates */
    EXPECT_EQ(2, g_last_count.load());            /* each carries its own 2 */
}

TEST_F(IdsMTest, AggregationDisabledWhenZero) {
    init_default();   /* aggregation_interval_ms = 0 */
    report_n(3);
    EXPECT_TRUE(wait_until([&]{ return g_dem_count.load() >= 3; }, 2000));
}

TEST_F(IdsMTest, AggregationIsPerSevIndependent) {
    IdsM_SecurityEventConfigType sevs[2] = {
        make_sev(0x8001), make_sev(0x8002)
    };
    sevs[0].aggregation_interval_ms = 150;   /* aggregates */
    sevs[1].aggregation_interval_ms = 0;     /* passes through */
    auto cfg = make_config(sevs, 2);
    ASSERT_EQ(E_OK, IdsM_Init(&cfg));
    IdsM_SetDemReportCallback(dem_cb);
    std::this_thread::sleep_for(std::chrono::milliseconds(15));

    for (int i = 0; i < 2; ++i) IdsM_ReportSecurityEvent(0, nullptr, 0, 1, 1, nullptr);
    for (int i = 0; i < 2; ++i) IdsM_ReportSecurityEvent(1, nullptr, 0, 1, 1, nullptr);

    /* sev0: staged (0 so far); sev1: 2 passed */
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    EXPECT_EQ(2, g_dem_count.load());

    /* sev0's window expires -> 1 aggregate */
    ASSERT_TRUE(wait_until([&]{ return g_dem_count.load() >= 3; }, 2000));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(3, g_dem_count.load());
}

TEST_F(IdsMTest, FlushReleasesPendingAggregation) {
    auto sev = make_sev(0x8001);
    sev.aggregation_interval_ms = 5000;   /* far in the future */
    init_with_sev(sev);

    report_n(2);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_EQ(0, g_dem_count.load());

    EXPECT_EQ(E_OK, IdsM_FlushEvents(0));
    ASSERT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_EQ(1, g_dem_count.load());
    EXPECT_EQ(2, g_last_count.load());    /* aggregate with merged count */
}

/* ═══════════════════════════════════════════════════════════════════════════
   Event Threshold Filter (CP §7.6.3.2)
   ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(IdsMTest, ThresholdDropsUntilAccumulatedThenPasses) {
    /* threshold=3: first two SEvs (count=1) dropped, third onwards passes */
    auto sev = make_sev(0x8001);
    sev.event_threshold = {3, 500};
    init_with_sev(sev);

    report_n(2);
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    EXPECT_EQ(0, g_dem_count.load());     /* below threshold -> dropped */

    report_n(2);                          /* accumulated reaches 3 -> passes */
    ASSERT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }));
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    EXPECT_EQ(2, g_dem_count.load());     /* 3rd and 4th both pass immediately */
}

TEST_F(IdsMTest, ThresholdAccumulatesCount) {
    /* threshold=5, SEvs carry count=2: 2+2 dropped, 2+2 -> 6>=5 pass */
    auto sev = make_sev(0x8001);
    sev.event_threshold = {5, 500};
    init_with_sev(sev);

    report_default(2);
    report_default(2);
    report_default(2);
    EXPECT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }, 2000));
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    EXPECT_EQ(1, g_dem_count.load());     /* only the reaching SEv passed */
}

TEST_F(IdsMTest, ThresholdWindowExpiryResetsAccumulator) {
    auto sev = make_sev(0x8001);
    sev.event_threshold = {3, 100};
    init_with_sev(sev);

    report_n(2);                          /* accumulated 2 < 3 */
    std::this_thread::sleep_for(std::chrono::milliseconds(250)); /* window expires */
    report_n(1);                          /* fresh window: 1 < 3 -> dropped */
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    EXPECT_EQ(0, g_dem_count.load());

    report_n(3);                          /* reaches 3 -> passes */
    ASSERT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }, 2000));
}

TEST_F(IdsMTest, ThresholdDisabledWhenZero) {
    init_default();   /* event_threshold = {0, 0} */
    report_n(3);
    EXPECT_TRUE(wait_until([&]{ return g_dem_count.load() >= 3; }, 2000));
}

/* ═══════════════════════════════════════════════════════════════════════════
   Filter chain order & short-circuit [SWS_IdsM_01004/01005]
   ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(IdsMTest, ChainShortCircuitDownstreamCountersUntouched) {
    /* BlockState drops -> ForwardNth counter and threshold accumulator must
       not move [SWS_IdsM_01005]. After the block clears, the ForwardNth
       counter still forwards the FIRST SEv (proving nothing was counted). */
    static const IdsM_BlockStateFilterConfigType block_cfg = {{5}, 1};
    auto sev = make_sev(0x8001);
    sev.block_state         = &block_cfg;
    sev.forward_every_nth   = 3;
    sev.event_threshold     = {10, 500};
    init_with_sev(sev);

    IdsM_BswM_StateChanged(5);            /* block */
    report_n(4);                          /* all dropped at BlockState */
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    EXPECT_EQ(0, g_dem_count.load());

    IdsM_BswM_StateChanged(0);            /* unblock: ForwardNth counter still
                                             at n=3 -> first SEv forwards */
    report_default();                     /* 1 (fwd, thr 1<10) */
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    EXPECT_EQ(0, g_dem_count.load());     /* forwarded but below threshold */

    report_n(10);                         /* accumulate to threshold */
    ASSERT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }, 2000));
}

TEST_F(IdsMTest, ChainOrderAggregationBeforeThreshold) {
    /* Fixed order: aggregation (stage) -> threshold. A staged aggregate does
       NOT touch the threshold accumulator until the window releases it;
       meanwhile fresh SEvs... none — aggregation absorbs everything. With
       threshold=1 the released aggregate passes immediately on release. */
    auto sev = make_sev(0x8001);
    sev.aggregation_interval_ms = 150;
    sev.event_threshold         = {1, 500};
    init_with_sev(sev);

    report_n(3);
    ASSERT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }, 2000));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(1, g_dem_count.load());     /* single released aggregate */
    EXPECT_EQ(3, g_last_count.load());
}

TEST_F(IdsMTest, ChainDisabledFiltersPassThrough) {
    /* All filters disabled -> every SEv qualifies (chain optional) */
    init_default();
    report_n(5);
    EXPECT_TRUE(wait_until([&]{ return g_dem_count.load() >= 5; }, 2000));
}

/* ═══════════════════════════════════════════════════════════════════════════
   Config validation: time windows must be multiples of the MainFunction
   period [SWS_IdsM_01064]
   ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(IdsMTest, InitRejectsNonMultipleAggregationInterval) {
    auto sev = make_sev(0x8001);
    sev.aggregation_interval_ms = 205;    /* not a multiple of period 10 */
    auto cfg = make_config(&sev, 1);
    EXPECT_EQ(E_PARAM_CONFIG, IdsM_Init(&cfg));
}

TEST_F(IdsMTest, InitRejectsNonMultipleThresholdInterval) {
    auto sev = make_sev(0x8001);
    sev.event_threshold = {3, 55};        /* not a multiple of period 10 */
    auto cfg = make_config(&sev, 1);
    EXPECT_EQ(E_PARAM_CONFIG, IdsM_Init(&cfg));
}

TEST_F(IdsMTest, InitRejectsZeroMainFunctionPeriod) {
    auto sev = make_sev(0x8001);
    auto cfg = make_config(&sev, 1);
    cfg.main_function_period_ms = 0;
    EXPECT_EQ(E_PARAM_CONFIG, IdsM_Init(&cfg));
}

/* ═══════════════════════════════════════════════════════════════════════════
   QSEv structure (CP §7.8.1)
   ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(IdsMTest, QsevFieldsPopulatedFromConfig) {
    init_default();
    report_default();
    ASSERT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }));
    EXPECT_EQ(0x8001, g_last_ext_id.load());
    EXPECT_EQ(1, g_last_count.load());                    /* count initialized to 1 */
    EXPECT_EQ(IDSM_SEVERITY_HIGH, g_last_severity);       /* from SEv config */
    EXPECT_TRUE(g_last_has_ts);                           /* internal timestamp added */
    EXPECT_EQ(1, g_last_ctx_version.load());
}

TEST_F(IdsMTest, QsevCountReflectsSensorPreAggregation) {
    init_default();
    report_default(7 /* count */);
    ASSERT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }));
    EXPECT_EQ(7, g_last_count.load());
}

TEST_F(IdsMTest, SensorProvidedTimestampIsForwarded) {
    /* Capture via a local sink that inspects the timestamp */
    static std::atomic<uint32_t> captured_sec{0};
    static std::atomic<int>      captured_src{-1};
    auto sev = make_sev();
    auto cfg = make_config(&sev, 1);
    ASSERT_EQ(E_OK, IdsM_Init(&cfg));
    IdsM_SetDemReportCallback([](const IdsM_QualifiedSecurityEventType* q) {
        captured_sec.store(q->timestamp.seconds);
        captured_src.store(static_cast<int>(q->timestamp.source));
        g_dem_count++;
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(15));

    IdsM_TimestampDataType ts{};
    ts.seconds     = 123456;
    ts.nanoseconds = 789000000;
    ts.source      = IDSM_TIMESTAMP_SOURCE_OEM;
    IdsM_ReportSecurityEvent(0, nullptr, 0, 1, 1, &ts);

    ASSERT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }));
    EXPECT_EQ(123456u, captured_sec.load());
    EXPECT_EQ(static_cast<int>(IDSM_TIMESTAMP_SOURCE_OEM), captured_src.load());
}

/* ═══════════════════════════════════════════════════════════════════════════
   No operating mode gating (方案 A regression)
   ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(IdsMTest, EventsFlowImmediatelyAfterInitWithoutAnyModeSetup) {
    /* 方案 A: there is no operating mode. A DETAILED SEv must qualify events
       right after IdsM_Init without any mode-related call. */
    init_default(IDSM_REPORTING_DETAILED);
    report_default();
    EXPECT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }));
}

TEST_F(IdsMTest, BlockStateNotificationDoesNotGateEventsYet) {
    /* IdsM_BswM_StateChanged stores the state; the Block State filter itself
       arrives in phase 2. Events must still flow. */
    init_default();
    IdsM_BswM_StateChanged(3);
    report_default();
    EXPECT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }));
}

/* ═══════════════════════════════════════════════════════════════════════════
   Report guards & compatibility wrapper
   ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(IdsMTest, ReportToUnknownSevIsSilentlyDropped) {
    init_default();
    /* void API (spec-conformant); invalid ID -> dropped (DET error in P2) */
    IdsM_ReportSecurityEvent(0x99, g_test_payload, sizeof(g_test_payload), 1, 1, nullptr);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(0, g_dem_count.load());
}

TEST_F(IdsMTest, CompatReportEventForwardsViaNewApi) {
    init_default();
    IdsM_EventReportType old{};
    old.monitor_id   = 0;   /* interpreted as internal SEv ID */
    old.event_id     = 0x100;
    old.severity     = IDSM_SEVERITY_HIGH;
    old.payload      = g_test_payload;
    old.payload_len  = sizeof(g_test_payload);
    old.timestamp_ms = 1000;

    EXPECT_EQ(E_OK, IdsM_ReportEvent(&old));
    ASSERT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }));
    EXPECT_EQ(0x8001, g_last_ext_id.load());
    EXPECT_EQ(1, g_last_count.load());   /* count=1 fixed by wrapper */
}

TEST_F(IdsMTest, CompatReportEventRejectsNullAndUnknown) {
    init_default();
    EXPECT_EQ(E_PARAM_POINTER, IdsM_ReportEvent(nullptr));

    IdsM_EventReportType old{};
    old.monitor_id = 0x99;
    EXPECT_EQ(E_PARAM_CONFIG, IdsM_ReportEvent(&old));
}

/* ═══════════════════════════════════════════════════════════════════════════
   Detection Status
   ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(IdsMTest, StatusUninitializedForUnknownSev) {
    init_default();
    EXPECT_EQ(IDSM_STATUS_UNINITIALIZED, IdsM_GetDetectionStatus(0x99));
}

TEST_F(IdsMTest, StatusBecomesViolationAfterEvent) {
    init_default();
    report_default();
    ASSERT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }));
    EXPECT_EQ(IDSM_STATUS_VIOLATION, IdsM_GetDetectionStatus(0));
}

TEST_F(IdsMTest, ResetDetectionStatus) {
    init_default();
    report_default();
    ASSERT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }));
    EXPECT_EQ(E_OK, IdsM_ResetDetectionStatus(0));
    EXPECT_EQ(IDSM_STATUS_OK, IdsM_GetDetectionStatus(0));
}

TEST_F(IdsMTest, ResetUnknownSevReturnsError) {
    init_default();
    EXPECT_EQ(E_PARAM_CONFIG, IdsM_ResetDetectionStatus(0x99));
}

/* ═══════════════════════════════════════════════════════════════════════════
   Multiple SEvs & sinks
   ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(IdsMTest, MultipleSevsIndependent) {
    IdsM_SecurityEventConfigType sevs[2] = {
        make_sev(0x8001, IDSM_REPORTING_DETAILED),
        make_sev(0x8002, IDSM_REPORTING_OFF)
    };
    auto cfg = make_config(sevs, 2);
    ASSERT_EQ(E_OK, IdsM_Init(&cfg));
    IdsM_SetDemReportCallback(dem_cb);
    std::this_thread::sleep_for(std::chrono::milliseconds(15));

    IdsM_ReportSecurityEvent(0, nullptr, 0, 1, 1, nullptr);
    IdsM_ReportSecurityEvent(1, nullptr, 0, 1, 1, nullptr);   /* OFF -> dropped */

    ASSERT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_EQ(1, g_dem_count.load());
    EXPECT_EQ(IDSM_STATUS_VIOLATION, IdsM_GetDetectionStatus(0));
    EXPECT_EQ(IDSM_STATUS_UNINITIALIZED, IdsM_GetDetectionStatus(1));
}

TEST_F(IdsMTest, IdsrSinkReceivesQsevWhenConfigured) {
    static std::atomic<int> idsr_count{0};
    idsr_count.store(0);

    auto sev = make_sev(0x8001, IDSM_REPORTING_DETAILED);
    sev.sink_to_dem  = false;
    sev.sink_to_idsr = true;
    auto cfg = make_config(&sev, 1);
    ASSERT_EQ(E_OK, IdsM_Init(&cfg));
    IdsM_RegisterIdsrSink([](const IdsM_QualifiedSecurityEventType*) { idsr_count++; });
    std::this_thread::sleep_for(std::chrono::milliseconds(15));

    IdsM_ReportSecurityEvent(0, nullptr, 0, 1, 1, nullptr);
    EXPECT_TRUE(wait_until([&]{ return idsr_count.load() >= 1; }));
    EXPECT_EQ(0, g_dem_count.load());   /* dem sink disabled for this SEv */
}

TEST_F(IdsMTest, PendingCountTracksQueue) {
    init_default();
    report_default();
    /* Either still pending or already processed — counter must end at 0 */
    ASSERT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }));
    EXPECT_EQ(0u, IdsM_GetPendingEventCount(0));
    EXPECT_EQ(0u, IdsM_GetPendingEventCount(0x99)); /* unknown -> 0 */
}

TEST_F(IdsMTest, FlushUnknownSevReturnsError) {
    init_default();
    EXPECT_EQ(E_PARAM_CONFIG, IdsM_FlushEvents(0x99));
    EXPECT_EQ(E_OK, IdsM_FlushEvents(0));
}

/* ═══════════════════════════════════════════════════════════════════════════
   IDS Protocol serializer (PRS §5.1) — pure unit tests, no manager
   ═══════════════════════════════════════════════════════════════════════════ */

class IdsMProtocolTest : public ::testing::Test {
protected:
    IdsM_QualifiedSecurityEventType q{};

    void SetUp() override {
        q.idsm_instance_id     = 1;
        q.external_event_id    = 0x8001;
        q.sensor_instance_id   = 2;
        q.severity             = IDSM_SEVERITY_HIGH;
        q.count                = 3;
        q.has_timestamp        = false;
        q.context_data_version = 1;
        q.context_data         = nullptr;
        q.context_data_size    = 0;
    }
};

TEST_F(IdsMProtocolTest, EventFrameLayout) {
    uint8_t buf[8]{};
    ASSERT_EQ(8u, IdsM_Protocol_GetMessageSize(&q));
    ASSERT_EQ(8u, IdsM_Protocol_SerializeQSEv(&q, buf, sizeof(buf)));

    /* Byte0: version 2 in high nibble, no optional fields */
    EXPECT_EQ(0x20, buf[0]);
    /* Byte1-2: IdsM instance 1 (10 bit) | sensor instance 2 (6 bit)
       idsm=1 -> 0b0000000001, sensor=2 -> 0b000010
       Byte1 = idsm>>2 = 0; Byte2 = (idsm&3)<<6 | sensor = 0x40 | 0x02 */
    EXPECT_EQ(0x00, buf[1]);
    EXPECT_EQ(0x42, buf[2]);
    /* Byte3-4: external event ID big-endian */
    EXPECT_EQ(0x80, buf[3]);
    EXPECT_EQ(0x01, buf[4]);
    /* Byte5-6: count big-endian */
    EXPECT_EQ(0x00, buf[5]);
    EXPECT_EQ(0x03, buf[6]);
    /* Byte7: reserved */
    EXPECT_EQ(0x00, buf[7]);
}

TEST_F(IdsMProtocolTest, TimestampEncoding) {
    q.has_timestamp        = true;
    q.timestamp.seconds     = 0x01020304;
    q.timestamp.nanoseconds = 500000000;   /* 0x1DCD6500, fits 30 bit */
    q.timestamp.source      = IDSM_TIMESTAMP_SOURCE_AUTOSAR;

    uint8_t buf[16]{};
    ASSERT_EQ(16u, IdsM_Protocol_GetMessageSize(&q));
    ASSERT_EQ(16u, IdsM_Protocol_SerializeQSEv(&q, buf, sizeof(buf)));

    EXPECT_EQ(0x22, buf[0]);               /* header bit1 = timestamp */
    /* Byte8: source=0 (AUTOSAR) | ns bits 29..24 = 0x1DCD6500>>24 & 0x3F = 0x1D */
    EXPECT_EQ(0x1D, buf[8]);
    EXPECT_EQ(0xCD, buf[9]);
    EXPECT_EQ(0x65, buf[10]);
    EXPECT_EQ(0x00, buf[11]);
    /* seconds big-endian */
    EXPECT_EQ(0x01, buf[12]);
    EXPECT_EQ(0x02, buf[13]);
    EXPECT_EQ(0x03, buf[14]);
    EXPECT_EQ(0x04, buf[15]);
}

TEST_F(IdsMProtocolTest, TimestampOemSourceSetsBit7) {
    q.has_timestamp    = true;
    q.timestamp.source = IDSM_TIMESTAMP_SOURCE_OEM;
    uint8_t buf[16]{};
    ASSERT_EQ(16u, IdsM_Protocol_SerializeQSEv(&q, buf, sizeof(buf)));
    EXPECT_EQ(0x80, buf[8] & 0x80);
}

TEST_F(IdsMProtocolTest, ContextDataShortFormLength) {
    static const uint8_t ctx[13] = {0,0,1,0x23,8,1,2,3,4,5,6,7,8};
    q.context_data      = ctx;
    q.context_data_size = sizeof(ctx);
    q.context_data_version = 0x0102;

    uint8_t buf[8 + 2 + 1 + 13]{};
    ASSERT_EQ(sizeof(buf), IdsM_Protocol_GetMessageSize(&q));
    ASSERT_EQ(sizeof(buf), IdsM_Protocol_SerializeQSEv(&q, buf, sizeof(buf)));

    EXPECT_EQ(0x21, buf[0]);               /* header bit0 = context data */
    EXPECT_EQ(0x01, buf[8]);               /* version high byte */
    EXPECT_EQ(0x02, buf[9]);               /* version low byte */
    EXPECT_EQ(13, buf[10]);                /* 7-bit short length */
    EXPECT_EQ(0, std::memcmp(&buf[11], ctx, sizeof(ctx)));
}

TEST_F(IdsMProtocolTest, ContextDataLongFormLength) {
    static uint8_t ctx[200];
    for (int i = 0; i < 200; ++i) ctx[i] = static_cast<uint8_t>(i);
    q.context_data      = ctx;
    q.context_data_size = sizeof(ctx);

    uint8_t buf[8 + 2 + 4 + 200]{};
    ASSERT_EQ(sizeof(buf), IdsM_Protocol_GetMessageSize(&q));
    ASSERT_EQ(sizeof(buf), IdsM_Protocol_SerializeQSEv(&q, buf, sizeof(buf)));

    /* 31-bit long form: byte0 = 0x80 | (len>>24), then 3 bytes */
    EXPECT_EQ(0x80, buf[10]);
    EXPECT_EQ(0x00, buf[11]);
    EXPECT_EQ(0x00, buf[12]);
    EXPECT_EQ(0xC8, buf[13]);              /* 200 */
    EXPECT_EQ(0, std::memcmp(&buf[14], ctx, sizeof(ctx)));
}

TEST_F(IdsMProtocolTest, RejectsNullAndSmallBuffer) {
    uint8_t buf[8]{};
    EXPECT_EQ(0u, IdsM_Protocol_SerializeQSEv(nullptr, buf, sizeof(buf)));
    EXPECT_EQ(0u, IdsM_Protocol_SerializeQSEv(&q, nullptr, sizeof(buf)));
    EXPECT_EQ(0u, IdsM_Protocol_SerializeQSEv(&q, buf, 7));   /* too small */
    EXPECT_EQ(0u, IdsM_Protocol_GetMessageSize(nullptr));
}

TEST_F(IdsMProtocolTest, FullMessageRoundTripFieldCheck) {
    /* All optional fields: event frame + timestamp + context */
    static const uint8_t ctx[2] = {0xAA, 0xBB};
    q.has_timestamp        = true;
    q.timestamp.seconds     = 42;
    q.timestamp.nanoseconds = 1000;
    q.context_data          = ctx;
    q.context_data_size     = sizeof(ctx);
    q.context_data_version  = 5;

    uint8_t buf[8 + 8 + 2 + 1 + 2]{};
    ASSERT_EQ(sizeof(buf), IdsM_Protocol_SerializeQSEv(&q, buf, sizeof(buf)));
    EXPECT_EQ(0x23, buf[0]);   /* version 2 + context + timestamp bits */
}
