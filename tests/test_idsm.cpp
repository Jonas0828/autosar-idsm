#include <gtest/gtest.h>
#include <atomic>
#include <thread>
#include <chrono>
#include <functional>
#include "IdsM.h"

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

static IdsM_MonitorConfigType make_monitor(
    uint16_t id,
    uint32_t buf   = 10,
    uint32_t flood = 0,
    bool pre = false, bool run = true, bool post = false)
{
    IdsM_MonitorConfigType m{};
    m.monitor_id          = id;
    m.event_buffer_size   = buf;
    m.flood_protection_ms = flood;
    m.severity_threshold  = IDSM_SEVERITY_LOW;
    m.enabled_in_pre_run  = pre;
    m.enabled_in_run      = run;
    m.enabled_in_post_run = post;
    return m;
}

/* Persistent payload buffer for test events — must outlive ReportEvent call.
   ReportEvent deep-copies, so this is safe as a static. */
static uint8_t g_test_payload[1] = {0xAB};

static IdsM_EventReportType make_event(uint16_t mon, uint16_t evt,
                                        IdsM_EventSeverityType sev = IDSM_SEVERITY_HIGH) {
    IdsM_EventReportType e{};
    e.monitor_id   = mon;
    e.event_id     = evt;
    e.severity     = sev;
    g_test_payload[0] = 0xAB;
    e.payload      = g_test_payload;
    e.payload_len  = 1;
    e.timestamp_ms = 1000;
    return e;
}

/* ── Shared callback state ────────────────────────────────────────────────── */

static std::atomic<int>      g_dem_count{0};
static std::atomic<uint16_t> g_last_monitor{0};

static void dem_cb(const IdsM_EventReportType* e) {
    g_dem_count++;
    g_last_monitor.store(e->monitor_id);
}

/* ── Fixture ──────────────────────────────────────────────────────────────── */

class IdsMTest : public ::testing::Test {
protected:
    void SetUp() override {
        g_dem_count.store(0);
        g_last_monitor.store(0);
    }

    void TearDown() override {
        IdsM_DeInit();
    }

    void init_default(uint16_t mon_id = 0x001, uint32_t buf = 10,
                      uint32_t flood = 0) {
        auto cfg = make_monitor(mon_id, buf, flood);
        ASSERT_EQ(E_OK, IdsM_Init(&cfg, 1));
        IdsM_SetDemReportCallback(dem_cb);
        IdsM_SetOperatingMode(IDSM_RUN_MODE);
        /* Give the worker thread a moment to start and enter wait */
        std::this_thread::sleep_for(std::chrono::milliseconds(15));
    }
};

/* ═══════════════════════════════════════════════════════════════════════════
   Lifecycle
   ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(IdsMTest, InitDeInit) {
    auto cfg = make_monitor(0x001);
    EXPECT_EQ(E_OK, IdsM_Init(&cfg, 1));
    EXPECT_EQ(E_OK, IdsM_DeInit());
}

TEST_F(IdsMTest, InitNullConfigZeroCount) {
    EXPECT_EQ(E_OK, IdsM_Init(nullptr, 0));
}

TEST_F(IdsMTest, InitNullConfigNonZeroCount) {
    EXPECT_EQ(E_PARAM_POINTER, IdsM_Init(nullptr, 1));
}

/* ═══════════════════════════════════════════════════════════════════════════
   Operating Mode
   ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(IdsMTest, DefaultModeIsPreRun) {
    auto cfg = make_monitor(0x001);
    ASSERT_EQ(E_OK, IdsM_Init(&cfg, 1));
    EXPECT_EQ(IDSM_PRE_RUN_MODE, IdsM_GetOperatingMode());
}

TEST_F(IdsMTest, SetAndGetMode) {
    auto cfg = make_monitor(0x001);
    ASSERT_EQ(E_OK, IdsM_Init(&cfg, 1));
    EXPECT_EQ(E_OK, IdsM_SetOperatingMode(IDSM_RUN_MODE));
    EXPECT_EQ(IDSM_RUN_MODE, IdsM_GetOperatingMode());
    EXPECT_EQ(E_OK, IdsM_SetOperatingMode(IDSM_POST_RUN_MODE));
    EXPECT_EQ(IDSM_POST_RUN_MODE, IdsM_GetOperatingMode());
}

/* ═══════════════════════════════════════════════════════════════════════════
   ReportEvent guards
   ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(IdsMTest, ReportNullEvent) {
    auto cfg = make_monitor(0x001);
    ASSERT_EQ(E_OK, IdsM_Init(&cfg, 1));
    EXPECT_EQ(E_PARAM_POINTER, IdsM_ReportEvent(nullptr));
}

TEST_F(IdsMTest, ReportUnknownMonitor) {
    init_default();
    auto evt = make_event(0x999, 0x001);
    EXPECT_EQ(E_MODE_INVALID, IdsM_ReportEvent(&evt));
}

TEST_F(IdsMTest, ReportInWrongMode) {
    auto cfg = make_monitor(0x001, 10, 0, false, true, false);
    ASSERT_EQ(E_OK, IdsM_Init(&cfg, 1));
    /* Default mode is PRE_RUN; monitor only enabled in RUN */
    auto evt = make_event(0x001, 0x001);
    EXPECT_EQ(E_MODE_INVALID, IdsM_ReportEvent(&evt));
}

/* ═══════════════════════════════════════════════════════════════════════════
   DEM callback
   ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(IdsMTest, DemCallbackFires) {
    init_default();
    auto evt = make_event(0x001, 0x100);
    ASSERT_EQ(E_OK, IdsM_ReportEvent(&evt));

    EXPECT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }));
    EXPECT_EQ(1, g_dem_count.load());
    EXPECT_EQ(0x001, g_last_monitor.load());
}

TEST_F(IdsMTest, DemCallbackNotFiredWhenNoCallback) {
    auto cfg = make_monitor(0x001);
    ASSERT_EQ(E_OK, IdsM_Init(&cfg, 1));
    IdsM_SetOperatingMode(IDSM_RUN_MODE);
    std::this_thread::sleep_for(std::chrono::milliseconds(15));

    auto evt = make_event(0x001, 0x100);
    ASSERT_EQ(E_OK, IdsM_ReportEvent(&evt));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(0, g_dem_count.load());
}

TEST_F(IdsMTest, MultipleEventsAllForwarded) {
    init_default(0x001, 20, 0);

    for (int i = 0; i < 5; ++i) {
        auto evt = make_event(0x001, static_cast<uint16_t>(0x100 + i));
        ASSERT_EQ(E_OK, IdsM_ReportEvent(&evt));
    }
    EXPECT_TRUE(wait_until([&]{ return g_dem_count.load() >= 5; }, 2000));
    EXPECT_EQ(5, g_dem_count.load());
}

/* ═══════════════════════════════════════════════════════════════════════════
   Detection Status
   ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(IdsMTest, StatusUninitializedForUnknownMonitor) {
    auto cfg = make_monitor(0x001);
    ASSERT_EQ(E_OK, IdsM_Init(&cfg, 1));
    EXPECT_EQ(IDSM_STATUS_UNINITIALIZED, IdsM_GetDetectionStatus(0x999));
}

TEST_F(IdsMTest, StatusBecomesViolationAfterEvent) {
    init_default();
    auto evt = make_event(0x001, 0x100);
    ASSERT_EQ(E_OK, IdsM_ReportEvent(&evt));
    EXPECT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }));
    EXPECT_EQ(IDSM_STATUS_VIOLATION, IdsM_GetDetectionStatus(0x001));
}

TEST_F(IdsMTest, ResetDetectionStatus) {
    init_default();
    auto evt = make_event(0x001, 0x100);
    ASSERT_EQ(E_OK, IdsM_ReportEvent(&evt));
    EXPECT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }));
    EXPECT_EQ(E_OK, IdsM_ResetDetectionStatus(0x001));
    EXPECT_EQ(IDSM_STATUS_OK, IdsM_GetDetectionStatus(0x001));
}

TEST_F(IdsMTest, ResetUnknownMonitorReturnsError) {
    auto cfg = make_monitor(0x001);
    ASSERT_EQ(E_OK, IdsM_Init(&cfg, 1));
    EXPECT_EQ(E_PARAM_CONFIG, IdsM_ResetDetectionStatus(0x999));
}

/* ═══════════════════════════════════════════════════════════════════════════
   Mode transitions
   ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(IdsMTest, ModeTransitionClearsBuffer) {
    init_default();
    auto evt = make_event(0x001, 0x100);
    ASSERT_EQ(E_OK, IdsM_ReportEvent(&evt));
    EXPECT_TRUE(wait_until([&]{ return g_dem_count.load() >= 1; }));
    EXPECT_EQ(IDSM_STATUS_VIOLATION, IdsM_GetDetectionStatus(0x001));

    IdsM_SetOperatingMode(IDSM_POST_RUN_MODE);
    EXPECT_EQ(IDSM_STATUS_UNINITIALIZED, IdsM_GetDetectionStatus(0x001));
}

/* ═══════════════════════════════════════════════════════════════════════════
   Flood protection
   ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(IdsMTest, FloodProtectionLimitsForwarding) {
    /* 10-second flood window — only one event should pass */
    init_default(0x001, 10, 10000);

    for (int i = 0; i < 5; ++i) {
        auto evt = make_event(0x001, static_cast<uint16_t>(0x100 + i));
        IdsM_ReportEvent(&evt);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(1, g_dem_count.load());
}

TEST_F(IdsMTest, FloodProtectionDisabledWhenZero) {
    init_default(0x001, 20, 0);

    for (int i = 0; i < 3; ++i) {
        auto evt = make_event(0x001, static_cast<uint16_t>(0x100 + i));
        IdsM_ReportEvent(&evt);
    }
    EXPECT_TRUE(wait_until([&]{ return g_dem_count.load() >= 3; }, 2000));
    EXPECT_EQ(3, g_dem_count.load());
}

/* ═══════════════════════════════════════════════════════════════════════════
   Multiple monitors
   ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(IdsMTest, MultipleMonitorsIndependent) {
    IdsM_MonitorConfigType cfgs[2] = {
        make_monitor(0x001, 10, 0, false, true, false),
        make_monitor(0x002, 10, 0, false, true, false)
    };
    ASSERT_EQ(E_OK, IdsM_Init(cfgs, 2));
    IdsM_SetDemReportCallback(dem_cb);
    IdsM_SetOperatingMode(IDSM_RUN_MODE);
    std::this_thread::sleep_for(std::chrono::milliseconds(15));

    auto e1 = make_event(0x001, 0x100);
    auto e2 = make_event(0x002, 0x200);
    IdsM_ReportEvent(&e1);
    IdsM_ReportEvent(&e2);

    EXPECT_TRUE(wait_until([&]{ return g_dem_count.load() >= 2; }, 2000));
    EXPECT_EQ(IDSM_STATUS_VIOLATION, IdsM_GetDetectionStatus(0x001));
    EXPECT_EQ(IDSM_STATUS_VIOLATION, IdsM_GetDetectionStatus(0x002));
}

/* ═══════════════════════════════════════════════════════════════════════════
   Flush
   ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(IdsMTest, FlushUnknownMonitorReturnsError) {
    auto cfg = make_monitor(0x001);
    ASSERT_EQ(E_OK, IdsM_Init(&cfg, 1));
    EXPECT_EQ(E_PARAM_CONFIG, IdsM_FlushEvents(0x999));
}
