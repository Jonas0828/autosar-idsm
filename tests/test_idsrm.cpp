#include <gtest/gtest.h>
#include <atomic>
#include <thread>
#include <chrono>
#include <functional>
#include <cstring>
#include <string>

/* POSIX socket for in-process mock HTTP server */
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include "IdsM.h"
#include "IdsRm.h"

/* ── Helpers ──────────────────────────────────────────────────────────────── */

static bool wait_until(std::function<bool()> cond, int max_ms = 1000) {
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(max_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (cond()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return cond();
}

static IdsRm_ConfigType make_idsrm_config(const char* url, bool enabled = true,
                                            uint32_t timeout = 2000,
                                            uint8_t  retries = 0) {
    IdsRm_ConfigType cfg{};
    std::strncpy(cfg.soc_url, url, IDSRM_MAX_URL_LEN - 1);
    cfg.auth_token[0] = '\0';
    cfg.timeout_ms    = timeout;
    cfg.retry_count   = retries;
    cfg.enabled       = enabled;
    return cfg;
}

static IdsM_MonitorConfigType make_monitor(uint16_t id) {
    IdsM_MonitorConfigType m{};
    m.monitor_id          = id;
    m.event_buffer_size   = 10;
    m.flood_protection_ms = 0;
    m.severity_threshold  = IDSM_SEVERITY_LOW;
    m.enabled_in_pre_run  = false;
    m.enabled_in_run      = true;
    m.enabled_in_post_run = false;
    return m;
}

/* Persistent payload buffer — must outlive ReportEvent call (deep-copied). */
static uint8_t g_test_payload[4] = {0xDE, 0xAD, 0xBE, 0xEF};

static IdsM_EventReportType make_event(uint16_t mon = 0x001, uint16_t evt = 0x100) {
    IdsM_EventReportType e{};
    e.monitor_id   = mon;
    e.event_id     = evt;
    e.severity     = IDSM_SEVERITY_HIGH;
    e.payload      = g_test_payload;
    e.payload_len  = sizeof(g_test_payload);
    e.timestamp_ms = 42000;
    return e;
}

/* ── In-process mock SOC HTTP server ──────────────────────────────────────── */

class MockSocServer {
public:
    explicit MockSocServer(int port) : m_port(port) {}

    void start() {
        m_fd = socket(AF_INET, SOCK_STREAM, 0);
        ASSERT_GE(m_fd, 0) << "socket() failed";

        int opt = 1;
        setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port        = htons(static_cast<uint16_t>(m_port));
        ASSERT_EQ(0, bind(m_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)));
        ASSERT_EQ(0, listen(m_fd, 16));

        m_running.store(true);
        m_thread = std::thread([this] {
            while (m_running.load()) {
                fd_set fds;
                FD_ZERO(&fds);
                FD_SET(m_fd, &fds);
                timeval tv{0, 50000}; /* 50ms select timeout */
                if (select(m_fd + 1, &fds, nullptr, nullptr, &tv) <= 0) continue;

                int client = accept(m_fd, nullptr, nullptr);
                if (client < 0) continue;

                char buf[4096]{};
                recv(client, buf, sizeof(buf) - 1, 0);

                const char* resp =
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    "Content-Length: 15\r\n\r\n{\"status\":\"ok\"}";
                send(client, resp, strlen(resp), 0);
                close(client);

                if (strstr(buf, "POST /api/idsm-violations")) {
                    m_count++;
                    const char* body_start = strstr(buf, "\r\n\r\n");
                    if (body_start) {
                        std::lock_guard<std::mutex> lk(m_body_mutex);
                        m_last_body = std::string(body_start + 4);
                    }
                }
            }
        });
    }

    void stop() {
        m_running.store(false);
        if (m_thread.joinable()) m_thread.join();
        if (m_fd >= 0) { close(m_fd); m_fd = -1; }
    }

    int count() const { return m_count.load(); }

    std::string last_body() const {
        std::lock_guard<std::mutex> lk(m_body_mutex);
        return m_last_body;
    }

private:
    int              m_port;
    int              m_fd{-1};
    std::thread      m_thread;
    std::atomic<bool>m_running{false};
    std::atomic<int> m_count{0};
    mutable std::mutex m_body_mutex;
    std::string        m_last_body;
};

/* ═══════════════════════════════════════════════════════════════════════════
   Fixture: IdsRmPreInitTest — tests that IDSRM is NOT initialized
   No IDSM, no IDSRM. Tests purely guard-clause behavior.
   ═══════════════════════════════════════════════════════════════════════════ */

class IdsRmPreInitTest : public ::testing::Test {};

TEST_F(IdsRmPreInitTest, NullConfigReturnsError) {
    EXPECT_EQ(E_PARAM_POINTER, IdsRm_Init(nullptr));
}

TEST_F(IdsRmPreInitTest, EnableBeforeInitReturnsError) {
    EXPECT_EQ(E_IDSRM_NOT_INIT, IdsRm_Enable());
}

TEST_F(IdsRmPreInitTest, DisableBeforeInitReturnsError) {
    EXPECT_EQ(E_IDSRM_NOT_INIT, IdsRm_Disable());
}

TEST_F(IdsRmPreInitTest, SetSocUrlBeforeInitReturnsError) {
    EXPECT_EQ(E_IDSRM_NOT_INIT, IdsRm_SetSocUrl("http://example.com"));
}

TEST_F(IdsRmPreInitTest, IsEnabledReturnsFalseBeforeInit) {
    EXPECT_FALSE(IdsRm_IsEnabled());
}

/* ═══════════════════════════════════════════════════════════════════════════
   Fixture: IdsRmTest — IDSM is running, tests init/deinit IDSRM
   ═══════════════════════════════════════════════════════════════════════════ */

class IdsRmTest : public ::testing::Test {
protected:
    bool m_idsm_up = false;
    bool m_idsrm_up = false;

    void SetUp() override {
        auto idsm_cfg = make_monitor(0x001);
        ASSERT_EQ(E_OK, IdsM_Init(&idsm_cfg, 1));
        IdsM_SetOperatingMode(IDSM_RUN_MODE);
        m_idsm_up = true;
        std::this_thread::sleep_for(std::chrono::milliseconds(15));
    }

    void TearDown() override {
        if (m_idsrm_up) IdsRm_DeInit();
        if (m_idsm_up)  IdsM_DeInit();
    }

    void init_idsrm(const char* url, bool enabled = true) {
        auto cfg = make_idsrm_config(url, enabled);
        ASSERT_EQ(E_OK, IdsRm_Init(&cfg));
        m_idsrm_up = true;
    }
};

TEST_F(IdsRmTest, InitDeInit) {
    init_idsrm("http://127.0.0.1:19999/api/idsm-violations");
    EXPECT_EQ(E_OK, IdsRm_DeInit());
    m_idsrm_up = false; /* avoid double-deinit in TearDown */
}

TEST_F(IdsRmTest, DoubleInitReturnsError) {
    init_idsrm("http://127.0.0.1:19999/api/idsm-violations");
    auto cfg2 = make_idsrm_config("http://127.0.0.1:19999/other");
    EXPECT_EQ(E_NOT_OK, IdsRm_Init(&cfg2));
}

TEST_F(IdsRmTest, EnableDisableToggle) {
    init_idsrm("http://127.0.0.1:19999/api/idsm-violations", true);
    EXPECT_TRUE(IdsRm_IsEnabled());

    EXPECT_EQ(E_OK, IdsRm_Disable());
    EXPECT_FALSE(IdsRm_IsEnabled());

    EXPECT_EQ(E_OK, IdsRm_Enable());
    EXPECT_TRUE(IdsRm_IsEnabled());
}

TEST_F(IdsRmTest, InitWithEnabledFalse) {
    init_idsrm("http://127.0.0.1:19999/api/idsm-violations", false);
    EXPECT_FALSE(IdsRm_IsEnabled());
}

TEST_F(IdsRmTest, SetSocUrlNullReturnsError) {
    init_idsrm("http://127.0.0.1:19999/api/idsm-violations");
    EXPECT_EQ(E_PARAM_POINTER, IdsRm_SetSocUrl(nullptr));
}

TEST_F(IdsRmTest, SetAuthTokenNullReturnsError) {
    init_idsrm("http://127.0.0.1:19999/api/idsm-violations");
    EXPECT_EQ(E_PARAM_POINTER, IdsRm_SetAuthToken(nullptr));
}

TEST_F(IdsRmTest, DroppedCountWhenDisabled) {
    init_idsrm("http://127.0.0.1:19999/api/idsm-violations", false);

    auto evt = make_event();
    IdsM_ReportEvent(&evt);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    auto stats = IdsRm_GetStats();
    EXPECT_EQ(0u, stats.events_received);
    EXPECT_GE(stats.events_dropped, 1u);
}

TEST_F(IdsRmTest, ResetStats) {
    init_idsrm("http://127.0.0.1:19999/api/idsm-violations", false);

    auto evt = make_event();
    IdsM_ReportEvent(&evt);
    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    IdsRm_ResetStats();
    auto stats = IdsRm_GetStats();
    EXPECT_EQ(0u, stats.events_received);
    EXPECT_EQ(0u, stats.events_dropped);
    EXPECT_EQ(0u, stats.events_posted);
    EXPECT_EQ(0u, stats.events_failed);
}

/* ═══════════════════════════════════════════════════════════════════════════
   Fixture: IdsRmIntegrationTest — with mock HTTP server
   ═══════════════════════════════════════════════════════════════════════════ */

class IdsRmIntegrationTest : public ::testing::Test {
protected:
    static constexpr int PORT = 18765;
    MockSocServer server{PORT};
    bool m_idsrm_up = false;

    void SetUp() override {
        server.start();
        auto idsm_cfg = make_monitor(0x001);
        ASSERT_EQ(E_OK, IdsM_Init(&idsm_cfg, 1));
        IdsM_SetOperatingMode(IDSM_RUN_MODE);
        std::this_thread::sleep_for(std::chrono::milliseconds(15));
    }

    void TearDown() override {
        if (m_idsrm_up) IdsRm_DeInit();
        IdsM_DeInit();
        server.stop();
    }

    std::string soc_url() const {
        return "http://127.0.0.1:" + std::to_string(PORT) + "/api/idsm-violations";
    }

    void init_idsrm(bool enabled = true) {
        auto cfg = make_idsrm_config(soc_url().c_str(), enabled);
        ASSERT_EQ(E_OK, IdsRm_Init(&cfg));
        m_idsrm_up = true;
    }
};

TEST_F(IdsRmIntegrationTest, EventPostedToSoc) {
    init_idsrm();
    auto evt = make_event();
    ASSERT_EQ(E_OK, IdsM_ReportEvent(&evt));

    EXPECT_TRUE(wait_until([&]{ return server.count() >= 1; }));
    auto stats = IdsRm_GetStats();
    EXPECT_EQ(1u, stats.events_received);
    EXPECT_EQ(1u, stats.events_posted);
}

TEST_F(IdsRmIntegrationTest, JsonPayloadContainsExpectedFields) {
    init_idsrm();
    auto evt = make_event(0x001, 0x100);
    ASSERT_EQ(E_OK, IdsM_ReportEvent(&evt));

    EXPECT_TRUE(wait_until([&]{ return server.count() >= 1; }));

    std::string body = server.last_body();
    EXPECT_NE(std::string::npos, body.find("\"monitor_id\""));
    EXPECT_NE(std::string::npos, body.find("\"event_id\""));
    EXPECT_NE(std::string::npos, body.find("\"timestamp_ms\""));
    EXPECT_NE(std::string::npos, body.find("\"severity\""));
    EXPECT_NE(std::string::npos, body.find("\"payload\""));
    EXPECT_NE(std::string::npos, body.find("\"payload_len\""));
    EXPECT_NE(std::string::npos, body.find("DEADBEEF"));  /* hex-encoded payload bytes */
    EXPECT_NE(std::string::npos, body.find("HIGH"));
    EXPECT_NE(std::string::npos, body.find("42000"));
}

TEST_F(IdsRmIntegrationTest, DisabledDropsEvents) {
    init_idsrm(false);
    auto evt = make_event();
    IdsM_ReportEvent(&evt);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(0, server.count());
    auto stats = IdsRm_GetStats();
    EXPECT_GE(stats.events_dropped, 1u);
    EXPECT_EQ(0u, stats.events_posted);
}

TEST_F(IdsRmIntegrationTest, EnableAfterDisableResumesForwarding) {
    init_idsrm(false);

    auto evt = make_event();
    IdsM_ReportEvent(&evt);
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    EXPECT_EQ(0, server.count());

    IdsRm_Enable();
    auto evt2 = make_event(0x001, 0x200);
    ASSERT_EQ(E_OK, IdsM_ReportEvent(&evt2));

    EXPECT_TRUE(wait_until([&]{ return server.count() >= 1; }));
    EXPECT_EQ(1, server.count());
}

TEST_F(IdsRmIntegrationTest, RuntimeUrlChangeIsRespected) {
    /* Start pointing at a closed port — events fail */
    auto cfg = make_idsrm_config("http://127.0.0.1:19999/api/idsm-violations",
                                   true, 500, 0);
    ASSERT_EQ(E_OK, IdsRm_Init(&cfg));
    m_idsrm_up = true;

    auto evt = make_event();
    IdsM_ReportEvent(&evt);
    std::this_thread::sleep_for(std::chrono::milliseconds(700));
    EXPECT_EQ(0, server.count());

    IdsRm_SetSocUrl(soc_url().c_str());
    auto evt2 = make_event(0x001, 0x200);
    ASSERT_EQ(E_OK, IdsM_ReportEvent(&evt2));

    EXPECT_TRUE(wait_until([&]{ return server.count() >= 1; }));
    EXPECT_EQ(1, server.count());
}

TEST_F(IdsRmIntegrationTest, MultipleEventsAllPosted) {
    init_idsrm();

    for (int i = 0; i < 5; ++i) {
        auto evt = make_event(0x001, static_cast<uint16_t>(0x100 + i));
        ASSERT_EQ(E_OK, IdsM_ReportEvent(&evt));
    }

    EXPECT_TRUE(wait_until([&]{ return server.count() >= 5; }, 3000));
    auto stats = IdsRm_GetStats();
    EXPECT_EQ(5u, stats.events_received);
    EXPECT_EQ(5u, stats.events_posted);
}
