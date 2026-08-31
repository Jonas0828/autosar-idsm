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

/* Persistent payload buffer — deep-copied on report, safe as static. */
static uint8_t g_test_payload[4] = {0xDE, 0xAD, 0xBE, 0xEF};

/* Single SEv: internal ID 0, external ID 0x8001 (OEM range) */
static void init_idsm_single_sev() {
    IdsM_SecurityEventConfigType sev{};
    sev.external_event_id      = 0x8001;
    sev.sensor_instance_id     = 0;
    sev.severity               = IDSM_SEVERITY_HIGH;
    sev.default_reporting_mode = IDSM_REPORTING_DETAILED;
    sev.block_state            = nullptr;
    sev.forward_every_nth      = 0;
    sev.aggregation_interval_ms = 0;
    sev.event_threshold        = {0, 0};
    sev.sink_to_dem            = false;
    sev.sink_to_idsr           = true;

    IdsM_ConfigType cfg{};
    cfg.idsm_instance_id        = 1;
    cfg.main_function_period_ms = 10;
    cfg.rate_limitation         = {0, 0};
    cfg.traffic_limitation      = {0, 0};
    cfg.sev_configs             = &sev;
    cfg.sev_count               = 1;
    cfg.event_buffer_size       = 128;
    ASSERT_EQ(E_OK, IdsM_Init(&cfg));
}

static void report_default(uint16_t count = 1) {
    IdsM_ReportSecurityEvent(0, g_test_payload, sizeof(g_test_payload),
                             1 /*version*/, count, nullptr);
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

                char buf[8192]{};
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
        init_idsm_single_sev();
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

    report_default();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    auto stats = IdsRm_GetStats();
    EXPECT_EQ(0u, stats.events_received);
    EXPECT_GE(stats.events_dropped, 1u);
}

TEST_F(IdsRmTest, ResetStats) {
    init_idsrm("http://127.0.0.1:19999/api/idsm-violations", false);

    report_default();
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
        init_idsm_single_sev();
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
    report_default();

    EXPECT_TRUE(wait_until([&]{ return server.count() >= 1; }));
    auto stats = IdsRm_GetStats();
    EXPECT_EQ(1u, stats.events_received);
    EXPECT_EQ(1u, stats.events_posted);
}

TEST_F(IdsRmIntegrationTest, JsonPayloadContainsQsevFields) {
    init_idsrm();
    report_default(3);

    EXPECT_TRUE(wait_until([&]{ return server.count() >= 1; }));

    std::string body = server.last_body();
    /* Serialized IDS Message present */
    EXPECT_NE(std::string::npos, body.find("\"ids_message\""));
    /* Decoded QSEv fields */
    EXPECT_NE(std::string::npos, body.find("\"protocol_version\":2"));
    EXPECT_NE(std::string::npos, body.find("\"has_context_data\":true"));
    EXPECT_NE(std::string::npos, body.find("\"has_timestamp\":true"));
    EXPECT_NE(std::string::npos, body.find("\"idsm_instance_id\":1"));
    EXPECT_NE(std::string::npos, body.find("\"sensor_instance_id\":0"));
    EXPECT_NE(std::string::npos, body.find("\"event_id\":32769"));  /* 0x8001 */
    EXPECT_NE(std::string::npos, body.find("\"count\":3"));
    EXPECT_NE(std::string::npos, body.find("\"severity\":\"HIGH\""));
    EXPECT_NE(std::string::npos, body.find("\"context_data_version\":1"));
    EXPECT_NE(std::string::npos, body.find("\"payload\":\"DEADBEEF\""));
    EXPECT_NE(std::string::npos, body.find("\"payload_len\":4"));
}

TEST_F(IdsRmIntegrationTest, IdsMessageHexMatchesWireFormat) {
    init_idsrm();
    report_default();

    EXPECT_TRUE(wait_until([&]{ return server.count() >= 1; }));

    std::string body = server.last_body();
    /* Event frame (8B) + timestamp (8B) + context frame (2+1+4B):
       Byte0   0x23 = version 2, context+timestamp bits
       Byte1-2 0x00 0x40 = idsm instance 1, sensor instance 0
       Byte3-4 0x80 0x01 = external event ID (big-endian)
       Byte5-6 0x00 0x01 = count
       Byte7   0x00 reserved                                          */
    EXPECT_NE(std::string::npos, body.find("\"ids_message\":\"2300408001000100"));
}

TEST_F(IdsRmIntegrationTest, DisabledDropsEvents) {
    init_idsrm(false);
    report_default();
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(0, server.count());
    auto stats = IdsRm_GetStats();
    EXPECT_GE(stats.events_dropped, 1u);
    EXPECT_EQ(0u, stats.events_posted);
}

TEST_F(IdsRmIntegrationTest, EnableAfterDisableResumesForwarding) {
    init_idsrm(false);

    report_default();
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    EXPECT_EQ(0, server.count());

    IdsRm_Enable();
    report_default();

    EXPECT_TRUE(wait_until([&]{ return server.count() >= 1; }));
    EXPECT_EQ(1, server.count());
}

TEST_F(IdsRmIntegrationTest, RuntimeUrlChangeIsRespected) {
    /* Start pointing at a closed port — events fail */
    auto cfg = make_idsrm_config("http://127.0.0.1:19999/api/idsm-violations",
                                   true, 500, 0);
    ASSERT_EQ(E_OK, IdsRm_Init(&cfg));
    m_idsrm_up = true;

    report_default();
    std::this_thread::sleep_for(std::chrono::milliseconds(700));
    EXPECT_EQ(0, server.count());

    IdsRm_SetSocUrl(soc_url().c_str());
    report_default();

    EXPECT_TRUE(wait_until([&]{ return server.count() >= 1; }));
    EXPECT_EQ(1, server.count());
}

TEST_F(IdsRmIntegrationTest, MultipleEventsAllPosted) {
    init_idsrm();

    for (int i = 0; i < 5; ++i) {
        report_default();
    }

    EXPECT_TRUE(wait_until([&]{ return server.count() >= 5; }, 3000));
    auto stats = IdsRm_GetStats();
    EXPECT_EQ(5u, stats.events_received);
    EXPECT_EQ(5u, stats.events_posted);
}

TEST_F(IdsRmIntegrationTest, BriefReportingModeStripsContextBeforeSink) {
    init_idsrm();
    /* Switch SEv 0 to BRIEF: context data dropped before any sink sees it */
    ASSERT_EQ(E_OK, IdsM_SetReportingMode(0, IDSM_REPORTING_BRIEF));

    report_default();
    EXPECT_TRUE(wait_until([&]{ return server.count() >= 1; }));

    std::string body = server.last_body();
    EXPECT_NE(std::string::npos, body.find("\"has_context_data\":false"));
    EXPECT_NE(std::string::npos, body.find("\"payload_len\":0"));
}
