/*
 * test_idsrm_sink.cpp -- local UDS sink tests: qualified events are teed
 * to a unix-domain socket as NDJSON lines (production path to the IDSM
 * manager APK on Android). Shares the test_idsrm binary; each test
 * inits/deinits the IdsM + IdsRM singletons.
 */
#include <gtest/gtest.h>
#include <chrono>
#include <cstring>
#include <functional>
#include <string>
#include <thread>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "IdsM.h"
#include "IdsRm.h"

namespace {

bool wait_until(std::function<bool()> cond, int max_ms = 3000) {
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(max_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (cond()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return cond();
}

uint8_t g_payload[4] = {0x01, 0x02, 0x03, 0x04};

void init_idsm() {
    IdsM_SecurityEventConfigType sev{};
    sev.external_event_id       = 0x8001;
    sev.sensor_instance_id      = 0;
    sev.severity                = IDSM_SEVERITY_HIGH;
    sev.default_reporting_mode  = IDSM_REPORTING_DETAILED;
    sev.block_state             = nullptr;
    sev.forward_every_nth       = 0;
    sev.aggregation_interval_ms = 0;
    sev.event_threshold         = {0, 0};
    sev.sink_to_dem             = false;
    sev.sink_to_idsr            = true;

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

IdsRm_ConfigType make_cfg(const char* url) {
    IdsRm_ConfigType cfg{};
    std::strncpy(cfg.soc_url, url, IDSRM_MAX_URL_LEN - 1);
    cfg.auth_token[0] = '\0';
    cfg.timeout_ms    = 500;
    cfg.retry_count   = 0;
    cfg.enabled       = true;
    return cfg;
}

/* AF_UNIX listener standing in for the manager APK */
class UnixListener {
public:
    bool open(const std::string& path) {
        m_path = path;
        m_fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (m_fd < 0) return false;
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
        ::unlink(path.c_str());
        if (::bind(m_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
            return false;
        return ::listen(m_fd, 4) == 0;
    }
    ~UnixListener() {
        if (m_fd >= 0) ::close(m_fd);
        if (!m_path.empty()) ::unlink(m_path.c_str());
    }
    /* abstract-namespace bind (Android @name) — nothing to unlink */
    bool open_abstract(const std::string& name) {
        m_fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (m_fd < 0) return false;
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        if (name.size() >= sizeof(addr.sun_path)) return false;
        std::memcpy(addr.sun_path + 1, name.c_str(), name.size());
        return ::bind(m_fd, reinterpret_cast<sockaddr*>(&addr),
                      sizeof(addr)) == 0
            && ::listen(m_fd, 4) == 0;
    }
    int fd() const { return m_fd; }

private:
    int         m_fd{-1};
    std::string m_path;
};

std::string read_line(int fd) {
    std::string out;
    char c;
    while (::read(fd, &c, 1) == 1) {
        if (c == '\n') break;
        out += c;
        if (out.size() > 65536) break;  /* runaway guard */
    }
    return out;
}

TEST(IdsRmSink, ForwardsNdjsonLineToUdsPeer) {
    const std::string path =
        "/tmp/idsrm_sink_" + std::to_string(::getpid()) + ".sock";
    UnixListener listener;
    ASSERT_TRUE(listener.open(path));

    init_idsm();
    IdsRm_ConfigType cfg = make_cfg("");  /* HTTP off, sink only */
    ASSERT_EQ(E_OK, IdsRm_Init(&cfg));
    ASSERT_EQ(E_OK, IdsRm_SetLocalSink(path.c_str()));

    IdsM_ReportSecurityEvent(0, g_payload, sizeof(g_payload),
                             1 /*version*/, 1, nullptr);

    const int conn = ::accept(listener.fd(), nullptr, nullptr);
    ASSERT_GE(conn, 0);
    const std::string line = read_line(conn);
    ::close(conn);

    EXPECT_NE(line.find("\"event_id\":32769"), std::string::npos);  /* 0x8001 */
    EXPECT_NE(line.find("\"payload\":\"01020304\""), std::string::npos);
    EXPECT_NE(line.find("\"ids_message\""), std::string::npos);

    ASSERT_EQ(E_OK, IdsRm_DeInit());
    IdsM_DeInit();
}

TEST(IdsRmSink, SupportsAndroidAbstractSocket) {
    const std::string name =
        "idsrm_abs_" + std::to_string(::getpid());
    UnixListener listener;
    ASSERT_TRUE(listener.open_abstract(name));

    init_idsm();
    IdsRm_ConfigType cfg = make_cfg("");  /* HTTP off, sink only */
    ASSERT_EQ(E_OK, IdsRm_Init(&cfg));
    ASSERT_EQ(E_OK, IdsRm_SetLocalSink(("@" + name).c_str()));

    IdsM_ReportSecurityEvent(0, g_payload, sizeof(g_payload),
                             1 /*version*/, 1, nullptr);

    const int conn = ::accept(listener.fd(), nullptr, nullptr);
    ASSERT_GE(conn, 0);
    const std::string line = read_line(conn);
    ::close(conn);

    EXPECT_NE(line.find("\"event_id\":32769"), std::string::npos);

    ASSERT_EQ(E_OK, IdsRm_DeInit());
    IdsM_DeInit();
}

TEST(IdsRmSink, DropsWhenPeerDownAndSkipsHttp) {
    init_idsm();
    IdsRm_ConfigType cfg = make_cfg("");  /* no HTTP target, no sink peer */
    ASSERT_EQ(E_OK, IdsRm_Init(&cfg));
    ASSERT_EQ(E_OK, IdsRm_SetLocalSink("/tmp/idsrm_sink_no_such_peer.sock"));

    IdsM_ReportSecurityEvent(0, g_payload, sizeof(g_payload),
                             1 /*version*/, 1, nullptr);

    /* sink thread drops after its connect backoff; HTTP path counts the
       event as posted because the sink owns delivery */
    EXPECT_TRUE(wait_until([] {
        return IdsRm_GetStats().events_dropped >= 1;
    }));
    EXPECT_TRUE(wait_until([] {
        return IdsRm_GetStats().events_posted >= 1;
    }));
    EXPECT_EQ(IdsRm_GetStats().http_retries, 0u);  /* no curl traffic */

    ASSERT_EQ(E_OK, IdsRm_DeInit());
    IdsM_DeInit();
}

}  /* namespace */
