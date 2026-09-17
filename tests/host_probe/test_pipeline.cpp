/*
 * test_pipeline.cpp -- end-to-end pipeline tests: baseline loading +
 * event feeding through parse_host_event() lines, matching how
 * --events replay drives the probe.
 */
#include "pipeline.h"

#include <gtest/gtest.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>

using namespace hostprobe;

namespace {

std::vector<HostAlert> g_alerts;

void collect(const HostAlert& a) { g_alerts.push_back(a); }

bool has_alert(uint8_t type) {
    for (const auto& a : g_alerts)
        if (a.detector_type == type) return true;
    return false;
}

const HostAlert* find_alert(uint8_t type) {
    for (const auto& a : g_alerts)
        if (a.detector_type == type) return &a;
    return nullptr;
}

/* parse one replay line and feed it */
void feed_line(HostProbePipeline& p, const char* line) {
    HostEvent ev{};
    ASSERT_TRUE(parse_host_event(line, ev));
    p.feed_event(ev);
}

} /* namespace */

class PipelineTest : public ::testing::Test {
protected:
    void SetUp() override { g_alerts.clear(); }
};

TEST_F(PipelineTest, ExecEventsReachExecDetectors) {
    HostProbePipeline p(&collect);

    feed_line(p, "exec 0 200 199 1000 0 1000 0 sh adbd /system/bin/sh");
    /* allowlist not loaded: unknown-exec disabled, but priv-esc and
       rev-shell are stateless and must fire */
    ASSERT_EQ(g_alerts.size(), 2u);
    EXPECT_TRUE(has_alert(DT_PRIV_ESC));
    EXPECT_TRUE(has_alert(DT_REV_SHELL));
}

TEST_F(PipelineTest, AllowlistSuppressesUnknownExec) {
    const char* path = "/tmp/host_probe_test_exec.txt";
    {
        std::ofstream out(path);
        out << "# allowlist\n"
               "/usr/bin/ls\n"
               "sshd\n"
               "gar bage entry with spaces\n";
    }

    HostProbePipeline p(&collect);
    std::string err;
    size_t bad = 0;
    ASSERT_TRUE(p.load_exec_allowlist(path, err, &bad));
    EXPECT_EQ(bad, 1u);
    EXPECT_EQ(p.unknown_exec().allowed_count(), 2u);
    std::remove(path);

    feed_line(p, "exec 0 1 0 0 0 0 0 ls sh /usr/bin/ls");
    feed_line(p, "exec 0 2 0 0 0 0 0 sshd init /usr/sbin/sshd");
    EXPECT_TRUE(g_alerts.empty());

    feed_line(p, "exec 0 3 0 0 0 0 0 evil init /usr/bin/evil");
    ASSERT_EQ(g_alerts.size(), 1u);
    EXPECT_EQ(g_alerts[0].detector_type, DT_UNKNOWN_EXEC);
}

TEST_F(PipelineTest, FileBaselineDrivesIntegrityDetectors) {
    /* baseline: /etc/known has digest 0xAA.., /usr/bin/passwd known */
    const char* path = "/tmp/host_probe_test_files.txt";
    {
        std::ofstream out(path);
        out << "# file baseline (sha256sum format)\n"
               "aa00000000000000000000000000000000000000000000000000000000000000  /etc/known\n"
               "bb00000000000000000000000000000000000000000000000000000000000000  /usr/bin/passwd\n"
               "not_a_hash  /bad\n";
    }

    HostProbePipeline p(&collect);
    std::string err;
    size_t bad = 0;
    ASSERT_TRUE(p.load_file_baseline(path, err, &bad));
    EXPECT_EQ(bad, 1u);
    EXPECT_EQ(p.file_mod().baseline().size(), 2u);
    EXPECT_EQ(p.new_setuid().baseline_count(), 2u);
    std::remove(path);

    /* matching file: silent */
    feed_line(p, "file 0 /etc/known 1 0644 0 "
                 "aa00000000000000000000000000000000000000000000000000000000000000");
    EXPECT_TRUE(g_alerts.empty());

    /* hash mismatch: FILE_MOD */
    feed_line(p, "file 0 /etc/known 1 0644 0 "
                 "cc00000000000000000000000000000000000000000000000000000000000000");
    ASSERT_EQ(g_alerts.size(), 1u);
    EXPECT_EQ(g_alerts[0].detector_type, DT_FILE_MOD);
    EXPECT_EQ(g_alerts[0].aux, FILE_MOD_HASH);

    /* new setuid-root binary outside baseline: NEW_SETUID */
    feed_line(p, "file 0 /tmp/.x 1 4755 0 "
                 "dd00000000000000000000000000000000000000000000000000000000000000");
    ASSERT_EQ(g_alerts.size(), 2u);
    EXPECT_EQ(g_alerts[1].detector_type, DT_NEW_SETUID);

    /* setuid-root but a KNOWN path: silent */
    feed_line(p, "file 0 /usr/bin/passwd 1 4755 0 "
                 "bb00000000000000000000000000000000000000000000000000000000000000");
    EXPECT_EQ(g_alerts.size(), 2u);
}

TEST_F(PipelineTest, ModuleBaselineDrivesKmodDetection) {
    const char* path = "/tmp/host_probe_test_mods.txt";
    {
        std::ofstream out(path);
        out << "binder\n"
               "# comment\n"
               "\n"
               "ashmem\n";
    }

    HostProbePipeline p(&collect);
    std::string err;
    size_t bad = 0;
    ASSERT_TRUE(p.load_module_baseline(path, err, &bad));
    EXPECT_EQ(bad, 0u);
    EXPECT_EQ(p.kmod().baseline_count(), 2u);
    std::remove(path);

    feed_line(p, "module 0 binder");
    EXPECT_TRUE(g_alerts.empty());
    feed_line(p, "module 0 evil_rootkit");
    ASSERT_EQ(g_alerts.size(), 1u);
    EXPECT_EQ(g_alerts[0].detector_type, DT_KMOD_LOAD);
}

TEST_F(PipelineTest, SnapshotsDriveZombieAndResDetectors) {
    HostProbePipeline p(&collect);

    feed_line(p, "snap 0 0 100 0 100 idle 100 0 1024 idle");
    EXPECT_TRUE(g_alerts.empty());

    feed_line(p, "snap 0 150 200 0 950 hog 200 0 1048576 fat");
    EXPECT_TRUE(has_alert(DT_ZOMBIE_STORM));
    EXPECT_TRUE(has_alert(DT_RES_EXHAUST));

    const HostAlert* z = find_alert(DT_ZOMBIE_STORM);
    ASSERT_NE(z, nullptr);
    EXPECT_EQ(z->aux, 150u);
    const HostAlert* r = find_alert(DT_RES_EXHAUST);
    ASSERT_NE(r, nullptr);
    EXPECT_EQ(r->aux, RES_EXHAUST_CPU);  /* CPU checked first */
}

TEST_F(PipelineTest, RootShellFlowsThrough) {
    HostProbePipeline p(&collect);
    feed_line(p, "exec 0 1 100 0 0 0 0 bash sshd /bin/bash");
    /* sshd -> bash fires BOTH root-shell and rev-shell */
    ASSERT_EQ(g_alerts.size(), 2u);
    EXPECT_TRUE(has_alert(DT_ROOT_SHELL));
    EXPECT_TRUE(has_alert(DT_REV_SHELL));
    const HostAlert* r = find_alert(DT_ROOT_SHELL);
    ASSERT_NE(r, nullptr);
    EXPECT_EQ(r->aux, ROOT_SHELL_NET);
}

TEST_F(PipelineTest, MissingMonitoredFileAlerts) {
    const char* path = "/tmp/host_probe_test_files2.txt";
    {
        std::ofstream out(path);
        out << "aa00000000000000000000000000000000000000000000000000000000000000  /etc/critical.conf\n";
    }
    HostProbePipeline p(&collect);
    std::string err;
    ASSERT_TRUE(p.load_file_baseline(path, err));
    std::remove(path);

    feed_line(p, "file 0 /etc/critical.conf 0 0 0 -");
    ASSERT_EQ(g_alerts.size(), 1u);
    EXPECT_EQ(g_alerts[0].detector_type, DT_FILE_MOD);
    EXPECT_EQ(g_alerts[0].aux, FILE_MOD_GONE);
    EXPECT_TRUE(g_alerts[0].flags & HF_MISSING);
}
