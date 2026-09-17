/*
 * test_detectors.cpp -- per-detector unit tests: trigger, mute, config.
 */
#include "detectors.h"

#include <gtest/gtest.h>

#include <cstring>

using namespace hostprobe;

namespace {

ExecEvent exec(uint32_t pid, uint32_t ppid, uint32_t uid, uint32_t euid,
               const char* comm, const char* parent = "init",
               const char* exe = "") {
    ExecEvent e;
    e.pid  = pid;
    e.ppid = ppid;
    e.uid  = uid;
    e.euid = euid;
    std::strncpy(e.comm, comm, sizeof(e.comm) - 1);
    std::strncpy(e.parent_comm, parent, sizeof(e.parent_comm) - 1);
    e.exe = exe;
    return e;
}

} /* namespace */

TEST(UnknownExecTest, DisabledWithoutAllowlist) {
    UnknownExecDetector d;
    EXPECT_FALSE(d.enabled());
    EXPECT_FALSE(d.feed(exec(1, 0, 0, 0, "evil", "init", "/usr/bin/evil"), 0));
}

TEST(UnknownExecTest, AlertsOnceThenMutes) {
    UnknownExecDetector d;
    d.add_allowed("/usr/bin/ls");
    d.add_allowed("sshd");
    ASSERT_TRUE(d.enabled());

    EXPECT_FALSE(d.feed(exec(1, 0, 0, 0, "ls", "init", "/usr/bin/ls"), 0));
    EXPECT_FALSE(d.feed(exec(2, 0, 0, 0, "sshd", "init", ""), 0));

    auto a = d.feed(exec(3, 0, 0, 0, "evil", "init", "/usr/bin/evil"), 0);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->detector_type, DT_UNKNOWN_EXEC);
    EXPECT_STREQ(a->name, "evil");

    /* muted within cooldown */
    EXPECT_FALSE(d.feed(exec(4, 0, 0, 0, "evil", "init", "/usr/bin/evil"), 1000));
    /* after cooldown: alerts again */
    EXPECT_TRUE(d.feed(exec(5, 0, 0, 0, "evil", "init", "/usr/bin/evil"),
                       60001).has_value());
}

TEST(PrivEscTest, SetuidRootExecByNonRoot) {
    PrivEscDetector d;
    auto a = d.feed(exec(1, 100, 1000, 0, "su", "sh", "/system/xbin/su"), 0);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->detector_type, DT_PRIV_ESC);
    EXPECT_TRUE(a->flags & HF_SETUID);
}

TEST(PrivEscTest, IgnoresRootOnRootAndPlainExec) {
    PrivEscDetector d;
    EXPECT_FALSE(d.feed(exec(1, 0, 0, 0, "init", "", "/sbin/init"), 0));
    EXPECT_FALSE(d.feed(exec(2, 100, 1000, 1000, "app", "sh"), 0));
}

TEST(ForkFloodTest, AlertsOncePerWindow) {
    ForkFloodDetector d(ForkFloodDetector::Config{1000, 5});
    std::optional<HostAlert> a;
    for (int i = 0; i < 5; ++i)
        a = d.feed(exec(static_cast<uint32_t>(i), 0, 0, 0, "x"), 0);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->detector_type, DT_FORK_FLOOD);
    EXPECT_EQ(a->aux, 5u);

    /* same window: no second alert */
    EXPECT_FALSE(d.feed(exec(9, 0, 0, 0, "x"), 500));
    /* next window: alerts again */
    std::optional<HostAlert> b;
    for (int i = 0; i < 5; ++i)
        b = d.feed(exec(static_cast<uint32_t>(i), 0, 0, 0, "x"), 1000 + i);
    EXPECT_TRUE(b.has_value());
}

TEST(RevShellTest, ShellUnderNetworkDaemon) {
    RevShellDetector d;
    auto a = d.feed(exec(1, 200, 2000, 2000, "sh", "adbd", ""), 0);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->detector_type, DT_REV_SHELL);
    EXPECT_TRUE(a->flags & HF_NET_PARENT);
    EXPECT_EQ(a->aux, 200u);  /* parent pid */
}

TEST(RevShellTest, IgnoresRegularShellsAndDaemons) {
    RevShellDetector d;
    EXPECT_FALSE(d.feed(exec(1, 1, 0, 0, "sh", "init"), 0));
    EXPECT_FALSE(d.feed(exec(2, 1, 0, 0, "bash", "bash"), 0));
    EXPECT_FALSE(d.feed(exec(3, 200, 0, 0, "adbd", "init"), 0));
}

TEST(FileModTest, HashMismatchAndMissing) {
    FileModDetector d;
    FileBaseline fb;
    uint8_t want[SHA256_LEN]{};
    want[0] = 0xAA;
    fb["/etc/passwd"] = std::array<uint8_t, SHA256_LEN>{};
    std::memcpy(fb["/etc/passwd"].data(), want, SHA256_LEN);
    d.set_baseline(std::move(fb));
    ASSERT_TRUE(d.enabled());

    FileScanEvent match;
    match.path = "/etc/passwd";
    match.present = true;
    std::memcpy(match.sha256, want, SHA256_LEN);
    EXPECT_FALSE(d.feed(match, 0));

    FileScanEvent changed = match;
    changed.sha256[0] = 0xBB;
    auto a = d.feed(changed, 0);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->detector_type, DT_FILE_MOD);
    EXPECT_EQ(a->aux, FILE_MOD_HASH);

    /* muted within cooldown */
    EXPECT_FALSE(d.feed(changed, 1000));

    FileScanEvent gone;
    gone.path = "/etc/passwd";
    gone.present = false;
    auto b = d.feed(gone, 600001);
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(b->aux, FILE_MOD_GONE);
    EXPECT_TRUE(b->flags & HF_MISSING);

    FileScanEvent other;
    other.path = "/etc/hosts";
    other.present = true;
    EXPECT_FALSE(d.feed(other, 0));  /* not monitored */
}

TEST(NewSetuidTest, OnlyNewRootOwnedSetuidFiles) {
    NewSetuidDetector d;
    d.add_baseline_path("/usr/bin/passwd");
    ASSERT_TRUE(d.enabled());

    FileScanEvent f;
    f.present = true;
    f.mode = 04755;
    f.uid = 0;

    f.path = "/usr/bin/passwd";  /* known path: silent */
    EXPECT_FALSE(d.feed(f, 0));

    f.path = "/tmp/.hidden";     /* new setuid-root binary */
    auto a = d.feed(f, 0);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->detector_type, DT_NEW_SETUID);
    EXPECT_TRUE(a->flags & HF_SETUID);

    f.mode = 0755;               /* not setuid */
    EXPECT_FALSE(d.feed(f, 600001));

    f.mode = 04755;
    f.uid = 1000;                /* setuid but not root-owned */
    EXPECT_FALSE(d.feed(f, 600001));
}

TEST(KmodLoadTest, OnlyOutOfBaselineModules) {
    KmodLoadDetector d;
    d.add_baseline("binder");
    ASSERT_TRUE(d.enabled());

    ModuleScanEvent m;
    m.name = "binder";
    EXPECT_FALSE(d.feed(m, 0));

    m.name = "evil_rootkit";
    auto a = d.feed(m, 0);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->detector_type, DT_KMOD_LOAD);
    EXPECT_STREQ(a->name, "evil_rootki");  /* 11-char name field */
    EXPECT_FALSE(d.feed(m, 1000));        /* muted */
}

TEST(ZombieStormTest, AlertsOncePerWindow) {
    ZombieStormDetector d(ZombieStormDetector::Config{1000, 10});
    SnapshotEvent s;
    s.zombies = 9;
    EXPECT_FALSE(d.feed(s, 0));
    s.zombies = 12;
    auto a = d.feed(s, 500);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->detector_type, DT_ZOMBIE_STORM);
    EXPECT_EQ(a->aux, 12u);
    s.zombies = 50;
    EXPECT_FALSE(d.feed(s, 900));   /* already alerted this window */
    s.zombies = 11;
    EXPECT_TRUE(d.feed(s, 1001).has_value());  /* next window */
}

TEST(ResExhaustTest, CpuAndMemThresholds) {
    ResExhaustDetector d;
    SnapshotEvent s;
    s.top_cpu_ppm = 899;
    s.top_mem_rss_kb = 1048575;
    EXPECT_FALSE(d.feed(s, 0));

    s.top_cpu_ppm = 900;
    auto a = d.feed(s, 0);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->aux, RES_EXHAUST_CPU);
    EXPECT_FALSE(d.feed(s, 1000));  /* muted */

    SnapshotEvent m;
    m.top_cpu_ppm = 0;
    m.top_mem_rss_kb = 1048576;
    auto b = d.feed(m, 60001);
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(b->aux, RES_EXHAUST_MEM);
}

TEST(RootShellTest, Uid0ShellOnly) {
    RootShellDetector d;

    auto a = d.feed(exec(1, 100, 0, 0, "sh", "sshd"), 0);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->detector_type, DT_ROOT_SHELL);
    EXPECT_EQ(a->aux, ROOT_SHELL_NET);

    EXPECT_FALSE(d.feed(exec(2, 1, 0, 0, "sh", "init"), 1000)); /* muted */
    EXPECT_FALSE(d.feed(exec(3, 1, 1000, 1000, "sh", "init"), 60001));
    EXPECT_FALSE(d.feed(exec(4, 1, 0, 0, "nginx", "init"), 60001));

    RootShellDetector d2;
    auto b = d2.feed(exec(5, 1, 0, 0, "bash", "init"), 0);
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(b->aux, ROOT_SHELL_TTY);
}
