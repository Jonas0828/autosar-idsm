/*
 * test_events.cpp -- replay-log line parsing (see event.h format).
 */
#include "event.h"
#include "sha256.h"

#include <gtest/gtest.h>

#include <cstring>

using namespace hostprobe;

TEST(EventParseTest, BlankAndCommentLines) {
    HostEvent ev{};
    EXPECT_FALSE(parse_host_event("", ev));
    EXPECT_FALSE(parse_host_event("   ", ev));
    EXPECT_FALSE(parse_host_event("# comment", ev));
    EXPECT_FALSE(parse_host_event("   # comment", ev));
}

TEST(EventParseTest, ExecLine) {
    HostEvent ev{};
    ASSERT_TRUE(parse_host_event(
        "exec 1000 200 199 1000 0 1000 0 sh adbd /system/bin/sh", ev));
    EXPECT_EQ(ev.kind, HostEventKind::EXEC);
    EXPECT_EQ(ev.ts_ms, 1000u);
    EXPECT_EQ(ev.exec.pid, 200u);
    EXPECT_EQ(ev.exec.ppid, 199u);
    EXPECT_EQ(ev.exec.uid, 1000u);
    EXPECT_EQ(ev.exec.euid, 0u);
    EXPECT_STREQ(ev.exec.comm, "sh");
    EXPECT_STREQ(ev.exec.parent_comm, "adbd");
    EXPECT_EQ(ev.exec.exe, "/system/bin/sh");
}

TEST(EventParseTest, ExecLineWithoutExe) {
    HostEvent ev{};
    ASSERT_TRUE(parse_host_event("exec 5 10 1 0 0 0 0 init init", ev));
    EXPECT_EQ(ev.exec.exe, "");
}

TEST(EventParseTest, FileLine) {
    HostEvent ev{};
    ASSERT_TRUE(parse_host_event(
        "file 2000 /etc/passwd 1 0644 0 "
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ev));
    EXPECT_EQ(ev.kind, HostEventKind::FILE_SCAN);
    EXPECT_EQ(ev.file.path, "/etc/passwd");
    EXPECT_TRUE(ev.file.present);
    EXPECT_EQ(ev.file.mode, 0644u);
    EXPECT_EQ(ev.file.uid, 0u);
    uint8_t want[32];
    sha256_from_hex(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        want);
    EXPECT_EQ(std::memcmp(ev.file.sha256, want, 32), 0);
}

TEST(EventParseTest, FileLineMissing) {
    HostEvent ev{};
    ASSERT_TRUE(parse_host_event("file 2000 /etc/shadow 0 0 0 -", ev));
    EXPECT_FALSE(ev.file.present);
}

TEST(EventParseTest, ModuleLine) {
    HostEvent ev{};
    ASSERT_TRUE(parse_host_event("module 3000 binder", ev));
    EXPECT_EQ(ev.kind, HostEventKind::MODULE_SCAN);
    EXPECT_EQ(ev.module.name, "binder");
}

TEST(EventParseTest, SnapshotLine) {
    HostEvent ev{};
    ASSERT_TRUE(parse_host_event(
        "snap 4000 42 100 0 950 hog 200 1000 2097152 fat", ev));
    EXPECT_EQ(ev.kind, HostEventKind::SNAPSHOT);
    EXPECT_EQ(ev.snap.zombies, 42u);
    EXPECT_EQ(ev.snap.top_cpu_pid, 100u);
    EXPECT_EQ(ev.snap.top_cpu_ppm, 950u);
    EXPECT_STREQ(ev.snap.top_cpu_comm, "hog");
    EXPECT_EQ(ev.snap.top_mem_pid, 200u);
    EXPECT_EQ(ev.snap.top_mem_rss_kb, 2097152u);
    EXPECT_STREQ(ev.snap.top_mem_comm, "fat");
}

TEST(EventParseTest, MalformedLines) {
    HostEvent ev{};
    EXPECT_FALSE(parse_host_event("exec 1 2 3", ev));
    EXPECT_FALSE(parse_host_event("exec xx 2 3 4 5 6 7 sh sh", ev));
    EXPECT_FALSE(parse_host_event("file 1 /x 1 0644 0 zz", ev));
    EXPECT_FALSE(parse_host_event("file 1 /x 1 0x644 0 -", ev));
    EXPECT_FALSE(parse_host_event("snap 1 2 3", ev));
    EXPECT_FALSE(parse_host_event("module", ev));
    EXPECT_FALSE(parse_host_event("bogus 1 2 3", ev));
}

TEST(EventParseTest, CommentStrippedFromLine) {
    HostEvent ev{};
    ASSERT_TRUE(parse_host_event("module 3000 binder   # built-in", ev));
    EXPECT_EQ(ev.module.name, "binder");
}
