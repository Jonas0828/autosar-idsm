#include "pipeline.h"

#include <gtest/gtest.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>

using namespace canprobe;

namespace {

std::vector<CanAlert> g_alerts;

void collect(const CanAlert& a) { g_alerts.push_back(a); }

bool has_alert(uint8_t type) {
    for (const auto& a : g_alerts)
        if (a.detector_type == type) return true;
    return false;
}

CanFrame frame(uint32_t id, std::initializer_list<uint8_t> payload = {}) {
    CanFrame f;
    f.can_id = id;
    f.dlc    = static_cast<uint8_t>(payload.size());
    f.len    = f.dlc;
    std::memset(f.data, 0, sizeof(f.data));
    size_t i = 0;
    for (uint8_t b : payload) f.data[i++] = b;
    return f;
}

} /* namespace */

class PipelineTest : public ::testing::Test {
protected:
    void SetUp() override { g_alerts.clear(); }
};

TEST_F(PipelineTest, UnknownIdFlowsThroughCallback) {
    CanProbePipeline p(&collect);
    p.unknown_id().add_known(0x100);

    p.feed_frame(frame(0x100), 0);          /* known: silent */
    p.feed_frame(frame(0x321), 0);          /* unknown: alert */
    ASSERT_EQ(g_alerts.size(), 1u);
    EXPECT_EQ(g_alerts[0].detector_type, DT_UNKNOWN_ID);
    EXPECT_EQ(g_alerts[0].can_id, 0x321u);
}

TEST_F(PipelineTest, DiagnosticsRangeNeverUnknown) {
    CanProbePipeline p(&collect);
    p.unknown_id().add_known(0x100);

    p.feed_frame(frame(0x7DF, {0x3E, 0x00}), 0);
    p.feed_frame(frame(0x7E8, {0x7F, 0x3E, 0x78}), 0);
    EXPECT_FALSE(has_alert(DT_UNKNOWN_ID));
}

TEST_F(PipelineTest, LoadIdsEnablesWhitelistAndCycle) {
    const char* path = "/tmp/can_probe_test_ids.txt";
    {
        std::ofstream out(path);
        out << "# comment line\n"
               "\n"
               "100 90\n"     /* known, 90 ms min interval */
               "123\n"        /* known, no cycle check */
               "not_hex\n";   /* skipped */
    }

    CanProbePipeline p(&collect);
    std::string err;
    size_t bad = 0;
    ASSERT_TRUE(p.load_ids(path, err, &bad));
    EXPECT_EQ(bad, 1u);
    EXPECT_EQ(p.unknown_id().known_count(), 2u);
    std::remove(path);

    p.feed_frame(frame(0x100), 0);
    p.feed_frame(frame(0x100), 50);   /* 50 < 90: cycle anomaly */
    p.feed_frame(frame(0x123), 60);   /* no min interval: fine */
    ASSERT_TRUE(has_alert(DT_CYCLE_ANOMALY));
    EXPECT_FALSE(has_alert(DT_UNKNOWN_ID));
}

TEST_F(PipelineTest, LoadIdsMissingFileFails) {
    CanProbePipeline p(&collect);
    std::string err;
    EXPECT_FALSE(p.load_ids("/tmp/definitely_not_there_42.txt", err));
    EXPECT_FALSE(err.empty());
}

TEST_F(PipelineTest, ErrorFramesOnlyFeedErrorBurst) {
    CanProbePipeline p(&collect);
    p.err_burst().set_config(ErrorBurstDetector::Config{1000, 2});

    CanFrame e1, e2;
    e1.err = true;
    e2.err = true;
    p.feed_frame(e1, 0);
    p.feed_frame(e2, 1);
    ASSERT_TRUE(has_alert(DT_ERROR_BURST));
    EXPECT_EQ(g_alerts.size(), 1u);
    EXPECT_EQ(g_alerts[0].detector_type, DT_ERROR_BURST);
}

TEST_F(PipelineTest, SecurityAccessBruteForceOnDiagId) {
    CanProbePipeline p(&collect);
    p.sec_access().set_config(UdsSecAccessDetector::Config{60000, 3, 9});

    /* same SID 0x27 requestSeed from 0x7E0 three times */
    p.feed_frame(frame(0x7E0, {0x27, 0x01}), 0);
    p.feed_frame(frame(0x7E0, {0x27, 0x01}), 1);
    p.feed_frame(frame(0x7E0, {0x27, 0x01}), 2);
    ASSERT_TRUE(has_alert(DT_UDS_SEC_ACCESS));
    /* no diag flood by default config at 3 frames/s */
    EXPECT_FALSE(has_alert(DT_DIAG_FLOOD));
}

TEST_F(PipelineTest, UdsFramesOnNonDiagIdAreIgnoredByDiagDetectors) {
    CanProbePipeline p(&collect);
    p.diag_flood().set_config(DiagFloodDetector::Config{1000, 1});
    p.sec_access().set_config(UdsSecAccessDetector::Config{60000, 1, 1});

    p.feed_frame(frame(0x100, {0x27, 0x01}), 0);
    EXPECT_TRUE(g_alerts.empty());
}

TEST_F(PipelineTest, FeedRawParsesSocketCanRecord) {
    CanProbePipeline p(&collect);
    p.unknown_id().add_known(0x100);

    uint8_t raw[CAN_FRAME_LEN] = {};
    const uint32_t raw_id = 0x321;  /* unknown id */
    std::memcpy(raw, &raw_id, 4);
    raw[4] = 2;
    raw[8] = 0xDE;
    raw[9] = 0xAD;

    p.feed_raw(raw, sizeof(raw), 0);
    ASSERT_EQ(g_alerts.size(), 1u);
    EXPECT_EQ(g_alerts[0].detector_type, DT_UNKNOWN_ID);
    EXPECT_EQ(g_alerts[0].can_id, 0x321u);
}

TEST_F(PipelineTest, FeedRawDropsMalformedRecords) {
    CanProbePipeline p(&collect);
    uint8_t garbage[13] = {};
    p.feed_raw(garbage, sizeof(garbage), 0);
    EXPECT_TRUE(g_alerts.empty());
}