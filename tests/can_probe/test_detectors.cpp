#include "detectors.h"

#include <gtest/gtest.h>

#include <cstring>

using namespace canprobe;

namespace {

CanFrame make_frame(uint32_t id, uint8_t dlc = 8, bool eff = false) {
    CanFrame f;
    f.can_id = id;
    f.eff    = eff;
    f.dlc    = dlc;
    f.len    = dlc <= 8 ? dlc : 8;
    return f;
}

CanFrame make_diag(uint32_t id, std::initializer_list<uint8_t> payload) {
    CanFrame f = make_frame(id, static_cast<uint8_t>(payload.size()));
    std::memset(f.data, 0, sizeof(f.data));
    size_t i = 0;
    for (uint8_t b : payload) f.data[i++] = b;
    return f;
}

CanFrame make_err_frame() {
    CanFrame f;
    f.err = true;
    return f;
}

} /* namespace */

TEST(DlcAnomalyTest, ClassicDlcAboveEightAlerts) {
    auto a = check_dlc_anomaly(make_frame(0x100, 12));
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->detector_type, DT_DLC_ANOMALY);
    EXPECT_EQ(a->aux, DLC_ANOMALY_CLASSIC_GT8);

    EXPECT_FALSE(check_dlc_anomaly(make_frame(0x100, 8)).has_value());
}

TEST(DlcAnomalyTest, CanFdLenAboveSixtyFourAlerts) {
    CanFrame f = make_frame(0x100, 70);
    f.fd  = true;
    f.len = 64;
    auto a = check_dlc_anomaly(f);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->aux, DLC_ANOMALY_FD_LEN);
}

TEST(DlcAnomalyTest, SkipsErrorAndRemoteFrames) {
    EXPECT_FALSE(check_dlc_anomaly(make_err_frame()).has_value());
    CanFrame rtr = make_frame(0x100, 12);
    rtr.rtr = true;
    EXPECT_FALSE(check_dlc_anomaly(rtr).has_value());
}

TEST(RemoteFrameTest, AlertsOnRtr) {
    CanFrame f = make_frame(0x55, 0);
    f.rtr = true;
    auto a = check_remote_frame(f);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->detector_type, DT_REMOTE_FRAME);
    EXPECT_FALSE(check_remote_frame(make_frame(0x55, 0)).has_value());
}

TEST(UnknownIdTest, AlertsOnlyForUnknownIds) {
    UnknownIdDetector det;
    EXPECT_FALSE(det.enabled());
    det.add_known(0x100);
    det.add_known(0x123);
    EXPECT_TRUE(det.enabled());

    EXPECT_FALSE(det.feed(make_frame(0x100), 0).has_value());
    auto a = det.feed(make_frame(0x200), 0);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->detector_type, DT_UNKNOWN_ID);
    EXPECT_EQ(a->can_id, 0x200u);
}

TEST(IdFloodTest, TriggersAtThresholdAndMutes) {
    IdFloodDetector det(IdFloodDetector::Config{1000, 3});
    EXPECT_FALSE(det.feed(make_frame(0x100), 0).has_value());
    EXPECT_FALSE(det.feed(make_frame(0x100), 1).has_value());
    auto a = det.feed(make_frame(0x100), 2);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->detector_type, DT_ID_FLOOD);
    EXPECT_EQ(a->count, 3u);
    EXPECT_EQ(a->aux, 3u);  /* 3 frames in 1000 ms */
    /* same window: muted even above threshold */
    EXPECT_FALSE(det.feed(make_frame(0x100), 3).has_value());
    /* other ID unaffected */
    EXPECT_FALSE(det.feed(make_frame(0x200), 3).has_value());
}

TEST(IdFloodTest, WindowExpiryResets) {
    IdFloodDetector det(IdFloodDetector::Config{100, 2});
    EXPECT_FALSE(det.feed(make_frame(0x100), 0).has_value());
    auto a = det.feed(make_frame(0x100), 1);
    ASSERT_TRUE(a.has_value());
    /* next window starts clean */
    EXPECT_FALSE(det.feed(make_frame(0x100), 101).has_value());
}

TEST(IdFloodTest, IgnoresErrorFrames) {
    IdFloodDetector det(IdFloodDetector::Config{1000, 1});
    EXPECT_FALSE(det.feed(make_err_frame(), 0).has_value());
}

TEST(BusFloodTest, CountsEveryFrame) {
    BusFloodDetector det(BusFloodDetector::Config{1000, 4});
    EXPECT_FALSE(det.feed(make_frame(0x100), 0).has_value());
    EXPECT_FALSE(det.feed(make_frame(0x200), 1).has_value());
    EXPECT_FALSE(det.feed(make_frame(0x300), 2).has_value());
    auto a = det.feed(make_frame(0x400), 3);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->detector_type, DT_BUS_FLOOD);
    EXPECT_EQ(a->count, 4u);
}

TEST(ErrorBurstTest, TriggersOnErrorCount) {
    ErrorBurstDetector det(ErrorBurstDetector::Config{1000, 3});
    EXPECT_FALSE(det.feed(make_err_frame(), 0).has_value());
    EXPECT_FALSE(det.feed(make_err_frame(), 1).has_value());
    auto a = det.feed(make_err_frame(), 2);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->detector_type, DT_ERROR_BURST);
    EXPECT_EQ(a->aux, 3u);
    EXPECT_FALSE(det.feed(make_err_frame(), 3).has_value());
}

TEST(DiagFloodTest, PerTesterId) {
    DiagFloodDetector det(DiagFloodDetector::Config{1000, 3});
    EXPECT_FALSE(det.feed(make_diag(0x7E0, {0x10, 0x01}), 0).has_value());
    EXPECT_FALSE(det.feed(make_diag(0x7E0, {0x10, 0x01}), 1).has_value());
    auto a = det.feed(make_diag(0x7E0, {0x10, 0x01}), 2);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->detector_type, DT_DIAG_FLOOD);
    /* different tester: independent window */
    EXPECT_FALSE(det.feed(make_diag(0x7E1, {0x10, 0x01}), 3).has_value());
}

TEST(SecAccessTest, SeedFloodOnOddSubFunction) {
    UdsSecAccessDetector det(UdsSecAccessDetector::Config{60000, 3, 3});
    /* requestSeed: SID 0x27 subfn 0x01 (odd) */
    EXPECT_FALSE(det.feed(make_diag(0x7E0, {0x27, 0x01}), 0).has_value());
    EXPECT_FALSE(det.feed(make_diag(0x7E0, {0x27, 0x03}), 1).has_value());
    auto a = det.feed(make_diag(0x7E0, {0x27, 0x01}), 2);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->detector_type, DT_UDS_SEC_ACCESS);
    EXPECT_EQ(a->aux, SEC_ACCESS_SEED_FLOOD);
    EXPECT_EQ(a->count, 3u);
    EXPECT_FALSE(det.feed(make_diag(0x7E0, {0x27, 0x01}), 3).has_value());
}

TEST(SecAccessTest, KeyGuessOnEvenSubFunction) {
    UdsSecAccessDetector det(UdsSecAccessDetector::Config{60000, 9, 2});
    /* sendKey: subfn 0x02 (even) */
    EXPECT_FALSE(det.feed(make_diag(0x7E0, {0x27, 0x02}), 0).has_value());
    auto a = det.feed(make_diag(0x7E0, {0x27, 0x02}), 1);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->aux, SEC_ACCESS_KEY_GUESS);
}

TEST(SecAccessTest, IgnoresNonSecurityAccess) {
    UdsSecAccessDetector det(UdsSecAccessDetector::Config{60000, 1, 1});
    EXPECT_FALSE(det.feed(make_diag(0x7E0, {0x10, 0x01}), 0).has_value());
    EXPECT_FALSE(det.feed(make_diag(0x7E0, {0x27}), 0).has_value());
}

TEST(SvcScanTest, DistinctSidCount) {
    UdsSvcScanDetector det(UdsSvcScanDetector::Config{10000, 4});
    for (uint8_t i = 1; i <= 3; ++i)
        EXPECT_FALSE(det.feed(make_diag(0x7E0, {i, 0x00}), i).has_value());
    /* repeats of a known SID do not grow the set */
    EXPECT_FALSE(det.feed(make_diag(0x7E0, {0x01, 0x00}), 4).has_value());
    auto a = det.feed(make_diag(0x7E0, {0x04, 0x00}), 5);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->detector_type, DT_UDS_SVC_SCAN);
    EXPECT_EQ(a->aux, 4u);
}

TEST(CycleAnomalyTest, FasterThanMinIntervalAlerts) {
    CycleAnomalyDetector det;
    CycleAnomalyDetector::Config cfg;
    cfg.cooldown_ms = 1000;
    det.set_config(cfg);
    det.add_min_interval(0x100, 100);

    EXPECT_FALSE(det.feed(make_frame(0x100), 0).has_value());
    EXPECT_FALSE(det.feed(make_frame(0x100), 100).has_value());  /* exactly at min */
    auto a = det.feed(make_frame(0x100), 150);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->detector_type, DT_CYCLE_ANOMALY);
    EXPECT_EQ(a->aux, 50u);  /* observed interval */
    /* muted during cooldown */
    EXPECT_FALSE(det.feed(make_frame(0x100), 180).has_value());
    /* interval back to normal: no alert */
    EXPECT_FALSE(det.feed(make_frame(0x100), 2100).has_value());
    /* after cooldown, a fresh violation alerts again */
    auto b = det.feed(make_frame(0x100), 2150);
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(b->aux, 50u);
}

TEST(CycleAnomalyTest, UntrackedIdIgnored) {
    CycleAnomalyDetector det;
    det.add_min_interval(0x100, 100);
    EXPECT_FALSE(det.feed(make_frame(0x200), 0).has_value());
    EXPECT_FALSE(det.feed(make_frame(0x200), 10).has_value());
}