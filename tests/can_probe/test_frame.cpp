#include "frame.h"

#include <gtest/gtest.h>

#include <cstring>

using namespace canprobe;

namespace {

/* build a raw 16-byte classic CAN record */
void put_can_frame(uint8_t* out, uint32_t raw_id, uint8_t dlc,
                   const uint8_t* data = nullptr) {
    std::memcpy(out, &raw_id, 4);
    out[4] = dlc;
    out[5] = out[6] = out[7] = 0;
    if (data) std::memcpy(out + 8, data, 8);
}

} /* namespace */

TEST(FrameParseTest, ClassicDataFrame) {
    uint8_t raw[CAN_FRAME_LEN] = {};
    const uint8_t payload[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    put_can_frame(raw, 0x123, 8, payload);

    CanFrame f;
    ASSERT_TRUE(parse_can_frame(raw, sizeof(raw), f));
    EXPECT_EQ(f.can_id, 0x123u);
    EXPECT_FALSE(f.eff);
    EXPECT_FALSE(f.rtr);
    EXPECT_FALSE(f.err);
    EXPECT_FALSE(f.fd);
    EXPECT_EQ(f.dlc, 8);
    EXPECT_EQ(f.len, 8);
    EXPECT_EQ(std::memcmp(f.data, payload, 8), 0);
}

TEST(FrameParseTest, FlagBitsAreStripped) {
    uint8_t raw[CAN_FRAME_LEN] = {};
    put_can_frame(raw, CAN_EFF_FLAG | 0x1ABCDE, 0);
    CanFrame f;
    ASSERT_TRUE(parse_can_frame(raw, sizeof(raw), f));
    EXPECT_TRUE(f.eff);
    EXPECT_EQ(f.can_id, 0x1ABCDEu);

    put_can_frame(raw, CAN_RTR_FLAG | 0x55, 0);
    ASSERT_TRUE(parse_can_frame(raw, sizeof(raw), f));
    EXPECT_TRUE(f.rtr);
    EXPECT_EQ(f.can_id, 0x55u);

    put_can_frame(raw, CAN_ERR_FLAG | 0x30, 0);
    ASSERT_TRUE(parse_can_frame(raw, sizeof(raw), f));
    EXPECT_TRUE(f.err);
    EXPECT_EQ(f.can_id, 0x30u);
}

TEST(FrameParseTest, ClassicDlcOutOfRangeKeptForDetector) {
    uint8_t raw[CAN_FRAME_LEN] = {};
    put_can_frame(raw, 0x100, 12);
    CanFrame f;
    ASSERT_TRUE(parse_can_frame(raw, sizeof(raw), f));
    EXPECT_EQ(f.dlc, 12);   /* preserved */
    EXPECT_EQ(f.len, 8);    /* clamped to physically present bytes */
}

TEST(FrameParseTest, CanFdFrame) {
    uint8_t raw[CANFD_FRAME_LEN] = {};
    const uint32_t raw_id = 0x321;
    std::memcpy(raw, &raw_id, 4);
    raw[4] = 12;              /* len */
    raw[5] = 0x01;            /* flags: BRS */
    for (int i = 0; i < 64; ++i) raw[8 + i] = static_cast<uint8_t>(i);

    CanFrame f;
    ASSERT_TRUE(parse_can_frame(raw, sizeof(raw), f));
    EXPECT_TRUE(f.fd);
    EXPECT_EQ(f.can_id, 0x321u);
    EXPECT_EQ(f.dlc, 12);
    EXPECT_EQ(f.len, 12);
    EXPECT_EQ(f.data[63], 63);
}

TEST(FrameParseTest, CanFdLenOutOfRangeClamped) {
    uint8_t raw[CANFD_FRAME_LEN] = {};
    raw[4] = 70;              /* invalid len > 64 */
    CanFrame f;
    ASSERT_TRUE(parse_can_frame(raw, sizeof(raw), f));
    EXPECT_TRUE(f.fd);
    EXPECT_EQ(f.dlc, 70);
    EXPECT_EQ(f.len, 64);
}

TEST(FrameParseTest, RejectsBadSizes) {
    CanFrame f;
    uint8_t buf[CANFD_FRAME_LEN] = {};
    EXPECT_FALSE(parse_can_frame(nullptr, CAN_FRAME_LEN, f));
    EXPECT_FALSE(parse_can_frame(buf, 0, f));
    EXPECT_FALSE(parse_can_frame(buf, 15, f));
    EXPECT_FALSE(parse_can_frame(buf, 17, f));
    EXPECT_FALSE(parse_can_frame(buf, 71, f));
    EXPECT_FALSE(parse_can_frame(buf, 73, f));
}

TEST(DiagIdTest, RecognizesDiagnosticsRange) {
    EXPECT_TRUE(is_diag_request_id(0x7DF));
    EXPECT_TRUE(is_diag_request_id(0x7E0));
    EXPECT_TRUE(is_diag_request_id(0x7E7));
    EXPECT_FALSE(is_diag_request_id(0x7E8));
    EXPECT_FALSE(is_diag_request_id(0x100));

    EXPECT_TRUE(is_diag_response_id(0x7E8));
    EXPECT_TRUE(is_diag_response_id(0x7EF));
    EXPECT_FALSE(is_diag_response_id(0x7E7));
    EXPECT_FALSE(is_diag_response_id(0x7DF));
}