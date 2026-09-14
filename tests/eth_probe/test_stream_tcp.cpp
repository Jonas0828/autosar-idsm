#include "stream_tcp.h"

#include <gtest/gtest.h>

#include <cstring>
#include <vector>

using ethprobe::ParsedPacket;
using ethprobe::TcpReassembly;

namespace {

/* Build a TCP ParsedPacket for one direction of the 10.0.0.1:49152 ↔ 10.0.0.2:80 flow */
ParsedPacket make_tcp(bool from_client, uint32_t seq, uint8_t flags,
                      const std::vector<uint8_t>& payload = {}) {
    ParsedPacket p;
    p.is_ipv4 = true;
    p.is_tcp  = true;
    p.l4_proto = ethprobe::IP_PROTO_TCP;
    if (from_client) {
        p.src_ip[0] = 10; p.src_ip[3] = 1; p.src_port = 49152;
        p.dst_ip[0] = 10; p.dst_ip[3] = 2; p.dst_port = 80;
    } else {
        p.src_ip[0] = 10; p.src_ip[3] = 2; p.src_port = 80;
        p.dst_ip[0] = 10; p.dst_ip[3] = 1; p.dst_port = 49152;
    }
    p.tcp_seq   = seq;
    p.tcp_flags = flags;
    p.payload     = payload.empty() ? nullptr : payload.data();
    p.payload_len = payload.size();
    return p;
}

std::vector<uint8_t> bytes(const char* s) {
    return std::vector<uint8_t>(s, s + std::strlen(s));
}

} /* namespace */

TEST(TcpReassemblyTest, DeliversInOrderSegments) {
    TcpReassembly tcp;
    // Arrange: SYN then two in-order data segments
    auto syn = make_tcp(true, 1000, ethprobe::TCP_SYN);
    tcp.add_segment(syn, 0);

    // Act
    auto r1 = tcp.add_segment(make_tcp(true, 1001, ethprobe::TCP_ACK, bytes("GET ")), 10);
    auto r2 = tcp.add_segment(make_tcp(true, 1005, ethprobe::TCP_ACK, bytes("/index")), 20);

    // Assert
    ASSERT_TRUE(r1.has_data);
    EXPECT_EQ(r1.data, bytes("GET "));
    EXPECT_EQ(r1.dir, 0);
    ASSERT_TRUE(r2.has_data);
    EXPECT_EQ(r2.data, bytes("/index"));
}

TEST(TcpReassemblyTest, BuffersAndDrainsOutOfOrder) {
    TcpReassembly tcp;
    tcp.add_segment(make_tcp(true, 1000, ethprobe::TCP_SYN), 0);

    // Act: send 1005..1011 first (gap at 1001..1005), then the gap
    auto r1 = tcp.add_segment(make_tcp(true, 1005, ethprobe::TCP_ACK, bytes("/index")), 10);
    EXPECT_FALSE(r1.has_data);
    auto r2 = tcp.add_segment(make_tcp(true, 1001, ethprobe::TCP_ACK, bytes("GET ")), 20);

    // Assert: gap fill delivers both chunks in order
    ASSERT_TRUE(r2.has_data);
    EXPECT_EQ(r2.data, bytes("GET /index"));
    EXPECT_EQ(tcp.buffered_bytes(), 0u);
}

TEST(TcpReassemblyTest, RetransmitFirstSeenWins) {
    TcpReassembly tcp;
    tcp.add_segment(make_tcp(true, 1000, ethprobe::TCP_SYN), 0);

    auto r1 = tcp.add_segment(make_tcp(true, 1001, ethprobe::TCP_ACK, bytes("DATA")), 10);
    ASSERT_TRUE(r1.has_data);
    // retransmit same range with different content: ignored
    auto r2 = tcp.add_segment(make_tcp(true, 1001, ethprobe::TCP_ACK, bytes("XXXX")), 20);
    EXPECT_FALSE(r2.has_data);
    // next in-order still aligns
    auto r3 = tcp.add_segment(make_tcp(true, 1005, ethprobe::TCP_ACK, bytes("+")), 30);
    ASSERT_TRUE(r3.has_data);
    EXPECT_EQ(r3.data, bytes("+"));
}

TEST(TcpReassemblyTest, LeadingOverlapIsTrimmed) {
    TcpReassembly tcp;
    tcp.add_segment(make_tcp(true, 1000, ethprobe::TCP_SYN), 0);
    tcp.add_segment(make_tcp(true, 1001, ethprobe::TCP_ACK, bytes("ABCD")), 10);
    // segment overlapping by 2 bytes: [1003, 1009)
    auto r = tcp.add_segment(make_tcp(true, 1003, ethprobe::TCP_ACK, bytes("CDEFGH")), 20);
    ASSERT_TRUE(r.has_data);
    EXPECT_EQ(r.data, bytes("EFGH"));
}

TEST(TcpReassemblyTest, GapSkippedAfterTimeout) {
    // Arrange
    TcpReassembly::Config cfg;
    cfg.gap_timeout_ms = 100;
    TcpReassembly tcp(cfg);
    tcp.add_segment(make_tcp(true, 1000, ethprobe::TCP_SYN), 0);
    // future segment arrives, gap 1001..1005 never comes
    tcp.add_segment(make_tcp(true, 1005, ethprobe::TCP_ACK, bytes("LATE")), 10);

    // Act: next segment after gap timeout triggers skip
    auto r = tcp.add_segment(make_tcp(true, 1009, ethprobe::TCP_ACK, bytes("!")), 200);

    // Assert: gap skipped, buffered + new data delivered in order
    ASSERT_TRUE(r.has_data);
    EXPECT_EQ(r.data, bytes("LATE!"));
}

TEST(TcpReassemblyTest, FinClosesAfterBothDirections) {
    TcpReassembly tcp;
    tcp.add_segment(make_tcp(true, 1000, ethprobe::TCP_SYN), 0);
    tcp.add_segment(make_tcp(false, 2000, ethprobe::TCP_SYN | ethprobe::TCP_ACK), 5);

    auto r1 = tcp.add_segment(make_tcp(true, 1001, ethprobe::TCP_FIN | ethprobe::TCP_ACK), 10);
    EXPECT_FALSE(r1.closed);
    auto r2 = tcp.add_segment(make_tcp(false, 2001, ethprobe::TCP_FIN | ethprobe::TCP_ACK), 20);
    EXPECT_TRUE(r2.closed);
    EXPECT_EQ(tcp.active_flows(), 0u);
}

TEST(TcpReassemblyTest, RstClosesImmediately) {
    TcpReassembly tcp;
    tcp.add_segment(make_tcp(true, 1000, ethprobe::TCP_SYN), 0);
    auto r = tcp.add_segment(make_tcp(true, 1001, ethprobe::TCP_RST), 10);
    EXPECT_TRUE(r.closed);
    EXPECT_EQ(tcp.active_flows(), 0u);
}

TEST(TcpReassemblyTest, FlowCountCapEvictsAndFlags) {
    // Arrange: room for 1 flow
    TcpReassembly::Config cfg;
    cfg.max_flows = 1;
    TcpReassembly tcp(cfg);
    tcp.add_segment(make_tcp(true, 1000, ethprobe::TCP_SYN), 0);

    // Act: a different flow appears
    auto other = make_tcp(true, 500, ethprobe::TCP_SYN);
    other.dst_port = 8080;  /* different 4-tuple */
    auto r = tcp.add_segment(other, 10);

    // Assert
    EXPECT_TRUE(r.evicted);
    EXPECT_EQ(tcp.active_flows(), 1u);
}

TEST(TcpReassemblyTest, IdleFlowsExpire) {
    TcpReassembly::Config cfg;
    cfg.idle_timeout_ms = 1000;
    TcpReassembly tcp(cfg);
    tcp.add_segment(make_tcp(true, 1000, ethprobe::TCP_SYN), 0);
    EXPECT_EQ(tcp.active_flows(), 1u);
    EXPECT_EQ(tcp.expire(500), 0u);
    EXPECT_EQ(tcp.expire(1500), 1u);
    EXPECT_EQ(tcp.active_flows(), 0u);
}

TEST(TcpReassemblyTest, ServerDirectionUsesDirOne) {
    TcpReassembly tcp;
    tcp.add_segment(make_tcp(false, 2000, ethprobe::TCP_SYN), 0);  /* server initiates */
    auto r = tcp.add_segment(make_tcp(false, 2001, ethprobe::TCP_ACK, bytes("OK")), 10);
    ASSERT_TRUE(r.has_data);
    EXPECT_EQ(r.dir, 1);
    /* flow key normalization: A = 10.0.0.1:49152 regardless of who initiated */
    EXPECT_EQ(r.flow.a_ip[3], 1);
    EXPECT_EQ(r.flow.a_port, 49152);
}
