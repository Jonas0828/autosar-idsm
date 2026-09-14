#include "ip_defrag.h"

#include <gtest/gtest.h>

#include <vector>

using ethprobe::IpDefrag;
using ethprobe::ParsedPacket;

namespace {

ParsedPacket make_frag(bool v6, uint32_t id, uint32_t off, bool more,
                       uint8_t proto = ethprobe::IP_PROTO_UDP) {
    ParsedPacket p;
    p.is_ipv4 = !v6;
    p.is_ipv6 = v6;
    p.is_fragment = true;
    p.first_fragment = (off == 0);
    p.frag_id = id;
    p.frag_offset = off;
    p.frag_more = more;
    p.l4_proto = proto;
    p.src_ip[0] = 10; p.src_ip[3] = 1;
    p.dst_ip[0] = 10; p.dst_ip[3] = 2;
    return p;
}

/* Payload of N bytes filled with sequence base..base+N-1 (mod 256) */
std::vector<uint8_t> seq_bytes(uint8_t base, size_t n) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>(base + i);
    return v;
}

} /* namespace */

TEST(IpDefragTest, ReassemblesOutOfOrderFragments) {
    // Arrange: a 40-byte datagram split 16/16/8, fed last-first
    IpDefrag defrag;
    auto d = seq_bytes(0, 40);

    // Act: last fragment (offset 32, no MF)
    auto p3 = make_frag(false, 100, 32, false);
    auto r3 = defrag.add_fragment(p3, d.data() + 32, 8, 1000);
    EXPECT_FALSE(r3.complete);
    // middle (offset 16, MF)
    auto p2 = make_frag(false, 100, 16, true);
    auto r2 = defrag.add_fragment(p2, d.data() + 16, 16, 1010);
    EXPECT_FALSE(r2.complete);
    // first (offset 0, MF)
    auto p1 = make_frag(false, 100, 0, true);
    auto r1 = defrag.add_fragment(p1, d.data(), 16, 1020);

    // Assert
    ASSERT_TRUE(r1.complete);
    ASSERT_EQ(r1.datagram.size(), 40u);
    EXPECT_EQ(r1.datagram, d);
    EXPECT_EQ(defrag.active_datagrams(), 0u);   /* entry cleaned up */
    EXPECT_EQ(defrag.buffered_bytes(), 0u);
}

TEST(IpDefragTest, OverlapFirstSeenWins) {
    // Arrange: two overlapping fragments covering [0,16): first says 'A's...
    IpDefrag defrag;
    std::vector<uint8_t> frag1(16, 0xAA);
    std::vector<uint8_t> frag2(16, 0xBB);  /* overlapping [8,24) */
    std::vector<uint8_t> frag3(8, 0xCC);   /* last [24,32) */

    // Act
    auto r1 = defrag.add_fragment(make_frag(false, 7, 0, true), frag1.data(), 16, 0);
    EXPECT_FALSE(r1.complete);
    auto r2 = defrag.add_fragment(make_frag(false, 7, 8, true), frag2.data(), 16, 10);
    EXPECT_FALSE(r2.complete);
    auto r3 = defrag.add_fragment(make_frag(false, 7, 24, false), frag3.data(), 8, 20);

    // Assert: bytes [0,8) from frag1, [8,16) still 0xAA (first-seen), rest 0xBB/0xCC
    ASSERT_TRUE(r3.complete);
    ASSERT_EQ(r3.datagram.size(), 32u);
    EXPECT_EQ(r3.datagram[0], 0xAA);
    EXPECT_EQ(r3.datagram[15], 0xAA);   /* overlap region keeps first writer */
    EXPECT_EQ(r3.datagram[16], 0xBB);
    EXPECT_EQ(r3.datagram[23], 0xBB);
    EXPECT_EQ(r3.datagram[24], 0xCC);
}

TEST(IpDefragTest, RetransmittedFragmentIsHarmless) {
    IpDefrag defrag;
    auto d = seq_bytes(0, 16);
    auto p = make_frag(false, 9, 0, false);
    EXPECT_TRUE(defrag.add_fragment(p, d.data(), 16, 0).complete);
    /* same fragment again on a fresh id-9 entry: completes identically */
    EXPECT_TRUE(defrag.add_fragment(p, d.data(), 16, 10).complete);
    EXPECT_EQ(defrag.active_datagrams(), 0u);
}

TEST(IpDefragTest, ExpireDropsStaleEntries) {
    // Arrange
    IpDefrag::Config cfg;
    cfg.timeout_ms = 5000;
    IpDefrag defrag(cfg);
    auto d = seq_bytes(0, 16);

    // Act: partial datagram at t=0, sweep at t=4000 (keep) and t=6000 (drop)
    defrag.add_fragment(make_frag(false, 5, 0, true), d.data(), 16, 0);
    EXPECT_EQ(defrag.active_datagrams(), 1u);
    EXPECT_EQ(defrag.expire(4000), 0u);
    EXPECT_EQ(defrag.expire(6000), 1u);

    // Assert
    EXPECT_EQ(defrag.active_datagrams(), 0u);
    EXPECT_EQ(defrag.buffered_bytes(), 0u);
}

TEST(IpDefragTest, MemoryCapEvictsLruAndFlagsEviction) {
    // Arrange: room for exactly one 16-byte datagram
    IpDefrag::Config cfg;
    cfg.max_mem_bytes = 16;
    cfg.max_datagrams = 16;
    IpDefrag defrag(cfg);
    auto d = seq_bytes(0, 16);

    // Act: datagram A (partial) then datagram B (needs memory)
    auto ra = defrag.add_fragment(make_frag(false, 1, 0, true), d.data(), 16, 0);
    EXPECT_FALSE(ra.evicted);
    auto rb = defrag.add_fragment(make_frag(false, 2, 0, true), d.data(), 16, 10);

    // Assert
    EXPECT_TRUE(rb.evicted);
    EXPECT_EQ(defrag.active_datagrams(), 1u);   /* only B survives */
}

TEST(IpDefragTest, DatagramCountCapEvictsOldest) {
    IpDefrag::Config cfg;
    cfg.max_datagrams = 2;
    IpDefrag defrag(cfg);
    auto d = seq_bytes(0, 8);
    defrag.add_fragment(make_frag(false, 1, 0, true), d.data(), 8, 0);
    defrag.add_fragment(make_frag(false, 2, 0, true), d.data(), 8, 10);
    auto r = defrag.add_fragment(make_frag(false, 3, 0, true), d.data(), 8, 20);
    EXPECT_TRUE(r.evicted);
    EXPECT_EQ(defrag.active_datagrams(), 2u);
}

TEST(IpDefragTest, V4AndV6SameIdDoNotCollide) {
    IpDefrag defrag;
    auto d = seq_bytes(0, 16);
    auto r4 = defrag.add_fragment(make_frag(false, 42, 0, true), d.data(), 16, 0);
    auto r6 = defrag.add_fragment(make_frag(true, 42, 0, false), d.data(), 16, 10);
    EXPECT_FALSE(r4.complete);
    EXPECT_TRUE(r6.complete);   /* v6 entry completes on its own */
    EXPECT_EQ(defrag.active_datagrams(), 1u);  /* v4 entry still pending */
}

TEST(IpDefragTest, RejectsOversizedFragment) {
    IpDefrag defrag;
    std::vector<uint8_t> d(64, 0);
    auto p = make_frag(false, 1, 70000, true);  /* beyond max datagram size */
    auto r = defrag.add_fragment(p, d.data(), 64, 0);
    EXPECT_FALSE(r.complete);
    EXPECT_EQ(defrag.active_datagrams(), 0u);
}
