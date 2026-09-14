#include "packet.h"

#include <gtest/gtest.h>

#include <cstring>
#include <vector>

using ethprobe::ParsedPacket;
using ethprobe::parse_packet;

namespace {

/* --- Byte-builders (Arrange helpers) ------------------------------------- */

void put16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(static_cast<uint8_t>(x >> 8));
    v.push_back(static_cast<uint8_t>(x));
}
void put32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(static_cast<uint8_t>(x >> 24));
    v.push_back(static_cast<uint8_t>(x >> 16));
    v.push_back(static_cast<uint8_t>(x >> 8));
    v.push_back(static_cast<uint8_t>(x));
}
void put_bytes(std::vector<uint8_t>& v, std::initializer_list<uint8_t> b) {
    v.insert(v.end(), b.begin(), b.end());
}

const std::initializer_list<uint8_t> DST_MAC = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
const std::initializer_list<uint8_t> SRC_MAC = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
/* 10.0.0.1 / 10.0.0.2 */
const std::initializer_list<uint8_t> IP_A = {10, 0, 0, 1};
const std::initializer_list<uint8_t> IP_B = {10, 0, 0, 2};

std::vector<uint8_t> eth_header(uint16_t ethertype) {
    std::vector<uint8_t> v;
    put_bytes(v, DST_MAC);
    put_bytes(v, SRC_MAC);
    put16(v, ethertype);
    return v;
}

struct Ipv4Opts {
    uint8_t  proto   = 6;
    uint16_t id      = 0x1234;
    uint16_t flags_off = 0;    /* raw flags+offset field */
    size_t   payload = 0;
};

/* Minimal IPv4 header (IHL=5, no options) + zeroed L4 head + payload */
std::vector<uint8_t> ipv4_packet(const Ipv4Opts& o, size_t l4_hdr = 20) {
    std::vector<uint8_t> v;
    const uint16_t total = static_cast<uint16_t>(20 + l4_hdr + o.payload);
    v.push_back(0x45);
    v.push_back(0);            /* DSCP */
    put16(v, total);
    put16(v, o.id);
    put16(v, o.flags_off);
    v.push_back(64);           /* TTL */
    v.push_back(o.proto);
    put16(v, 0);               /* checksum (not validated) */
    put_bytes(v, IP_A);
    put_bytes(v, IP_B);
    for (size_t i = 0; i < l4_hdr + o.payload; ++i) v.push_back(0);
    return v;
}

void set_tcp_header(std::vector<uint8_t>& v, size_t l4_off, uint16_t sport, uint16_t dport,
                    uint32_t seq, uint8_t flags) {
    v[l4_off + 0] = static_cast<uint8_t>(sport >> 8);
    v[l4_off + 1] = static_cast<uint8_t>(sport);
    v[l4_off + 2] = static_cast<uint8_t>(dport >> 8);
    v[l4_off + 3] = static_cast<uint8_t>(dport);
    v[l4_off + 4] = static_cast<uint8_t>(seq >> 24);
    v[l4_off + 5] = static_cast<uint8_t>(seq >> 16);
    v[l4_off + 6] = static_cast<uint8_t>(seq >> 8);
    v[l4_off + 7] = static_cast<uint8_t>(seq);
    v[l4_off + 12] = 0x50;  /* data offset 5 (20 bytes) */
    v[l4_off + 13] = flags;
}

} /* namespace */

/* --- Tests ---------------------------------------------------------------- */

TEST(PacketTest, ParsesEthernetIpv4TcpSyn) {
    // Arrange
    std::vector<uint8_t> f = eth_header(0x0800);
    auto ip = ipv4_packet(Ipv4Opts{});
    const size_t l4_off = f.size() + 20;
    f.insert(f.end(), ip.begin(), ip.end());
    set_tcp_header(f, l4_off, 49152, 13400, 1000, ethprobe::TCP_SYN);

    // Act
    ParsedPacket p;
    ASSERT_TRUE(parse_packet(f.data(), f.size(), p));

    // Assert
    EXPECT_EQ(p.ethertype, 0x0800);
    EXPECT_TRUE(p.is_ipv4);
    EXPECT_TRUE(p.is_tcp);
    EXPECT_EQ(p.src_port, 49152);
    EXPECT_EQ(p.dst_port, 13400);
    EXPECT_EQ(p.tcp_seq, 1000u);
    EXPECT_EQ(p.tcp_flags, ethprobe::TCP_SYN);
    EXPECT_EQ(p.src_ip[0], 10);
    EXPECT_EQ(p.src_ip[3], 1);
    EXPECT_EQ(p.dst_ip[3], 2);
    EXPECT_EQ(p.payload_len, 0u);
    EXPECT_FALSE(p.truncated);
    EXPECT_FALSE(p.is_fragment);
}

TEST(PacketTest, ParsesVlanTaggedFrame) {
    // Arrange: Eth + VLAN(0x8100, TCI, inner 0x0800) + IPv4/TCP
    std::vector<uint8_t> f = eth_header(0x8100);
    put16(f, 0x0064);        /* TCI */
    put16(f, 0x0800);
    auto ip = ipv4_packet(Ipv4Opts{});
    const size_t l4_off = f.size() + 20;
    f.insert(f.end(), ip.begin(), ip.end());
    set_tcp_header(f, l4_off, 1000, 2000, 0, ethprobe::TCP_ACK);

    // Act
    ParsedPacket p;
    ASSERT_TRUE(parse_packet(f.data(), f.size(), p));

    // Assert
    EXPECT_EQ(p.vlan_tags, 1);
    EXPECT_EQ(p.ethertype, 0x0800);
    EXPECT_TRUE(p.is_tcp);
    EXPECT_EQ(p.dst_port, 2000);
}

TEST(PacketTest, Ipv4FirstFragmentKeepsL4MidFragmentDoesNot) {
    // Arrange: first fragment (MF=1, offset=0)
    std::vector<uint8_t> f1 = eth_header(0x0800);
    auto ip1 = ipv4_packet(Ipv4Opts{.id = 0x7777, .flags_off = 0x2000});
    const size_t l4_off = f1.size() + 20;
    f1.insert(f1.end(), ip1.begin(), ip1.end());
    set_tcp_header(f1, l4_off, 1111, 2222, 0, ethprobe::TCP_SYN);

    ParsedPacket p1;
    ASSERT_TRUE(parse_packet(f1.data(), f1.size(), p1));
    EXPECT_TRUE(p1.is_fragment);
    EXPECT_TRUE(p1.first_fragment);
    EXPECT_TRUE(p1.frag_more);
    EXPECT_TRUE(p1.is_tcp);          /* L4 visible on first fragment */
    EXPECT_EQ(p1.frag_id, 0x7777u);

    // Arrange: mid fragment (offset=185 -> 1480 bytes)
    std::vector<uint8_t> f2 = eth_header(0x0800);
    auto ip2 = ipv4_packet(Ipv4Opts{.id = 0x7777, .flags_off = 0x00B9}, /*l4_hdr=*/8);
    f2.insert(f2.end(), ip2.begin(), ip2.end());

    ParsedPacket p2;
    ASSERT_TRUE(parse_packet(f2.data(), f2.size(), p2));
    EXPECT_TRUE(p2.is_fragment);
    EXPECT_FALSE(p2.first_fragment);
    EXPECT_EQ(p2.frag_offset, 185u * 8u);
    EXPECT_FALSE(p2.is_tcp);         /* L4 not decoded for mid fragments */
    EXPECT_EQ(p2.src_port, 0);
}

TEST(PacketTest, ParsesUdpPayload) {
    // Arrange
    std::vector<uint8_t> f = eth_header(0x0800);
    Ipv4Opts o;
    o.proto = ethprobe::IP_PROTO_UDP;
    o.payload = 4;
    auto ip = ipv4_packet(o, /*l4_hdr=*/8);
    f.insert(f.end(), ip.begin(), ip.end());
    const size_t u = f.size() - 8 - 4;
    f[u + 0] = 0x77; f[u + 1] = 0x2A;              /* sport 30506 */
    f[u + 2] = 0x77; f[u + 3] = 0x2B;              /* dport 30507 */
    f[u + 4] = 0;    f[u + 5] = 12;                /* udp len */
    f[u + 8] = 0xDE; f[u + 9] = 0xAD; f[u + 10] = 0xBE; f[u + 11] = 0xEF;

    // Act
    ParsedPacket p;
    ASSERT_TRUE(parse_packet(f.data(), f.size(), p));

    // Assert
    EXPECT_TRUE(p.is_udp);
    EXPECT_EQ(p.src_port, 30506);
    EXPECT_EQ(p.dst_port, 30507);
    ASSERT_EQ(p.payload_len, 4u);
    EXPECT_EQ(p.payload[0], 0xDE);
    EXPECT_EQ(p.payload[3], 0xEF);
}

TEST(PacketTest, ParsesIpv6Tcp) {
    // Arrange
    std::vector<uint8_t> f = eth_header(0x86DD);
    std::vector<uint8_t> ip6;
    ip6.push_back(0x60); put_bytes(ip6, {0, 0, 0});
    put16(ip6, 20);            /* payload length = TCP header */
    ip6.push_back(6);          /* next header = TCP */
    ip6.push_back(64);         /* hop limit */
    for (int i = 0; i < 15; ++i) ip6.push_back(0);
    ip6.push_back(1);          /* src ::1 */
    for (int i = 0; i < 15; ++i) ip6.push_back(0);
    ip6.push_back(2);          /* dst ::2 */
    const size_t l4_off = f.size() + 40;
    f.insert(f.end(), ip6.begin(), ip6.end());
    for (int i = 0; i < 20; ++i) f.push_back(0);
    set_tcp_header(f, l4_off, 5000, 6000, 42, ethprobe::TCP_PSH | ethprobe::TCP_ACK);

    // Act
    ParsedPacket p;
    ASSERT_TRUE(parse_packet(f.data(), f.size(), p));

    // Assert
    EXPECT_TRUE(p.is_ipv6);
    EXPECT_TRUE(p.is_tcp);
    EXPECT_EQ(p.src_ip[15], 1);
    EXPECT_EQ(p.dst_ip[15], 2);
    EXPECT_EQ(p.src_port, 5000);
    EXPECT_EQ(p.tcp_seq, 42u);
}

TEST(PacketTest, ParsesIpv6FragmentHeader) {
    // Arrange: IPv6 + fragment header (offset 0, M=1, id=0xABCD) + UDP
    std::vector<uint8_t> f = eth_header(0x86DD);
    std::vector<uint8_t> ip6;
    ip6.push_back(0x60); put_bytes(ip6, {0, 0, 0});
    put16(ip6, 8 + 8);         /* frag hdr + UDP hdr */
    ip6.push_back(44);         /* next = fragment */
    ip6.push_back(64);
    for (int i = 0; i < 15; ++i) ip6.push_back(0);
    ip6.push_back(1);
    for (int i = 0; i < 15; ++i) ip6.push_back(0);
    ip6.push_back(2);
    /* fragment header */
    ip6.push_back(17);         /* next = UDP */
    ip6.push_back(0);
    put16(ip6, 0x0001);        /* offset 0, M=1 */
    put32(ip6, 0xABCD);
    f.insert(f.end(), ip6.begin(), ip6.end());
    for (int i = 0; i < 8; ++i) f.push_back(0);   /* UDP header */

    // Act
    ParsedPacket p;
    ASSERT_TRUE(parse_packet(f.data(), f.size(), p));

    // Assert
    EXPECT_TRUE(p.is_fragment);
    EXPECT_TRUE(p.first_fragment);
    EXPECT_TRUE(p.frag_more);
    EXPECT_EQ(p.frag_id, 0xABCDu);
    EXPECT_TRUE(p.is_udp);
}

TEST(PacketTest, ParsesArpRequest) {
    // Arrange
    std::vector<uint8_t> f = eth_header(0x0806);
    put16(f, 1);               /* htype Ethernet */
    put16(f, 0x0800);          /* ptype IPv4 */
    f.push_back(6); f.push_back(4);
    put16(f, 1);               /* opcode request */
    put_bytes(f, SRC_MAC);     /* sha */
    put_bytes(f, IP_A);        /* spa */
    put_bytes(f, {0, 0, 0, 0, 0, 0});  /* tha */
    put_bytes(f, IP_B);        /* tpa */

    // Act
    ParsedPacket p;
    ASSERT_TRUE(parse_packet(f.data(), f.size(), p));

    // Assert
    EXPECT_TRUE(p.is_arp);
    EXPECT_EQ(p.arp_opcode, 1);
    EXPECT_EQ(p.src_ip[0], 10);
    EXPECT_EQ(p.src_ip[3], 1);
    EXPECT_EQ(p.dst_ip[3], 2);
    EXPECT_EQ(p.src_mac.b[5], 0x02);
}

TEST(PacketTest, RejectsShortFrame) {
    uint8_t tiny[10] = {};
    ParsedPacket p;
    EXPECT_FALSE(parse_packet(tiny, sizeof(tiny), p));
    EXPECT_FALSE(parse_packet(nullptr, 100, p));
}

TEST(PacketTest, RejectsUnsupportedEthertype) {
    auto f = eth_header(0x88B5);  /* experimental */
    f.resize(60, 0);
    ParsedPacket p;
    EXPECT_FALSE(parse_packet(f.data(), f.size(), p));
}

TEST(PacketTest, FlagsTruncatedOnShortIpHeader) {
    // Arrange: IPv4 ethertype but only 10 bytes of IP header
    auto f = eth_header(0x0800);
    for (int i = 0; i < 10; ++i) f.push_back(0x45);

    ParsedPacket p;
    EXPECT_TRUE(parse_packet(f.data(), f.size(), p));
    EXPECT_TRUE(p.truncated);
    EXPECT_FALSE(p.is_tcp);
}

TEST(PacketTest, FlagsTruncatedOnShortTcpHeader) {
    // Arrange: full IPv4 header but only 5 bytes of TCP
    auto f = eth_header(0x0800);
    auto ip = ipv4_packet(Ipv4Opts{}, /*l4_hdr=*/5);
    f.insert(f.end(), ip.begin(), ip.end());

    ParsedPacket p;
    EXPECT_TRUE(parse_packet(f.data(), f.size(), p));
    EXPECT_TRUE(p.truncated);
    EXPECT_FALSE(p.is_tcp);
}

TEST(PacketTest, ParsesIcmpTypeCode) {
    // Arrange: ICMP echo request (type 8, code 0)
    auto f = eth_header(0x0800);
    Ipv4Opts o;
    o.proto = ethprobe::IP_PROTO_ICMP;
    o.payload = 4;
    auto ip = ipv4_packet(o, /*l4_hdr=*/4);
    f.insert(f.end(), ip.begin(), ip.end());
    const size_t ic = f.size() - 8;
    f[ic] = 8; f[ic + 1] = 0;

    ParsedPacket p;
    ASSERT_TRUE(parse_packet(f.data(), f.size(), p));
    EXPECT_EQ(p.l4_proto, ethprobe::IP_PROTO_ICMP);
    EXPECT_EQ(p.src_port, 8);   /* ICMP type */
    EXPECT_EQ(p.dst_port, 0);   /* ICMP code */
    EXPECT_EQ(p.payload_len, 4u);
}
