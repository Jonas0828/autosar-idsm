#include "alert.h"
#include "pipeline.h"
#include "proto_doip.h"
#include "proto_someip.h"

#include <gtest/gtest.h>

#include <cstring>
#include <vector>

using namespace ethprobe;

namespace {

/* ---- frame builders (same helpers as test_packet) ---- */

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

std::vector<uint8_t> eth_ipv4(uint8_t proto, uint8_t src_last, uint8_t dst_last,
                              const std::vector<uint8_t>& l4) {
    std::vector<uint8_t> v;
    put_bytes(v, {0x02, 0, 0, 0, 0, 1});   /* dst mac */
    put_bytes(v, {0x02, 0, 0, 0, 0, 2});   /* src mac */
    put16(v, 0x0800);
    v.push_back(0x45);
    v.push_back(0);
    put16(v, static_cast<uint16_t>(20 + l4.size()));
    put16(v, 0x1234);
    put16(v, 0);
    v.push_back(64);
    v.push_back(proto);
    put16(v, 0);
    put_bytes(v, {10, 0, 0, src_last});
    put_bytes(v, {10, 0, 0, dst_last});
    v.insert(v.end(), l4.begin(), l4.end());
    return v;
}

std::vector<uint8_t> tcp_segment(uint16_t sport, uint16_t dport, uint32_t seq,
                                 uint8_t flags, const std::vector<uint8_t>& payload = {}) {
    std::vector<uint8_t> v;
    put16(v, sport);
    put16(v, dport);
    put32(v, seq);
    put32(v, 0);        /* ack */
    v.push_back(0x50);  /* data offset 5 */
    v.push_back(flags);
    put16(v, 65535);    /* window */
    put16(v, 0); put16(v, 0);
    v.insert(v.end(), payload.begin(), payload.end());
    return v;
}

std::vector<uint8_t> udp_dgram(uint16_t sport, uint16_t dport,
                               const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> v;
    put16(v, sport);
    put16(v, dport);
    put16(v, static_cast<uint16_t>(8 + payload.size()));
    put16(v, 0);
    v.insert(v.end(), payload.begin(), payload.end());
    return v;
}

/* Collect alerts from a pipeline */
struct Collector {
    std::vector<ProbeAlert> alerts;
    ProbePipeline pipe{[this](const ProbeAlert& a) { alerts.push_back(a); }};

    std::vector<ProbeAlert> of_type(uint8_t dt) const {
        std::vector<ProbeAlert> out;
        for (const auto& a : alerts) if (a.detector_type == dt) out.push_back(a);
        return out;
    }
};

/* write temp rules file */
std::string write_rules(const char* content, int tag) {
    const std::string path = "/tmp/eth_probe_pipe_rules_" + std::to_string(tag) + ".rules";
    FILE* f = std::fopen(path.c_str(), "w");
    std::fputs(content, f);
    std::fclose(f);
    return path;
}

} /* namespace */

TEST(PipelineTest, CrossPacketContentRuleFiresAfterReassembly) {
    // Arrange: rule matches "27 01" (UDS SecurityAccess); split across two TCP segments
    Collector c;
    const std::string path = write_rules(
        "alert tcp any any -> any 13400 (msg:\"uds\"; sid:1000001; content:\"|27 01|\";)\n", 1);
    std::vector<std::string> warn;
    ASSERT_EQ(c.pipe.rules().load_file(path, {}, warn), 1u);
    std::remove(path.c_str());

    // Act: SYN, then segment with 0x27, then segment with 0x01 (cross-packet pattern)
    auto syn = eth_ipv4(IP_PROTO_TCP, 1, 2, tcp_segment(49152, 13400, 1000, TCP_SYN));
    c.pipe.feed_frame(syn.data(), syn.size(), 0);
    auto seg1 = eth_ipv4(IP_PROTO_TCP, 1, 2,
                         tcp_segment(49152, 13400, 1001, TCP_ACK, {0xAA, 0x27}));
    c.pipe.feed_frame(seg1.data(), seg1.size(), 10);
    auto seg2 = eth_ipv4(IP_PROTO_TCP, 1, 2,
                         tcp_segment(49152, 13400, 1003, TCP_ACK, {0x01, 0xBB}));
    c.pipe.feed_frame(seg2.data(), seg2.size(), 20);

    // Assert
    auto hits = c.of_type(DT_RULE_HIT);
    ASSERT_EQ(hits.size(), 1u);
    EXPECT_EQ(hits[0].aux, 1000001u);
    EXPECT_EQ(hits[0].dst_port, 13400);
}

TEST(PipelineTest, DoipRoutingActivationAlertsOverTcpStream) {
    // Arrange
    Collector c;
    /* DoIP routing activation frame split mid-header */
    std::vector<uint8_t> doip;
    put_bytes(doip, {0x02, 0xFD});
    put16(doip, DOIP_PT_ROUTING_ACTIVATION);
    put32(doip, 7);
    put_bytes(doip, {0x0E, 0x00, 0, 0, 0, 0, 0});

    // Act
    auto syn = eth_ipv4(IP_PROTO_TCP, 1, 2, tcp_segment(49152, 13400, 5000, TCP_SYN));
    c.pipe.feed_frame(syn.data(), syn.size(), 0);
    std::vector<uint8_t> part1(doip.begin(), doip.begin() + 6);
    std::vector<uint8_t> part2(doip.begin() + 6, doip.end());
    auto s1 = eth_ipv4(IP_PROTO_TCP, 1, 2, tcp_segment(49152, 13400, 5001, TCP_ACK, part1));
    c.pipe.feed_frame(s1.data(), s1.size(), 10);
    auto s2 = eth_ipv4(IP_PROTO_TCP, 1, 2, tcp_segment(49152, 13400, 5007, TCP_ACK, part2));
    c.pipe.feed_frame(s2.data(), s2.size(), 20);

    // Assert
    auto hits = c.of_type(DT_DOIP);
    ASSERT_EQ(hits.size(), 1u);
    EXPECT_EQ(hits[0].aux, DOIP_PT_ROUTING_ACTIVATION);
}

TEST(PipelineTest, SomeipSdRogueOfferAlertsOverUdp) {
    // Arrange
    Collector c;
    SomeipSdTracker::Config cfg;
    cfg.service_whitelist = {0x1000};
    c.pipe.sd_tracker().set_config(cfg);

    /* SD offer for service 0x9999 (not whitelisted) */
    std::vector<uint8_t> sd;
    sd.push_back(0x80);
    put_bytes(sd, {0, 0, 0});
    put32(sd, 16);
    sd.push_back(SOMEIP_SD_ENTRY_OFFER);
    put_bytes(sd, {0, 0, 0});
    put16(sd, 0x9999);
    put16(sd, 1);
    put_bytes(sd, {1, 0, 0, 3});  /* major + ttl */
    put32(sd, 0);
    put32(sd, 0);

    std::vector<uint8_t> msg;
    put16(msg, SOMEIP_SD_SERVICE);
    put16(msg, SOMEIP_SD_METHOD);
    put32(msg, static_cast<uint32_t>(8 + sd.size()));
    put16(msg, 1);
    put16(msg, 7);
    put_bytes(msg, {1, 1, SOMEIP_MT_NOTIFICATION, 0});
    msg.insert(msg.end(), sd.begin(), sd.end());

    // Act
    auto f = eth_ipv4(IP_PROTO_UDP, 1, 2, udp_dgram(30490, 30490, msg));
    c.pipe.feed_frame(f.data(), f.size(), 0);

    // Assert
    auto hits = c.of_type(DT_SOMEIP);
    ASSERT_EQ(hits.size(), 1u);
    EXPECT_EQ(hits[0].aux, 0x1000u + 0x9999u);
}

TEST(PipelineTest, PortScanAndFlagAnomalyAlert) {
    // Arrange
    Collector c;
    c.pipe.port_scan().set_config(PortScanDetector::Config{10000, 3});

    // Act: 3 SYNs to distinct ports from one source
    for (uint16_t port = 100; port <= 102; ++port) {
        auto f = eth_ipv4(IP_PROTO_TCP, 9, 99, tcp_segment(49152, port, 1000, TCP_SYN));
        c.pipe.feed_frame(f.data(), f.size(), port);
    }
    /* Xmas scan */
    auto xmas = eth_ipv4(IP_PROTO_TCP, 9, 99,
                         tcp_segment(49152, 80, 2000, TCP_FIN | TCP_PSH | TCP_URG));
    c.pipe.feed_frame(xmas.data(), xmas.size(), 200);

    // Assert
    auto scans = c.of_type(DT_PORT_SCAN);
    ASSERT_EQ(scans.size(), 1u);
    EXPECT_EQ(scans[0].aux, 3u);
    auto flags = c.of_type(DT_FLAG_ANOMALY);
    ASSERT_EQ(flags.size(), 1u);
    EXPECT_EQ(flags[0].aux, FLAG_ANOMALY_XMAS);
}

TEST(PipelineTest, CrossBorderAlertsWithCooldown) {
    // Arrange
    Collector c;
    const std::string cidr_path = "/tmp/eth_probe_pipe_cidrs.txt";
    FILE* f = std::fopen(cidr_path.c_str(), "w");
    std::fputs("1.0.1.0/24\n", f);
    std::fclose(f);
    ASSERT_TRUE(c.pipe.geoip().load_cidrs(cidr_path));
    std::remove(cidr_path.c_str());

    /* 10.0.0.1 (home) → 8.8.8.8 (foreign) */
    auto mk = [] {
        std::vector<uint8_t> v;
        put_bytes(v, {0x02, 0, 0, 0, 0, 1});
        put_bytes(v, {0x02, 0, 0, 0, 0, 2});
        put16(v, 0x0800);
        v.push_back(0x45); v.push_back(0);
        put16(v, 20 + 8);
        put16(v, 1); put16(v, 0);
        v.push_back(64); v.push_back(IP_PROTO_UDP);
        put16(v, 0);
        put_bytes(v, {10, 0, 0, 1});
        put_bytes(v, {8, 8, 8, 8});
        const auto dgram = udp_dgram(12345, 53, {0xAA});
        v.insert(v.end(), dgram.begin(), dgram.end());
        return v;
    };

    // Act
    auto frame = mk();
    c.pipe.feed_frame(frame.data(), frame.size(), 0);
    c.pipe.feed_frame(frame.data(), frame.size(), 1000);   /* within cooldown */

    // Assert
    auto hits = c.of_type(DT_CROSS_BORDER);
    EXPECT_EQ(hits.size(), 1u);
    EXPECT_EQ(hits[0].dst_ip[0], 8);
}

TEST(PipelineTest, MulticastAndBroadcastNeverCrossBorder) {
    // Arrange
    Collector c;
    const std::string cidr_path = "/tmp/eth_probe_pipe_cidrs2.txt";
    FILE* f = std::fopen(cidr_path.c_str(), "w");
    std::fputs("1.0.1.0/24\n", f);
    std::fclose(f);
    ASSERT_TRUE(c.pipe.geoip().load_cidrs(cidr_path));
    std::remove(cidr_path.c_str());

    auto mk = [](uint8_t d0, uint8_t d1, uint8_t d2, uint8_t d3) {
        std::vector<uint8_t> v;
        put_bytes(v, {0x02, 0, 0, 0, 0, 1});
        put_bytes(v, {0x02, 0, 0, 0, 0, 2});
        put16(v, 0x0800);
        v.push_back(0x45); v.push_back(0);
        put16(v, 20 + 9);
        put16(v, 1); put16(v, 0);
        v.push_back(64); v.push_back(IP_PROTO_UDP);
        put16(v, 0);
        put_bytes(v, {172, 16, 51, 152});   /* home src */
        put_bytes(v, {d0, d1, d2, d3});
        const auto dgram = udp_dgram(5353, 5353, {0xAA});
        v.insert(v.end(), dgram.begin(), dgram.end());
        return v;
    };

    // Act: mDNS multicast, link-local, broadcast — none should alert
    auto mdns = mk(224, 0, 0, 251);
    c.pipe.feed_frame(mdns.data(), mdns.size(), 0);
    auto llmnr = mk(224, 0, 0, 252);
    c.pipe.feed_frame(llmnr.data(), llmnr.size(), 10);
    auto linklocal = mk(169, 254, 1, 1);
    c.pipe.feed_frame(linklocal.data(), linklocal.size(), 20);
    auto bcast = mk(255, 255, 255, 255);
    c.pipe.feed_frame(bcast.data(), bcast.size(), 30);

    // Assert: zero cross-border alerts
    EXPECT_TRUE(c.of_type(DT_CROSS_BORDER).empty());
}

TEST(PipelineTest, FragmentedUdpReassembledThenInspected) {
    // Arrange: UDP datagram split into two IPv4 fragments
    Collector c;
    std::vector<uint8_t> payload(32, 0x55);
    auto udp = udp_dgram(1234, 30490, payload);  /* goes to SOME/IP port → malformed alert */
    ASSERT_EQ(udp.size(), 40u);

    auto frag = [&](uint32_t off_bytes, bool more, const uint8_t* data, size_t n) {
        std::vector<uint8_t> v;
        put_bytes(v, {0x02, 0, 0, 0, 0, 1});
        put_bytes(v, {0x02, 0, 0, 0, 0, 2});
        put16(v, 0x0800);
        v.push_back(0x45); v.push_back(0);
        put16(v, static_cast<uint16_t>(20 + n));
        put16(v, 0x4321);
        put16(v, static_cast<uint16_t>((more ? 0x2000 : 0) | (off_bytes / 8)));
        v.push_back(64); v.push_back(IP_PROTO_UDP);
        put16(v, 0);
        put_bytes(v, {10, 0, 0, 1});
        put_bytes(v, {10, 0, 0, 2});
        v.insert(v.end(), data, data + n);
        return v;
    };

    // Act: feed second fragment first (out of order)
    auto f2 = frag(24, false, udp.data() + 24, 16);
    c.pipe.feed_frame(f2.data(), f2.size(), 10);
    auto f1 = frag(0, true, udp.data(), 24);
    c.pipe.feed_frame(f1.data(), f1.size(), 20);

    // Assert: reassembled datagram hit SOME/IP parser → malformed header alert
    /* payload is 0x55-filled: length field is nonsense → length error first */
    auto hits = c.of_type(DT_SOMEIP);
    ASSERT_EQ(hits.size(), 1u);
    EXPECT_EQ(hits[0].aux, static_cast<uint32_t>(SOMEIP_ERR_LENGTH));
}
