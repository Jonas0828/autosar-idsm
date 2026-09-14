#include "detectors.h"

#include <gtest/gtest.h>

#include <cstring>

using namespace ethprobe;

namespace {

ParsedPacket make_tcp_syn(uint8_t src_last, uint16_t dport, uint8_t flags = TCP_SYN) {
    ParsedPacket p;
    p.is_ipv4 = true;
    p.is_tcp  = true;
    p.l4_proto = IP_PROTO_TCP;
    p.src_ip[0] = 10; p.src_ip[3] = src_last;
    p.dst_ip[0] = 10; p.dst_ip[3] = 99;
    p.src_port = 49152;
    p.dst_port = dport;
    p.tcp_flags = flags;
    return p;
}

ParsedPacket make_arp(uint8_t spa_last, uint8_t mac_last, uint16_t opcode,
                      bool gratuitous_req = false) {
    ParsedPacket p;
    p.is_arp = true;
    p.arp_opcode = opcode;
    p.src_mac = MacAddress{{0x02, 0, 0, 0, 0, mac_last}};
    p.src_ip[0] = 10; p.src_ip[3] = spa_last;
    p.dst_ip[0] = 10; p.dst_ip[3] = gratuitous_req ? spa_last : 77;
    return p;
}

} /* namespace */

TEST(FlagAnomalyTest, DetectsNullXmasSynFin) {
    auto nullp = make_tcp_syn(1, 80, 0);
    auto a1 = check_flag_anomaly(nullp);
    ASSERT_TRUE(a1.has_value());
    EXPECT_EQ(a1->detector_type, DT_FLAG_ANOMALY);
    EXPECT_EQ(a1->aux, FLAG_ANOMALY_NULL);

    auto xmas = make_tcp_syn(1, 80, TCP_FIN | TCP_PSH | TCP_URG);
    EXPECT_EQ(check_flag_anomaly(xmas)->aux, FLAG_ANOMALY_XMAS);

    auto synfin = make_tcp_syn(1, 80, TCP_SYN | TCP_FIN);
    EXPECT_EQ(check_flag_anomaly(synfin)->aux, FLAG_ANOMALY_SYN_FIN);

    auto normal = make_tcp_syn(1, 80, TCP_SYN);
    EXPECT_FALSE(check_flag_anomaly(normal).has_value());
}

TEST(PortScanDetectorTest, TriggersOnUniquePortThreshold) {
    PortScanDetector::Config cfg;
    cfg.window_ms = 1000;
    cfg.unique_threshold = 5;
    PortScanDetector det(cfg);

    /* 4 distinct ports: no alert */
    for (uint16_t port = 1; port <= 4; ++port)
        EXPECT_FALSE(det.feed(make_tcp_syn(1, port), port).has_value());
    /* 5th distinct port: alert with count */
    auto a = det.feed(make_tcp_syn(1, 5), 5);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->detector_type, DT_PORT_SCAN);
    EXPECT_EQ(a->aux, 5u);
    /* same window: muted */
    EXPECT_FALSE(det.feed(make_tcp_syn(1, 6), 6).has_value());
}

TEST(PortScanDetectorTest, WindowExpiryResetsState) {
    PortScanDetector::Config cfg;
    cfg.window_ms = 100;
    cfg.unique_threshold = 3;
    PortScanDetector det(cfg);

    det.feed(make_tcp_syn(1, 10), 0);
    det.feed(make_tcp_syn(1, 11), 10);
    /* window slides past both before the third distinct port arrives */
    det.feed(make_tcp_syn(1, 12), 200);
    /* only 1 unique port in window → no alert */
    EXPECT_FALSE(det.feed(make_tcp_syn(1, 13), 210).has_value());
}

TEST(PortScanDetectorTest, DifferentSourcesIndependent) {
    PortScanDetector::Config cfg;
    cfg.unique_threshold = 2;
    PortScanDetector det(cfg);
    EXPECT_FALSE(det.feed(make_tcp_syn(1, 100), 0).has_value());
    /* same port from another source does not combine */
    auto a = det.feed(make_tcp_syn(2, 100), 10);
    EXPECT_FALSE(a.has_value());
    auto b = det.feed(make_tcp_syn(2, 101), 20);
    ASSERT_TRUE(b.has_value());
}

TEST(RateFloodDetectorTest, TriggersAndPreAggregates) {
    RateFloodDetector::Config cfg;
    cfg.window_ms = 1000;
    cfg.pps_threshold = 10;
    RateFloodDetector det(cfg);

    std::optional<ProbeAlert> alert;
    for (int i = 0; i < 10; ++i) {
        auto r = det.feed(make_tcp_syn(1, 80), i * 10);
        if (r) alert = r;
    }
    ASSERT_TRUE(alert.has_value());
    EXPECT_EQ(alert->detector_type, DT_RATE_FLOOD);
    EXPECT_EQ(alert->count, 10u);   /* pre-aggregated */
    EXPECT_EQ(alert->aux, 10u);
}

TEST(RateFloodDetectorTest, BelowThresholdSilent) {
    RateFloodDetector::Config cfg;
    cfg.pps_threshold = 100;
    RateFloodDetector det(cfg);
    for (int i = 0; i < 50; ++i)
        EXPECT_FALSE(det.feed(make_tcp_syn(1, 80), i * 100).has_value());
}

TEST(ArpSpoofDetectorTest, BindingChangeAlerts) {
    ArpSpoofDetector det;
    /* IP .5 first seen from MAC ...:05 */
    EXPECT_FALSE(det.feed(make_arp(5, 0x05, 2), 0).has_value());
    /* same MAC again: fine */
    EXPECT_FALSE(det.feed(make_arp(5, 0x05, 2), 10).has_value());
    /* different MAC claims the same IP: alert */
    auto a = det.feed(make_arp(5, 0x66, 2), 20);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->detector_type, DT_ARP);
    EXPECT_EQ(a->aux, ARP_ALERT_BINDING_CHANGE);
}

TEST(ArpSpoofDetectorTest, GratuitousStormAlerts) {
    ArpSpoofDetector::Config cfg;
    cfg.gratuitous_threshold = 3;
    cfg.window_ms = 1000;
    ArpSpoofDetector det(cfg);

    EXPECT_FALSE(det.feed(make_arp(9, 0x09, 1, true), 0).has_value());
    EXPECT_FALSE(det.feed(make_arp(9, 0x09, 1, true), 10).has_value());
    auto a = det.feed(make_arp(9, 0x09, 1, true), 20);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->aux, ARP_ALERT_GRATUITOUS_STORM);
}
