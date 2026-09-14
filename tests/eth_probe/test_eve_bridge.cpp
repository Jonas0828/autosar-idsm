#include "eve.h"

#include <gtest/gtest.h>

#include <cstring>

using evebridge::EveAlert;
using evebridge::ip_literal_to_bytes;
using evebridge::parse_eve_alert;

TEST(EveBridgeTest, ParsesStandardAlertRecord) {
    // Arrange: representative Suricata EVE alert line
    const std::string line = R"({"timestamp":"2026-09-14T10:00:00.000000+0000","flow_id":1234,"event_type":"alert","src_ip":"192.168.0.10","src_port":49152,"dest_ip":"10.0.0.5","dest_port":13400,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2010935,"rev":3,"signature":"ET SCAN Nmap Scripting Engine User-Agent Detected","category":"Attempted Information Leak","severity":2}})";

    // Act
    const EveAlert a = parse_eve_alert(line);

    // Assert
    ASSERT_TRUE(a.valid);
    EXPECT_EQ(a.src_ip, "192.168.0.10");
    EXPECT_EQ(a.src_port, 49152);
    EXPECT_EQ(a.dest_ip, "10.0.0.5");
    EXPECT_EQ(a.dest_port, 13400);
    EXPECT_EQ(a.proto, "TCP");
    EXPECT_EQ(a.signature_id, 2010935u);
    EXPECT_EQ(a.severity, 2);
    EXPECT_EQ(a.signature, "ET SCAN Nmap Scripting Engine User-Agent Detected");
}

TEST(EveBridgeTest, RejectsNonAlertRecords) {
    const EveAlert a = parse_eve_alert(
        R"({"event_type":"flow","src_ip":"1.2.3.4","dest_ip":"5.6.7.8"})");
    EXPECT_FALSE(a.valid);
}

TEST(EveBridgeTest, RejectsMalformedJson) {
    EXPECT_FALSE(parse_eve_alert("not json at all").valid);
    EXPECT_FALSE(parse_eve_alert(R"({"event_type":"alert"})").valid);  /* missing ips */
}

TEST(EveBridgeTest, ToleratesMissingOptionalFields) {
    const EveAlert a = parse_eve_alert(
        R"({"event_type":"alert","src_ip":"1.2.3.4","dest_ip":"5.6.7.8","alert":{"signature_id":100}})");
    ASSERT_TRUE(a.valid);
    EXPECT_EQ(a.src_port, 0);       /* absent → zero */
    EXPECT_EQ(a.signature_id, 100u);
}

TEST(EveBridgeTest, IpLiteralConversions) {
    uint8_t ip[16];
    ASSERT_TRUE(ip_literal_to_bytes("10.20.30.40", ip));
    EXPECT_EQ(ip[0], 10);
    EXPECT_EQ(ip[3], 40);
    for (int i = 4; i < 16; ++i) EXPECT_EQ(ip[i], 0);

    ASSERT_TRUE(ip_literal_to_bytes("fd12::1", ip));
    EXPECT_EQ(ip[0], 0xfd);
    EXPECT_EQ(ip[1], 0x12);
    EXPECT_EQ(ip[15], 1);

    EXPECT_FALSE(ip_literal_to_bytes("999.1.2.3", ip));
    EXPECT_FALSE(ip_literal_to_bytes("garbage", ip));
}
