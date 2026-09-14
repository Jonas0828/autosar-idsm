#include "geoip.h"

#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>

using ethprobe::GeoIp;

namespace {

std::string write_cidrs(const char* content, int tag) {
    const std::string path = "/tmp/eth_probe_test_cidrs_" + std::to_string(tag) + ".txt";
    std::ofstream out(path);
    out << content;
    return path;
}

void ip4(uint8_t ip[16], uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    ip[0] = a; ip[1] = b; ip[2] = c; ip[3] = d;
    for (int i = 4; i < 16; ++i) ip[i] = 0;
}

} /* namespace */

TEST(GeoIpTest, ClassifiesHomeDomesticForeign) {
    // Arrange
    const std::string path = write_cidrs(
        "# domestic sample\n"
        "1.0.1.0/24\n"
        "1.0.2.0/23\n"
        "203.0.113.0/24\n", 1);
    GeoIp g;
    ASSERT_TRUE(g.load_cidrs(path));
    std::remove(path.c_str());
    EXPECT_EQ(g.cidr_count(), 3u);

    uint8_t ip[16] = {};

    // home (RFC1918 default)
    ip4(ip, 10, 20, 0, 7);
    EXPECT_EQ(g.classify(ip, false), GeoIp::Verdict::HOME);
    ip4(ip, 192, 168, 5, 5);
    EXPECT_EQ(g.classify(ip, false), GeoIp::Verdict::HOME);

    // domestic
    ip4(ip, 1, 0, 1, 99);
    EXPECT_EQ(g.classify(ip, false), GeoIp::Verdict::DOMESTIC);
    ip4(ip, 1, 0, 3, 1);            /* covered by 1.0.2.0/23 */
    EXPECT_EQ(g.classify(ip, false), GeoIp::Verdict::DOMESTIC);

    // foreign
    ip4(ip, 8, 8, 8, 8);
    EXPECT_EQ(g.classify(ip, false), GeoIp::Verdict::FOREIGN);
    ip4(ip, 203, 0, 114, 1);        /* just outside 203.0.113.0/24 */
    EXPECT_EQ(g.classify(ip, false), GeoIp::Verdict::FOREIGN);
}

TEST(GeoIpTest, UnknownWhenNotLoaded) {
    GeoIp g;
    uint8_t ip[16] = {};
    ip4(ip, 8, 8, 8, 8);
    EXPECT_EQ(g.classify(ip, false), GeoIp::Verdict::UNKNOWN);
    /* home nets still work without the domestic list */
    ip4(ip, 172, 16, 1, 1);
    EXPECT_EQ(g.classify(ip, false), GeoIp::Verdict::HOME);
}

TEST(GeoIpTest, BadLinesSkippedAndCounted) {
    const std::string path = write_cidrs(
        "1.0.1.0/24\n"
        "not-an-ip\n"
        "999.1.2.3/24\n"
        "1.0.2.0/33\n", 2);
    GeoIp g;
    size_t bad = 0;
    ASSERT_TRUE(g.load_cidrs(path, &bad));
    std::remove(path.c_str());
    EXPECT_EQ(bad, 3u);
    EXPECT_EQ(g.cidr_count(), 1u);
}

TEST(GeoIpTest, CustomHomeNetsReplaceDefaults) {
    GeoIp g;
    ASSERT_TRUE(g.set_home_nets({"10.60.0.0/16"}));
    uint8_t ip[16] = {};
    ip4(ip, 10, 60, 1, 1);
    EXPECT_EQ(g.classify(ip, false), GeoIp::Verdict::HOME);
    /* 10.x outside the custom home net is no longer HOME */
    ip4(ip, 10, 20, 1, 1);
    EXPECT_EQ(g.classify(ip, false), GeoIp::Verdict::UNKNOWN);
}

TEST(GeoIpTest, Ipv6Classification) {
    const std::string path = write_cidrs("2400:3200::/32\n", 3);
    GeoIp g;
    ASSERT_TRUE(g.load_cidrs(path));
    std::remove(path.c_str());

    uint8_t ip[16] = {};
    ip[0] = 0x24; ip[1] = 0x00; ip[2] = 0x32; ip[3] = 0x00; ip[15] = 1;
    EXPECT_EQ(g.classify(ip, true), GeoIp::Verdict::DOMESTIC);

    ip[2] = 0x33;  /* 2400:3300:: outside /32 */
    EXPECT_EQ(g.classify(ip, true), GeoIp::Verdict::FOREIGN);

    uint8_t loop[16] = {};
    loop[15] = 1;  /* ::1 is home by default */
    EXPECT_EQ(g.classify(loop, true), GeoIp::Verdict::HOME);
}

TEST(GeoIpTest, MissingFileReturnsFalse) {
    GeoIp g;
    EXPECT_FALSE(g.load_cidrs("/tmp/eth_probe_no_such_file.txt"));
    EXPECT_FALSE(g.loaded());
}
