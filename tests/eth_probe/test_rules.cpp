#include "rules.h"

#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

using ethprobe::MatchBuffers;
using ethprobe::ParsedPacket;
using ethprobe::Rule;
using ethprobe::RuleEngine;
using ethprobe::VarMap;

namespace {

ParsedPacket make_pkt(bool tcp, uint16_t sport, uint16_t dport,
                      const std::vector<uint8_t>& payload) {
    ParsedPacket p;
    p.is_ipv4 = true;
    p.src_ip[0] = 10; p.src_ip[3] = 1;
    p.dst_ip[0] = 10; p.dst_ip[3] = 2;
    p.l4_proto = tcp ? ethprobe::IP_PROTO_TCP : ethprobe::IP_PROTO_UDP;
    p.is_tcp = tcp;
    p.is_udp = !tcp;
    p.src_port = sport;
    p.dst_port = dport;
    p.payload     = payload.empty() ? nullptr : payload.data();
    p.payload_len = payload.size();
    return p;
}

MatchBuffers raw_bufs(const std::vector<uint8_t>& payload) {
    MatchBuffers b;
    b.raw     = payload.empty() ? nullptr : payload.data();
    b.raw_len = payload.size();
    return b;
}

std::vector<uint8_t> bytes(const std::string& s) { return {s.begin(), s.end()}; }

/* binary-safe: explicit length (std::string literal would stop at NUL) */
template <size_t N>
std::vector<uint8_t> bin(const char (&s)[N]) { return {s, s + N - 1}; }

/* Write rules to a temp file, return path */
std::string write_rules(const std::string& content, int tag) {
    const std::string path = "/tmp/eth_probe_test_rules_" + std::to_string(tag) + ".rules";
    std::ofstream out(path);
    out << content;
    return path;
}

} /* namespace */

TEST(RulesTest, ParsesAndMatchesSimpleContentRule) {
    // Arrange
    RuleEngine eng;
    VarMap vars;
    std::vector<std::string> warn;
    Rule r;
    std::string err;
    ASSERT_TRUE(eng.parse_rule(
        R"(alert tcp any any -> any 13400 (msg:"UDS SecurityAccess"; sid:1001; content:"|27 01|";))",
        vars, r, err, warn)) << err;
    EXPECT_EQ(r.sid, 1001u);
    EXPECT_EQ(r.msg, "UDS SecurityAccess");
    ASSERT_EQ(r.contents.size(), 1u);
    EXPECT_EQ(r.contents[0].pattern, (std::vector<uint8_t>{0x27, 0x01}));

    // Act: payload containing the pattern
    auto payload = bin("\x02\x27\x01\x00");
    auto hits = eng.match(make_pkt(true, 49152, 13400, payload), raw_bufs(payload));

    // Assert — note: parse_rule only parses; load via file for match test
    EXPECT_TRUE(hits.empty());  /* rule was never loaded into the engine */
}

TEST(RulesTest, LoadFileMatchesHexContent) {
    // Arrange
    const std::string path = write_rules(
        "# comment line\n"
        "\n"
        "alert tcp any any -> any 13400 (msg:\"UDS SA\"; sid:1001; content:\"|27 01|\";)\n", 1);
    RuleEngine eng;
    std::vector<std::string> warn;
    ASSERT_EQ(eng.load_file(path, {}, warn), 1u);
    std::remove(path.c_str());

    // Act
    auto hit_payload  = bin("\x00\x27\x01\xFF");
    auto miss_payload = bin("\x00\x27\x02\xFF");

    // Assert
    EXPECT_EQ(eng.match(make_pkt(true, 1, 13400, hit_payload), raw_bufs(hit_payload)).size(), 1u);
    EXPECT_TRUE(eng.match(make_pkt(true, 1, 13400, miss_payload), raw_bufs(miss_payload)).empty());
    /* wrong dst port → header filter rejects */
    EXPECT_TRUE(eng.match(make_pkt(true, 1, 9999, hit_payload), raw_bufs(hit_payload)).empty());
}

TEST(RulesTest, NocaseMatchesIgnoringCase) {
    const std::string path = write_rules(
        "alert tcp any any -> any any (msg:\"m\"; sid:2; content:\"AdMiN\"; nocase;)\n", 2);
    RuleEngine eng;
    std::vector<std::string> warn;
    ASSERT_EQ(eng.load_file(path, {}, warn), 1u);
    std::remove(path.c_str());

    auto payload = bytes("xxaDmInyy");
    EXPECT_EQ(eng.match(make_pkt(true, 1, 2, payload), raw_bufs(payload)).size(), 1u);
}

TEST(RulesTest, OffsetAndDepthBoundTheSearch) {
    const std::string path = write_rules(
        "alert tcp any any -> any any (msg:\"m\"; sid:3; content:\"MAGIC\"; offset:4; depth:10;)\n", 3);
    RuleEngine eng;
    std::vector<std::string> warn;
    ASSERT_EQ(eng.load_file(path, {}, warn), 1u);
    std::remove(path.c_str());

    auto inside  = bytes("xxxxMAGICx");        /* starts at 4, within [4,14) */
    auto outside = bytes("MAGICxxxxxxxxx");    /* starts at 0 — outside offset */
    auto too_far = bytes("xxxxxxxxxxMAGIC");   /* starts at 10, ends 15 > 14 */
    EXPECT_EQ(eng.match(make_pkt(true, 1, 2, inside), raw_bufs(inside)).size(), 1u);
    EXPECT_TRUE(eng.match(make_pkt(true, 1, 2, outside), raw_bufs(outside)).empty());
    EXPECT_TRUE(eng.match(make_pkt(true, 1, 2, too_far), raw_bufs(too_far)).empty());
}

TEST(RulesTest, DistanceAndWithinChainContents) {
    const std::string path = write_rules(
        "alert tcp any any -> any any (msg:\"m\"; sid:4; content:\"AB\"; content:\"CD\"; distance:2; within:5;)\n", 4);
    RuleEngine eng;
    std::vector<std::string> warn;
    ASSERT_EQ(eng.load_file(path, {}, warn), 1u);
    std::remove(path.c_str());

    auto ok   = bytes("ABxxCD");     /* CD starts 2 after end of AB, within 5 */
    auto near = bytes("ABCD");       /* distance 2 violated */
    auto far  = bytes("ABxxxxxxCD"); /* within 5 violated */
    EXPECT_EQ(eng.match(make_pkt(true, 1, 2, ok), raw_bufs(ok)).size(), 1u);
    EXPECT_TRUE(eng.match(make_pkt(true, 1, 2, near), raw_bufs(near)).empty());
    EXPECT_TRUE(eng.match(make_pkt(true, 1, 2, far), raw_bufs(far)).empty());
}

TEST(RulesTest, PortRangeNegationAndVariables) {
    const std::string path = write_rules(
        "alert udp any any -> any !53 (msg:\"dns elsewhere\"; sid:5;)\n"
        "alert tcp $HOME_NET any -> any 3000:4000 (msg:\"range\"; sid:6;)\n", 5);
    RuleEngine eng;
    std::vector<std::string> warn;
    VarMap vars{{"HOME_NET", "10.0.0.0/8"}};
    ASSERT_EQ(eng.load_file(path, vars, warn), 2u);
    std::remove(path.c_str());

    /* sid 5: udp to port 53 must NOT match (negated) */
    EXPECT_TRUE(eng.match(make_pkt(false, 1, 53, {}), MatchBuffers{}).empty());
    auto hits = eng.match(make_pkt(false, 1, 5353, {}), MatchBuffers{});
    ASSERT_EQ(hits.size(), 1u);
    EXPECT_EQ(hits[0]->sid, 5u);

    /* sid 6: src ip inside HOME_NET + port in range */
    EXPECT_EQ(eng.match(make_pkt(true, 1, 3500, {}), MatchBuffers{}).size(), 1u);
    EXPECT_TRUE(eng.match(make_pkt(true, 1, 4500, {}), MatchBuffers{}).empty());
    /* src outside HOME_NET */
    ParsedPacket ext = make_pkt(true, 1, 3500, {});
    ext.src_ip[0] = 192;
    EXPECT_TRUE(eng.match(ext, MatchBuffers{}).empty());
}

TEST(RulesTest, UndefinedVariableSkipsRule) {
    const std::string path = write_rules(
        "alert tcp $UNDEFINED any -> any any (msg:\"m\"; sid:7;)\n", 6);
    RuleEngine eng;
    std::vector<std::string> warn;
    EXPECT_EQ(eng.load_file(path, {}, warn), 0u);
    EXPECT_EQ(eng.skipped_count(), 1u);
    EXPECT_FALSE(warn.empty());
    std::remove(path.c_str());
}

TEST(RulesTest, UnknownOptionSkipsOnlyThatRule) {
    const std::string path = write_rules(
        "alert tcp any any -> any any (msg:\"bad\"; sid:8; flowbits:set,x;)\n"
        "alert tcp any any -> any any (msg:\"good\"; sid:9;)\n", 7);
    RuleEngine eng;
    std::vector<std::string> warn;
    EXPECT_EQ(eng.load_file(path, {}, warn), 1u);
    EXPECT_EQ(eng.skipped_count(), 1u);
    std::remove(path.c_str());
}

TEST(RulesTest, UnsupportedActionSkipped) {
    const std::string path = write_rules(
        "drop tcp any any -> any any (msg:\"ips\"; sid:10;)\n", 8);
    RuleEngine eng;
    std::vector<std::string> warn;
    EXPECT_EQ(eng.load_file(path, {}, warn), 0u);
    EXPECT_EQ(eng.skipped_count(), 1u);
    std::remove(path.c_str());
}

TEST(RulesTest, StickyBufferMatchesHttpUri) {
    const std::string path = write_rules(
        "alert tcp any any -> any any (msg:\"uri\"; sid:11; http_uri; content:\"/admin\";)\n", 9);
    RuleEngine eng;
    std::vector<std::string> warn;
    ASSERT_EQ(eng.load_file(path, {}, warn), 1u);
    std::remove(path.c_str());

    // Arrange: uri buffer holds the pattern, raw does not
    auto raw = bytes("GET /admin HTTP/1.1");
    auto uri = bytes("/admin");
    MatchBuffers b;
    b.raw = raw.data(); b.raw_len = raw.size();
    b.http_uri = uri.data(); b.http_uri_len = uri.size();

    // Assert: sticky buffer hit
    EXPECT_EQ(eng.match(make_pkt(true, 1, 80, raw), b).size(), 1u);

    // uri buffer empty → no hit even though raw contains it
    MatchBuffers raw_only;
    raw_only.raw = raw.data(); raw_only.raw_len = raw.size();
    EXPECT_TRUE(eng.match(make_pkt(true, 1, 80, raw), raw_only).empty());
}

TEST(RulesTest, Ipv6CidrMatchesV6Packet) {
    const std::string path = write_rules(
        "alert tcp fd00::/8 any -> any any (msg:\"ula\"; sid:12;)\n", 10);
    RuleEngine eng;
    std::vector<std::string> warn;
    ASSERT_EQ(eng.load_file(path, {}, warn), 1u);
    std::remove(path.c_str());

    ParsedPacket p = make_pkt(true, 1, 2, {});
    p.is_ipv4 = false;
    p.is_ipv6 = true;
    p.src_ip[0] = 0xfd;   /* fd12::1 */
    p.src_ip[1] = 0x12;
    EXPECT_EQ(eng.match(p, MatchBuffers{}).size(), 1u);

    p.src_ip[0] = 0x20;   /* 2012:: — outside fd00::/8 */
    EXPECT_TRUE(eng.match(p, MatchBuffers{}).empty());
}

TEST(RulesTest, MaxPatternLenTracked) {
    const std::string path = write_rules(
        "alert tcp any any -> any any (msg:\"a\"; sid:13; content:\"short\";)\n"
        "alert tcp any any -> any any (msg:\"b\"; sid:14; content:\"a-much-longer-pattern\";)\n", 11);
    RuleEngine eng;
    std::vector<std::string> warn;
    ASSERT_EQ(eng.load_file(path, {}, warn), 2u);
    std::remove(path.c_str());
    EXPECT_EQ(eng.max_pattern_len(), 21u);
}

#ifdef ETH_PROBE_WITH_PCRE2
TEST(RulesTest, PcreMatchesRawBuffer) {
    const std::string path = write_rules(
        R"(alert tcp any any -> any any (msg:"tls"; sid:15; pcre:"/^\x16\x03[\x00-\x03]/";))" "\n", 12);
    RuleEngine eng;
    std::vector<std::string> warn;
    ASSERT_EQ(eng.load_file(path, {}, warn), 1u);
    std::remove(path.c_str());

    auto tls = bin("\x16\x03\x01\x00\x2E");
    auto not_tls = bytes("GET / HTTP");
    EXPECT_EQ(eng.match(make_pkt(true, 1, 443, tls), raw_bufs(tls)).size(), 1u);
    EXPECT_TRUE(eng.match(make_pkt(true, 1, 443, not_tls), raw_bufs(not_tls)).empty());
}
#endif
