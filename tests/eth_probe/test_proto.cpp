#include "proto_doip.h"
#include "proto_someip.h"
#include "proto_tls.h"
#include "proto_http.h"
#include "proto_dns.h"
#include "md5.h"

#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <vector>

using namespace ethprobe;

namespace {

template <size_t N>
std::vector<uint8_t> bin(const char (&s)[N]) { return {s, s + N - 1}; }
std::vector<uint8_t> bytes(const std::string& s) { return {s.begin(), s.end()}; }

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

/* DoIP frame: version 0x02, type, payload */
std::vector<uint8_t> doip_frame(uint16_t type, const std::vector<uint8_t>& payload,
                                uint8_t version = 0x02) {
    std::vector<uint8_t> v;
    v.push_back(version);
    v.push_back(static_cast<uint8_t>(~version));
    put16(v, type);
    put32(v, static_cast<uint32_t>(payload.size()));
    v.insert(v.end(), payload.begin(), payload.end());
    return v;
}

/* SOME/IP header + payload */
std::vector<uint8_t> someip_frame(uint16_t service, uint16_t method,
                                  uint16_t session, uint8_t proto_ver,
                                  uint8_t msg_type,
                                  const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> v;
    put16(v, service);
    put16(v, method);
    put32(v, static_cast<uint32_t>(8 + payload.size()));  /* length = 8 + payload */
    put16(v, 0x0001);   /* client id */
    put16(v, session);
    v.push_back(proto_ver);
    v.push_back(1);     /* iface ver */
    v.push_back(msg_type);
    v.push_back(0);     /* return code */
    v.insert(v.end(), payload.begin(), payload.end());
    return v;
}

/* SD payload offering service 0x1234 instance 1 ttl 3 */
std::vector<uint8_t> sd_payload_offer(uint16_t service, uint32_t ttl = 3) {
    std::vector<uint8_t> v;
    v.push_back(0x80);            /* flags: reboot */
    v.insert(v.end(), {0, 0, 0}); /* reserved */
    put32(v, 16);                 /* one 16-byte entry */
    v.push_back(SOMEIP_SD_ENTRY_OFFER);
    v.insert(v.end(), {0, 0, 0}); /* idx/options */
    put16(v, service);
    put16(v, 1);                  /* instance */
    v.push_back(1);               /* major */
    v.push_back(static_cast<uint8_t>(ttl >> 16));
    v.push_back(static_cast<uint8_t>(ttl >> 8));
    v.push_back(static_cast<uint8_t>(ttl));
    put32(v, 0);                  /* minor */
    put32(v, 0);                  /* options length */
    return v;
}

/* Minimal TLS ClientHello with SNI "ecu-ota.example.com" */
std::vector<uint8_t> tls_client_hello() {
    std::vector<uint8_t> body;
    put16(body, 0x0303);                 /* client version TLS 1.2 */
    for (int i = 0; i < 32; ++i) body.push_back(0xAA);  /* random */
    body.push_back(0);                   /* session id len */
    put16(body, 4);                      /* cipher suites len */
    put16(body, 0x0A0A);                 /* GREASE — must be filtered */
    put16(body, 0xC02F);                 /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
    body.push_back(1); body.push_back(0);/* compression: null */
    /* extensions */
    std::vector<uint8_t> ext;
    const std::string sni = "ecu-ota.example.com";
    put16(ext, 0x0000);                  /* server_name */
    put16(ext, static_cast<uint16_t>(2 + 1 + 2 + sni.size()));
    put16(ext, static_cast<uint16_t>(1 + 2 + sni.size()));
    ext.push_back(0);                    /* host_name */
    put16(ext, static_cast<uint16_t>(sni.size()));
    ext.insert(ext.end(), sni.begin(), sni.end());
    put16(ext, 0x000A);                  /* supported_groups */
    put16(ext, 6);
    put16(ext, 4);
    put16(ext, 23);                      /* secp256r1 */
    put16(ext, 24);                      /* secp384r1 */
    put16(ext, 0x000B);                  /* ec_point_formats */
    put16(ext, 2);
    ext.push_back(1);
    ext.push_back(0);                    /* uncompressed */
    put16(body, static_cast<uint16_t>(ext.size()));
    body.insert(body.end(), ext.begin(), ext.end());

    std::vector<uint8_t> hs;
    hs.push_back(1);                     /* client_hello */
    const uint32_t bl = static_cast<uint32_t>(body.size());
    hs.push_back(static_cast<uint8_t>(bl >> 16));
    hs.push_back(static_cast<uint8_t>(bl >> 8));
    hs.push_back(static_cast<uint8_t>(bl));
    hs.insert(hs.end(), body.begin(), body.end());

    std::vector<uint8_t> rec;
    rec.push_back(22);                   /* handshake */
    put16(rec, 0x0301);
    put16(rec, static_cast<uint16_t>(hs.size()));
    rec.insert(rec.end(), hs.begin(), hs.end());
    return rec;
}

/* DNS query for www.example.com A */
std::vector<uint8_t> dns_query(uint16_t qtype = 1) {
    std::vector<uint8_t> v;
    put16(v, 0x1234);      /* txid */
    put16(v, 0x0100);      /* standard query, RD */
    put16(v, 1);           /* qdcount */
    put16(v, 0);           /* ancount */
    put16(v, 0); put16(v, 0);
    const char* labels[] = {"www", "example", "com"};
    for (const char* l : labels) {
        v.push_back(static_cast<uint8_t>(std::strlen(l)));
        v.insert(v.end(), l, l + std::strlen(l));
    }
    v.push_back(0);
    put16(v, qtype);
    put16(v, 1);           /* IN */
    return v;
}

} /* namespace */

/* ---- DoIP ---- */

TEST(ProtoDoipTest, ParsesRoutingActivationAndAlerts) {
    auto f = doip_frame(DOIP_PT_ROUTING_ACTIVATION, {0x0E, 0x00, 0, 0, 0, 0, 0});
    auto info = parse_doip(f.data(), f.size());
    ASSERT_TRUE(info.valid);
    EXPECT_EQ(info.payload_type, DOIP_PT_ROUTING_ACTIVATION);
    auto v = inspect_doip(info);
    EXPECT_TRUE(v.alert);
    EXPECT_EQ(v.aux, DOIP_PT_ROUTING_ACTIVATION);
}

TEST(ProtoDoipTest, DiagMessageDoesNotAlert) {
    auto f = doip_frame(DOIP_PT_DIAG_MESSAGE, {0x22, 0xF1, 0x90});
    auto info = parse_doip(f.data(), f.size());
    ASSERT_TRUE(info.valid);
    EXPECT_FALSE(inspect_doip(info).alert);
}

TEST(ProtoDoipTest, VersionInverseMismatchAlerts) {
    auto f = doip_frame(DOIP_PT_DIAG_MESSAGE, {0x22});
    f[1] = 0x00;  /* break inverse */
    auto info = parse_doip(f.data(), f.size());
    EXPECT_FALSE(info.valid);
    EXPECT_EQ(info.error, DOIP_ERR_VERSION_INVERSE);
    auto v = inspect_doip(info);
    EXPECT_TRUE(v.alert);
    EXPECT_EQ(v.aux, DOIP_ERR_VERSION_INVERSE);
}

TEST(ProtoDoipTest, DeclaredLengthBeyondFrameAlerts) {
    auto f = doip_frame(DOIP_PT_DIAG_MESSAGE, {0x22});
    f[7] = 100;  /* declare 100 bytes, only 1 present */
    auto info = parse_doip(f.data(), f.size());
    EXPECT_EQ(info.error, DOIP_ERR_LENGTH);
    EXPECT_TRUE(inspect_doip(info).alert);
}

TEST(ProtoDoipTest, UnknownPayloadTypeAlerts) {
    auto f = doip_frame(0x7777, {});
    auto info = parse_doip(f.data(), f.size());
    EXPECT_EQ(info.error, DOIP_ERR_UNKNOWN_TYPE);
    EXPECT_TRUE(inspect_doip(info).alert);
}

/* ---- SOME/IP ---- */

TEST(ProtoSomeipTest, ParsesValidHeader) {
    auto f = someip_frame(0x1234, 0x0001, 5, 1, SOMEIP_MT_REQUEST, {0xDE, 0xAD});
    auto info = parse_someip(f.data(), f.size());
    ASSERT_TRUE(info.valid);
    EXPECT_EQ(info.service_id, 0x1234);
    EXPECT_EQ(info.session_id, 5);
    EXPECT_EQ(info.avail, 2u);
}

TEST(ProtoSomeipTest, RejectsBadLengthVersionType) {
    auto bad_len = someip_frame(0x1234, 1, 1, 1, SOMEIP_MT_REQUEST, {1});
    bad_len[7] = 0xFF;  /* length field huge */
    EXPECT_EQ(parse_someip(bad_len.data(), bad_len.size()).error, SOMEIP_ERR_LENGTH);

    auto bad_ver = someip_frame(0x1234, 1, 1, 2, SOMEIP_MT_REQUEST, {1});
    EXPECT_EQ(parse_someip(bad_ver.data(), bad_ver.size()).error, SOMEIP_ERR_PROTO_VER);

    auto bad_type = someip_frame(0x1234, 1, 1, 1, 0x42, {1});
    EXPECT_EQ(parse_someip(bad_type.data(), bad_type.size()).error, SOMEIP_ERR_MSG_TYPE);
}

TEST(ProtoSomeipTest, ParsesSdOfferEntry) {
    auto f = someip_frame(SOMEIP_SD_SERVICE, SOMEIP_SD_METHOD, 1, 1,
                          SOMEIP_MT_NOTIFICATION, sd_payload_offer(0x1234));
    auto info = parse_someip(f.data(), f.size());
    ASSERT_TRUE(info.valid);
    ASSERT_TRUE(info.is_sd());
    std::vector<SdEntry> entries;
    ASSERT_TRUE(parse_someip_sd_entries(info.payload, info.avail, entries));
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(entries[0].type, SOMEIP_SD_ENTRY_OFFER);
    EXPECT_EQ(entries[0].service_id, 0x1234);
    EXPECT_EQ(entries[0].ttl, 3u);
}

TEST(ProtoSomeipTest, TrackerAlertsNonWhitelistedOffer) {
    SomeipSdTracker::Config cfg;
    cfg.service_whitelist = {0x1000, 0x2000};
    SomeipSdTracker tracker(cfg);
    uint8_t src[16] = {10, 0, 0, 5};

    auto allowed = someip_frame(SOMEIP_SD_SERVICE, SOMEIP_SD_METHOD, 1, 1,
                                SOMEIP_MT_NOTIFICATION, sd_payload_offer(0x1000));
    auto info_a = parse_someip(allowed.data(), allowed.size());
    EXPECT_TRUE(tracker.inspect(info_a, src, 0).empty());

    auto rogue = someip_frame(SOMEIP_SD_SERVICE, SOMEIP_SD_METHOD, 2, 1,
                              SOMEIP_MT_NOTIFICATION, sd_payload_offer(0x9999));
    auto info_r = parse_someip(rogue.data(), rogue.size());
    auto alerts = tracker.inspect(info_r, src, 10);
    ASSERT_EQ(alerts.size(), 1u);
    EXPECT_EQ(alerts[0], 0x1000u + 0x9999u);
}

TEST(ProtoSomeipTest, TrackerDetectsSessionWrap) {
    SomeipSdTracker tracker;
    uint8_t src[16] = {10, 0, 0, 7};
    auto f1 = someip_frame(SOMEIP_SD_SERVICE, SOMEIP_SD_METHOD, 500, 1,
                           SOMEIP_MT_NOTIFICATION, sd_payload_offer(0x1000));
    auto i1 = parse_someip(f1.data(), f1.size());
    tracker.inspect(i1, src, 0);
    /* session drops 500 → 3 (not a 0xFFFF wrap): reboot/spoof signal */
    auto f2 = someip_frame(SOMEIP_SD_SERVICE, SOMEIP_SD_METHOD, 3, 1,
                           SOMEIP_MT_NOTIFICATION, sd_payload_offer(0x1000));
    auto i2 = parse_someip(f2.data(), f2.size());
    auto alerts = tracker.inspect(i2, src, 10);
    ASSERT_EQ(alerts.size(), 1u);
    EXPECT_EQ(alerts[0], 0x2000u);
}

/* ---- TLS ---- */

TEST(ProtoTlsTest, ParsesClientHelloSniAndJa3) {
    auto f = tls_client_hello();
    ASSERT_TRUE(looks_like_tls(f.data(), f.size()));
    auto h = parse_tls_client_hello(f.data(), f.size());
    ASSERT_TRUE(h.valid) << h.error;
    EXPECT_EQ(h.client_version, 0x0303);
    EXPECT_EQ(h.sni, "ecu-ota.example.com");
    /* JA3: version, ciphers (GREASE filtered), extensions, groups, formats */
    EXPECT_EQ(h.ja3, "771,49199,0-10-11,23-24,0");
    EXPECT_EQ(h.ja3_hash.size(), 32u);
}

TEST(ProtoTlsTest, RejectsNonTlsAndTruncated) {
    auto not_tls = bytes("GET / HTTP/1.1\r\n");
    EXPECT_FALSE(looks_like_tls(not_tls.data(), not_tls.size()));
    EXPECT_EQ(parse_tls_client_hello(not_tls.data(), not_tls.size()).error, TLS_NOT_TLS);

    auto f = tls_client_hello();
    f.resize(f.size() / 2);  /* cut mid-record */
    EXPECT_EQ(parse_tls_client_hello(f.data(), f.size()).error, TLS_ERR_TRUNCATED);
}

/* ---- md5 ---- */

TEST(Md5Test, KnownVectors) {
    EXPECT_EQ(Md5().final_hex(), "d41d8cd98f00b204e9800998ecf8427e");
    Md5 abc;
    abc.update("abc");
    EXPECT_EQ(abc.final_hex(), "900150983cd24fb0d6963f7d28e17f72");
    /* 56-byte edge (padding boundary) */
    Md5 edge;
    edge.update("12345678901234567890123456789012345678901234567890123456");
    EXPECT_EQ(edge.final_hex(), "49f193adce178490e34d1b3a4ec0064c");
}

/* ---- HTTP ---- */

TEST(ProtoHttpTest, ParsesRequest) {
    auto f = bytes("GET /update/manifest.json HTTP/1.1\r\nHost: ota.local\r\n\r\n");
    auto m = parse_http(f.data(), f.size());
    ASSERT_EQ(m.error, HTTP_OK);
    EXPECT_TRUE(m.is_request);
    EXPECT_EQ(m.method, "GET");
    EXPECT_EQ(m.uri, "/update/manifest.json");
    EXPECT_EQ(m.consumed, f.size());
    ASSERT_NE(m.header_block, nullptr);
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(m.header_block),
                          m.header_block_len), "Host: ota.local");
}

TEST(ProtoHttpTest, ParsesResponse) {
    auto f = bytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    auto m = parse_http(f.data(), f.size());
    ASSERT_EQ(m.error, HTTP_OK);
    EXPECT_TRUE(m.is_response);
    EXPECT_EQ(m.status, 200);
}

TEST(ProtoHttpTest, IncompleteHeaderWaitsForMore) {
    auto f = bytes("POST /flash HTTP/1.1\r\nHost: x");
    EXPECT_EQ(parse_http(f.data(), f.size()).error, HTTP_INCOMPLETE);
    EXPECT_EQ(parse_http(f.data(), f.size()).error, HTTP_INCOMPLETE);
}

TEST(ProtoHttpTest, MalformedAndLongUriDetected) {
    auto bad = bytes("GARBAGE\r\n\r\n");
    EXPECT_EQ(parse_http(bad.data(), bad.size()).error, HTTP_NOT_HTTP);

    std::string long_uri = "/" + std::string(3000, 'a');
    auto f = bytes("GET " + long_uri + " HTTP/1.1\r\n\r\n");
    EXPECT_EQ(parse_http(f.data(), f.size()).error, HTTP_ERR_URI_TOO_LONG);
}

/* ---- DNS ---- */

TEST(ProtoDnsTest, ParsesQueryName) {
    auto f = dns_query();
    auto i = parse_dns(f.data(), f.size());
    ASSERT_TRUE(i.valid) << i.error;
    EXPECT_EQ(i.txid, 0x1234);
    EXPECT_EQ(i.qname, "www.example.com");
    EXPECT_EQ(i.qtype, 1);
    EXPECT_FALSE(i.is_response);
}

TEST(ProtoDnsTest, CompressionPointerLoopRejected) {
    auto f = dns_query();
    /* overwrite qname with a pointer to itself (offset 12) */
    f[12] = 0xC0;
    f[13] = 12;
    EXPECT_EQ(parse_dns(f.data(), f.size()).error, DNS_ERR_MALFORMED);
}

TEST(ProtoDnsTest, BinaryGarbageInNameFlagged) {
    auto f = dns_query();
    f[12] = 2;
    f[13] = 0x01;  /* non-printable label bytes */
    f[14] = 0x02;
    EXPECT_EQ(parse_dns(f.data(), f.size()).error, DNS_ERR_QNAME);
}

TEST(ProtoDnsTest, SuspiciousQtypes) {
    EXPECT_TRUE(dns_qtype_suspicious(252));  /* AXFR */
    EXPECT_TRUE(dns_qtype_suspicious(255));  /* ANY */
    EXPECT_TRUE(dns_qtype_suspicious(10));   /* NULL */
    EXPECT_FALSE(dns_qtype_suspicious(1));   /* A */
    EXPECT_FALSE(dns_qtype_suspicious(28));  /* AAAA */

    auto f = dns_query(252);
    auto i = parse_dns(f.data(), f.size());
    ASSERT_TRUE(i.valid);
    EXPECT_TRUE(dns_qtype_suspicious(i.qtype));
}
