#pragma once
/*
 * proto_dns.h — DNS query/response header + question section parsing.
 * Answers are counted, not expanded. Compression pointers are followed
 * with a strict hop bound (loop protection).
 */
#include <cstddef>
#include <cstdint>
#include <string>

namespace ethprobe {

enum DnsError : int {
    DNS_OK = 0,
    DNS_ERR_TRUNCATED = 1,
    DNS_ERR_MALFORMED = 2,   /* bad label structure / pointer loop */
    DNS_ERR_QNAME     = 3,   /* overlong or illegal query name (tunnel signal) */
};

inline constexpr uint16_t DNS_PORT = 53;

struct DnsInfo {
    bool     valid = false;
    uint16_t txid    = 0;
    bool     is_response = false;
    uint8_t  rcode   = 0;
    uint16_t qdcount = 0;
    uint16_t ancount = 0;
    std::string qname;
    uint16_t qtype  = 0;
    uint16_t qclass = 0;
    int      error = DNS_OK;
};

/* UDP form: message as-is. TCP form: caller strips the 2-byte length prefix. */
DnsInfo parse_dns(const uint8_t* data, size_t len);

/* qtypes that are unusual on a vehicle network (tunnel / zone-transfer signals) */
bool dns_qtype_suspicious(uint16_t qtype);

/* alert aux codes for detector_type 11 */
inline constexpr uint32_t DNS_ALERT_QNAME_ILLEGAL  = 0xB001;
inline constexpr uint32_t DNS_ALERT_SUSPICIOUS_QTYPE = 0xB002; /* + qtype in low 16 bits */

} /* namespace ethprobe */
