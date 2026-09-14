#include "proto_dns.h"

namespace ethprobe {

namespace {

inline uint16_t rd16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

/* printable DNS label character check (conservative: alnum, '-', '_', '.') */
bool label_char_ok(uint8_t c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '_';
}

} /* namespace */

DnsInfo parse_dns(const uint8_t* data, size_t len) {
    DnsInfo i;
    if (data == nullptr || len < 12) {
        i.error = DNS_ERR_TRUNCATED;
        return i;
    }
    i.txid        = rd16(data);
    const uint16_t flags = rd16(data + 2);
    i.is_response = (flags & 0x8000) != 0;
    i.rcode       = flags & 0xF;
    i.qdcount     = rd16(data + 4);
    i.ancount     = rd16(data + 6);

    if (i.qdcount == 0) {  /* response without question: header-only is fine */
        i.valid = true;
        return i;
    }

    /* walk the qname (labels + optional compression pointer at the end) */
    size_t off = 12;
    size_t hops = 0;
    size_t total_name_len = 0;
    size_t qend = 0;  /* offset just past the name in the original message */
    std::string name;
    while (true) {
        if (++hops > 32 || off >= len) {
            i.error = DNS_ERR_MALFORMED;
            return i;
        }
        const uint8_t l = data[off];
        if ((l & 0xC0) == 0xC0) {  /* compression pointer */
            if (off + 1 >= len) { i.error = DNS_ERR_MALFORMED; return i; }
            const uint16_t ptr = static_cast<uint16_t>(((l & 0x3F) << 8) | data[off + 1]);
            if (ptr >= len) { i.error = DNS_ERR_MALFORMED; return i; }
            if (qend == 0) qend = off + 2;  /* qtype follows the pointer */
            off = ptr;
            continue;
        }
        if (l == 0) { if (qend == 0) qend = off + 1; break; }
        if (l > 63 || off + 1 + l > len) {
            i.error = DNS_ERR_MALFORMED;
            return i;
        }
        total_name_len += l + 1;
        if (total_name_len > 255) {
            i.error = DNS_ERR_QNAME;
            return i;
        }
        bool label_ok = true;
        for (uint8_t j = 0; j < l; ++j) {
            if (!label_char_ok(data[off + 1 + j])) label_ok = false;
            name.push_back(static_cast<char>(data[off + 1 + j]));
        }
        if (!label_ok) {
            i.error = DNS_ERR_QNAME;  /* binary garbage in name: tunnel signal */
            return i;
        }
        name.push_back('.');
        off += 1 + l;
        /* after the first pointer-follow the offsets are unreliable;
           only the original question name (no pointers) is supported here */
    }
    if (!name.empty() && name.back() == '.') name.pop_back();
    i.qname = std::move(name);

    if (qend + 4 > len) { i.error = DNS_ERR_TRUNCATED; return i; }
    i.qtype  = rd16(data + qend);
    i.qclass = rd16(data + qend + 2);
    i.valid  = true;
    return i;
}

bool dns_qtype_suspicious(uint16_t qtype) {
    switch (qtype) {
        case 10:   /* NULL */
        case 251:  /* IXFR */
        case 252:  /* AXFR */
        case 255:  /* ANY */
            return true;
        default:
            return false;
    }
}

} /* namespace ethprobe */
