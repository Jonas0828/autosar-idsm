#include "packet.h"

#include <cstring>

namespace ethprobe {

namespace {

inline uint16_t rd16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

inline uint32_t rd32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |  static_cast<uint32_t>(p[3]);
}

constexpr uint16_t ETH_P_IPV4 = 0x0800;
constexpr uint16_t ETH_P_ARP  = 0x0806;
constexpr uint16_t ETH_P_VLAN = 0x8100;
constexpr uint16_t ETH_P_QINQ = 0x88A8;
constexpr uint16_t ETH_P_IPV6 = 0x86DD;

/* IPv6 extension header types we know how to skip */
constexpr uint8_t IP6_HBH  = 0;   /* Hop-by-Hop Options */
constexpr uint8_t IP6_RT   = 43;  /* Routing */
constexpr uint8_t IP6_FRAG = 44;  /* Fragment */
constexpr uint8_t IP6_AH   = 51;  /* Authentication Header */
constexpr uint8_t IP6_DST  = 60;  /* Destination Options */

void parse_arp(const uint8_t* p, size_t len, ParsedPacket& out) {
    /* ARP header: htype(2) ptype(2) hlen(1) plen(1) opcode(2)
                   sha(6) spa(4) tha(6) tpa(4)  (Ethernet/IPv4 form) */
    if (len < 8) { out.truncated = true; return; }
    const uint16_t htype  = rd16(p);
    const uint16_t ptype  = rd16(p + 2);
    const uint8_t  hlen   = p[4];
    const uint8_t  plen   = p[5];
    out.arp_opcode = rd16(p + 6);
    if (htype != 1 || ptype != ETH_P_IPV4 || hlen != 6 || plen != 4) {
        out.truncated = true;  /* non Ethernet/IPv4 ARP variant: not decoded */
        return;
    }
    if (len < 8 + 2 * (6 + 4)) { out.truncated = true; return; }
    std::memcpy(out.src_mac.b, p + 8, 6);
    std::memcpy(out.src_ip, p + 14, 4);
    std::memcpy(out.dst_mac.b, p + 18, 6);
    std::memcpy(out.dst_ip, p + 24, 4);
}

void parse_l4(const uint8_t* p, size_t len, uint8_t proto, ParsedPacket& out) {
    if (proto == IP_PROTO_TCP) {
        if (len < 20) { out.truncated = true; return; }
        out.is_tcp    = true;
        out.src_port  = rd16(p);
        out.dst_port  = rd16(p + 2);
        out.tcp_seq   = rd32(p + 4);
        out.tcp_ack   = rd32(p + 8);
        const size_t hdr_len = static_cast<size_t>((p[12] >> 4) & 0xF) * 4;
        out.tcp_flags = p[13] & 0x3F;
        if (hdr_len < 20 || hdr_len > len) { out.truncated = true; return; }
        out.payload     = p + hdr_len;
        out.payload_len = len - hdr_len;
    } else if (proto == IP_PROTO_UDP) {
        if (len < 8) { out.truncated = true; return; }
        out.is_udp    = true;
        out.src_port  = rd16(p);
        out.dst_port  = rd16(p + 2);
        const size_t udp_len = rd16(p + 4);
        size_t pay_len = (udp_len >= 8 && udp_len <= len) ? udp_len - 8 : len - 8;
        out.payload     = p + 8;
        out.payload_len = pay_len;
    } else if (proto == IP_PROTO_ICMP || proto == IP_PROTO_ICMPV6) {
        /* type/code only; rest counts as payload */
        if (len < 4) { out.truncated = true; return; }
        out.src_port    = p[0];  /* ICMP type  (repurposed for context data) */
        out.dst_port    = p[1];  /* ICMP code */
        out.payload     = p + 4;
        out.payload_len = len - 4;
    } else {
        out.payload     = p;
        out.payload_len = len;
    }
}

void parse_ipv4(const uint8_t* p, size_t len, ParsedPacket& out) {
    if (len < 20) { out.truncated = true; return; }
    const uint8_t  ver_ihl = p[0];
    if ((ver_ihl >> 4) != 4) { out.truncated = true; return; }
    const size_t ihl = static_cast<size_t>(ver_ihl & 0xF) * 4;
    if (ihl < 20 || ihl > len) { out.truncated = true; return; }

    const uint16_t total_len = rd16(p + 2);
    if (total_len < ihl) { out.truncated = true; return; }
    const size_t ip_len = (total_len <= len) ? total_len : len; /* tolerate L2 padding */

    out.is_ipv4   = true;
    out.frag_id   = rd16(p + 4);
    const uint16_t flags_off  = rd16(p + 6);
    out.frag_more    = (flags_off & 0x2000) != 0;
    out.frag_offset  = static_cast<uint32_t>(flags_off & 0x1FFF) * 8;
    out.is_fragment  = out.frag_more || out.frag_offset > 0;
    out.first_fragment = out.frag_offset == 0;
    out.l4_proto    = p[9];
    std::memcpy(out.src_ip, p + 12, 4);
    std::memcpy(out.dst_ip, p + 16, 4);

    out.l4_data = p + ihl;
    out.l4_len  = ip_len - ihl;
    if (out.is_fragment && !out.first_fragment) return;  /* no L4 in mid fragments */
    parse_l4(p + ihl, ip_len - ihl, out.l4_proto, out);
}

void parse_ipv6(const uint8_t* p, size_t len, ParsedPacket& out) {
    if (len < 40) { out.truncated = true; return; }
    if ((p[0] >> 4) != 6) { out.truncated = true; return; }

    out.is_ipv6 = true;
    uint8_t next = p[6];
    std::memcpy(out.src_ip, p + 8, 16);
    std::memcpy(out.dst_ip, p + 24, 16);

    size_t off = 40;
    /* Walk extension headers (bounded loop) */
    for (int hops = 0; hops < 8; ++hops) {
        if (next == IP6_HBH || next == IP6_RT || next == IP6_DST) {
            if (len < off + 2) { out.truncated = true; return; }
            const uint8_t following = p[off];
            const size_t ext_len = (static_cast<size_t>(p[off + 1]) + 1) * 8;
            if (len < off + ext_len) { out.truncated = true; return; }
            next = following;
            off += ext_len;
        } else if (next == IP6_AH) {
            if (len < off + 2) { out.truncated = true; return; }
            const uint8_t following = p[off];
            const size_t ext_len = (static_cast<size_t>(p[off + 1]) + 2) * 4;
            if (len < off + ext_len) { out.truncated = true; return; }
            next = following;
            off += ext_len;
        } else if (next == IP6_FRAG) {
            if (len < off + 8) { out.truncated = true; return; }
            const uint8_t following = p[off];
            const uint16_t off_m   = rd16(p + off + 2);
            out.frag_offset  = (off_m >> 3) * 8;
            out.frag_more    = (off_m & 1) != 0;
            out.frag_id      = rd32(p + off + 4);
            out.is_fragment  = true;
            out.first_fragment = out.frag_offset == 0;
            next = following;
            off += 8;
            break;  /* fragment header is last we walk */
        } else {
            break;  /* reached L4 protocol */
        }
    }

    out.l4_proto = next;
    out.l4_data  = (off <= len) ? p + off : nullptr;
    out.l4_len   = (off <= len) ? len - off : 0;
    if (out.is_fragment && !out.first_fragment) return;
    parse_l4(p + off, len - off, next, out);
}

} /* namespace */

bool MacAddress::operator==(const MacAddress& o) const {
    return std::memcmp(b, o.b, sizeof(b)) == 0;
}

bool parse_packet(const uint8_t* data, size_t len, ParsedPacket& out) {
    out = ParsedPacket{};
    if (data == nullptr || len < 14) return false;

    std::memcpy(out.dst_mac.b, data, 6);
    std::memcpy(out.src_mac.b, data + 6, 6);
    uint16_t ethertype = rd16(data + 12);
    size_t off = 14;

    /* Up to two VLAN/QinQ tags */
    while ((ethertype == ETH_P_VLAN || ethertype == ETH_P_QINQ) && out.vlan_tags < 2) {
        if (len < off + 4) { out.truncated = true; return false; }
        ethertype = rd16(data + off + 2);
        off += 4;
        ++out.vlan_tags;
    }
    out.ethertype = ethertype;

    switch (ethertype) {
        case ETH_P_IPV4: parse_ipv4(data + off, len - off, out); break;
        case ETH_P_IPV6: parse_ipv6(data + off, len - off, out); break;
        case ETH_P_ARP:  out.is_arp = true; parse_arp(data + off, len - off, out); break;
        default: return false;  /* unsupported ethertype */
    }
    return true;
}

void parse_l4_only(uint8_t proto, const uint8_t* data, size_t len, ParsedPacket& out) {
    parse_l4(data, len, proto, out);
}

bool ip_is_v4_mapped(const uint8_t ip[16]) {
    /* Our convention: IPv4 addresses occupy the first 4 bytes, rest zero */
    static const uint8_t zero12[12] = {};
    return std::memcmp(ip + 4, zero12, 12) == 0;
}

bool ip_equals(const uint8_t a[16], const uint8_t b[16]) {
    return std::memcmp(a, b, 16) == 0;
}

} /* namespace ethprobe */
