#pragma once
/*
 * packet.h — L2-L4 packet parser for the eth_probe Ethernet IDS probe.
 *
 * Pure functions over raw bytes; no allocation, no globals. Parses
 * Ethernet II (incl. up to 2 VLAN tags), ARP, IPv4, IPv6 (incl. common
 * extension headers), TCP, UDP and ICMP into a ParsedPacket view that
 * borrows the caller's buffer (payload pointer is NOT owned).
 *
 * Fragmented IP datagrams are reported as-is (is_fragment=true); L4 fields
 * are only filled for the first fragment. Reassembly lives in ip_defrag.
 */
#include <cstddef>
#include <cstdint>

namespace ethprobe {

/* L4 protocol numbers (IANA) */
inline constexpr uint8_t IP_PROTO_ICMP   = 1;
inline constexpr uint8_t IP_PROTO_TCP    = 6;
inline constexpr uint8_t IP_PROTO_UDP    = 17;
inline constexpr uint8_t IP_PROTO_ICMPV6 = 58;

/* TCP flag bits (offset 13 of the TCP header) */
inline constexpr uint8_t TCP_FIN = 0x01;
inline constexpr uint8_t TCP_SYN = 0x02;
inline constexpr uint8_t TCP_RST = 0x04;
inline constexpr uint8_t TCP_PSH = 0x08;
inline constexpr uint8_t TCP_ACK = 0x10;
inline constexpr uint8_t TCP_URG = 0x20;

struct MacAddress {
    uint8_t b[6]{};
    bool operator==(const MacAddress& o) const;
    bool operator!=(const MacAddress& o) const { return !(*this == o); }
};

struct ParsedPacket {
    /* L2 */
    MacAddress src_mac{};
    MacAddress dst_mac{};
    uint16_t ethertype = 0;   /* innermost ethertype after VLAN tags */
    uint8_t  vlan_tags = 0;

    /* ARP (ethertype 0x0806): sender → src_*, target → dst_* */
    bool     is_arp    = false;
    uint16_t arp_opcode = 0;  /* 1=request, 2=reply */

    /* L3 */
    bool     is_ipv4 = false;
    bool     is_ipv6 = false;
    uint8_t  src_ip[16]{};    /* IPv4 in first 4 bytes */
    uint8_t  dst_ip[16]{};
    uint8_t  l4_proto = 0;    /* IP_PROTO_* */

    /* Fragmentation (either offset>0 or MF set / v6 fragment header seen) */
    bool     is_fragment    = false;
    bool     first_fragment = false;  /* offset == 0 */
    uint32_t frag_id      = 0;        /* v4 identification / v6 identification */
    uint32_t frag_offset  = 0;        /* payload offset in bytes */
    bool     frag_more    = false;    /* MF / M flag */

    /* L4 (filled for non-fragments and first fragments) */
    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    /* TCP */
    bool     is_tcp    = false;
    uint32_t tcp_seq   = 0;
    uint32_t tcp_ack   = 0;
    uint8_t  tcp_flags = 0;

    /* UDP */
    bool is_udp = false;

    /* Payload view into the caller's buffer (borrowed, not owned) */
    const uint8_t* payload     = nullptr;
    size_t         payload_len = 0;

    /* L4 datagram start (IP payload: L4 header + data), always set when L3
       parsed — including mid fragments where payload stays null. This is
       the slice ip_defrag consumes. */
    const uint8_t* l4_data = nullptr;
    size_t         l4_len  = 0;

    /* Parse stopped early (truncated/corrupt); fields filled so far are valid */
    bool truncated = false;
};

/*
 * Parse one frame. Returns false only when nothing usable was decoded
 * (len < Ethernet header, or unsupported ethertype); on success out is
 * filled and out.truncated flags any mid-parse truncation.
 */
bool parse_packet(const uint8_t* data, size_t len, ParsedPacket& out);

/* Helpers for logging / rule matching */
bool ip_is_v4_mapped(const uint8_t ip[16]);         /* IPv4 stored in ip[] */
bool ip_equals(const uint8_t a[16], const uint8_t b[16]);

/*
 * Re-run L4 parsing on a reassembled datagram (from ip_defrag). Fills the
 * L4 fields of out (ports, TCP fields, payload view into `data`). out's L3
 * fields must already be set (typically copied from the first fragment).
 */
void parse_l4_only(uint8_t proto, const uint8_t* data, size_t len, ParsedPacket& out);

} /* namespace ethprobe */
