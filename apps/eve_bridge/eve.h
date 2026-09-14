#pragma once
/*
 * eve.h — minimal EVE JSON alert parser for the Suricata bridge (rail B).
 *
 * Not a general JSON parser: extracts the flat scalar fields the bridge
 * needs from Suricata's well-known EVE alert records. Robust to key order
 * and whitespace; malformed input yields an error, never crashes.
 */
#include <cstdint>
#include <string>

namespace evebridge {

struct EveAlert {
    bool        valid = false;
    std::string src_ip;
    uint16_t    src_port = 0;
    std::string dest_ip;
    uint16_t    dest_port = 0;
    std::string proto;          /* "TCP" / "UDP" / "ICMP" */
    uint32_t    signature_id = 0;
    uint8_t     severity = 0;
    std::string signature;      /* rule msg text (for logging) */
};

/* Parse one EVE JSON line. Returns valid=false on non-alert records or
   malformed JSON. */
EveAlert parse_eve_alert(const std::string& line);

/* dotted-quad IPv4 or IPv6 literal → 16-byte form (v4 in first 4 bytes).
   Returns false on parse failure. */
bool ip_literal_to_bytes(const std::string& s, uint8_t out[16]);

} /* namespace evebridge */
