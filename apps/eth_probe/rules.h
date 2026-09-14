#pragma once
/*
 * rules.h — Suricata/Snort-syntax-subset rule engine.
 *
 * Supported grammar (one rule per line, '#' comments):
 *   alert <proto> <src_ip> <src_port> -> <dst_ip> <dst_port> ( options )
 *     action : only "alert" (drop/pass are rejected — probe is not inline)
 *     proto  : tcp | udp | icmp | ip
 *     addr   : any | [!]<ipv4[/plen]> | [!]<ipv6[/plen]> | $VAR
 *     port   : any | [!]<n> | [!]<a:b> | [!]<a:> | [!]<:b>
 *     options: msg:"..."; sid:N; rev:N;
 *              content:"..|DE AD|.."; [nocase;] [offset:N;] [depth:N;]
 *              [distance:N;] [within:N;]
 *              pcre:"/.../i";        (only when built with pcre2)
 *              http_method; http_uri; http_header; dns_query;  (sticky buffers)
 *              classtype:...; metadata:...;   (stored, no match effect)
 * Unknown options → the rule is skipped with a warning (never fatal).
 *
 * Matching semantics: all contents must match in order; each content's
 * search starts at the previous match's end unless offset/distance say
 * otherwise (Snort-style). pcre patterns run on the raw payload buffer.
 */
#include "packet.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace ethprobe {

using VarMap = std::map<std::string, std::string>;

enum class RuleProto : uint8_t { ANY, TCP, UDP, ICMP };

struct IpMatcher {
    struct Cidr {
        uint8_t addr[16]{};
        uint8_t prefix = 0;
        bool    v6     = false;
    };
    std::vector<Cidr> cidrs;
    bool any     = false;
    bool negated = false;

    bool matches(const uint8_t ip[16], bool ip_is_v6) const;
};

struct PortMatcher {
    struct Range { uint16_t lo = 0, hi = 0; };
    std::vector<Range> ranges;
    bool any     = false;
    bool negated = false;

    bool matches(uint16_t port) const;
};

enum class MatchBuffer : uint8_t {
    RAW, HTTP_METHOD, HTTP_URI, HTTP_HEADER, DNS_QUERY
};

struct ContentMatch {
    std::vector<uint8_t> pattern;
    MatchBuffer buffer = MatchBuffer::RAW;
    bool     nocase = false;
    bool     has_offset = false, has_distance = false;
    bool     has_depth  = false, has_within   = false;
    uint32_t offset = 0, depth = 0, distance = 0, within = 0;
};

struct Rule {
    uint32_t    sid = 0;
    uint32_t    rev = 0;
    std::string msg;
    RuleProto   proto = RuleProto::ANY;
    IpMatcher   src_ip, dst_ip;
    PortMatcher src_port, dst_port;
    std::vector<ContentMatch> contents;
    std::vector<std::string>  pcre_patterns;  /* raw text; compiled internally */
};

/* Application-layer buffers a rule can bind to (filled by proto parsers) */
struct MatchBuffers {
    const uint8_t* raw = nullptr;      size_t raw_len = 0;
    const uint8_t* http_method = nullptr; size_t http_method_len = 0;
    const uint8_t* http_uri = nullptr;    size_t http_uri_len = 0;
    const uint8_t* http_header = nullptr; size_t http_header_len = 0;
    const uint8_t* dns_query = nullptr;  size_t dns_query_len = 0;
};

class RuleEngine {
public:
    RuleEngine();
    ~RuleEngine();

    RuleEngine(const RuleEngine&) = delete;
    RuleEngine& operator=(const RuleEngine&) = delete;

    /* Parse one rule line. Returns false (and fills `err`) when the rule is
       unusable; unknown-option warnings are appended to `warnings`. */
    bool parse_rule(const std::string& line, const VarMap& vars,
                    Rule& out, std::string& err, std::vector<std::string>& warnings);

    /* Load a rules file; bad lines are skipped with warnings. Returns the
       number of rules loaded. */
    size_t load_file(const std::string& path, const VarMap& vars,
                     std::vector<std::string>& warnings);

    size_t rule_count() const;
    size_t skipped_count() const;

    /* Longest content pattern across all rules (for cross-chunk tail
       retention when matching reassembled streams). */
    size_t max_pattern_len() const;

    /* Header prefilter + full option match. Returns matched rules. */
    std::vector<const Rule*> match(const ParsedPacket& pp,
                                   const MatchBuffers& bufs) const;

private:
    struct Impl;
    std::unique_ptr<Impl> m_;
};

} /* namespace ethprobe */
