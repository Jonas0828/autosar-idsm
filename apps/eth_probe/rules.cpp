#include "rules.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <sstream>

#ifdef ETH_PROBE_WITH_PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

namespace ethprobe {

namespace {

/* ---- byte search ------------------------------------------------------- */

const uint8_t* memfind(const uint8_t* hay, size_t hay_len,
                       const uint8_t* needle, size_t needle_len, bool nocase) {
    if (needle_len == 0 || hay_len < needle_len) return nullptr;
    for (size_t i = 0; i + needle_len <= hay_len; ++i) {
        size_t j = 0;
        for (; j < needle_len; ++j) {
            uint8_t a = hay[i + j], b = needle[j];
            if (nocase) {
                a = static_cast<uint8_t>(std::tolower(a));
                b = static_cast<uint8_t>(std::tolower(b));
            }
            if (a != b) break;
        }
        if (j == needle_len) return hay + i;
    }
    return nullptr;
}

/* ---- small parsing helpers --------------------------------------------- */

std::string trim(std::string s) {
    auto not_space = [](unsigned char c) { return !std::isspace(c); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
    s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
    return s;
}

bool parse_u16(const std::string& s, uint16_t& out) {
    if (s.empty()) return false;
    char* end = nullptr;
    const unsigned long v = std::strtoul(s.c_str(), &end, 10);
    if (end == s.c_str() || *end != '\0' || v > 65535) return false;
    out = static_cast<uint16_t>(v);
    return true;
}

bool parse_u32(const std::string& s, uint32_t& out) {
    if (s.empty()) return false;
    char* end = nullptr;
    const unsigned long v = std::strtoul(s.c_str(), &end, 10);
    if (end == s.c_str() || *end != '\0') return false;
    out = static_cast<uint32_t>(v);
    return true;
}

bool parse_ipv4(const std::string& s, uint8_t out[4]) {
    unsigned a, b, c, d;
    char extra;
    if (std::sscanf(s.c_str(), "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    out[0] = static_cast<uint8_t>(a);
    out[1] = static_cast<uint8_t>(b);
    out[2] = static_cast<uint8_t>(c);
    out[3] = static_cast<uint8_t>(d);
    return true;
}

/* Minimal IPv6 literal parser (full and ::-compressed forms) */
bool parse_ipv6(const std::string& s, uint8_t out[16]) {
    std::memset(out, 0, 16);
    if (s.find(':') == std::string::npos) return false;
    const auto dcolon = s.find("::");
    const bool compressed = dcolon != std::string::npos;

    std::vector<uint16_t> head, tail;
    auto parse_groups = [](const std::string& part, std::vector<uint16_t>& groups) {
        size_t pos = 0;
        while (pos < part.size()) {
            const size_t colon = part.find(':', pos);
            const std::string g = part.substr(pos, colon == std::string::npos ? colon : colon - pos);
            if (g.empty() || g.size() > 4) return false;
            char* end = nullptr;
            const long v = std::strtol(g.c_str(), &end, 16);
            if (end == g.c_str() || *end != '\0' || v < 0 || v > 0xFFFF) return false;
            groups.push_back(static_cast<uint16_t>(v));
            pos = (colon == std::string::npos) ? part.size() : colon + 1;
        }
        return true;
    };

    if (compressed) {
        if (s.find("::", dcolon + 2) != std::string::npos) return false;  /* two "::" */
        if (!parse_groups(s.substr(0, dcolon), head)) return false;
        if (!parse_groups(s.substr(dcolon + 2), tail)) return false;
        if (head.size() + tail.size() > 14) return false;
    } else {
        if (!parse_groups(s, head) || head.size() != 8) return false;
    }
    size_t idx = 0;
    for (uint16_t g : head) { out[idx++] = static_cast<uint8_t>(g >> 8); out[idx++] = static_cast<uint8_t>(g); }
    idx = 16 - tail.size() * 2;
    for (uint16_t g : tail) { out[idx++] = static_cast<uint8_t>(g >> 8); out[idx++] = static_cast<uint8_t>(g); }
    return true;
}

bool parse_cidr(const std::string& tok, IpMatcher::Cidr& out) {
    std::string addr = tok;
    uint32_t plen = 0xFFFFFFFFu;
    const auto slash = tok.find('/');
    if (slash != std::string::npos) {
        addr = tok.substr(0, slash);
        if (!parse_u32(tok.substr(slash + 1), plen)) return false;
    }
    if (addr.find(':') != std::string::npos) {
        out.v6 = true;
        if (!parse_ipv6(addr, out.addr)) return false;
        if (plen == 0xFFFFFFFFu) plen = 128;
        if (plen > 128) return false;
    } else {
        out.v6 = false;
        if (!parse_ipv4(addr, out.addr)) return false;
        if (plen == 0xFFFFFFFFu) plen = 32;
        if (plen > 32) return false;
    }
    out.prefix = static_cast<uint8_t>(plen);
    return true;
}

bool parse_ip_matcher(std::string tok, const VarMap& vars, IpMatcher& out,
                      std::string& err) {
    if (tok == "any") { out.any = true; return true; }
    if (!tok.empty() && tok[0] == '!') {
        out.negated = true;
        tok = tok.substr(1);
    }
    if (!tok.empty() && tok[0] == '$') {
        const auto it = vars.find(tok.substr(1));
        if (it == vars.end()) { err = "undefined variable " + tok; return false; }
        tok = it->second;
    }
    /* bracketed list [a,b,c] */
    if (!tok.empty() && tok.front() == '[' && tok.back() == ']') {
        tok = tok.substr(1, tok.size() - 2);
        std::istringstream ss(tok);
        std::string item;
        while (std::getline(ss, item, ',')) {
            IpMatcher::Cidr c;
            if (!parse_cidr(trim(item), c)) { err = "bad CIDR in list: " + item; return false; }
            out.cidrs.push_back(c);
        }
        return !out.cidrs.empty();
    }
    IpMatcher::Cidr c;
    if (!parse_cidr(tok, c)) { err = "bad address: " + tok; return false; }
    out.cidrs.push_back(c);
    return true;
}

bool parse_port_matcher(std::string tok, PortMatcher& out, std::string& err) {
    if (tok == "any") { out.any = true; return true; }
    if (!tok.empty() && tok[0] == '!') {
        out.negated = true;
        tok = tok.substr(1);
    }
    const auto colon = tok.find(':');
    if (colon != std::string::npos) {
        PortMatcher::Range r;
        const std::string lo = tok.substr(0, colon), hi = tok.substr(colon + 1);
        r.lo = 0; r.hi = 65535;
        if (!lo.empty() && !parse_u16(lo, r.lo)) { err = "bad port range: " + tok; return false; }
        if (!hi.empty() && !parse_u16(hi, r.hi)) { err = "bad port range: " + tok; return false; }
        if (r.lo > r.hi) { err = "inverted port range: " + tok; return false; }
        out.ranges.push_back(r);
        return true;
    }
    PortMatcher::Range r;
    if (!parse_u16(tok, r.lo)) { err = "bad port: " + tok; return false; }
    r.hi = r.lo;
    out.ranges.push_back(r);
    return true;
}

/* Split option string on ';' outside double quotes */
std::vector<std::string> split_options(const std::string& body) {
    std::vector<std::string> opts;
    std::string cur;
    bool in_quotes = false;
    for (char c : body) {
        if (c == '"') in_quotes = !in_quotes;
        if (c == ';' && !in_quotes) {
            opts.push_back(trim(cur));
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!trim(cur).empty()) opts.push_back(trim(cur));
    return opts;
}

/* content value: "...|DE AD BE|..." → bytes. Handles \\ \" \| escapes. */
bool parse_content_value(const std::string& raw, std::vector<uint8_t>& out,
                         std::string& err) {
    if (raw.size() < 2 || raw.front() != '"' || raw.back() != '"') {
        err = "content value must be quoted";
        return false;
    }
    const std::string v = raw.substr(1, raw.size() - 2);
    bool hex = false;
    int  hi = -1;
    for (size_t i = 0; i < v.size(); ++i) {
        const char c = v[i];
        if (c == '\\' && !hex && i + 1 < v.size()) {
            out.push_back(static_cast<uint8_t>(v[++i]));
            continue;
        }
        if (c == '|') { hex = !hex; hi = -1; continue; }
        if (hex) {
            if (std::isspace(static_cast<unsigned char>(c))) continue;
            if (!std::isxdigit(static_cast<unsigned char>(c))) {
                err = "bad hex in content";
                return false;
            }
            const int nib = std::isdigit(static_cast<unsigned char>(c))
                ? c - '0' : std::tolower(static_cast<unsigned char>(c)) - 'a' + 10;
            if (hi < 0) { hi = nib; }
            else { out.push_back(static_cast<uint8_t>((hi << 4) | nib)); hi = -1; }
        } else {
            out.push_back(static_cast<uint8_t>(c));
        }
    }
    if (hex || hi >= 0) { err = "unterminated hex block in content"; return false; }
    if (out.empty()) { err = "empty content"; return false; }
    return true;
}

std::string unquote(const std::string& raw) {
    if (raw.size() >= 2 && raw.front() == '"' && raw.back() == '"')
        return raw.substr(1, raw.size() - 2);
    return raw;
}

} /* namespace */

/* ---- matchers ----------------------------------------------------------- */

bool IpMatcher::matches(const uint8_t ip[16], bool ip_is_v6) const {
    if (any) return true;
    for (const auto& c : cidrs) {
        if (c.v6 != ip_is_v6) continue;
        const uint8_t full = c.prefix / 8, rem = c.prefix % 8;
        bool same = full == 0 || std::memcmp(c.addr, ip, full) == 0;
        if (same && rem != 0) {
            const uint8_t mask = static_cast<uint8_t>(0xFF << (8 - rem));
            same = (c.addr[full] & mask) == (ip[full] & mask);
        }
        if (same) return !negated;
    }
    return negated;
}

bool PortMatcher::matches(uint16_t port) const {
    if (any) return true;
    for (const auto& r : ranges) {
        if (port >= r.lo && port <= r.hi) return !negated;
    }
    return negated;
}

/* ---- rule engine -------------------------------------------------------- */

struct RuleEngine::Impl {
    struct CompiledRule {
        Rule rule;
#ifdef ETH_PROBE_WITH_PCRE2
        std::vector<pcre2_code_8*> pcre_codes;
        ~CompiledRule() {
            for (auto* c : pcre_codes) pcre2_code_free_8(c);
        }
#endif
    };
    std::vector<std::unique_ptr<CompiledRule>> rules;
    size_t skipped = 0;
};

RuleEngine::RuleEngine() : m_(std::make_unique<Impl>()) {}
RuleEngine::~RuleEngine() = default;

bool RuleEngine::parse_rule(const std::string& line_in, const VarMap& vars,
                            Rule& out, std::string& err,
                            std::vector<std::string>& warnings) {
    const std::string line = trim(line_in);
    const auto lp = line.find('(');
    const auto rp = line.rfind(')');
    if (lp == std::string::npos || rp == std::string::npos || rp <= lp) {
        err = "missing option parens";
        return false;
    }

    /* header tokens */
    std::istringstream hs(line.substr(0, lp));
    std::string action, proto, sip, sport, dir, dip, dport;
    if (!(hs >> action >> proto >> sip >> sport >> dir >> dip >> dport)) {
        err = "malformed rule header";
        return false;
    }
    if (action != "alert") { err = "unsupported action: " + action; return false; }
    if (dir != "->") { err = "unsupported direction: " + dir; return false; }

    if      (proto == "tcp")  out.proto = RuleProto::TCP;
    else if (proto == "udp")  out.proto = RuleProto::UDP;
    else if (proto == "icmp") out.proto = RuleProto::ICMP;
    else if (proto == "ip")   out.proto = RuleProto::ANY;
    else { err = "unsupported protocol: " + proto; return false; }

    if (!parse_ip_matcher(sip, vars, out.src_ip, err)) return false;
    if (!parse_ip_matcher(dip, vars, out.dst_ip, err)) return false;
    if (!parse_port_matcher(sport, out.src_port, err)) return false;
    if (!parse_port_matcher(dport, out.dst_port, err)) return false;

    /* options */
    MatchBuffer cur_buffer = MatchBuffer::RAW;
    for (const auto& opt : split_options(line.substr(lp + 1, rp - lp - 1))) {
        if (opt.empty()) continue;
        const auto colon = opt.find(':');
        const std::string key = trim(colon == std::string::npos ? opt : opt.substr(0, colon));
        const std::string val = colon == std::string::npos ? "" : trim(opt.substr(colon + 1));

        if (key == "msg") {
            out.msg = unquote(val);
        } else if (key == "sid") {
            if (!parse_u32(val, out.sid)) { err = "bad sid"; return false; }
        } else if (key == "rev") {
            if (!parse_u32(val, out.rev)) { err = "bad rev"; return false; }
        } else if (key == "content") {
            ContentMatch cm;
            cm.buffer = cur_buffer;
            if (!parse_content_value(val, cm.pattern, err)) return false;
            out.contents.push_back(std::move(cm));
        } else if (key == "nocase") {
            if (out.contents.empty()) { err = "nocase without content"; return false; }
            out.contents.back().nocase = true;
        } else if (key == "offset" || key == "depth" || key == "distance" || key == "within") {
            if (out.contents.empty()) { err = key + " without content"; return false; }
            uint32_t v;
            if (!parse_u32(val, v)) { err = "bad " + key; return false; }
            auto& c = out.contents.back();
            if      (key == "offset")   { c.has_offset = true;   c.offset = v; }
            else if (key == "depth")    { c.has_depth = true;    c.depth = v; }
            else if (key == "distance") { c.has_distance = true; c.distance = v; }
            else                        { c.has_within = true;   c.within = v; }
        } else if (key == "http_method") {
            cur_buffer = MatchBuffer::HTTP_METHOD;
        } else if (key == "http_uri") {
            cur_buffer = MatchBuffer::HTTP_URI;
        } else if (key == "http_header") {
            cur_buffer = MatchBuffer::HTTP_HEADER;
        } else if (key == "dns_query") {
            cur_buffer = MatchBuffer::DNS_QUERY;
        } else if (key == "pcre") {
            out.pcre_patterns.push_back(unquote(val));
        } else if (key == "classtype" || key == "metadata" || key == "reference" ||
                   key == "gid" || key == "priority" || key == "flow") {
            /* accepted, no match effect in this engine */
        } else {
            warnings.push_back("unknown option '" + key + "' — rule skipped");
            err = "unknown option: " + key;
            return false;
        }
    }

    if (out.sid == 0) { err = "missing sid"; return false; }
    return true;
}

size_t RuleEngine::load_file(const std::string& path, const VarMap& vars,
                             std::vector<std::string>& warnings) {
    std::ifstream in(path);
    if (!in) {
        warnings.push_back("cannot open rules file: " + path);
        return 0;
    }
    size_t loaded = 0;
    std::string line;
    size_t lineno = 0;
    while (std::getline(in, line)) {
        ++lineno;
        /* strip trailing comment outside quotes */
        bool in_q = false;
        size_t cut = std::string::npos;
        for (size_t i = 0; i < line.size(); ++i) {
            if (line[i] == '"') in_q = !in_q;
            if (line[i] == '#' && !in_q) { cut = i; break; }
        }
        const std::string stripped = trim(cut == std::string::npos ? line : line.substr(0, cut));
        if (stripped.empty()) continue;

        Rule r;
        std::string err;
        const bool ok = parse_rule(stripped, vars, r, err, warnings);
        if (!ok) {
            warnings.push_back(path + ":" + std::to_string(lineno) + ": " + err);
            ++m_->skipped;
            continue;
        }
        auto cr = std::make_unique<Impl::CompiledRule>();
        cr->rule = std::move(r);
#ifdef ETH_PROBE_WITH_PCRE2
        bool pcre_ok = true;
        for (const auto& pat : cr->rule.pcre_patterns) {
            /* strip surrounding /.../ and trailing flags */
            std::string body = pat;
            if (body.size() >= 2 && body.front() == '/') {
                const auto last = body.rfind('/');
                if (last > 0) body = body.substr(1, last - 1);
            }
            int errcode = 0;
            PCRE2_SIZE erroff = 0;
            pcre2_code_8* code = pcre2_compile_8(
                reinterpret_cast<PCRE2_SPTR8>(body.c_str()), body.size(),
                0, &errcode, &erroff, nullptr);
            if (!code) {
                warnings.push_back(path + ":" + std::to_string(lineno) +
                                   ": pcre compile failed — rule skipped");
                pcre_ok = false;
                break;
            }
            cr->pcre_codes.push_back(code);
        }
        if (!pcre_ok) { ++m_->skipped; continue; }
#else
        if (!cr->rule.pcre_patterns.empty()) {
            warnings.push_back(path + ":" + std::to_string(lineno) +
                               ": pcre not supported in this build — rule skipped");
            ++m_->skipped;
            continue;
        }
#endif
        m_->rules.push_back(std::move(cr));
        ++loaded;
    }
    return loaded;
}

size_t RuleEngine::rule_count() const { return m_->rules.size(); }
size_t RuleEngine::skipped_count() const { return m_->skipped; }

size_t RuleEngine::max_pattern_len() const {
    size_t n = 0;
    for (const auto& cr : m_->rules)
        for (const auto& c : cr->rule.contents)
            n = std::max(n, c.pattern.size());
    return n;
}

namespace {

std::pair<const uint8_t*, size_t> select_buffer(const MatchBuffers& b, MatchBuffer which) {
    switch (which) {
        case MatchBuffer::HTTP_METHOD: return {b.http_method, b.http_method_len};
        case MatchBuffer::HTTP_URI:    return {b.http_uri, b.http_uri_len};
        case MatchBuffer::HTTP_HEADER: return {b.http_header, b.http_header_len};
        case MatchBuffer::DNS_QUERY:   return {b.dns_query, b.dns_query_len};
        default:                       return {b.raw, b.raw_len};
    }
}

bool content_matches(const uint8_t* buf, size_t len, const ContentMatch& c,
                     size_t prev_end, size_t& match_end) {
    size_t start;
    if      (c.has_distance) start = prev_end + c.distance;
    else if (c.has_offset)   start = c.offset;
    else                     start = prev_end;

    size_t limit = len;
    if (c.has_within) limit = std::min(limit, prev_end + static_cast<size_t>(c.within));
    if (c.has_depth)  limit = std::min(limit, (c.has_offset ? c.offset : 0) + static_cast<size_t>(c.depth));
    if (start > len || c.pattern.size() > limit || limit - start < c.pattern.size())
        return false;

    const uint8_t* found = memfind(buf + start, limit - start,
                                   c.pattern.data(), c.pattern.size(), c.nocase);
    if (!found) return false;
    match_end = static_cast<size_t>(found - buf) + c.pattern.size();
    return true;
}

} /* namespace */

std::vector<const Rule*> RuleEngine::match(const ParsedPacket& pp,
                                           const MatchBuffers& bufs) const {
    std::vector<const Rule*> hits;
    for (const auto& cr : m_->rules) {
        const Rule& r = cr->rule;

        /* header prefilter */
        bool proto_ok = false;
        switch (r.proto) {
            case RuleProto::TCP:  proto_ok = pp.is_tcp; break;
            case RuleProto::UDP:  proto_ok = pp.is_udp; break;
            case RuleProto::ICMP: proto_ok = (pp.l4_proto == IP_PROTO_ICMP ||
                                              pp.l4_proto == IP_PROTO_ICMPV6); break;
            case RuleProto::ANY:  proto_ok = true; break;
        }
        if (!proto_ok) continue;
        const bool v6 = pp.is_ipv6;
        if (!r.src_ip.matches(pp.src_ip, v6) || !r.dst_ip.matches(pp.dst_ip, v6)) continue;
        if (!r.src_port.matches(pp.src_port) || !r.dst_port.matches(pp.dst_port)) continue;

        /* contents: all must match in order; prev_end tracked per buffer */
        size_t prev_end[5] = {0, 0, 0, 0, 0};
        bool all = true;
        for (const auto& c : r.contents) {
            auto [buf, len] = select_buffer(bufs, c.buffer);
            const auto bi = static_cast<size_t>(c.buffer);
            size_t end = 0;
            if (buf == nullptr || !content_matches(buf, len, c, prev_end[bi], end)) {
                all = false;
                break;
            }
            prev_end[bi] = end;
        }
        if (!all) continue;

#ifdef ETH_PROBE_WITH_PCRE2
        for (auto* code : cr->pcre_codes) {
            pcre2_match_data_8* md = pcre2_match_data_create_from_pattern_8(code, nullptr);
            const int rc = pcre2_match_8(code,
                reinterpret_cast<PCRE2_SPTR8>(bufs.raw), bufs.raw_len,
                0, 0, md, nullptr);
            pcre2_match_data_free_8(md);
            if (rc < 0) { all = false; break; }
        }
        if (!all) continue;
#endif
        hits.push_back(&r);
    }
    return hits;
}

} /* namespace ethprobe */
