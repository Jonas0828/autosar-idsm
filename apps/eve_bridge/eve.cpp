#include "eve.h"

#include <cctype>
#include <cstring>
#include <vector>

namespace evebridge {

namespace {

/* Find "key" at JSON object level and return pointer past the colon, or
   nullptr. Skips into nested objects only for the "alert" section when
   asked via section prefix "alert.". */
const char* find_key(const char* p, const char* key, const char* section) {
    const std::string needle = std::string("\"") + key + "\"";
    const char* s = p;
    if (section != nullptr) {
        /* locate the section object first */
        const std::string sec = std::string("\"") + section + "\"";
        s = std::strstr(s, sec.c_str());
        if (s == nullptr) return nullptr;
        s = std::strchr(s, '{');
        if (s == nullptr) return nullptr;
    }
    s = std::strstr(s, needle.c_str());
    if (s == nullptr) return nullptr;
    s += needle.size();
    while (*s == ' ' || *s == '\t' || *s == ':') ++s;
    return s;
}

bool parse_json_string(const char* p, std::string& out, const char** end) {
    if (*p != '"') return false;
    ++p;
    out.clear();
    while (*p && *p != '"') {
        if (*p == '\\' && p[1]) {
            ++p;
            switch (*p) {
                case 'n': out.push_back('\n'); break;
                case 't': out.push_back('\t'); break;
                case 'r': out.push_back('\r'); break;
                default:  out.push_back(*p); break;
            }
        } else {
            out.push_back(*p);
        }
        ++p;
    }
    if (*p != '"') return false;
    if (end) *end = p + 1;
    return true;
}

bool parse_json_u32(const char* p, uint32_t& out) {
    if (!std::isdigit(static_cast<unsigned char>(*p))) return false;
    char* end = nullptr;
    const unsigned long v = std::strtoul(p, &end, 10);
    out = static_cast<uint32_t>(v);
    return true;
}

bool get_string(const char* json, const char* key, const char* section,
                std::string& out) {
    const char* p = find_key(json, key, section);
    return p != nullptr && parse_json_string(p, out, nullptr);
}

bool get_u32(const char* json, const char* key, const char* section,
             uint32_t& out) {
    const char* p = find_key(json, key, section);
    return p != nullptr && parse_json_u32(p, out);
}

bool parse_ipv4(const std::string& s, uint8_t out[4]) {
    unsigned a, b, c, d;
    char extra;
    if (std::sscanf(s.c_str(), "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4)
        return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    out[0] = static_cast<uint8_t>(a);
    out[1] = static_cast<uint8_t>(b);
    out[2] = static_cast<uint8_t>(c);
    out[3] = static_cast<uint8_t>(d);
    return true;
}

} /* namespace */

bool ip_literal_to_bytes(const std::string& s, uint8_t out[16]) {
    std::memset(out, 0, 16);
    if (s.find(':') == std::string::npos) return parse_ipv4(s, out);
    /* minimal v6: hex groups with optional '::' */
    std::vector<uint16_t> head, tail;
    const auto dc = s.find("::");
    auto part = [](const std::string& str, std::vector<uint16_t>& g) {
        size_t pos = 0;
        if (str.empty()) return true;
        while (pos <= str.size()) {
            const auto c = str.find(':', pos);
            const std::string t = str.substr(pos, c == std::string::npos ? c : c - pos);
            if (t.empty() || t.size() > 4) return false;
            char* e = nullptr;
            const long v = std::strtol(t.c_str(), &e, 16);
            if (*e != '\0' || v > 0xFFFF) return false;
            g.push_back(static_cast<uint16_t>(v));
            if (c == std::string::npos) break;
            pos = c + 1;
        }
        return true;
    };
    if (dc != std::string::npos) {
        if (!part(s.substr(0, dc), head) || !part(s.substr(dc + 2), tail)) return false;
    } else {
        if (!part(s, head) || head.size() != 8) return false;
    }
    size_t i = 0;
    for (auto g : head) { out[i++] = static_cast<uint8_t>(g >> 8); out[i++] = static_cast<uint8_t>(g); }
    i = 16 - tail.size() * 2;
    for (auto g : tail) { out[i++] = static_cast<uint8_t>(g >> 8); out[i++] = static_cast<uint8_t>(g); }
    return true;
}

EveAlert parse_eve_alert(const std::string& line) {
    EveAlert a;
    /* quick reject: must be an alert record */
    std::string event_type;
    if (!get_string(line.c_str(), "event_type", nullptr, event_type) ||
        event_type != "alert") {
        return a;
    }
    if (!get_string(line.c_str(), "src_ip", nullptr, a.src_ip)) return a;
    if (!get_string(line.c_str(), "dest_ip", nullptr, a.dest_ip)) return a;
    get_string(line.c_str(), "proto", nullptr, a.proto);
    get_string(line.c_str(), "signature", "alert", a.signature);
    uint32_t v;
    if (get_u32(line.c_str(), "src_port", nullptr, v)) a.src_port = static_cast<uint16_t>(v);
    if (get_u32(line.c_str(), "dest_port", nullptr, v)) a.dest_port = static_cast<uint16_t>(v);
    if (!get_u32(line.c_str(), "signature_id", "alert", v)) return a;
    a.signature_id = v;
    if (get_u32(line.c_str(), "severity", "alert", v)) a.severity = static_cast<uint8_t>(v);
    a.valid = true;
    return a;
}

} /* namespace evebridge */
