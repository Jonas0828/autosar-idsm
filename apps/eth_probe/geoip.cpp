#include "geoip.h"

#include <cstring>
#include <fstream>
#include <vector>

namespace ethprobe {

namespace {

struct TrieNode {
    TrieNode* child[2] = {nullptr, nullptr};
    bool terminal = false;
};

struct Trie {
    TrieNode root;
    size_t inserted = 0;

    Trie() = default;
    ~Trie() { destroy(&root); }

    Trie(const Trie&) = delete;
    Trie& operator=(const Trie&) = delete;

    Trie(Trie&& o) noexcept { steal(o); }
    Trie& operator=(Trie&& o) noexcept {
        if (this != &o) {
            destroy(&root);
            root = TrieNode{};
            steal(o);
        }
        return *this;
    }

    void steal(Trie& o) {
        root.child[0] = o.root.child[0];
        root.child[1] = o.root.child[1];
        root.terminal = o.root.terminal;
        inserted = o.inserted;
        o.root.child[0] = o.root.child[1] = nullptr;
        o.root.terminal = false;
        o.inserted = 0;
    }

    static void destroy(TrieNode* n) {
        for (auto* c : n->child) {
            if (c) { destroy(c); delete c; }
        }
    }

    void insert(const uint8_t* addr, uint8_t prefix, uint8_t max_bits) {
        TrieNode* n = &root;
        for (uint8_t i = 0; i < prefix && i < max_bits; ++i) {
            const int bit = (addr[i / 8] >> (7 - (i % 8))) & 1;
            if (!n->child[bit]) n->child[bit] = new TrieNode();
            n = n->child[bit];
        }
        n->terminal = true;
        ++inserted;
    }

    bool contains(const uint8_t* addr, uint8_t max_bits) const {
        const TrieNode* n = &root;
        for (uint8_t i = 0; i < max_bits; ++i) {
            if (n->terminal) return true;
            const int bit = (addr[i / 8] >> (7 - (i % 8))) & 1;
            n = n->child[bit];
            if (!n) return false;
        }
        return n->terminal;
    }
};

bool parse_addr_cidr(const std::string& line, uint8_t addr[16], uint8_t& prefix,
                     bool& is_v6) {
    std::string a = line;
    uint32_t plen = 0xFFFFFFFFu;
    const auto slash = line.find('/');
    if (slash != std::string::npos) {
        a = line.substr(0, slash);
        char* end = nullptr;
        plen = std::strtoul(line.c_str() + slash + 1, &end, 10);
        if (end == line.c_str() + slash + 1 || *end != '\0') return false;
    }
    if (a.find(':') != std::string::npos) {
        is_v6 = true;
        /* reuse a minimal v6 parser: groups of hex, '::' compression */
        std::memset(addr, 0, 16);
        std::vector<uint16_t> head, tail;
        const auto dc = a.find("::");
        auto parse_part = [](const std::string& s, std::vector<uint16_t>& g) {
            size_t pos = 0;
            if (s.empty()) return true;
            while (pos <= s.size()) {
                const auto c = s.find(':', pos);
                const std::string tok = s.substr(pos, c == std::string::npos ? c : c - pos);
                if (tok.empty() || tok.size() > 4) return false;
                char* e = nullptr;
                const long v = std::strtol(tok.c_str(), &e, 16);
                if (*e != '\0' || v > 0xFFFF) return false;
                g.push_back(static_cast<uint16_t>(v));
                if (c == std::string::npos) break;
                pos = c + 1;
            }
            return true;
        };
        if (dc != std::string::npos) {
            if (!parse_part(a.substr(0, dc), head) || !parse_part(a.substr(dc + 2), tail))
                return false;
        } else {
            if (!parse_part(a, head) || head.size() != 8) return false;
        }
        size_t idx = 0;
        for (auto g : head) { addr[idx++] = static_cast<uint8_t>(g >> 8); addr[idx++] = static_cast<uint8_t>(g); }
        idx = 16 - tail.size() * 2;
        for (auto g : tail) { addr[idx++] = static_cast<uint8_t>(g >> 8); addr[idx++] = static_cast<uint8_t>(g); }
        if (plen == 0xFFFFFFFFu) plen = 128;
        if (plen > 128) return false;
    } else {
        is_v6 = false;
        unsigned b0, b1, b2, b3;
        char extra;
        if (std::sscanf(a.c_str(), "%u.%u.%u.%u%c", &b0, &b1, &b2, &b3, &extra) != 4)
            return false;
        if (b0 > 255 || b1 > 255 || b2 > 255 || b3 > 255) return false;
        addr[0] = static_cast<uint8_t>(b0);
        addr[1] = static_cast<uint8_t>(b1);
        addr[2] = static_cast<uint8_t>(b2);
        addr[3] = static_cast<uint8_t>(b3);
        if (plen == 0xFFFFFFFFu) plen = 32;
        if (plen > 32) return false;
    }
    prefix = static_cast<uint8_t>(plen);
    return true;
}

} /* namespace */

struct GeoIp::Impl {
    Trie domestic_v4, domestic_v6;
    Trie home_v4, home_v6;
    bool domestic_loaded = false;

    void add_default_home() {
        static const char* defaults[] = {
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
            "127.0.0.0/8", "169.254.0.0/16", "fe80::/10", "::1/128",
        };
        for (const char* c : defaults) {
            uint8_t addr[16]; uint8_t plen; bool v6;
            if (parse_addr_cidr(c, addr, plen, v6)) {
                (v6 ? home_v6 : home_v4).insert(addr, plen, v6 ? 128 : 32);
            }
        }
    }
};

GeoIp::GeoIp() : m_(std::make_unique<Impl>()) {
    m_->add_default_home();
}

GeoIp::~GeoIp() = default;

bool GeoIp::load_cidrs(const std::string& path, size_t* bad_lines) {
    std::ifstream in(path);
    if (!in) return false;
    size_t bad = 0;
    std::string line;
    while (std::getline(in, line)) {
        /* trim */
        const auto b = line.find_first_not_of(" \t\r\n");
        if (b == std::string::npos || line[b] == '#') continue;
        const auto e = line.find_last_not_of(" \t\r\n");
        const std::string tok = line.substr(b, e - b + 1);
        uint8_t addr[16]; uint8_t plen; bool v6;
        if (!parse_addr_cidr(tok, addr, plen, v6)) { ++bad; continue; }
        (v6 ? m_->domestic_v6 : m_->domestic_v4).insert(addr, plen, v6 ? 128 : 32);
    }
    if (bad_lines) *bad_lines = bad;
    m_->domestic_loaded = true;
    return true;
}

bool GeoIp::set_home_nets(const std::vector<std::string>& cidrs) {
    Trie hv4, hv6;
    for (const auto& c : cidrs) {
        uint8_t addr[16]; uint8_t plen; bool v6;
        if (!parse_addr_cidr(c, addr, plen, v6)) return false;
        (v6 ? hv6 : hv4).insert(addr, plen, v6 ? 128 : 32);
    }
    m_->home_v4 = std::move(hv4);
    m_->home_v6 = std::move(hv6);
    return true;
}

GeoIp::Verdict GeoIp::classify(const uint8_t ip[16], bool is_v6) const {
    const bool home = is_v6 ? m_->home_v6.contains(ip, 128)
                            : m_->home_v4.contains(ip, 32);
    if (home) return Verdict::HOME;
    if (!m_->domestic_loaded) return Verdict::UNKNOWN;
    const bool domestic = is_v6 ? m_->domestic_v6.contains(ip, 128)
                                : m_->domestic_v4.contains(ip, 32);
    return domestic ? Verdict::DOMESTIC : Verdict::FOREIGN;
}

bool   GeoIp::loaded()      const { return m_->domestic_loaded; }
size_t GeoIp::cidr_count()  const {
    return m_->domestic_v4.inserted + m_->domestic_v6.inserted;
}

} /* namespace ethprobe */
