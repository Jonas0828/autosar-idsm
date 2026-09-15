#pragma once
/*
 * geoip.h — CIDR-based cross-border IP analysis.
 *
 * Loads a domestic CIDR list (chnroutes format: one "x.x.x.0/24" per line,
 * '#' comments) plus a configurable set of vehicle-internal "home" nets,
 * and classifies addresses as HOME / DOMESTIC / FOREIGN. Used to flag
 * outbound connections to non-domestic IPs (data-export compliance,
 * GB 44495 data security).
 *
 * Lookup structure: binary prefix trie per address family — O(32)/O(128)
 * per query, no allocation during lookup.
 */
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ethprobe {

/* Standalone CIDR set (prefix trie) — used for alert-source whitelisting
   where no "loaded" gating or home/domestic semantics are wanted. */
class CidrSet {
public:
    CidrSet();
    ~CidrSet();
    CidrSet(const CidrSet&) = delete;
    CidrSet& operator=(const CidrSet&) = delete;

    /* Add one CIDR ("10.0.0.0/8", "fd00::/8", bare IPs allowed). */
    bool add(const std::string& cidr);
    /* Parse a comma-separated list; returns false on first bad entry. */
    bool add_list(const std::string& csv);

    bool contains(const uint8_t ip[16], bool is_v6) const;
    bool empty() const;
    size_t count() const;

private:
    struct Impl;
    std::unique_ptr<Impl> m_;
};

class GeoIp {
public:
    enum class Verdict : uint8_t {
        UNKNOWN,   /* domestic list not loaded — detector disabled */
        HOME,      /* vehicle-internal address */
        DOMESTIC,  /* in the domestic CIDR list */
        FOREIGN,   /* public and not in the domestic list */
    };

    GeoIp();
    ~GeoIp();

    GeoIp(const GeoIp&) = delete;
    GeoIp& operator=(const GeoIp&) = delete;

    /* Load domestic CIDRs from a text file. Returns false on open error;
       malformed lines are skipped and counted (bad_lines). */
    bool load_cidrs(const std::string& path, size_t* bad_lines = nullptr);

    /* Replace the home-net list (default: RFC1918 + link-local + loopback) */
    bool set_home_nets(const std::vector<std::string>& cidrs);

    Verdict classify(const uint8_t ip[16], bool is_v6) const;

    bool   loaded() const;      /* domestic list present */
    size_t cidr_count() const;

private:
    struct Impl;
    std::unique_ptr<Impl> m_;
};

} /* namespace ethprobe */
