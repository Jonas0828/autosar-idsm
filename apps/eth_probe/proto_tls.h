#pragma once
/*
 * proto_tls.h — TLS record / ClientHello metadata parsing.
 *
 * Passive probe: extracts handshake metadata only (SNI, versions, cipher
 * suites, extensions → JA3 fingerprint). Content decryption is out of
 * scope (ECDHE forward secrecy makes it cryptographically impossible for
 * a passive listener).
 */
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ethprobe {

enum TlsError : int {
    TLS_OK = 0,
    TLS_NOT_TLS       = 1,  /* first bytes do not look like a TLS record */
    TLS_ERR_TRUNCATED = 2,  /* incomplete record/handshake (stream may deliver more) */
    TLS_ERR_NOT_CLIENTHELLO = 3,
    TLS_ERR_MALFORMED = 4,
};

/* True when buf starts with a plausible TLS record (type 20-23, ver 3.x) */
bool looks_like_tls(const uint8_t* data, size_t len);

struct TlsClientHello {
    bool     valid = false;
    uint16_t record_version = 0;   /* from the record layer */
    uint16_t client_version = 0;   /* legacy_version in ClientHello */
    std::string sni;               /* empty when not present */
    std::string ja3;               /* "ver,ciphers,exts,curves,formats" */
    std::string ja3_hash;          /* md5 hex of ja3 */
    size_t consumed = 0;           /* bytes used (record + handshake) */
    int    error = TLS_OK;
};

/* Parse one TLS record carrying a ClientHello from a stream chunk. */
TlsClientHello parse_tls_client_hello(const uint8_t* data, size_t len);

/* alert aux codes for detector_type 9 */
inline constexpr uint32_t TLS_ALERT_SEEN_ON_VEHICLE_NET = 0x9001; /* TLS where plain protocols are expected */
inline constexpr uint32_t TLS_ALERT_VERSION_LT_1_2      = 0x9002; /* weak protocol version */
inline constexpr uint32_t TLS_ALERT_MALFORMED           = 0x9003;

} /* namespace ethprobe */
