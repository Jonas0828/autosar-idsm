#pragma once
/*
 * sha256.h -- self-contained SHA-256 (FIPS 180-4) for host_probe.
 *
 * Used to hash monitored files against the integrity baseline so the
 * probe has no OpenSSL/libcrypto dependency (embedded / Android
 * friendly). One-shot helper only; streaming contexts stay internal.
 */
#include <cstddef>
#include <cstdint>
#include <string>

namespace hostprobe {

constexpr size_t SHA256_LEN = 32;

/* digest of a buffer */
void sha256(const uint8_t* data, size_t len, uint8_t out[SHA256_LEN]);

/* digest of a whole file; false on open/read error */
bool sha256_file(const std::string& path, uint8_t out[SHA256_LEN]);

/* lowercase hex of a digest */
std::string sha256_hex(const uint8_t digest[SHA256_LEN]);

/* parse 64-char hex (upper or lower case) into a digest */
bool sha256_from_hex(const std::string& hex, uint8_t out[SHA256_LEN]);

} /* namespace hostprobe */
