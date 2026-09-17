/*
 * sha256.cpp -- compact SHA-256 implementation (FIPS 180-4).
 *
 * Straightforward block-based implementation; only what host_probe
 * needs: one-shot buffer/file hashing against the integrity baseline.
 */
#include "sha256.h"

#include <array>
#include <cstring>
#include <fstream>

namespace hostprobe {

namespace {

constexpr std::array<uint32_t, 64> K = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

inline uint32_t rotr(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

struct Ctx {
    uint32_t h[8] = {0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
                     0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};
    uint8_t  buf[64]{};
    size_t   buf_len   = 0;
    uint64_t total_len = 0;   /* message bytes, for the length field */
};

void compress(uint32_t h[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (size_t i = 0; i < 16; ++i) {
        w[i] = (static_cast<uint32_t>(block[4 * i]) << 24) |
               (static_cast<uint32_t>(block[4 * i + 1]) << 16) |
               (static_cast<uint32_t>(block[4 * i + 2]) << 8) |
               static_cast<uint32_t>(block[4 * i + 3]);
    }
    for (size_t i = 16; i < 64; ++i) {
        const uint32_t s0 =
            rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 =
            rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

    for (size_t i = 0; i < 64; ++i) {
        const uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const uint32_t ch = (e & f) ^ (~e & g);
        const uint32_t t1 = hh + s1 + ch + K[i] + w[i];
        const uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t t2 = s0 + mj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void ctx_update(Ctx& c, const uint8_t* data, size_t len) {
    c.total_len += len;
    while (len > 0) {
        const size_t space = 64 - c.buf_len;
        const size_t take  = len < space ? len : space;
        std::memcpy(c.buf + c.buf_len, data, take);
        c.buf_len += take;
        data += take;
        len  -= take;
        if (c.buf_len == 64) {
            compress(c.h, c.buf);
            c.buf_len = 0;
        }
    }
}

void ctx_final(Ctx& c, uint8_t out[SHA256_LEN]) {
    const uint64_t bit_len = c.total_len * 8;
    static const uint8_t k_pad = 0x80, k_zero = 0x00;

    ctx_update(c, &k_pad, 1);
    while (c.buf_len != 56) ctx_update(c, &k_zero, 1);

    uint8_t len_be[8];
    for (int i = 0; i < 8; ++i)
        len_be[i] = static_cast<uint8_t>(bit_len >> (56 - 8 * i));
    ctx_update(c, len_be, 8);  /* total_len grows, bit_len was saved */

    for (int i = 0; i < 8; ++i) {
        out[4 * i]     = static_cast<uint8_t>(c.h[i] >> 24);
        out[4 * i + 1] = static_cast<uint8_t>(c.h[i] >> 16);
        out[4 * i + 2] = static_cast<uint8_t>(c.h[i] >> 8);
        out[4 * i + 3] = static_cast<uint8_t>(c.h[i]);
    }
}

} /* namespace */

void sha256(const uint8_t* data, size_t len, uint8_t out[SHA256_LEN]) {
    Ctx c;
    ctx_update(c, data, len);
    ctx_final(c, out);
}

bool sha256_file(const std::string& path, uint8_t out[SHA256_LEN]) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;

    Ctx c;
    std::array<char, 65536> buf{};
    while (in) {
        in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        const std::streamsize n = in.gcount();
        if (n > 0)
            ctx_update(c, reinterpret_cast<const uint8_t*>(buf.data()),
                       static_cast<size_t>(n));
    }
    if (in.bad()) return false;
    ctx_final(c, out);
    return true;
}

std::string sha256_hex(const uint8_t digest[SHA256_LEN]) {
    static const char k_hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(SHA256_LEN * 2);
    for (size_t i = 0; i < SHA256_LEN; ++i) {
        out.push_back(k_hex[digest[i] >> 4]);
        out.push_back(k_hex[digest[i] & 0x0f]);
    }
    return out;
}

bool sha256_from_hex(const std::string& hex, uint8_t out[SHA256_LEN]) {
    if (hex.size() != SHA256_LEN * 2) return false;
    for (size_t i = 0; i < SHA256_LEN; ++i) {
        const auto nib = [](char ch) -> int {
            if (ch >= '0' && ch <= '9') return ch - '0';
            if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
            if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
            return -1;
        };
        const int hi = nib(hex[2 * i]);
        const int lo = nib(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

} /* namespace hostprobe */
