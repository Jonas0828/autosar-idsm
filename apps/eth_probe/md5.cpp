#include "md5.h"

#include <cstring>

namespace ethprobe {

namespace {

inline uint32_t rotl(uint32_t x, uint32_t n) { return (x << n) | (x >> (32 - n)); }

/* per-round shift amounts and sine constants */
constexpr uint8_t  S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};
constexpr uint32_t K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

void transform(uint32_t st[4], const uint8_t block[64]) {
    uint32_t m[16];
    for (int i = 0; i < 16; ++i)
        m[i] = static_cast<uint32_t>(block[i * 4]) |
               (static_cast<uint32_t>(block[i * 4 + 1]) << 8) |
               (static_cast<uint32_t>(block[i * 4 + 2]) << 16) |
               (static_cast<uint32_t>(block[i * 4 + 3]) << 24);

    uint32_t a = st[0], b = st[1], c = st[2], d = st[3];
    for (int i = 0; i < 64; ++i) {
        uint32_t f;
        int g;
        if (i < 16)      { f = (b & c) | (~b & d);          g = i; }
        else if (i < 32) { f = (d & b) | (~d & c);          g = (5 * i + 1) % 16; }
        else if (i < 48) { f = b ^ c ^ d;                   g = (3 * i + 5) % 16; }
        else             { f = c ^ (b | ~d);                g = (7 * i) % 16; }
        const uint32_t tmp = d;
        d = c;
        c = b;
        b = b + rotl(a + f + K[i] + m[g], S[i]);
        a = tmp;
    }
    st[0] += a;
    st[1] += b;
    st[2] += c;
    st[3] += d;
}

} /* namespace */

Md5::Md5() {
    state_[0] = 0x67452301;
    state_[1] = 0xefcdab89;
    state_[2] = 0x98badcfe;
    state_[3] = 0x10325476;
}

void Md5::update(const uint8_t* data, size_t len) {
    bits_ += static_cast<uint64_t>(len) * 8;
    while (len > 0) {
        const size_t take = (64 - buf_len_ < len) ? 64 - buf_len_ : len;
        std::memcpy(buf_ + buf_len_, data, take);
        buf_len_ += take;
        data += take;
        len  -= take;
        if (buf_len_ == 64) {
            transform(state_, buf_);
            buf_len_ = 0;
        }
    }
}

void Md5::update(const std::string& s) {
    update(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

void Md5::final(uint8_t out[16]) {
    /* padding: 0x80 then zeros until 56 mod 64, then 8-byte little-endian bit count */
    const uint64_t total_bits = bits_;
    uint8_t pad = 0x80;
    update(&pad, 1);
    uint8_t zero = 0;
    while (buf_len_ != 56) update(&zero, 1);
    uint8_t len_le[8];
    for (int i = 0; i < 8; ++i) len_le[i] = static_cast<uint8_t>(total_bits >> (8 * i));
    /* update() would re-count bits; write through the buffer directly */
    std::memcpy(buf_ + buf_len_, len_le, 8);
    transform(state_, buf_);
    buf_len_ = 0;
    for (int i = 0; i < 4; ++i) {
        out[i * 4]     = static_cast<uint8_t>(state_[i]);
        out[i * 4 + 1] = static_cast<uint8_t>(state_[i] >> 8);
        out[i * 4 + 2] = static_cast<uint8_t>(state_[i] >> 16);
        out[i * 4 + 3] = static_cast<uint8_t>(state_[i] >> 24);
    }
}

std::string Md5::final_hex() {
    uint8_t d[16];
    final(d);
    static const char* hex = "0123456789abcdef";
    std::string s;
    s.reserve(32);
    for (uint8_t b : d) {
        s.push_back(hex[b >> 4]);
        s.push_back(hex[b & 0xF]);
    }
    return s;
}

} /* namespace ethprobe */
