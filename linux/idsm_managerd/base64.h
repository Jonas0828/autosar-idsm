/*
 * base64.h -- 最小 Base64 编解码(标准字母表, 无换行)。
 * canonical 规则签名串与 Android 侧 Base64.NO_WRAP 逐字节一致。
 */
#pragma once

#include <cstdint>
#include <string>

namespace idsm {

inline std::string base64Encode(const uint8_t* data, size_t len) {
    static const char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        const uint32_t a = data[i];
        const uint32_t b = i + 1 < len ? data[i + 1] : 0;
        const uint32_t c = i + 2 < len ? data[i + 2] : 0;
        const uint32_t n = (a << 16) | (b << 8) | c;
        out += kAlphabet[(n >> 18) & 63];
        out += kAlphabet[(n >> 12) & 63];
        out += (i + 1 < len) ? kAlphabet[(n >> 6) & 63] : '=';
        out += (i + 2 < len) ? kAlphabet[n & 63] : '=';
    }
    return out;
}

inline std::string base64Encode(const std::string& s) {
    return base64Encode(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

inline bool base64Decode(const std::string& in, std::string& out) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    out.clear();
    if (in.size() % 4 != 0) return false;
    for (size_t i = 0; i < in.size(); i += 4) {
        const int a = val(in[i]);
        const int b = val(in[i + 1]);
        const bool pad2 = in[i + 2] == '=';
        const bool pad1 = in[i + 3] == '=';
        const int c = pad2 ? 0 : val(in[i + 2]);
        const int d = pad1 ? 0 : val(in[i + 3]);
        if (a < 0 || b < 0 || c < 0 || d < 0) return false;
        const uint32_t n = (static_cast<uint32_t>(a) << 18) |
                           (static_cast<uint32_t>(b) << 12) |
                           (static_cast<uint32_t>(c) << 6) |
                           static_cast<uint32_t>(d);
        out += static_cast<char>((n >> 16) & 0xFF);
        if (!pad2) out += static_cast<char>((n >> 8) & 0xFF);
        if (!pad1) out += static_cast<char>(n & 0xFF);
    }
    return true;
}

}  /* namespace idsm */
