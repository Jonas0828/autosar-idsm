#pragma once
/*
 * md5.h — minimal self-contained MD5 (RFC 1321) for JA3 fingerprinting.
 * Avoids an external crypto dependency on embedded targets.
 */
#include <cstddef>
#include <cstdint>
#include <string>

namespace ethprobe {

class Md5 {
public:
    Md5();
    void update(const uint8_t* data, size_t len);
    void update(const std::string& s);
    /* 16-byte digest */
    void final(uint8_t out[16]);
    /* lowercase hex of the digest (32 chars) */
    std::string final_hex();

private:
    uint32_t state_[4];
    uint64_t bits_ = 0;
    uint8_t  buf_[64];
    size_t   buf_len_ = 0;
};

} /* namespace ethprobe */
