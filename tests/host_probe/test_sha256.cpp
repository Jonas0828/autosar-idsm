/*
 * test_sha256.cpp -- SHA-256 known-answer tests + file roundtrip.
 */
#include "sha256.h"

#include <gtest/gtest.h>

#include <cstdio>
#include <cstring>
#include <fstream>

using namespace hostprobe;

namespace {

std::string hex_of(const std::string& s) {
    uint8_t d[SHA256_LEN];
    sha256(reinterpret_cast<const uint8_t*>(s.data()), s.size(), d);
    return sha256_hex(d);
}

} /* namespace */

TEST(Sha256Test, EmptyString) {
    EXPECT_EQ(hex_of(""),
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(Sha256Test, Abc) {
    EXPECT_EQ(hex_of("abc"),
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(Sha256Test, TwoBlocks) {
    EXPECT_EQ(hex_of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST(Sha256Test, ExactlyOneBlockMinusOne) {
    /* 55 bytes: padding must spill into a second block */
    const std::string s(55, 'a');
    EXPECT_EQ(hex_of(s),
              "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");
}

TEST(Sha256Test, FileRoundtrip) {
    const char* path = "/tmp/host_probe_test_sha.txt";
    {
        std::ofstream out(path, std::ios::binary);
        out << "hello integrity";
    }
    uint8_t d[SHA256_LEN];
    ASSERT_TRUE(sha256_file(path, d));
    std::remove(path);
    EXPECT_EQ(sha256_hex(d), hex_of("hello integrity"));
}

TEST(Sha256Test, FileMissing) {
    uint8_t d[SHA256_LEN];
    EXPECT_FALSE(sha256_file("/tmp/host_probe_no_such_file_zzz", d));
}

TEST(Sha256Test, FromHexRoundtrip) {
    const std::string h =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    uint8_t d[SHA256_LEN];
    ASSERT_TRUE(sha256_from_hex(h, d));
    EXPECT_EQ(sha256_hex(d), h);
    EXPECT_FALSE(sha256_from_hex("zz", d));
    EXPECT_FALSE(sha256_from_hex("abcd", d));
}
