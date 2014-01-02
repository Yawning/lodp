/*
 * ip_address_test.cc: IP address/port wrapper tests
 *
 * Copyright (c) 2013, Yawning Angel <yawning at schwanenlied dot me>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <cstring>
#include <array>

#include <arpa/inet.h>

#include "schwanenlied/ip_address.h"
#include "schwanenlied/crypto/siphash.h"
#include "gtest/gtest.h"

namespace schwanenlied {

class IPAddressTest : public ::testing::Test {
 protected:
  virtual void SetUp() {};
  virtual void TearDown() {};

  ::std::array<uint8_t, crypto::SipHash::kKeyLength> key_;
};

TEST_F(IPAddressTest, IPv4Test) {
  crypto::SipHash hash(key_.data(), key_.size());
  struct sockaddr_in v4addr;

  ::memset(&v4addr, 0, sizeof(v4addr));

  // Set up an address for comparison
  v4addr.sin_family = AF_INET;
  v4addr.sin_port = htons(6969);
  inet_pton(AF_INET, "127.0.0.1", &v4addr.sin_addr);

  IPAddress addr(hash, reinterpret_cast<struct sockaddr*>(&v4addr),
                 sizeof(v4addr), false);
  const struct sockaddr_in *cmp_addr = reinterpret_cast<const struct
      sockaddr_in*>(addr.sockaddr());

  // Compare with what was passed in.
  ASSERT_EQ(0x7f000001, ntohl(cmp_addr->sin_addr.s_addr));
  ASSERT_EQ(6969, ntohs(cmp_addr->sin_port));
  ASSERT_EQ(sizeof(v4addr), addr.length());
  ASSERT_EQ(4, addr.version());

  // Test the hash routine
  const uint8_t hash_buf[6] = { 0x7f, 0x00, 0x00, 0x01, 0x1b, 0x39 };
  uint64_t digest = hash.digest(hash_buf, sizeof(hash_buf));
  ASSERT_EQ(digest, addr.hash());

  // Test the unsafe to_string() variant
  ::std::string cmp_str("127.0.0.1:6969");
  ASSERT_EQ(cmp_str, addr.to_string());

  // Test the safe to_string() variant
  IPAddress s_addr(hash, reinterpret_cast<struct sockaddr*>(&v4addr),
                   sizeof(v4addr), true);
  ::std::string s_str("[scrubbed]:6969");
  ASSERT_EQ(s_str, s_addr.to_string());

  ASSERT_TRUE(addr == s_addr);
  ASSERT_FALSE(addr != s_addr);
  ASSERT_FALSE(addr < s_addr);

  IPAddress addr_copy(addr);
  ASSERT_TRUE(addr == addr_copy);
}

TEST_F(IPAddressTest, IPv6Test) {
  crypto::SipHash hash(key_.data(), key_.size());
  struct sockaddr_in6 v6addr;
  ::std::memset(&v6addr, 0, sizeof(v6addr));

  // Set up an address for comparison
  v6addr.sin6_family = AF_INET6;
  v6addr.sin6_port = htons(6969);
  inet_pton(AF_INET6, "::1", &v6addr.sin6_addr);

  IPAddress addr(hash, reinterpret_cast<struct sockaddr*>(&v6addr),
                 sizeof(v6addr), false);
  const struct sockaddr_in6 *cmp_addr = reinterpret_cast<const struct
      sockaddr_in6*>(addr.sockaddr());
  // Compare with what was passed in.
  const uint8_t raw_addr[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01
  };
  ASSERT_EQ(0, ::std::memcmp(raw_addr, &cmp_addr->sin6_addr, 16));
  ASSERT_EQ(6969, ntohs(cmp_addr->sin6_port));
  ASSERT_EQ(sizeof(v6addr), addr.length());
  ASSERT_EQ(6, addr.version());

  // Test the hash routine
  const uint8_t hash_buf[18] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x1b, 0x39
  };
  uint64_t digest = hash.digest(hash_buf, sizeof(hash_buf));
  ASSERT_EQ(digest, addr.hash());

  // Test the unsafe to_string() variant
  ::std::string cmp_str("[::1]:6969");
  ASSERT_EQ(cmp_str, addr.to_string());

  // Test the safe to_string() variant
  IPAddress s_addr(hash, reinterpret_cast<struct sockaddr*>(&v6addr),
                   sizeof(v6addr), true);
  ::std::string s_str("[scrubbed]:6969");
  ASSERT_EQ(s_str, s_addr.to_string());

  ASSERT_TRUE(addr == s_addr);
  ASSERT_FALSE(addr != s_addr);
  ASSERT_FALSE(addr < s_addr);
}

} // namespace schwanenlied
