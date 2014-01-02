/*
 * curve25519_test.cc: Curve25519 ECDH tests
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

#include <array>

#include "schwanenlied/crypto/curve25519.h"
#include "gtest/gtest.h"

namespace schwanenlied {
namespace crypto {

class Curve25519Test : public ::testing::Test {
 protected:
  virtual void SetUp() {}
  virtual void TearDown() {}
};

// Test routines based on agl's curve25519_donna tests
TEST_F(Curve25519Test, DonnaTests) {
  // agl uses { 3 } and { 5 } for the initial private keys, but
  ::std::array<uint8_t, Curve25519::PrivateKey::kKeyLength> raw_e1 = { 3 };
  ::std::array<uint8_t, Curve25519::PrivateKey::kKeyLength> raw_e2 = { 5 };

  for (auto i = 0; i < 1000; i++) {
    Curve25519::PrivateKey e1(raw_e1.data(), raw_e1.size(), false);
    Curve25519::PublicKey e1k(e1);

    Curve25519::PrivateKey e2(raw_e2.data(), raw_e2.size(), false);
    Curve25519::PublicKey e2k(e2);

    Curve25519::SharedSecret e2e1k(e1k, e2);
    Curve25519::SharedSecret e1e2k(e2k, e1);

    ASSERT_EQ(0, memequals(e2e1k.data(), e1e2k.data(),
                          Curve25519::SharedSecret::kLength));

    const uint8_t* raw_e2k = e2k.data();
    for (size_t j = 0; j < e2k.length(); j++)
      raw_e1[j] ^= raw_e2k[j];
    const uint8_t* raw_e1k = e1k.data();
    for (size_t j = 0; j < e1k.length(); j++)
      raw_e2[j] ^= raw_e1k[j];
    // agl messes with the basepoint here as well, but my C++ implementation
    // hard codes that.
  }
}

} // namespace crypto
} // namespace schwanenlied
