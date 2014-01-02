/*
 * hkdf_blake2s_test.cc: HKDF-BLAKE2s tests
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

#include "schwanenlied/crypto/hkdf_blake2s.h"
#include "gtest/gtest.h"

namespace schwanenlied {
namespace crypto {

class HkdfBlake2sTest : public ::testing::Test {
 protected:
  virtual void SetUp() {}
  virtual void TearDown() {}
};

TEST_F(HkdfBlake2sTest, ExtractSmokeTest) {
  const uint8_t salt[] = { 'T', 'e', 's', 't', 'S', 'a', 'l', 't' };
  SecureBuffer ikm(Blake2s::kDigestLength, 0);

  SecureBuffer prk = HkdfBlake2s::extract(salt, sizeof(salt), ikm);
  ASSERT_NE(0, ::memcmp(ikm.data(), prk.data(), ikm.length()));
}

TEST_F(HkdfBlake2sTest, ExpandSmokeTest) {
  const uint8_t salt[] = { 'T', 'e', 's', 't', 'S', 'a', 'l', 't' };
  const uint8_t info[] = { 'T', 'e', 's', 't', 'I', 'n', 'f', 'o' };
  SecureBuffer ikm(Blake2s::kDigestLength, 0);

  SecureBuffer prk = HkdfBlake2s::extract(salt, sizeof(salt), ikm);
  SecureBuffer okm = HkdfBlake2s::expand(prk, info, sizeof(info), 64);
  ASSERT_EQ(64, okm.length());
}

} // namespace schwanenlied
} // namespace crypto
