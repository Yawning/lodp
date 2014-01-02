/*
 * blake2s_test.cc: BLAKE2s tests
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

#include "schwanenlied/crypto/blake2s.h"
#include "ext/blake2-kat.h"
#include "gtest/gtest.h"

namespace schwanenlied {
namespace crypto {

class Blake2sTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    for (size_t i = 0; i < test_key_.size(); ++i)
      test_key_[i] = static_cast<uint8_t>(i);

    for (size_t i = 0; i < KAT_LENGTH; ++i)
      test_data_[i] = static_cast<uint8_t>(i);
  }
  virtual void TearDown() {}

  ::std::array<uint8_t, Blake2s::kKeyLength> test_key_;
  ::std::array<uint8_t, KAT_LENGTH> test_data_;
};

TEST_F(Blake2sTest, TestVectorsOneShot) {
  Blake2s h(test_key_.data(), test_key_.size());

  for (auto i = 0; i < KAT_LENGTH; ++i) {
    uint8_t digest[Blake2s::kDigestLength];

    bool ret = h.digest(test_data_.data(), i, digest, sizeof(digest));
    ASSERT_TRUE(ret);
    ASSERT_EQ(0, ::std::memcmp(digest, blake2s_keyed_kat[i], sizeof(digest)));
  }
}

TEST_F(Blake2sTest, TestVectorsStreaming) {
  Blake2s h(test_key_.data(), test_key_.size());

  uint8_t* ptr = test_data_.data();
  bool ret = h.init(Blake2s::kDigestLength);
  ASSERT_TRUE(ret);
  for (auto i = KAT_LENGTH - 1; i > 0; /* Derp */) {
    size_t j = (i > 32) ? 32 : i;
    ret = h.update(ptr, j);
    ASSERT_TRUE(ret);
    ptr += j;
    i -= j;
  }

  ::std::array<uint8_t, Blake2s::kDigestLength> digest;
  ret = h.final(digest.data(), digest.size());
  ASSERT_TRUE(ret);
  ASSERT_EQ(0, ::std::memcmp(digest.data(), blake2s_keyed_kat[255],
                             digest.size()));
}

TEST_F(Blake2sTest, RandomKey) {
  Random rng;
  Blake2s h(nullptr, 0);
  ::std::array<uint8_t, Blake2s::kDigestLength> digest;
  bool ret = h.digest(test_data_.data(), test_data_.size(), digest.data(),
                      digest.size());
  ASSERT_TRUE(ret);

  Blake2s h_rand(rng);
  ::std::array<uint8_t, Blake2s::kDigestLength> digest_rand;
  ret = h_rand.digest(test_data_.data(), test_data_.size(), digest_rand.data(),
                      digest_rand.size());
  ASSERT_TRUE(ret);
  ASSERT_NE(0, ::std::memcmp(digest.data(), digest_rand.data(),
                             digest.size()));
}

} // namespace crypto
} // namespace schwanenlied
