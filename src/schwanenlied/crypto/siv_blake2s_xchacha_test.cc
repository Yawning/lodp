/*
 * siv_blake2s_xchacha_test.cc: SIV-BLAKE2s-XCHACHA/20 tests
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
#include <cstring>

#include "schwanenlied/crypto/siv_blake2s_xchacha.h"
#include "gtest/gtest.h"

namespace schwanenlied {
namespace crypto {

class SIVBlake2sXChaChaTest : public ::testing::Test {
  protected:
   virtual void SetUp() {
     for (size_t i = 0; i < test_key_.size(); ++i)
       test_key_[i] = static_cast<uint8_t>(i);

     for (size_t i = 0; i < test_data_.size(); ++i)
       test_data_[i] = static_cast<uint8_t>(i);
   }

   virtual void TearDown() {}

   ::std::array<uint8_t, SIVBlake2sXChaCha::kKeyLength> test_key_;
   ::std::array<uint8_t, 65536> test_data_;
};

TEST_F(SIVBlake2sXChaChaTest, ValidData) {
  Random rng;
  SIVBlake2sXChaCha siv(rng, test_key_.data(), test_key_.size());

  ::std::string in(reinterpret_cast<char*>(test_data_.data()),
                   test_data_.size());
  ::std::string out;

  // Encrypt
  siv.encrypt(in, out);
  ASSERT_EQ(in.length() + SIVBlake2sXChaCha::kSIVLength +
            SIVBlake2sXChaCha::kNonceLength, out.length());
  ASSERT_NE(0, ::std::memcmp(in.data(), out.data() +
                             SIVBlake2sXChaCha::kSIVLength +
                             SIVBlake2sXChaCha::kNonceLength, in.length()));

  // Decrypt
  ::std::string in_cmp;
  bool ret = siv.decrypt(reinterpret_cast<const uint8_t*>(out.data()),
                         out.length(), in_cmp);
  ASSERT_EQ(ret, ret); // Authenticated
  ASSERT_EQ(in.length(), in_cmp.length());

  // Compare
  ASSERT_EQ(0, ::std::memcmp(in.data(), in_cmp.data(), in.length()));
}

TEST_F(SIVBlake2sXChaChaTest, InvalidData) {
  Random rng;
  SIVBlake2sXChaCha siv(rng, test_key_.data(), test_key_.size());

  ::std::string in(reinterpret_cast<char*>(test_data_.data()),
                   test_data_.size());
  ::std::string out;

  // Encrypt
  siv.encrypt(in, out);
  ASSERT_EQ(in.length() + SIVBlake2sXChaCha::kSIVLength +
            SIVBlake2sXChaCha::kNonceLength, out.length());
  ASSERT_NE(0, ::std::memcmp(in.data(), out.data() +
                             SIVBlake2sXChaCha::kSIVLength +
                             SIVBlake2sXChaCha::kNonceLength, in.length()));

  // Mess with the tag.
  for (size_t i = 0; i < SIVBlake2sXChaCha::kSIVLength; i++)
    out[i] = '\0';

  // Decrypt
  ::std::string in_cmp;
  bool ret = siv.decrypt(reinterpret_cast<const uint8_t*>(out.data()),
                         out.length(), in_cmp);
  ASSERT_FALSE(ret);
}

} // namespace crypto
} // namespace schwanenlied
