/*
 * xchacha_test.cc: XChaCha/20 tests
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

#include "schwanenlied/crypto/xchacha.h"
#include "gtest/gtest.h"

namespace schwanenlied {
namespace crypto {

class XChaChaTest : public ::testing::Test {
 protected:
  virtual void SetUp() {}
  virtual void TearDown() {}
};

// Test the XChaCha/20 implementation
TEST_F(XChaChaTest, XChaCha) {
  // Run the library's built in tests.
  ASSERT_EQ(1, ::chacha_check_validity());

  // Since there aren't any test vectors for XChaCha, work under the assumption
  // that the library is valid at this point and just compare the raw output
  // with that from our class.

  const size_t buf_sz = 65535;
  ::std::string buf;
  buf.resize(buf_sz);
  for (size_t i = 0; i < buf_sz; i++) {
    buf[i] = static_cast<unsigned char>(i);
  }

  chacha_key_t key;
  for (size_t i = 0; i < sizeof(key.b); i++) {
    key.b[i] = static_cast<uint8_t>(i);
  }
  chacha_iv24_t iv;
  for (size_t i = 0; i < sizeof(iv.b); i++) {
    iv.b[i] = static_cast<uint8_t>(i);
  }

  // Call the raw implementation
  uint8_t cmp[buf_sz];
  ::xchacha(&key, &iv, reinterpret_cast<const uint8_t*>(buf.data()), cmp,
            buf_sz, XChaCha::kRounds);

  // Ensure the raw implementation actually changes data
  ASSERT_NE(0, ::std::memcmp(cmp, buf.data(), buf_sz));

  // Call the class
  uint8_t out[buf_sz];
  XChaCha x(key.b, sizeof(key.b));
  x.encrypt(iv.b, buf, out, buf_sz);

  // Compare
  ASSERT_EQ(0, ::std::memcmp(out, cmp, buf_sz));

  // Decrypt
  x.encrypt(iv.b, out, out, buf_sz);
  ASSERT_EQ(0, ::std::memcmp(out, buf.data(), buf_sz));
}

} // namespace crypto
} // namespace schwanenlied
