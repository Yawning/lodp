/*
 * random_test.cc: libottery wrapper tests
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

#include "schwanenlied/crypto/random.h"
#include "gtest/gtest.h"

namespace schwanenlied {
namespace crypto {

class RandomTest : public ::testing::Test {
  virtual void SetUp() {}
  virtual void TearDown() {}
};

// Test the libottery wrapper.  Note that this test will fail once in a blue
// moon because libottery happened to return a buffer full of 0s, though that's
// extremely unlikel (1 in 2^10 unlikely).
TEST_F(RandomTest, GetBytes) {
  const uint8_t cmp[1024] = { 0 };
  uint8_t buf[1024];
  Random rng;

  rng.get_bytes(buf, sizeof(buf));
  ASSERT_NE(0, ::std::memcmp(buf, cmp, sizeof(buf)));
}

} // namespace crypto
} // namespace schwanenlied
