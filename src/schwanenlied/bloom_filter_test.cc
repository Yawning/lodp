/*
 * bloom_filter_test.cc: Bloom Filter tests
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

#include <string>

#include "schwanenlied/bloom_filter.h"
#include "schwanenlied/crypto/random.h"
#include "gtest/gtest.h"

namespace schwanenlied {

class BloomFilterTest : public ::testing::Test {
 protected:
  virtual void SetUp() {};
  virtual void TearDown() {};
};

TEST_F(BloomFilterTest, SmokeTest) {
  crypto::Random rng;
  BloomFilter bf(rng, 10, 0.01); // 106 entries (* 2)
  uint32_t buf[212];

  ASSERT_EQ(106, bf.nr_entries_max());

  // Make some test data
  for (size_t i = 0; i < 212; i++) {
    buf[i] = rng.get_uint32();
  }

  // Test the first entry.
  bool ret = bf.test_and_set(&buf[0], sizeof(uint32_t));
  ASSERT_FALSE(ret);
  ret = bf.test(&buf[0], sizeof(uint32_t));
  ASSERT_TRUE(ret);

  // Fully saturate Active 1
  for (size_t i = 1; i < 106; i++) {
    bf.test_and_set(&buf[i], sizeof(uint32_t));
  }

  // Test Active 1 being saturated
  for (size_t i = 0; i < 106; i++) {
    ret = bf.test(&buf[i], sizeof(uint32_t));
    ASSERT_TRUE(ret);
  }

  // Fill Active 1 again
  for (size_t i = 106; i < 212; i++) {
    bf.test_and_set(&buf[i], sizeof(uint32_t));
  }

  // Test Active 1 with the new data set
  for (size_t i = 106; i < 212; i++) {
    ret = bf.test(&buf[i], sizeof(uint32_t));
    ASSERT_TRUE(ret);
  }

  // Test Active 2 with the old data set, the moment we do a lookup that hits,
  // Active2 gets flushed, so only check 1. :(
  ret = bf.test(&buf[0], sizeof(uint32_t));
  ASSERT_TRUE(ret);
}

} // namespace schwanenlied
