/*
 * Copyright (c) 2014, Yawning Angel <yawning at schwanenlied dot me>
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

#include "schwanenlied/bip_buffer.h"
#include "gtest/gtest.h"

namespace schwanenlied {

class BipBufferTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
     for (size_t i = 0; i < test_data_.size(); i++)
       test_data_[i] = static_cast<uint8_t>(i);
  };

  virtual void TearDown() {};

  static const size_t kTestBufferSz = 1024;
  ::std::array<uint8_t, kTestBufferSz> test_data_;
};

// Test the basic functionality that doesn't involve calls to linearize()
TEST_F(BipBufferTest, BasicTests) {
  BipBuffer buf(kTestBufferSz);

  ASSERT_EQ(0, buf.size());
  ASSERT_TRUE(kTestBufferSz == buf.max_size());
  ASSERT_EQ(0, buf.reserve_size());
  ASSERT_TRUE(buf.empty());

  // Test peek()ing an empty buffer
  size_t sz = kTestBufferSz;
  ASSERT_EQ(nullptr, buf.peek(sz));
  ASSERT_EQ(0, sz);

  // Reserve the full buffer
  uint8_t* foo = buf.reserve(kTestBufferSz, sz);
  ASSERT_NE(nullptr, foo);
  ASSERT_TRUE(kTestBufferSz == sz);
  ASSERT_TRUE(kTestBufferSz == buf.reserve_size());

  // Copy data into the buffer and commit
  ::std::memcpy(foo, test_data_.data(), sz);
  buf.commit(sz);

  // Validate that the data was appended
  ASSERT_EQ(sz, buf.size());
  ASSERT_EQ(0, buf.reserve_size());
  ASSERT_FALSE(buf.empty());
  const uint8_t *bar = buf.peek(sz);
  ASSERT_TRUE(kTestBufferSz == sz);
  ASSERT_EQ(0, ::std::memcmp(test_data_.data(), bar, sz));

  // Ensure that it is impossible to reserve more space (buffer full)
  ASSERT_EQ(nullptr, buf.reserve(1, sz));
  ASSERT_EQ(0, sz);

  // Consume some data out of the buffer
  const size_t consume_sz = 256;
  buf.pop_front(consume_sz);
  ASSERT_TRUE(kTestBufferSz - consume_sz == buf.size());

  // Append more data to the buffer (this will create a B region)
  const ::std::array<uint8_t, consume_sz> b_cmp = { 0 };
  foo = buf.reserve(consume_sz, sz);
  ASSERT_NE(nullptr, foo);
  ASSERT_TRUE(consume_sz == sz);
  ASSERT_TRUE(consume_sz == buf.reserve_size());
  ::std::memcpy(foo, b_cmp.data(), sz);
  buf.commit(sz);
  ASSERT_TRUE(kTestBufferSz == buf.size());

  // Peeking should give us the A region
  bar = buf.peek(sz);
  ASSERT_TRUE(kTestBufferSz - consume_sz == sz);
  ASSERT_EQ(0, ::std::memcmp(test_data_.data() + consume_sz, bar, sz));

  // copy() the entire buffer
  ::std::array<uint8_t, kTestBufferSz> cmp;
  buf.copy(cmp.data(), kTestBufferSz);
  ASSERT_EQ(0, ::std::memcmp(test_data_.data(), cmp.data(), kTestBufferSz -
                             consume_sz));
  ASSERT_EQ(0, ::std::memcmp(b_cmp.data(), cmp.data() + (kTestBufferSz -
                                                         consume_sz),
                             consume_sz));

  // copy(), offset, source only in A
  buf.copy(cmp.data(), consume_sz, consume_sz);
  ASSERT_EQ(0, ::std::memcmp(test_data_.data() + consume_sz, cmp.data(),
                             consume_sz));

  // copy(), offset, source only in B
  buf.copy(cmp.data(), consume_sz - 1, kTestBufferSz - consume_sz + 1);
  ASSERT_EQ(0, ::std::memcmp(b_cmp.data() + 1, cmp.data(), consume_sz - 1));

  // copy(), offset, stradding A + B
  buf.copy(cmp.data(), consume_sz, kTestBufferSz - (consume_sz + 128));
  ASSERT_EQ(0, ::std::memcmp(test_data_.data() + (kTestBufferSz - consume_sz -
                                                  128), cmp.data(), 128));
  ASSERT_EQ(0, ::std::memcmp(b_cmp.data(), cmp.data() + 128, consume_sz - 128));

  // Pop off the A region, and ensure that the B region is there
  buf.pop_front(sz);
  bar = buf.peek(sz);
  ASSERT_EQ(consume_sz, sz);
  ASSERT_EQ(consume_sz, buf.size());
  ASSERT_EQ(0, ::std::memcmp(b_cmp.data(), bar, sz));

  // Pop off what is now the A region, check to see if the buffer is empty
  buf.pop_front(sz);
  ASSERT_EQ(0, buf.size());
  ASSERT_TRUE(buf.empty());
}

// Test the routines that call linearize
TEST_F(BipBufferTest, LinearizeTest) {
  BipBuffer buf(kTestBufferSz);

  // Fill the first 1000 bytes of the buffer (24 bytes free after A)
  size_t sz = buf.push_back(test_data_.data(), 1000);
  ASSERT_EQ(1000, sz);
  ASSERT_EQ(1000, buf.size());

  // Pop off data from the head of the buffer
  buf.pop_front(64);

  // Add data that requires both the space after A and a new B region
  const ::std::array<uint8_t, 64 + 24> b_cmp = { 0 };
  sz = buf.push_back(b_cmp.data(), b_cmp.size());
  ASSERT_EQ(sz, b_cmp.size());

  // Validate the contents
  const uint8_t* ptr = buf.peek(sz);
  ASSERT_EQ(sz, buf.size());
  ASSERT_EQ(0, ::std::memcmp(test_data_.data() + 64, ptr, 1000 - 64));
  ASSERT_EQ(0, ::std::memcmp(b_cmp.data(), ptr + (1000 - 64), b_cmp.size()));

  buf.clear();

  // Fill again
  sz = buf.push_back(test_data_.data(), 1000);
  buf.pop_front(64);

  // Add data as a B region
  sz = buf.push_back(b_cmp.data(), 64);
  ASSERT_EQ(64, sz);
  ptr = buf.peek(sz);
  ASSERT_EQ(1000 - 64, sz);

  // Ensure that the buffer looks like | B | A | Blank space
  ASSERT_EQ(24, buf.max_size() - buf.size());
  ASSERT_EQ(nullptr, buf.reserve(24, sz));

  // Through the magic of transparently calling linearize, defragment the buffer
  // and add data
  sz = buf.push_back(test_data_.data(), 24);
  ASSERT_EQ(24, sz);
  ASSERT_EQ(0, buf.max_size() - buf.size());

  // The buffer is linear at this point, validate
  ptr = buf.peek(sz);
  ASSERT_EQ(sz, buf.size());
  ASSERT_EQ(0, ::std::memcmp(test_data_.data() + 64, ptr, 1000 - 64));
  ASSERT_EQ(0, ::std::memcmp(b_cmp.data(), ptr + 1000 - 64, 64));
  ASSERT_EQ(0, ::std::memcmp(test_data_.data(), ptr + 1000, 24));
}

} // namespace schwanenlied
