/**
 * @file    bip_buffer.cc
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   Bip-partite Buffer (IMPLEMENTATION)
 */

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

#include "schwanenlied/common.h"
#include "schwanenlied/bip_buffer.h"

namespace schwanenlied {

BipBuffer::BipBuffer(const size_t sz) :
    buffer_(new uint8_t[sz]),
    buffer_size_(sz),
    a_offset_(0),
    a_size_(0),
    b_size_(0),
    reserve_offset_(0),
    reserve_size_(0) {
  ::std::memset(buffer_.get(), 0, sz);
}

BipBuffer::~BipBuffer() {
  // Nothing special to clean up
}

void BipBuffer::clear() {
  a_offset_ = 0;
  a_size_ = 0;
  b_size_ = 0;
  reserve_offset_ = 0;
  reserve_size_ = 0;
}

const uint8_t* BipBuffer::peek(size_t& sz) const {
  if (a_size_ == 0) {
    sz = 0;
    return nullptr;
  }

  sz = a_size_;
  return buffer_.get() + a_offset_;
}

const size_t BipBuffer::push_back(const uint8_t* buf,
                                  const size_t sz) {
  SL_ASSERT(buf != nullptr);

  if (sz == 0)
    return 0;

  /*
   * linearize() if:
   *  * The buffer theoretically has sufficient free space
   *    * B exists, but there is insufficient space after B
   *    * B does not exist, and neither a new B NOR the space after A is
   *      sufficient to hold the new data
   */
  if (max_size() - size() >= sz) {
    if ((b_size_ > 0 && a_offset_ - b_size_ < sz) ||
        (b_size_ == 0 && a_offset_ < sz && max_size() - (a_offset_ +
                                                         a_size_) < sz))
      linearize();
  }

  size_t to_copy = sz;
  while (to_copy > 0) {
    size_t avail = 0;
    uint8_t* dst = reserve(to_copy, avail);
    if (dst == nullptr)
      break;
    ::std::memcpy(dst, buf + (sz - to_copy), avail);
    commit(avail);
    to_copy -= avail;
  }

  return sz - to_copy;
}

void BipBuffer::pop_front(const size_t sz) {
  SL_ASSERT(sz <= size());

  if (sz == 0)
    return;
  else if (sz == size())
    clear();
  else if (sz < a_size_) {
    a_offset_ += sz;
    a_size_ -= sz;
  } else {
    a_offset_ = sz - a_size_;
    a_size_ = b_size_ - a_offset_;
    b_size_ = 0;
  }
}

const void BipBuffer::copy(uint8_t* buf,
                           const size_t sz,
                           const size_t offset) const {
  SL_ASSERT(offset + sz <= size());

  if (sz == 0)
    return;

  if (offset + sz <= a_size_) {
    ::std::memcpy(buf, buffer_.get() + a_offset_ + offset, sz);
  } else if (offset > a_size_) {
    SL_ASSERT(b_size_ >= sz + (offset - a_size_));
    ::std::memcpy(buf, buffer_.get() + (offset - a_size_), sz);
  } else {
    const size_t a_to_copy = a_size_ - offset;
    SL_ASSERT(b_size_ >= sz - a_to_copy);
    ::std::memcpy(buf, buffer_.get() + a_offset_ + offset, a_to_copy);
    ::std::memcpy(buf + a_to_copy, buffer_.get(), sz - a_to_copy);
  }
}

uint8_t* BipBuffer::reserve(const size_t sz,
                            size_t& reserved) {
  SL_ASSERT(reserve_offset_ == 0);
  SL_ASSERT(reserve_size_ == 0);

  reserved = 0;
  if (sz == 0)
    return nullptr;

  if (b_size_ > 0) {
    // Always append to B if B exists
    size_t avail = a_offset_ - b_size_;

    if (avail == 0)
      return nullptr;
    if (sz < avail)
      avail = sz;

    reserve_offset_ = b_size_;
    reserve_size_ = avail;
    reserved = avail;

    return buffer_.get() + reserve_offset_;
  } else {
    size_t avail = max_size() - (a_offset_ + a_size_);
    if (avail >= a_offset_) {
      // Reserve after A
      if (avail == 0)
        return nullptr;
      if (sz < avail)
        avail = sz;

      reserve_offset_ = a_offset_ + a_size_;
      reserve_size_ = avail;
      reserved = avail;

      return buffer_.get() + reserve_offset_;
    } else {
      // Reserve as a new B
      avail = a_offset_;
      if (a_offset_ == 0)
        return nullptr;
      if (sz < avail)
        avail = sz;

      reserve_offset_ = 0;
      reserve_size_ = avail;
      reserved = avail;

      return buffer_.get();
    }
  }
}

void BipBuffer::commit(const size_t sz) {
  SL_ASSERT(reserve_size_ > 0);
  SL_ASSERT(sz <= reserve_size_);

  if (sz != 0) {
    if (empty()) {
      a_offset_ = reserve_offset_;
      a_size_ = sz;
    } else if (reserve_offset_ == a_offset_ + a_size_)
      a_size_ += sz;
    else
      b_size_ += sz;
  }

  reserve_offset_ = 0;
  reserve_size_ = 0;
}

void BipBuffer::linearize() {
  SL_ASSERT(reserve_offset_ == 0);
  SL_ASSERT(reserve_size_ == 0);

  if (empty())
    return;

  if (b_size_ == 0) {
    ::std::memmove(buffer_.get(), buffer_.get() + a_offset_, a_size_);
  } else {
    size_t tmp_sz = ::std::min(a_size_, b_size_);
    ::std::unique_ptr<uint8_t[]> tmp(new uint8_t[tmp_sz]);
    if (a_size_ <= b_size_) {
      ::std::memcpy(tmp.get(), buffer_.get() + a_offset_, a_size_);
      ::std::memmove(buffer_.get() + a_size_, buffer_.get(), b_size_);
      ::std::memcpy(buffer_.get(), tmp.get(), a_size_);
    } else {
      ::std::memcpy(tmp.get(), buffer_.get(), b_size_);
      ::std::memmove(buffer_.get(), buffer_.get() + a_offset_, a_size_);
      ::std::memcpy(buffer_.get() + a_size_, tmp.get(), b_size_);
    }
  }

  a_offset_ = 0;
  a_size_ = a_size_ + b_size_;
  b_size_ = 0;
}

} // namespace schwanenlied
