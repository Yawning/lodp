/**
 * @file    blake2s.cc
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   BLAKE2s Cryptographic Hash Algorithm (IMPLEMENTATION)
 */

/*
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

#include "schwanenlied/crypto/blake2s.h"

namespace schwanenlied {
namespace crypto {

Blake2s::Blake2s(const uint8_t* key,
                 const size_t key_len) :
    stream_state_(State::kINVALID),
    has_key_(true) {
  SL_ASSERT(key_len <= kKeyLength);
  key_.assign(key, key_len);
}

Blake2s::Blake2s(Random& rng) :
    stream_state_(State::kINVALID),
    has_key_(true),
    key_(kKeyLength, 0) {
  rng.get_bytes(&key_[0], key_.length());
}

Blake2s::~Blake2s() {
  memwipe(&state_, sizeof(state_));
}

void Blake2s::set_key(const uint8_t* key,
                      const size_t key_len) {
  SL_ASSERT(stream_state_ == State::kINVALID);
  SL_ASSERT(key_len <= kKeyLength);
  key_.assign(key, key_len);
  has_key_ = true;
}

void Blake2s::clear_key() {
  if (has_key_) {
    clear();
    memwipe(&key_[0], key_.length());
    has_key_ = false;
  }
}

bool Blake2s::init(const uint8_t out_len) {
  if (stream_state_ != State::kINVALID)
    return false;

  SL_ASSERT(has_key_);

  int i = ::blake2s_init_key(&state_, out_len, key_.data(), key_.length());
  if (i)
    return false;
  stream_state_ = State::kINIT;

  return true;
}

bool Blake2s::update(const uint8_t* buf,
                     const size_t len) {
  if ((stream_state_ != State::kINIT) && (stream_state_ != State::kUPDATE))
    return false;

  int i = ::blake2s_update(&state_, buf, len);
  if (i) {
    clear();
    return false;
  }
  stream_state_ = State::kUPDATE;

  return true;
}

bool Blake2s::final(uint8_t* out,
                    const size_t out_len) {
  if (stream_state_ != State::kUPDATE)
    return false;

  int i = ::blake2s_final(&state_, out, out_len);
  clear();
  if (i)
    return false;

  return true;
}

void Blake2s::clear() {
  memwipe(&state_, sizeof(state_));
  stream_state_ = State::kINVALID;
}

bool Blake2s::digest(const uint8_t* buf,
                     const size_t len,
                     uint8_t* out,
                     const size_t out_len) const {
  SL_ASSERT(has_key_);

  int i = ::blake2s(out, buf, key_.data(), out_len, len, key_.length());
  if (i)
    return false;

  return true;
}

} // namespace crypto
} // namespace schwanenlied
