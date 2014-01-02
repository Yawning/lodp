/**
 * @file    xchacha.cc
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   XChaCha/20 Stream Cipher (IMPLEMENTATION)
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

#include <mutex>

#include "schwanenlied/crypto/xchacha.h"

namespace schwanenlied {
namespace crypto {

static ::std::once_flag self_test;

XChaCha::XChaCha() :
    has_key_(false),
    key_(kKeyLength, 0) {
  ::std::call_once(self_test, []() {
    int ret = ::chacha_check_validity();
    SL_ASSERT(ret);
  });
}

XChaCha::XChaCha(const uint8_t* key,
                 const size_t key_len) :
    XChaCha() {
  SL_ASSERT(key_len == kKeyLength);
  key_.assign(key, key_len);
  has_key_ = true;
}

void XChaCha::set_key(const uint8_t* key,
                      const size_t key_len) {
  SL_ASSERT(key_len == kKeyLength);
  key_.assign(key, key_len);
  has_key_ = true;
}

void XChaCha::clear_key() {
  if (has_key_) {
    memwipe(&key_[0], key_.size());
    has_key_ = false;
  }
}

void XChaCha::encrypt(const uint8_t* iv,
                      const ::std::string &in,
                      uint8_t* out,
                      const size_t len) const {
  SL_ASSERT(has_key_);
  SL_ASSERT(in.size() == len);
  SL_ASSERT(out != 0);

  ::xchacha(reinterpret_cast<const chacha_key*>(key_.data()),
            reinterpret_cast<const chacha_iv24*>(iv),
            reinterpret_cast<const uint8_t*>(in.data()), out, len, kRounds);
}

void XChaCha::encrypt(const uint8_t* iv,
                      const uint8_t* in,
                      uint8_t* out,
                      const size_t len) const {
  SL_ASSERT(has_key_);
  SL_ASSERT(in != nullptr);
  SL_ASSERT(out != nullptr);

  ::xchacha(reinterpret_cast<const chacha_key*>(key_.data()),
            reinterpret_cast<const chacha_iv24*>(iv), in, out, len,
            kRounds);
}

} // namespace crypto
} // namespace schwanenlied
