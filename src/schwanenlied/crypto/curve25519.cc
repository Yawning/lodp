/**
 * @file    curve25519.cc
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   Curve25519 Elliptic Curve Diffie-Hellman (IMPLEMENTATION)
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

#include "schwanenlied/crypto/curve25519.h"

namespace schwanenlied {
namespace crypto {
namespace Curve25519 {

static const uint8_t kBasepoint[PublicKey::kKeyLength] = { 9 };
static const uint8_t kInfpoint[PublicKey::kKeyLength] = { 0 };

PrivateKey::PrivateKey(const uint8_t* key, const size_t key_len,
                       const bool fixup) {
  SL_ASSERT(key_len == kKeyLength);
  key_.assign(key, key_len);
  if (fixup) {
    key_[0] &= 248;
    key_[31] &= 127;
    key_[31] |= 64;
  }
}

PrivateKey::PrivateKey(const Random& rng) :
    key_(kKeyLength, 0) {
  key_.resize(kKeyLength, 0);
  rng.get_bytes(&key_[0], key_.size());

  key_[0] &= 248;
  key_[31] &= 127;
  key_[31] |= 64;
}

PublicKey::PublicKey(const PrivateKey& private_key) :
    key_(kKeyLength, 0) {
  int ret = ::curve25519_donna(&key_[0], private_key.data(), kBasepoint);
  SL_ASSERT(ret == 0);
}

PublicKey::PublicKey(const uint8_t* key, const size_t key_len) {
  SL_ASSERT(key_len == kKeyLength);
  key_.assign(key, key_len);
}

SharedSecret::SharedSecret(const PublicKey& public_key,
                           const PrivateKey &private_key) :
    is_valid_(true),
    secret_(kLength, 0) {
  int ret = ::curve25519_donna(&secret_[0], private_key.data(),
                               public_key.data());
  SL_ASSERT(ret == 0);
  is_valid_ &= !(0 == memequals(secret_.data(), kInfpoint, secret_.length()));
}

} // namespace Curve25519
} // namespace crypto
} // namespace schwanenlied
