/**
 * @file  siv_blake2s_xchacha.cc
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   SIV-BLAKE2s-XChaCha/20 AEAD (IMPLEMENTATION)
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

#include "schwanenlied/crypto/siv_blake2s_xchacha.h"

namespace schwanenlied {
namespace crypto {

SIVBlake2sXChaCha::SIVBlake2sXChaCha(const Random& rng) :
    rng_(rng),
    has_key_(false),
    mac_(),
    stream_() {
  // Nothing to do
}

SIVBlake2sXChaCha::SIVBlake2sXChaCha(const Random& rng,
                                     const uint8_t* key,
                                     const size_t key_len) :
    rng_(rng),
    has_key_(false),
    mac_(),
    stream_() {
  set_key(key, key_len);
}

void SIVBlake2sXChaCha::set_key(const uint8_t* key,
                                const size_t key_len) {
  SL_ASSERT(key_len == kKeyLength);

  // Feed the keys to the appropriate algorithms
  mac_.set_key(key, Blake2s::kKeyLength);
  stream_.set_key(key + Blake2s::kKeyLength, XChaCha::kKeyLength);
  has_key_ = true;
}

void SIVBlake2sXChaCha::clear_key() {
  if (has_key_) {
   mac_.clear_key();
   stream_.clear_key();
   has_key_ = false;
  }
}

void SIVBlake2sXChaCha::encrypt(const ::std::string& in,
                                ::std::string& out) {
  bool ret = true;

  SL_ASSERT(has_key_);

  out.resize(kSIVLength + kNonceLength + in.length());
  uint8_t* out_ptr = reinterpret_cast<uint8_t*>(&out[0]);
  ret &= mac_.init(kSIVLength);

  // Generate/MAC the Nonce
  uint8_t* nonce = out_ptr + kSIVLength;
  rng_.get_bytes(nonce, kNonceLength);
  ret &= mac_.update(nonce, kNonceLength);

  // MAC the plaintext, Generate the SIV
  const uint8_t* in_ptr = reinterpret_cast<const uint8_t*>(&in[0]);
  ret &= mac_.update(in_ptr, in.length());
  uint8_t* siv = out_ptr;
  ret &= mac_.final(siv, kSIVLength);

  // Encrypt
  out_ptr += kSIVLength + kNonceLength;
  stream_.encrypt(siv, in, out_ptr, in.length());

  SL_ASSERT(ret);
}

bool SIVBlake2sXChaCha::decrypt(const uint8_t* in,
                                const size_t in_len,
                                ::std::string& out) {
  SL_ASSERT(has_key_);
  SL_ASSERT(in_len >= kSIVLength + kNonceLength);

  bool ret = true;

  out.resize(in_len - (kSIVLength + kNonceLength));
  size_t out_len = out.length();
  uint8_t* out_ptr = reinterpret_cast<uint8_t*>(&out[0]);
  ret &= mac_.init(kSIVLength);

  // MAC the Nonce
  const uint8_t* nonce = in + kSIVLength;
  ret &= mac_.update(nonce, kNonceLength);

  // Decrypt the ciphertext
  const uint8_t* siv = in;
  stream_.encrypt(siv, in + kSIVLength + kNonceLength, out_ptr, out_len);
  ret &= mac_.update(out_ptr, out_len);

  // MAC the plaintext, compare the SIVs (Authenticate)
  uint8_t auth_siv[kSIVLength];
  ret &= mac_.final(auth_siv, sizeof(auth_siv));
  SL_ASSERT(ret); // The MAC routines will only fail on implementation error.
  ret &= (0 == memequals(auth_siv, siv, sizeof(auth_siv)));

  return ret;
}

} // namespace crypto
} // namespace schwanenlied
