/**
 * @file    hkdf_blake2s.cc
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   HKDF-BLAKE2s (IMPLEMENTATION)
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

#include <cstring>

#include "schwanenlied/crypto/hkdf_blake2s.h"

namespace schwanenlied {
namespace crypto {
namespace HkdfBlake2s {

SecureBuffer extract(const uint8_t* salt,
                     const size_t salt_len,
                     const SecureBuffer& ikm) {
  Blake2s h(salt, salt_len);
  SecureBuffer okm(Blake2s::kDigestLength, 0);

  bool ret = h.digest(ikm.data(), ikm.length(), &okm[0], okm.length());
  SL_ASSERT(ret == true);

  return okm;
}

SecureBuffer expand(const SecureBuffer& prk,
                    const uint8_t* info,
                    const size_t info_len,
                    size_t len) {
  SL_ASSERT(prk.length() == Blake2s::kKeyLength);

  size_t n = (len + Blake2s::kDigestLength - 1) / Blake2s::kDigestLength;
  SL_ASSERT(n <= 255);

  uint8_t t[Blake2s::kDigestLength];
  Blake2s h(prk.data(), prk.length());
  SecureBuffer okm(len, 0);
  uint8_t* p = &okm[0];
  size_t remaining = len;

  for (uint8_t i = 1; i <= n; i++) {
    size_t to_copy = (remaining > sizeof(t)) ? sizeof(t) : remaining;
    bool ret = h.init(sizeof(t));
    if (i > 1)
      ret &= h.update(t, sizeof(t));
    ret &= h.update(info, info_len);
    ret &= h.update(&i, sizeof(i));
    ret &= h.final(t, sizeof(t));
    SL_ASSERT(ret);
    ::std::memcpy(p, t, to_copy);
    p+= to_copy;
    remaining -= to_copy;
  }

  memwipe(t, sizeof(t));

  return okm;
}

} // namespace HkdfBlake2s
} // namespace crypto
} // namespace schwanenlied
