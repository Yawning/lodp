/**
 * @file    siphash.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   SipHash-2-4 Cryptographic Hash Algorithm
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

#ifndef SCHWANENLIED_CRYPTO_SIPHASH_H__
#define SCHWANENLIED_CRYPTO_SIPHASH_H__

#include "schwanenlied/common.h"
#include "schwanenlied/crypto/random.h"
#include "schwanenlied/crypto/utils.h"

namespace schwanenlied {
namespace crypto {

/**
 * The [SipHash-2-4](https://131002.net/siphash/) Cryptographic Hash Algorithm
 *
 * This provides the SipHash-2-4 Cryptographic Hash Algorithm.  Interally it
 * wraps the [implementation by Floodyberry](https://github.com/floodyberry/siphash)
 * to make it easier to use from C++ code, and handles safe removal of key
 * material.
 */
class SipHash {
 public:
  /** The key length in bytes */
  static const size_t kKeyLength = 16;

  /**
   * Construct a SipHash instance given a key
   *
   * @warning Attempting to pass in an invalid key will cause the code to
   * SL_ASSERT().
   *
   * @param[in] key      A pointer to the key to associate with this instance
   * @param[in] key_len The length of the key
   */
  SipHash(const uint8_t* key,
          const size_t key_len);

  /**
   * Construct a SipHash instance with a random 128 bit key
   *
   * @param[in] rng   The Random instance to use to generate the key
   */
  SipHash(Random& rng);

  /** @{ */
  /**
   * One shot digest calculation
   *
   * @param[in] buf A pointer to the buffer to be hashed
   * @param[in] len The size of the buffer to hash
   * @returns The 64 bit SipHash-2-4 digest
   */
  uint64_t digest(const uint8_t* buf,
                  const size_t len) const;
  /** @} */

 private:
  SipHash() = delete;
  SipHash(const SipHash&) = delete;
  void operator=(const SipHash&) = delete;

  SecureBuffer key_;  /**< The key storage object */
};

} // namespace crypto
} // namespace schwanenlied

#endif // SCHWANENLIED_CRYPTO_SIPHASH_H__
