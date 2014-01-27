/**
 * @file    siv_blake2s_xchacha.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   SIV-BLAKE2s-XChaCha/20 AEAD
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

#ifndef SCHWANENLIED_CRYPTO_SIV_BLAKE2S_XCHACHA_H__
#define SCHWANENLIED_CRYPTO_SIV_BLAKE2S_XCHACHA_H__

#include <string>

#include "schwanenlied/common.h"
#include "schwanenlied/crypto/blake2s.h"
#include "schwanenlied/crypto/random.h"
#include "schwanenlied/crypto/utils.h"
#include "schwanenlied/crypto/xchacha.h"

namespace schwanenlied {
namespace crypto {

/**
 * SIV-BLAKE2s-XChaCha/20 AEAD
 *
 * This provides [Synthetic Initialization Vector](http://www.cs.ucdavis.edu/~rogaway/papers/siv.pdf)
 * Authenticated Encryption with Associated Data based on the
 * [BLAKE2s](@ref Blake2s) hash algorithm and the [XChaCha/20](@ref XChaCha)
 * stream cipher.  Rogaway and Shrimpton's original paper specify SIV using
 * AES-CMAC and AES-CTR, however the construct itself is generic and thus
 * BLAKE2s and XChaCha/20 were chosen as replacements.
 *
 * This implementation uses a 512 bit key, 192 bit Synthetic IV, and
 * additionally features a 128 bit random nonce.
 */
class SIVBlake2sXChaCha {
 public:
  /** The key length in bytes (64 bytes/512 bits) */
  static const size_t kKeyLength = Blake2s::kKeyLength + XChaCha::kKeyLength;
  /** The Synthetic Initialization Vector length in bytes (24 bytes/192 bits) */
  static const size_t kSIVLength = XChaCha::kIvLength;
  /** The random nonce length in bytes (16 bytes/128 bits) */
  static const size_t kNonceLength = 16;

  /**
   * Construct a uninitialized SIVBlake2sXChaCha instance
   *
   * The application must call set_key() to actually use any of the functions.
   *
   * @param[in] rng   The Random instance to use when generating nonces
   */
  SIVBlake2sXChaCha(Random& rng);

  /**
   * Construct a SIVBlake2sXChaCha instance given a key
   *
   * @warning Attempting to pass in an invalid key will cause the code to
   * SL_ASSERT().
   *
   * @param[in] rng     The Random instance to use when generating nonces
   * @param[in] key     A pointer to the key to associate with this instance
   * @param[in] key_len The length of the key to use
   */
  SIVBlake2sXChaCha(Random& rng,
                    const uint8_t* key,
                    size_t key_len);

  /** @{ */
  /**
   * Set the key
   *
   * @warning Attempting to pass in an invalid key will cause the code to
   * SL_ASSERT().
   *
   * @param[in] key     A pointer to the key to associate with this instance
   * @param[in] key_len The length of the key
   */
  void set_key(const uint8_t* key,
               const size_t key_len);

  /**
   * Clear the key
   */
  void clear_key();
  /** @} */

  /** @{ */
  /**
   * Encrypt a given buffer
   *
   *     Let H(t, x) be BLAKE2s with key t, and message x.
   *
   *     Let E(t,v,x) be XChaCha/20 with key t, IV v, and message x.
   *
   *     Let R(n) be n bytes of output from a cryptographically strong random
   *     number generator seeded from a strong entropy source.
   *
   *     SIV-Encrypt(t, x) -> ciphertext
   *
   *         Nonce = R(kNonceLength)
   *
   *         SIV = H(leftmost(t, Blake2s::kKeyLength), Nonce | x)
   *
   *         CT = E(rightmost(t, XChaCha::kKeyLength), SIV, x)
   *
   *         ciphertext = SIV | V | CT
   *
   * @param[in]  in  The std::string containing the plaintext
   * @param[out] out The std::string where the ciphertext will be stored
   */
  void encrypt(const ::std::string& in,
               ::std::string& out);

  /**
   * Decrypt and authenticate a given buffer
   *
   *     Let H(t, x) be BLAKE2s with key t, and message x.
   *
   *     Let E(t,v,x) be XChaCha/20 with key t, IV v, and message x.
   *
   *     SIV-Decrypt(t, x) -> plaintext
   *
   *         SIV_Nonce = leftmost(x, kSivLength + kNonceLength)
   *
   *         SIV = leftmost(SIV_Nonce, kSivLength)
   *
   *         Nonce = rightmost(SIV_Nonce, kNonceLength)
   *
   *         SIV = H(leftmost(t, Blake2s::kKeyLength), Nonce | x)
   *
   *         PT = E(rightmost(t, XChaCha::kKeyLength), SIV, rightmost(x, X_LEN -
   *         (kSivLength + kNonceLength)))
   *
   *         SIV_Check = H(leftmost(t, Blake2s::kKeyLength, Nonce | PT)
   *
   *         if is_equal(SIV_Check, SIV)
   *
   *             plaintext = PT
   *
   *         else
   *
   *             return FAIL
   *
   * @param[in] in      A pointer to the ciphertext
   * @param[in] in_len  The lenght of the ciphertext
   * @param[out] out    The std::string where the plaintext will be stored
   *
   * @returns true - The plaintext was decrypted and authenticated
   *                 successfully
   * @returns false - The decryption failed
   */
  bool decrypt(const uint8_t* in,
               const size_t in_len,
               ::std::string& out);
  /**@} */

 private:
  SIVBlake2sXChaCha() = delete;
  SIVBlake2sXChaCha(const SIVBlake2sXChaCha&) = delete;
  void operator=(const SIVBlake2sXChaCha&) = delete;

  Random& rng_;       /**< The Random instance used when generating nonces */
  bool has_key_;      /**< Is a key currently set for this instance? */
  Blake2s mac_;       /**< The Blake2s object used to generate SIVs */
  XChaCha stream_;    /**< The XChaCha object used to encrypt/decrypt */
};

} // namespace crypto
} // namespace schwanenlied

#endif // SCHWANENLIED_CRYPTO_SIV_BLAKE2S_XCHACHA_H__
