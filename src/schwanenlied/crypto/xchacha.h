/**
 * @file    xchacha.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   XChaCha/20 Stream Cipher
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

#ifndef SCHWANENLIED_CRYPTO_XCHACHA_H__
#define SCHWANENLIED_CRYPTO_XCHACHA_H__

#include <string>

#include "schwanenlied/common.h"
#include "schwanenlied/crypto/utils.h"
#include "ext/chacha.h"

namespace schwanenlied {
namespace crypto {


/**
 * The [XChaCha/20](http://cr.yp.to/snuffle/xsalsa-20110204.pdf) Stream Cipher
 *
 * This provides the XChaCha/20 stream cipher.  Internally it wraps the
 * [implementation by Floodyberry](https://github.com/floodyberry/chacha-opt)
 * to make it easier to use from C++ code, and handles safe removal of key
 * material.
 *
 * @warning The first time any of the constructors are called, the underlying
 * implementation's self test is called, and the code will terminate on
 * failure.
 */
class XChaCha {
 public:
  /** The key length in bytes */
  static const size_t kKeyLength = 32;
  /** The Initialization Vector length in bytes */
  static const size_t kIvLength = 24;
  /** The number of rounds */
  static const int kRounds = 20;

  /**
   * Construct a uninitialized XChaCha instance
   *
   * The application must call set_key() to actually use any of the functions.
   */
  XChaCha();

  /**
   * Construct a XChaCha instance given a key
   *
   * @warning Attempting to pass in an invalid key will cause the code to
   * SL_ASSERT().
   *
   * @param[in] key      A pointer to the key to associate with this instance
   * @param[in] key_len The length of the key
   */
  XChaCha(const uint8_t* key,
          const size_t key_len);

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
   * Encrypt/Decrypt a given buffer
   *
   * @param[in] iv   A pointer to a kIvLength Initialization Vector
   * @param[in] in   The std::string containing the input data
   * @param[out] out A pointer to where the output should be stored
   * @param[in] len  The length of the buffer backed by out (*MUST MATCH*
   *                 in.size())
   */
  void encrypt(const uint8_t* iv,
               const ::std::string &in,
               uint8_t* out,
               const size_t len) const;

  /**
   * Encrypt/Decrypt a given buffer
   *
   * @param[in] iv   A pointer to a kIvLength Initialization Vector
   * @param[in] in   A pointer to the input data
   * @param[out] out A pointer to where the output should be stored
   * @param[in] len  The length of the buffer backed by in/out
   */
  void encrypt(const uint8_t* iv,
               const uint8_t* in,
               uint8_t* out,
               const size_t len) const;
  /** @} */

 private:
  XChaCha(const XChaCha&) = delete;
  void operator=(const XChaCha&) = delete;

  bool has_key_;      /**< Is a key currently set for this instance? */
  SecureBuffer key_;  /**< The key storage object */
};

} // namespace crypto
} // namespace schwanenlied

#endif // SCHWANENLIED_CRYPTO_XCHACHA_H__
