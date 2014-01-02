/**
 * @file    blake2s.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   BLAKE2s Cryptographic Hash Algorithm
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

#ifndef SCHWANENLIED_CRYPTO_BLAKE2S_H__
#define SCHWANENLIED_CRYPTO_BLAKE2S_H__

#include <string>

#include "schwanenlied/common.h"
#include "schwanenlied/crypto/random.h"
#include "schwanenlied/crypto/utils.h"
#include "ext/blake2.h"

namespace schwanenlied {
namespace crypto {

/**
 * The [BLAKE2s](https://blake2.net) Cryptographic Hash Algorithm
 *
 * This provides the BLAKE2s Cryptographic Hash Algorithm.  Interally it wraps
 * the [reference implementation](https://github.com/BLAKE2/BLAKE2) to make
 * it easier to use from C++ code, and handles safe removal of key material and
 * state.
 *
 * BLAKE2s supports digest and key sizes ranging from 1 to 32 bytes.
 */
class Blake2s {
 public:
  /** The maximum key length in bytes */
  static const size_t kKeyLength = BLAKE2S_KEYBYTES;
  /** The maximum digest length in bytes */
  static const size_t kDigestLength = BLAKE2S_OUTBYTES;

  /**
   * Construct a unintialized Blake2s instance
   *
   * The application must call set_key() to actually use any of the functions.
   */
  Blake2s() : stream_state_(State::kINVALID), has_key_(false) {}

  /**
   * Construct a Blake2s instance given a key
   *
   * @warning Attempting to pass in an invalid key will cause the code to
   * SL_ASSERT().
   *
   * @param[in] key     A pointer to the key to associate with this instance
   * @param[in] key_len The length of the key to use
   */
  Blake2s(const uint8_t* key,
          const size_t key_len);

  /**
   * Construct a Blake2s instance with a random 256 bit key
   *
   * @param[in] rng     The Random instance to use to generate the key
   */
  Blake2s(const Random& rng);
  ~Blake2s();

  /** @{ */
  /**
   * Set the key
   *
   * @warning Attempting to pass in an invalid key, or calling set_key() while
   * using the streaming API before final() has been called will cause the code
   * to SL_ASSERT().
   *
   * @param[in] key     A pointer to the key to associate with this instance
   * @param[in] key_len The length of the key to use
   */
  void set_key(const uint8_t* key,
               const size_t key_len);

  /**
   * Clear the key
   *
   * This securely wipes the key and resets the internal state to be equivalent
   * to the output of Blake2s().  Implementations **MUST** call set_key() to
   * continue to use the object.
   */
  void clear_key();
  /**@} */

  /** @{ */
  /**
   * Initialize the streaming interface
   *
   * @param[in] out_len The desired digest length
   *
   * @returns true  - Success
   * @returns false - Failure
   */
  bool init(const uint8_t out_len);

  /**
   * Hash additional data via the streaming interface
   *
   * @param[in] buf A pointer to the buffer to be hashed
   * @param[in] len The size of the buffer to hash
   *
   * @returns true  - Success
   * @returns false - Failure
   */
  bool update(const uint8_t* buf,
              const size_t len);


  /**
   * Hash additional data via the streaming interface
   *
   * @param[in] buf The std::string containing data to be hashed
   *
   * @returns true  - Success
   * @returns false - Failure
   */
  inline bool update(const ::std::string& buf) {
    return update(reinterpret_cast<const uint8_t*>(buf.data()), buf.length());
  }

  /**
   * Finalize the stream and return the digest
   *
   * @param[out] out    A pointer to where the digest should be stored
   * @param[in] out_len The length of the buffer where the digest will be stored
   *
   * @returns true  - Success
   * @returns false - Failure
   */
  bool final(uint8_t* out,
             const size_t out_len);

  /**
   * Clear and reset the state of the streaming interface
   */
  void clear();
  /** @} */

  /** @{ */
  /**
   * One shot digest calculation
   *
   * @param[in] buf     A pointer to the buffer to be hashed
   * @param[in] len     The size of the buffer to hash
   * @param[out] out    A pointer to where the digest should be stored
   * @param[in] out_len The length of the digest to calculate
   *
   * @returns true  - Success
   * @returns false - Failure
   */
  bool digest(const uint8_t* buf,
              const size_t len,
              uint8_t* out,
              const size_t out_len) const;
  /** @} */

 private:
  Blake2s(const Blake2s&) = delete;
  void operator=(const Blake2s&) = delete;

  /** The streaming interface state */
  enum class State {
    kINVALID, /**< init() has not been called */
    kINIT,    /**< init() has been called */
    kUPDATE   /**< update() has been called */
  } stream_state_;      /**< The streaming interface state */

  bool has_key_;        /**< Is a key is currently set for this instance? */
  SecureBuffer key_;    /**< The key storage object */
  blake2s_state state_; /**< The C reference implementation stream state */
};

} // namespace crypto
} // namespace schwanenlied

#endif // SCHWANENLIED_CRYPTO_BLAKE2S_H__
