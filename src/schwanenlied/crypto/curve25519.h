/**
 * @file    curve25519.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   Curve25519 Elliptic Curve Diffie-Hellman
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

#ifndef SCHWANENLIED_CRYPTO_CURVE25519_H__
#define SCHWANENLIED_CRYPTO_CURVE25519_H__

#include "schwanenlied/common.h"
#include "schwanenlied/crypto/random.h"
#include "schwanenlied/crypto/utils.h"

extern "C" {

extern int curve25519_donna(uint8_t* mypublic, const uint8_t* secret,
                            const uint8_t* basepoint);

} // namespace "C"

namespace schwanenlied {
namespace crypto {

/**
 * [Curve25519 Elliptic Curve Diffie-Hellman](http://cr.yp.to/ecdh.html)
 *
 * This provides the Curve25519 Elliptic Curve Diffie-Hellman algorithm.
 * Internally it wraps  the curve25519-donna compatible
 * [implementation by Floodyberry](https://github.com/floodyberry/curve25519-donna)
 * to make it easier to use from C++ code, and handles safe removal of key
 * material.
 */
namespace Curve25519 {

/**
 * Curve25519 ECDH Private Key
 */
class PrivateKey {
 public:
  /** The key length in bytes */
  static const size_t kKeyLength = 32;

  /**
   * Construct a PrivateKey instance given an existing key
   *
   * @warning Attempting to pass in an invalid key will cause the code to
   * SL_ASSERT().
   *
   * @param[in] key     A pointer to the existing key.
   * @param[in] key_len The length of the key to use
   * @param[in] fixup   Should the constructor bit-twiddle the key (Usually yes)
   */
  PrivateKey(const uint8_t* key, const size_t key_len, const bool fixup = true);

  /**
   * Construct a PrivateKey instance with a randomly generated private key
   *
   * @param[in] rng   The Random instance to use to generate the key
   */
  PrivateKey(const Random& rng);

  /** @{ */
  /** Return the raw key */
  const uint8_t* data() const { return key_.data(); }
  /** Return the size of the raw key in bytes */
  const size_t length() const { return key_.length(); }
  /** @} */

 private:
  PrivateKey() = delete;

  SecureBuffer key_;  /**< The key storage object */
};

/**
 * Curve25519 ECDH Public Key
 */
class PublicKey {
 public:
  /** The key length in bytes */
  static const size_t kKeyLength = 32;

  /**
   * Construct a PublicKey instance given an existing PrivateKey
   *
   * @param[in] private_key The PrivateKey that the PublicKey should be generated
   *                        from
   */
  PublicKey(const PrivateKey& private_key);

  /**
   * Construct a PublicKey instance given an existing key
   *
   * @warning Attempting to pass in an invalid key will cause the code to
   * SL_ASSERT().
   *
   * @param[in] key     A pointer to the existing private key.
   * @param[in] key_len The length of the key to use
   */
  PublicKey(const uint8_t* key, const size_t key_len);

  /** @{ */
  /** Return the raw key */
  const SecureBuffer& buf() const { return key_; }
  /** Return the raw key */
  const uint8_t* data() const { return key_.data(); }
  /** Return the size of the raw key in bytes */
  const size_t length() const { return key_.length(); }
  /** @} */

 private:
  PublicKey() = delete;

  SecureBuffer key_;  /**< The key storage object */
};

/**
 * Curve25519 ECDH Shared Secret
 */
class SharedSecret {
 public:
  /** The shared secret length in bytes */
  static const size_t kLength = 32;

  /**
   * Construct a SharedSecret instance given our PrivateKey and the remote
   * peer's PublicKey
   *
   * @param[in] public_key  The PublicKey used in the DH key exchange
   * @param[in] private_key The PrivateKey used in the DH key exchange
   */
  SharedSecret(const PublicKey& public_key, const PrivateKey &private_key);

  /** @{ */
  /** Return the raw shared secret */
  const uint8_t* data() const { return secret_.data(); }
  /** Return the size of the raw shared secret in bytes */
  const size_t length() const { return secret_.length(); }
  /** @} */

  /** @{ */
  /**
   * Return if the SharedSecret is safe to use in NtorHandshake
   *
   * The NtorHandshake specification states:
   * > Both parties check that none of the EXP() operations produced the point
   * > at infinity. [NOTE: This is an adequate replacement for checking Y for
   * > group membership, if the group is curve25519.]
   *
   * This routine performs that check.
   *
   * @returns true - The SharedSecret is safe to use in NtorHandshake
   * @returns false - The SharedSecret is **not** safe to use in NtorHandshake
   */
  const bool is_valid() const { return is_valid_; }
  /** @} */

 private:
  SharedSecret() = delete;

  bool is_valid_;       /**< Is the secret safe to use in NtorHandshake?  */
  SecureBuffer secret_; /**< The shared secret storage object */
};

} // namespace Curve25519
} // namespace crypto
} // namespace schwanenlied

#endif // SCHWANENLIED_CRYPTO_CURVE25519_H__
