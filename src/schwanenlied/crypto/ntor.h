/**
 * @file    ntor.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   ntor Handshake (LODP variant)
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

#ifndef SCHWANENLIED_CRYPTO_NTOR_H__
#define SCHWANENLIED_CRYPTO_NTOR_H__

#include "schwanenlied/crypto/blake2s.h"
#include "schwanenlied/crypto/curve25519.h"
#include "schwanenlied/crypto/utils.h"

namespace schwanenlied {
namespace crypto {

/**
 * The LODP variant of the [ntor handshake](https://gitweb.torproject.org/torspec.git/blob_plain/HEAD:/proposals/216-ntor-handshake.txt)
 *
 * This provides a implementation of the Tor Project's ntor handshake
 * authenticated key exchange protocol.  The changes that the LODP variant
 * introduces are:
 *
 *  * "Responder" is used instead of "Server" when deriving auth_input
 *  * tor uses HMAC-SHA256 for H(x,t), this implementation uses BLAKE2s
 *  * "lodp-ntor-1" is used for the ProtoID to differentiate it from the
 *    original ntor handshake.
 *
 * @warning This implementation will bail early if the id is invalid (0 length).
 * Additionally as it allocates space for the intermediary values on the heap,
 * it *may* leak timing information regarding the length of ID, so it is
 * **strongly recommended that fixed length node_ids are used**.
 */
class NtorHandshake {
 public:
  /** The length of the authentication tag in bytes (32 bytes) */
  static const size_t kAuthLength = Blake2s::kDigestLength;
  /** The length of the shared secret in bytes (32 bytes) */
  static const size_t kSecretLength = Blake2s::kDigestLength;

  /**
   * Construct a NtorHandshake instance
   */
  NtorHandshake();

  /** @{ */
  /**
   * Perform the responder (aka server) side of the NtorHandshake
   *
   * @param[in] public_peer_session The initiator's session PublicKey (X)
   * @param[in] public_identity     The responder's long term PublicKey (B)
   * @param[in] public_session      The responder's session PublicKey (Y)
   * @param[in] private_identity    The PrivateKey corresponding to
   *                                public_identity (b)
   * @param[in] private_session     The PrivateKey corresponding to
   *                                public_session (y)
   * @param[in] my_id               The responder's node id (ID)
   * @param[out] shared_secret      The buffer where the shared secret should be
   *                                stored.
   * @param[out] auth               The buffer where the authentication tag
   *                                should be stored.
   *
   * @returns true - The handshake succeded
   * @returns false - The handshake failed
   */
  bool responder(const Curve25519::PublicKey& public_peer_session,
                 const Curve25519::PublicKey& public_identity,
                 const Curve25519::PublicKey& public_session,
                 const Curve25519::PrivateKey& private_identity,
                 const Curve25519::PrivateKey& private_session,
                 const SecureBuffer& my_id,
                 SecureBuffer& shared_secret,
                 SecureBuffer& auth);

  /**
   * Perform the initiator (aka client) side of the NtorHandshake
   *
   * @param[in] public_peer_session   The responder's session PublicKey (Y)
   * @param[in] public_peer_identity  The responder's long term PublicKey (B)
   * @param[in] public_session        The initiator's session PublicKey (X)
   * @param[in] private_session       The PrivateKey corresponding to
   *                                  public_session (x)
   * @param[in] peer_id               The responder's node id (ID)
   * @param[in] peer_auth             The authentication tag received from the
   *                                  responder.
   * @param[out] shared_secret        The buffer where the shared secret should
   *                                  be stored.
   *
   * @returns true - The handshake succeded
   * @returns false - The handshake failed
   */
  bool initiator(const Curve25519::PublicKey& public_peer_session,
                 const Curve25519::PublicKey& public_peer_identity,
                 const Curve25519::PublicKey& public_session,
                 const Curve25519::PrivateKey& private_session,
                 const SecureBuffer& peer_id,
                 const SecureBuffer& peer_auth,
                 SecureBuffer& shared_secret);
  /* @} */

 private:
  NtorHandshake(const NtorHandshake&) = delete;
  void operator=(const NtorHandshake&) = delete;

  /**
   * Perform the parts of NtorHandshake shared between the initiator and
   * responder
   *
   * @param[in] exp_1          The result of the first EXP operation
   * @param[in] exp_2          The result of the second EXP operation
   * @param[in] B              The responder's long term PublicKey (B)
   * @param[in] X              The initiator's session PublicKey (X)
   * @param[in] Y              The responder's session PublicKey (Y)
   * @param[in] id             The responder's node id (ID)
   * @param[out] shared_secret The buffer where the shared secret should be
   *                           stored.
   * @param[out] auth          The buffer where the authentication tag
   *                           should be stored.
   *
   * @returns true - The routine succeeded
   * @returns false - The routine failed
   */
  bool derive_output(const Curve25519::SharedSecret& exp_1,
                     const Curve25519::SharedSecret& exp_2,
                     const Curve25519::PublicKey& B,
                     const Curve25519::PublicKey& X,
                     const Curve25519::PublicKey& Y,
                     const SecureBuffer& id,
                     SecureBuffer& shared_secret,
                     SecureBuffer& auth);

  Blake2s h_secret_;  /**< The Blake2s instance used to calculate KEY_SEED */
  Blake2s h_verify_;  /**< The Blake2s instance used to calculate verify */
  Blake2s h_auth_;    /**< The Blake2s instance used to calcuate AUTH */
};

} // namespace crypto
} // namespace schwanenlied

#endif // SCHWANENLIED_CRYPTO_NTOR_H__
