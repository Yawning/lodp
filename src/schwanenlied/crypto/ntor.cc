/**
 * @file    ntor.cc
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   ntor Handshake (LODP variant) (IMPLEMENTATION)
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

#include "schwanenlied/crypto/ntor.h"

namespace schwanenlied {
namespace crypto {

static const uint8_t kProtoID[] = {
 'l', 'o', 'd', 'p', '-', 'n', 't', 'o', 'r', '-',
 '1'
};

static const uint8_t kSharedSecretKey[] = {
 'l', 'o', 'd', 'p', '-', 'n', 't', 'o', 'r', '-',
 '1', ':', 'k', 'e', 'y', '_', 'e', 'x', 't', 'r',
 'a', 'c', 't'
};

static const uint8_t kVerifyKey[] = {
 'l', 'o', 'd', 'p', '-', 'n', 't', 'o', 'r', '-',
 '1', ':', 'k', 'e', 'y', '_', 'v', 'e', 'r', 'i',
 'f', 'y'
};

static const uint8_t kAuthKey[] = {
 'l', 'o', 'd', 'p', '-', 'n', 't', 'o', 'r', '-',
 '1', ':', 'm', 'a', 'c'
};

static const uint8_t kResponder[] = {
  'R', 'e', 's', 'p', 'o', 'n', 'd', 'e', 'r'
};

NtorHandshake::NtorHandshake() :
    h_secret_(kSharedSecretKey, sizeof(kSharedSecretKey)),
    h_verify_(kVerifyKey, sizeof(kVerifyKey)),
    h_auth_(kAuthKey, sizeof(kAuthKey)) {
  // Nothing further to do.
}

bool NtorHandshake::responder(const Curve25519::PublicKey& public_peer_session, 
                              const Curve25519::PublicKey& public_identity,
                              const Curve25519::PublicKey& public_session,
                              const Curve25519::PrivateKey& private_identity,
                              const Curve25519::PrivateKey& private_session,
                              const SecureBuffer& my_id,
                              SecureBuffer& shared_secret,
                              SecureBuffer& auth) {
  if (my_id.length() == 0)
    return false;

  shared_secret.resize(kSecretLength, 0);
  auth.resize(kAuthLength, 0);

  bool ret = true;
  Curve25519::SharedSecret exp_X_y(public_peer_session, private_session);
  Curve25519::SharedSecret exp_X_b(public_peer_session, private_identity);
  ret &= exp_X_y.is_valid();
  ret &= exp_X_b.is_valid();

  ret &= derive_output(exp_X_y, exp_X_b, public_identity, public_peer_session,
                       public_session, my_id, shared_secret, auth);

  return ret;
}

bool NtorHandshake::initiator(const Curve25519::PublicKey& public_peer_session, 
                              const Curve25519::PublicKey& public_peer_identity,
                              const Curve25519::PublicKey& public_session,
                              const Curve25519::PrivateKey& private_session,
                              const SecureBuffer& peer_id,
                              const SecureBuffer& peer_auth,
                              SecureBuffer& shared_secret) {
  if (peer_id.length() == 0)
    return false;

  shared_secret.resize(kSecretLength, 0);

  bool ret = true;
  Curve25519::SharedSecret exp_Y_x(public_peer_session, private_session);
  Curve25519::SharedSecret exp_B_x(public_peer_identity, private_session);
  ret &= exp_Y_x.is_valid();
  ret &= exp_B_x.is_valid();

  SecureBuffer auth(kAuthLength, 0);
  ret &= derive_output(exp_Y_x, exp_B_x, public_peer_identity, public_session,
                       public_peer_session, peer_id, shared_secret, auth);

  // Validate that the auth provided by the peer matches derived output
  ret &= (0 == memequals(auth.data(), peer_auth.data(), auth.length()));

  return ret;
}

bool NtorHandshake::derive_output(const Curve25519::SharedSecret& exp_1,
                                  const Curve25519::SharedSecret& exp_2,
                                  const Curve25519::PublicKey& B,
                                  const Curve25519::PublicKey& X,
                                  const Curve25519::PublicKey& Y,
                                  const SecureBuffer& id,
                                  SecureBuffer& shared_secret,
                                  SecureBuffer& auth) {
  bool ret = true;

  // Both SecretInput and AuthInput share "ID | B | X | Y | PROTOID",
  // so allocate one buffer that can fit both
  SecureBuffer foo_input;
  foo_input.reserve(2 * Curve25519::SharedSecret::kLength + id.length() +
                    3 * Curve25519::PublicKey::kKeyLength + sizeof(kProtoID) +
                    sizeof(kResponder));

  // Resp: SecretInput = EXP(X,y) | EXP(X,b) | ID | B | X | Y | PROTOID
  // Init: SecretInput = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
  foo_input.append(exp_1.data(), exp_1.length());
  foo_input.append(exp_2.data(), exp_1.length());
  foo_input.append(id.data(), id.length());
  foo_input.append(B.data(), B.length());
  foo_input.append(X.data(), B.length());
  foo_input.append(Y.data(), B.length());
  foo_input.append(kProtoID, sizeof(kProtoID));
  ret &= h_secret_.digest(foo_input.data(), foo_input.length(),
                          &shared_secret[0], shared_secret.length());

  // Verify = H(PROTOID | ":key_verify", SecretInput)
  SecureBuffer verify(Blake2s::kDigestLength, 0);
  ret &= h_verify_.digest(foo_input.data(), foo_input.length(), &verify[0],
                          verify.length());

  // AuthInput = Verify | ID | B | Y | X | PROTOID | "Responder"
  static_assert(Curve25519::PublicKey::kKeyLength == Blake2s::kDigestLength,
                "Curve25519 Public Key Length must equal BLAKE2s Digest Length");

  uint8_t *auth_input = &foo_input[0] + Curve25519::PublicKey::kKeyLength;
  ::std::memcpy(auth_input, verify.data(), verify.length());
  foo_input.append(kResponder, sizeof(kResponder));
  size_t auth_input_len = foo_input.length() - Curve25519::PublicKey::kKeyLength;

  // Auth = H(PROTOID | ":mac", AuthInput)
  ret &= h_auth_.digest(auth_input, auth_input_len, &auth[0], auth.length());

  // Any failures in this routine is a sign of a bug in Blake2s
  SL_ASSERT(ret);

  return ret;
}


} // namespace crypto
} // namespace schwanenlied
