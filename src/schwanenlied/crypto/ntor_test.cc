/*
 * ntor_test.cc: ntor handshake (LODP variant) tests
 *
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

#include <array>

#include "schwanenlied/crypto/ntor.h"
#include "schwanenlied/crypto/utils.h"
#include "gtest/gtest.h"

namespace schwanenlied {
namespace crypto {

class NtorHandshakeTest : public ::testing::Test {
 protected:
  virtual void SetUp() {}
  virtual void TearDown() {}
};

TEST_F(NtorHandshakeTest, SmokeTest) {
  const uint8_t raw_node_id[] = { 'T', 'e', 's', 't', 'N', 'o', 'd', 'e' };
  const ::std::array<uint8_t, Curve25519::PrivateKey::kKeyLength> raw_resp_id_private = { 3 };
  const ::std::array<uint8_t, Curve25519::PrivateKey::kKeyLength> raw_resp_session_private = { 5 };
  const ::std::array<uint8_t, Curve25519::PrivateKey::kKeyLength> raw_init_session_private = { 7 };

  SecureBuffer node_id(raw_node_id, sizeof(raw_node_id));

  Curve25519::PrivateKey resp_id_private(raw_resp_id_private.data(),
                                         raw_resp_id_private.size(), false);
  Curve25519::PublicKey resp_id_public(resp_id_private);

  Curve25519::PrivateKey resp_session_private(raw_resp_session_private.data(),
                                              raw_resp_session_private.size(),
                                              false);
  Curve25519::PublicKey resp_session_public(resp_session_private);

  Curve25519::PrivateKey init_session_private(raw_init_session_private.data(),
                                              raw_init_session_private.size(),
                                              false);
  Curve25519::PublicKey init_session_public(init_session_private);

  NtorHandshake hs;

  // Responder side
  SecureBuffer resp_shared_secret(NtorHandshake::kSecretLength, 0);
  SecureBuffer resp_auth(NtorHandshake::kAuthLength, 0);
  bool ret = hs.responder(init_session_public, resp_id_public,
                          resp_session_public, resp_id_private,
                          resp_session_private, node_id, resp_shared_secret,
                          resp_auth);
  ASSERT_TRUE(ret);

  // Initiator side
  SecureBuffer init_shared_secret(NtorHandshake::kSecretLength, 0);
  ret = hs.initiator(resp_session_public, resp_id_public, init_session_public,
                     init_session_private, node_id, resp_auth,
                     init_shared_secret);
  ASSERT_TRUE(ret);

  // Compare the two shared secrets
  ASSERT_EQ(0, memequals(resp_shared_secret.data(), init_shared_secret.data(),
                         resp_shared_secret.size()));
}

} // namespace crypto
} // namespace schwanenlied
