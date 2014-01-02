/**
 * @file    lodp_endpoint.cc
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   LODP endpoint (IMPLEMENTATION)
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

#include "schwanenlied/crypto/hkdf_blake2s.h"
#include "schwanenlied/lodp/lodp_endpoint.h"

namespace schwanenlied {
namespace lodp {

static const uint8_t kIntroSalt[] = {
 'L', 'O', 'D', 'P', '-', 'I', 'n', 't', 'r', 'o',
 '-', 'B', 'L', 'A', 'K', 'E', '2', 's'
};

LodpEndpoint::LodpEndpoint(const crypto::Random& rng,
                           LodpCallbacks& callbacks,
                           void* ctxt,
                           const bool safe_logging) :
    callbacks_(callbacks),
    ctxt_(ctxt),
    safe_logging_(safe_logging),
    rng_(rng),
    hash_(rng),
    is_listening_(false),
    stats_() {
  // Empty!
}

LodpEndpoint::LodpEndpoint(const crypto::Random& rng,
                           LodpCallbacks& callbacks,
                           void* ctxt,
                           const bool safe_logging,
                           const crypto::Curve25519::PrivateKey& private_key,
                           const uint8_t* node_id,
                           const size_t node_id_len) :
    callbacks_(callbacks),
    ctxt_(ctxt),
    safe_logging_(safe_logging),
    rng_(rng),
    hash_(rng),
    is_listening_(true),
    node_id_(new crypto::SecureBuffer(node_id, node_id_len)),
    identity_private_key_(new crypto::Curve25519::PrivateKey(private_key)),
    identity_public_key_(new crypto::Curve25519::PublicKey(private_key)),
    introduction_siv_(new crypto::SIVBlake2sXChaCha(rng)),
    ephemeral_tx_siv_(new crypto::SIVBlake2sXChaCha(rng)),
    init_filter_(new BloomFilter(rng, kInitFilterSize, 0.001)),
    cookie_filter_(new BloomFilter(rng, kCookieFilterSize, 0.001)),
    cookie_(new crypto::Blake2s(rng)),
    prev_cookie_(new crypto::Blake2s(rng)),
    cookie_rotate_time_(::std::chrono::steady_clock::now() +
                        ::std::chrono::seconds(kCookieRotateInterval)),
    cookie_expire_time_(::std::chrono::steady_clock::now()),
    stats_() {
  // Validate that the user didn't screw up
  SL_ASSERT(node_id_->length() > 0);

  // Derive and set the key for introduction_siv_
  const auto intro_siv_key = derive_intro_siv_key(*identity_public_key_);
  introduction_siv_->set_key(intro_siv_key.data(), intro_siv_key.length());
}

LodpEndpoint::~LodpEndpoint() {
  /** @todo Close off all of the sessions instead of asserting */
  SL_ASSERT(session_table_.empty());
}

int LodpEndpoint::connect(void* ctxt,
                          const crypto::Curve25519::PublicKey& public_key,
                          const uint8_t* node_id,
                          const size_t node_id_len,
                          const IPAddress& addr,
                          LodpSession*& session) {
  if (node_id == nullptr)
    return -EINVAL;
  if (node_id_len == 0)
    return -EINVAL;
  if (session_table_.count(addr) != 0)
    return -EISCONN;

  LodpSession* tcb = new LodpSession(*this, ctxt, public_key, node_id,
                                     node_id_len, addr);
  session_table_[addr] = ::std::unique_ptr<LodpSession>(tcb);
  session = tcb;

  return kErrorOk;
}

int LodpEndpoint::on_packet(const uint8_t* buf,
                            const size_t buf_len,
                            const IPAddress& addr) {
  if (buf == nullptr)
    return -EINVAL;
  if (buf_len == 0)
    return -EINVAL;

  stats_.rx_bytes_ += buf_len;

  // Drop packets that are under/oversized without further processing
  if (buf_len < kMinPacketLength) {
    stats_.rx_undersized_++;
    return kErrorUndersizedPacket;
  }
  if (buf_len > addr.udp_mtu()) {
    stats_.rx_oversized_++;
    return kErrorOversizedPacket;
  }

  // Allocate a buffer to store the plaintext
  ::std::string plaintext;  // TODO/Performance: Buffer pool

  // Attempt to decrypt the packet
  LodpSession* tcb = nullptr;
  bool session_decrypt = false;
  auto got = session_table_.find(addr);
  if (got != session_table_.end()) {
    tcb = got->second.get();
    // A Session exists, try the Session's keys
    session_decrypt = tcb->siv_decrypt(buf, buf_len, plaintext);
    if (session_decrypt)
      goto decrypt_ok;
  }
  if (is_listening_) {
    // Try the Endpoint's Introduction key
    if (introduction_siv_->decrypt(buf, buf_len, plaintext))
      goto decrypt_ok;
  }

  // Welp, failed to decrypt the packet, drop it and return
  stats_.rx_decrypt_failed_++;
  return kErrorDecryptionFailure;

decrypt_ok:
  // Deserialize the packet into a protobuf object
  ::std::unique_ptr<packet::Envelope> envelope(new packet::Envelope());  // TODO/Performance: Buffer pool
  if (!envelope->ParseFromString(plaintext)) {
    stats_.rx_invalid_envelope_++;
    return kErrorInvalidEnvelope;
  }
  if (!envelope->has_packet_type()) {
    stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }

  /*
   * Do the actual packet processing, now that we have a "tenatively" valid
   * packet (We could decrypt it, and it contained a valid protobuf)
   */
  if (session_decrypt) {
    SL_ASSERT(tcb != nullptr);
    // Packets aimed at a session
    switch (envelope->packet_type()) {
    case packet::Envelope::DATA:
      return tcb->on_data_packet(*envelope);
    case packet::Envelope::INIT_ACK:
      return tcb->on_init_ack_packet(*envelope);
    case packet::Envelope::HANDSHAKE_ACK:
      return tcb->on_handshake_ack_packet(*envelope);
    case packet::Envelope::REKEY:
      return tcb->on_rekey_packet(*envelope);
    case packet::Envelope::REKEY_ACK:
      return tcb->on_rekey_ack_packet(*envelope);
    case packet::Envelope::SHUTDOWN:
      return tcb->on_shutdown_packet(*envelope);
    default:
      break;
    }
  } else {
    // Packets aimed at the endpoint
    if (envelope->packet_type() == packet::Envelope::INIT)
      return on_init_packet(*envelope, addr, buf, buf_len);
    else if (envelope->packet_type() == packet::Envelope::HANDSHAKE)
      return on_handshake_packet(*envelope, addr, tcb);
  }

  // I-it's not like I decrypted that packet for you or anything.... baka.
  stats_.rx_bad_packet_format_++;
  return kErrorBadPacketFormat;
}

void LodpEndpoint::rotate_cookie() {
  SL_ASSERT(is_listening_);

  auto now = ::std::chrono::steady_clock::now();
  if (now > cookie_rotate_time_) {
    // Generate a new key
    ::std::array<uint8_t, crypto::Blake2s::kKeyLength> new_key;
    rng_.get_bytes(&new_key[0], new_key.size());

    // Flip the keys
    prev_cookie_->set_key(new_key.data(), new_key.size());
    cookie_.swap(prev_cookie_);
    cookie_expire_time_ = cookie_rotate_time_ +
        ::std::chrono::seconds(kCookieGraceInterval);
    cookie_rotate_time_ = now + ::std::chrono::seconds(kCookieRotateInterval);

    // Scrub the stack
    crypto::memwipe(&new_key[0], new_key.size());
  }
}

void LodpEndpoint::generate_cookie(crypto::Blake2s& hash,
                                   const IPAddress& addr,
                                   const packet::Envelope& pkt,
                                   ::std::array<uint8_t, kCookieLength>& cookie) {
  /*
   * The INIT/HANDSHAKE cookie defined in the spec is:
   *  BLAKE2s(key, source_ip | source_port | siv_key_source)
   *
   * Since we already have a cryptographic digest of the address/port,
   * just do BLAKE2s(key, addr.hash() | siv_key_source) instead, since it saves
   * us the trouble of having to deal with address types.
   */
  hash.init(cookie.size());
  uint64_t addr_hash = addr.hash();
  bool ret = true;
  ret &= hash.update(reinterpret_cast<uint8_t*>(&addr_hash), sizeof(addr_hash));

  // By the time this routine is invoked, the pkt is known to be valid
  if (pkt.packet_type() == packet::Envelope::INIT)
    ret &= hash.update(pkt.msg_init().intro_siv_key_source());
  else if (pkt.packet_type() == packet::Envelope::HANDSHAKE)
    ret &= hash.update(pkt.msg_handshake().intro_siv_key_source());
  else
    SL_ABORT("Unsupported packet type");

  ret &= hash.final(&cookie[0], cookie.size());
  SL_ASSERT(ret);
}

bool LodpEndpoint::validate_cookie(const IPAddress& addr,
                                   const packet::Envelope& pkt) {
  rotate_cookie();

  // By the time this routine gets called, pkt contains a valid INIT/HANDSHAKE

  // By virtue of calling rotate_cookie(), cookie_ is always the current key
  ::std::array<uint8_t, kCookieLength> cookie;
  generate_cookie(*cookie_, addr, pkt, cookie);
  if (0 == crypto::memequals(pkt.msg_handshake().handshake_cookie().data(),
                             cookie.data(), cookie.size()))
    return true;

  // If the previous cookie key is still valid, check with the old key
  if (::std::chrono::steady_clock::now() < cookie_expire_time_) {
    generate_cookie(*prev_cookie_, addr, pkt, cookie);
    if (0 == crypto::memequals(pkt.msg_handshake().handshake_cookie().data(),
                               cookie.data(), cookie.size()))
      return true;
  }

  return false;
}

int LodpEndpoint::on_init_packet(const packet::Envelope& pkt,
                                 const IPAddress& addr,
                                 const uint8_t* ciphertext,
                                 const size_t len) {
  // Validate that the INIT envelope is well formed
  if (!pkt.has_msg_init()) {
    stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }
  if (!pkt.msg_init().has_intro_siv_key_source()) {
    stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }
  if (pkt.msg_init().intro_siv_key_source().length() != kSIVSourceLength) {
    stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }

  /*
   * Check to see if this INIT packet was replayed, by looking for the SIV Nonce
   * in the bloom filter.  Potentially 2 different initiators could generate the
   * same 128 bit nonces but that's unlikely (and the Bloom Filter's false
   * positive rate is higher than the odds of that happening).
   *
   * By virtue of having a valid INIT packet, it's safe to look at the
   * ciphertext buffer directly (and this is the only place not in
   * on_init_packet() that does so.
   */
  if (init_filter_->test_and_set(ciphertext + crypto::SIVBlake2sXChaCha::kSIVLength,
                                 crypto::SIVBlake2sXChaCha::kNonceLength)) {
    stats_.rx_init_replays_++;
    return kErrorInitReplayed;
  }

  /*
   * Ok, at this point this is a legitamate peer trying to connect to us, or
   * someone that's trying to DDOS us by spamming INITs.  It would be nice to be
   * able to rate-limit incoming INITs by source IP/port, but that opens the
   * code up to resource exhaustion attacks.
   */

  // Generate the INIT ACK
  ::std::unique_ptr<packet::Envelope> init_ack(new packet::Envelope());  // TODO/Performance: Buffer pool
  init_ack->set_packet_type(packet::Envelope::INIT_ACK);
  ::std::array<uint8_t, kCookieLength> cookie;
  rotate_cookie();
  generate_cookie(*cookie_, addr, pkt, cookie);
  packet::InitAck* init_ack_msg = init_ack->mutable_msg_init_ack();
  init_ack_msg->set_handshake_cookie(cookie.data(), cookie.size());

  /*
   * To avoid amplification attacks, limit the amount of random padding to the
   * size of the random padding in the INIT packet that we just received.  This
   * limits the amplification factor to 1:1, at the expense of lowering the
   * amount of variance observed in packet sizes slightly.
   */

  /**
   * @todo Investigate the tradeoff made between amplification attack prevention
   * and annonymity here.
   */
  if (pkt.has_pad()) {
    ::std::string* pad = init_ack->mutable_pad();
    size_t pad_len = rng_.get_uint32_range(pkt.pad().length());
    pad->resize(pad_len, 0);
    char *ptr = const_cast<char *>(pad->data());
    rng_.get_bytes(ptr, pad_len);
  }

  // Transmit the packet
  return send_packet(*init_ack, addr, pkt.msg_init().intro_siv_key_source());
}

int LodpEndpoint::on_handshake_packet(const packet::Envelope& pkt,
                                      const IPAddress& addr,
                                      LodpSession* tcb) {
  // Validate that the HANDSHAKE packet is well formed
  if (!pkt.has_msg_handshake()) {
    stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }
  if (!pkt.msg_handshake().has_intro_siv_key_source()) {
    stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }
  if (pkt.msg_handshake().intro_siv_key_source().length() != kSIVSourceLength) {
    stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }
  if (!pkt.msg_handshake().has_initiator_public_key()) {
    stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }
  if (pkt.msg_handshake().initiator_public_key().length() !=
      crypto::Curve25519::PublicKey::kKeyLength) {
    stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }
  if (!pkt.msg_handshake().has_handshake_cookie()) {
    stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }
  if (pkt.msg_handshake().handshake_cookie().length() != kCookieLength) {
    stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }

  /*
   * Validate the cookie to ensure it is something that we have generated and
   * something that is sufficiently recent.
   */
  if (!validate_cookie(addr, pkt)) {
    stats_.rx_invalid_cookie_++;
    return kErrorInvalidCookie;
  }

  /*
   * If we already have an existing Session associated with this peer, have the
   * Session object handle this packet.
   *
   * Note:
   * This is explicitly before the reuse check is done since the case that is
   * being handled here occurs when the HANDSHAKE ACK packet gets lost.
   */
  if (tcb != nullptr)
    return tcb->on_handshake_packet(pkt);

  /*
   * Check to see if the cookie was reused.  Retransmitted HANDSHAKE packets
   * won't trigger this as they are processed by Session::on_handshake_packet().
   *
   * Doing the check here has the sideeffect of forcing the initiator to obtain
   * a new cookie if the user rejects the connection attempt from the callback.
   */
  if (cookie_filter_->test_and_set(pkt.msg_handshake().handshake_cookie().data(),
                                   pkt.msg_handshake().handshake_cookie().length())) {
    stats_.rx_cookie_replays_++;
    return kErrorCookieReplayed;
  }

  /*
   * Pull out the peer's session key, generate the session keys, and complete
   * the ntor handshake.
   */
  const crypto::Curve25519::PublicKey
      peer_public(reinterpret_cast<const
                  uint8_t*>(pkt.msg_handshake().initiator_public_key().data()),
                  pkt.msg_handshake().initiator_public_key().length());
  const crypto::Curve25519::PrivateKey session_private(rng_);
  const crypto::Curve25519::PublicKey session_public(session_private);
  crypto::SecureBuffer shared_secret(crypto::NtorHandshake::kSecretLength, 0);
  crypto::SecureBuffer auth(crypto::NtorHandshake::kAuthLength, 0);
  if (!ntor_.responder(peer_public, *identity_public_key_, session_public,
                       *identity_private_key_, session_private, *node_id_,
                       shared_secret, auth)) {
    stats_.rx_handshake_failed_++;
    return kErrorHandshakeFailed;
  }

  // Callback to the user to inform them that a peer wishes to talk to us
  if (!callbacks_.should_accept(*this, addr.sockaddr(), addr.length()))
    return -ECONNREFUSED;

  // Allocate the TCB
  LodpSession* new_tcb = new LodpSession(*this, session_public, peer_public,
                                         shared_secret, auth, addr);
  session_table_[addr] = ::std::unique_ptr<LodpSession>(new_tcb);

  // Have the session dispatch the HANDSHAKE ACK
  int ret = new_tcb->send_handshake_ack_packet(pkt.msg_handshake().intro_siv_key_source());
  callbacks_.on_accept(*this, new_tcb, addr.sockaddr(), addr.length());
  return ret;
}

int LodpEndpoint::send_packet(const packet::Envelope& pkt,
                              const IPAddress& addr,
                              const std::string& siv_key_source) {
  // Serialize the protobuf object to a binary blob
  ::std::string serialized; // TODO/Performance: Buffer Pool
  bool ret = pkt.SerializeToString(&serialized);
  SL_ASSERT(ret);

  /*
   * Derive the peer's Session RX key from the keying material they provided in
   * the INIT/INIT ACK, and encrypt the packet
   */
  const auto siv_key = derive_initiator_siv_key(siv_key_source);
  ephemeral_tx_siv_->set_key(siv_key.data(), siv_key.length());
  ::std::string ciphertext; // TODO/Performance: Buffer pool
  ephemeral_tx_siv_->encrypt(serialized, ciphertext);
  ephemeral_tx_siv_->clear_key();

  /** @bug Someone somewhere should scrub the intro_key_source() component that
   * siv_key_source is based off of.  It's not the end of the world if we don't
   * since the key has a lifespan of 2 packets, and it's ephemeral per session,
   * but wiping it is the right thing to do.
   */

  stats_.tx_bytes_ += ciphertext.length();
  return callbacks_.sendto(*this, ciphertext.data(), ciphertext.length(),
                           addr.sockaddr(), addr.length());
}

crypto::SecureBuffer derive_intro_siv_key(const crypto::Curve25519::PublicKey&
                                          public_key) {
  const auto prk = crypto::HkdfBlake2s::extract(kIntroSalt, sizeof(kIntroSalt),
                                                public_key.buf());
  return crypto::HkdfBlake2s::expand(prk, kIntroSalt, sizeof(kIntroSalt),
                                     crypto::SIVBlake2sXChaCha::kKeyLength);
}

static inline crypto::SecureBuffer derive_initiator_siv_key(const uint8_t* src) {
  const auto prk = crypto::HkdfBlake2s::extract(kIntroSalt, sizeof(kIntroSalt),
                                                src);
  return crypto::HkdfBlake2s::expand(prk, kIntroSalt, sizeof(kIntroSalt),
                                     crypto::SIVBlake2sXChaCha::kKeyLength);
}

crypto::SecureBuffer derive_initiator_siv_key(const crypto::SecureBuffer
                                              &key_source) {
  return derive_initiator_siv_key(key_source.data());
}

crypto::SecureBuffer derive_initiator_siv_key(const ::std::string &key_source) {
  return derive_initiator_siv_key(reinterpret_cast<const
                                  uint8_t*>(key_source.data()));
}

} // namespace schanenlied
} // namespace lodp
