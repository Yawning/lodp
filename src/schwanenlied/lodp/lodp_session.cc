/**
 * @file    lodp_session.cc
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   LODP Session (IMPLEMENTATION)
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
#include "schwanenlied/lodp/lodp_session.h"
#include "schwanenlied/lodp/lodp_endpoint.h"

namespace schwanenlied {
namespace lodp {

static const uint8_t kSessionSalt[] = {
 'L', 'O', 'D', 'P', '-', 'S', 'e', 's', 's', 'i',
 'o', 'n', '-', 'B', 'L', 'A', 'K', 'E', '2', 's'
};

static crypto::SecureBuffer derive_session_siv_key(const crypto::SecureBuffer&
                                                   secret) {
  return crypto::HkdfBlake2s::expand(secret, kSessionSalt, sizeof(kSessionSalt),
                                     crypto::SIVBlake2sXChaCha::kKeyLength * 2);
}

LodpSession::LodpSession(LodpEndpoint& ep, void *ctxt,
                         const crypto::Curve25519::PublicKey& peer_identity_key,
                         const uint8_t* node_id,
                         const size_t node_id_len,
                         const IPAddress& addr) :
    ctxt_(ctxt),
    endpoint_(ep),
    state_(State::kINIT),
    peer_addr_(addr),
    peer_identity_key_(new crypto::Curve25519::PublicKey(peer_identity_key)),
    node_id_(new crypto::SecureBuffer(node_id, node_id_len)),
    ephemeral_rx_siv_(new crypto::SIVBlake2sXChaCha(ep.rng_)),
    ephemeral_tx_siv_(new crypto::SIVBlake2sXChaCha(ep.rng_)),
    tx_last_seq_(0),
    rx_last_seq_(0),
    rx_bitmap_(0),
    has_cached_state_(false),
    siv_key_source_(new crypto::SecureBuffer(ep.kSIVSourceLength, 0)),
    stats_() {
  // Validate that the user didn't screw up
  SL_ASSERT(node_id_->length() > 0);

  //  RX key (Responder->Initiator) is based off random input to the KDF
  endpoint_.rng_.get_bytes(&(*siv_key_source_)[0], siv_key_source_->length());
  const auto rx_siv_key = derive_initiator_siv_key(*siv_key_source_);
  ephemeral_rx_siv_->set_key(rx_siv_key.data(), rx_siv_key.length());

  // TX key (Initiator->Responder) is derived from public_key
  const auto intro_siv_key = derive_intro_siv_key(*peer_identity_key_);
  ephemeral_tx_siv_->set_key(intro_siv_key.data(), intro_siv_key.length());
}

LodpSession::LodpSession(LodpEndpoint& ep,
                         const crypto::Curve25519::PublicKey& session_key,
                         const crypto::Curve25519::PublicKey& peer_session_key,
                         const crypto::SecureBuffer& shared_secret,
                         const crypto::SecureBuffer& auth,
                         const IPAddress& addr) :
    ctxt_(nullptr),
    endpoint_(ep),
    state_(State::kESTABLISHED),
    peer_addr_(addr),
    ephemeral_rx_siv_(new crypto::SIVBlake2sXChaCha(ep.rng_)),
    ephemeral_tx_siv_(new crypto::SIVBlake2sXChaCha(ep.rng_)),
    tx_last_seq_(0),
    rx_last_seq_(0),
    rx_bitmap_(0),
    has_cached_state_(true),
    session_key_(new crypto::Curve25519::PublicKey(session_key)),
    peer_session_key_(new crypto::Curve25519::PublicKey(peer_session_key)),
    auth_(new crypto::SecureBuffer(auth)),
    stats_() {
  // Setup the SIV keys based on the Shared Secret
  const auto key = derive_session_siv_key(shared_secret);
  ephemeral_rx_siv_->set_key(key.data(), crypto::SIVBlake2sXChaCha::kKeyLength);
  ephemeral_tx_siv_->set_key(key.data() + crypto::SIVBlake2sXChaCha::kKeyLength,
                             crypto::SIVBlake2sXChaCha::kKeyLength);
}

LodpSession::~LodpSession() {
  // Blow up in the user's face if they didn't close()
  SL_ASSERT(state_ == State::kINVALID);
}

const size_t LodpSession::mtu() const {
  return peer_addr_.udp_mtu() - LodpEndpoint::kMinPacketLength -
      kDataFramingOverhead;
}

int LodpSession::handshake() {
  if (!peer_identity_key_)
    return kErrorNotInitiator;

  switch (state_) {
  case State::kINIT:
    return send_init_packet();
    break;
  case State::kHANDSHAKE:
    return send_handshake_packet();
    break;
  case State::kESTABLISHED: // FALLSTHROUGH
  case State::kREKEY:
    return -EISCONN;
  default:
    return -EBADFD;
  }
}

int LodpSession::send(const void* buf,
                  const size_t len) {
  if (buf == nullptr && len > 0)
    return -EINVAL;
  if (len > mtu())
    return -EMSGSIZE;
  if (state_ == State::kREKEY)
    return kErrorMustRekey;
  if (state_ != State::kESTABLISHED)
    return -ENOTCONN;

  // Generate the DATA packet and transmit it
  ::std::unique_ptr<packet::Envelope> data(new packet::Envelope());  // TODO/Performance: Buffer pool
  data->set_packet_type(packet::Envelope::DATA);
  packet::Data* data_msg = data->mutable_msg_data();
  data_msg->set_sequence_number(++tx_last_seq_);
  data_msg->set_payload(buf, len);

  if (!tx_seq_ok())
    return -ECONNABORTED;

  stats_.tx_goodput_bytes_ += len;
  stats_.generation_tx_++;
  int ret = siv_encrypt_and_xmit(*data);

  if (should_rekey())
    endpoint_.callbacks_.on_rekey_needed(*this);

  return ret;
}

int LodpSession::rekey() {
  if (!peer_identity_key_)
    return kErrorNotInitiator;

  if (state_ != State::kESTABLISHED && state_ != State::kREKEY)
    return -ENOTCONN;

  state_ = State::kREKEY;

  return send_rekey_packet();
}

int LodpSession::close(const bool send_shutdown) {
  if (state_ != State::kINVALID) {
    if (send_shutdown)
      send_shutdown_packet();
    state_ = State::kINVALID;
    endpoint_.callbacks_.on_close(*this);
  }

  // Remove the session from the endpoint's connection table
  auto got = endpoint_.session_table_.find(peer_addr_);
  SL_ASSERT(got != endpoint_.session_table_.end());
  endpoint_.session_table_.erase(got);  // This invokes ~LodpSession()

  // Elvis has left the building, the session object is no longer valid

  return kErrorOk;
}

void LodpSession::scrub_handshake_state() {
  if (has_cached_state_) {
    session_key_.reset();
    session_private_key_.reset();
    peer_session_key_.reset();
    siv_key_source_.reset();
    auth_.reset();
    has_cached_state_ = false;
  }
}

void LodpSession::pad_packet(packet::Envelope& pkt) {
  const size_t mtu = peer_addr_.udp_mtu();
  size_t pkt_sz = LodpEndpoint::kMinPacketLength + pkt.ByteSize();

  SL_ASSERT(mtu >= pkt_sz);

  pkt_sz += kMaxPadFramingOverhead;
  if (mtu > pkt_sz) {
    size_t pad_len = endpoint_.callbacks_.pad_size(*this, mtu - pkt_sz);
    if (pad_len + pkt_sz > mtu)
      pad_len = mtu - pkt_sz;
    if (pad_len > 0) {
      ::std::string* pad = pkt.mutable_pad();
      pad->resize(pad_len, 0);
      char *ptr = const_cast<char*>(pad->data());
      endpoint_.rng_.get_bytes(ptr, pad_len);
      SL_ASSERT(LodpEndpoint::kMinPacketLength + pkt.ByteSize() <= mtu);
    }
  }
}

int LodpSession::siv_encrypt_and_xmit(packet::Envelope& pkt) {
  if (state_ == State::kINVALID || state_ == State::kERROR)
    return -EBADFD;

  pad_packet(pkt);

  // Serialize the protobuf object to a binary blob
  ::std::string serialized; // TODO/Performance: Buffer Pool
  bool ret = pkt.SerializeToString(&serialized);
  SL_ASSERT(ret);

  // Encrypt the packet
  // XXX: If this is the responder, I need to encrypt with the old key if
  // state_ == REKEY.
  ::std::string ciphertext; // TODO/Performance:: Buffer Pool
  if (!prev_ephemeral_tx_siv_)
    ephemeral_tx_siv_->encrypt(serialized, ciphertext);
  else {
    // Responder, REKEY ACK in flight, encrypt with the old key
    SL_ASSERT(!peer_identity_key_);
    SL_ASSERT(state_ == State::kREKEY);
    prev_ephemeral_tx_siv_->encrypt(serialized, ciphertext);
  }

  stats_.tx_bytes_ += ciphertext.length();
  endpoint_.stats_.tx_bytes_ += ciphertext.length();
  return endpoint_.callbacks_.sendto(this->endpoint_, ciphertext.data(),
                                     ciphertext.length(), peer_addr_.sockaddr(),
                                     peer_addr_.length());
}

bool LodpSession::siv_decrypt(const uint8_t* buf,
                              const size_t buf_len,
                              ::std::string& plaintext) {
  if (state_ == State::kINVALID || state_ == State::kERROR)
    return false;

  /*
   * Try the current key first, if it's successful, we know that we can discard
   * the handshake related data if present so do so.
   */
  bool ret = ephemeral_rx_siv_->decrypt(buf, buf_len, plaintext);
  if (!peer_identity_key_) {
    if (ret) {
      /*
       * If we have are the responder and we just received a packet encrypted with
       * what we thing the most recent session key is, we can destroy the
       * handshake/rekey state because the peer needs to have received the
       * HANDSHAKE ACK/REKEY ACK to have encrypted the packet.
       */
      scrub_handshake_state();
      if (state_ == State::kREKEY) {
        prev_ephemeral_rx_siv_.reset();
        prev_ephemeral_tx_siv_.reset();
        on_rekey_done();
      }
    } else if (prev_ephemeral_rx_siv_)
      ret = prev_ephemeral_rx_siv_->decrypt(buf, buf_len, plaintext);
  }

  if (ret)
    stats_.rx_bytes_ += buf_len;

  return ret;
}

inline bool LodpSession::tx_seq_ok() {
  /*
   * If the sequence number is 0, then something went horribly wrong and the
   * session wasn't rekeyed as it should have been.
   *
   * Note:
   * It's also possible that rekeying has failed for exceedingly large number of
   * attempts, but most likely the initiator in this connection is fucking
   * broken and doesn't support rekeying.
   */
  if (tx_last_seq_ == 0) {
    state_ = State::kERROR;
    return false;
  }

  return true;
}

inline bool LodpSession::rx_seq_ok(const uint32_t seq) {
  /*
   * This implements a sliding window scheme as proposed in RFC 2401, except
   * with a 64 bit bitmap.  This limits the number of packets that can be sent
   * without rekeying to 2^32 - 1, but the threshold for rekeying is
   * considerably earlier.
   */
  if (seq == 0)
    return false;
  if (seq > rx_last_seq_) {
    uint32_t diff = seq - rx_last_seq_;
    if (diff < sizeof(rx_bitmap_) * 8) {
      // In the window
      rx_bitmap_ <<= diff;
      rx_bitmap_ |= 1;
    } else {
      // To the right of window
      rx_bitmap_ = 1;
    }
    rx_last_seq_ = seq;
  } else {
    uint32_t diff = rx_last_seq_ - seq;
    if (diff > sizeof(rx_bitmap_) * 8) {
      // To the left of the window
      return false;
    }

    if (rx_bitmap_ & (1ull << diff)) {
      // Seen in the bitmap
      return false;
    }

    rx_bitmap_ |= (1ull << diff);
  }

  return true;
}

inline bool LodpSession::should_rekey() {
  if (state_ != State::kESTABLISHED)
    return false;

  /*
   * If a peer is horribly broken they can send more than 2^32 packets using
   * the same key by sending out of window data.  They just waste bandwidth, so
   * it's ok to use the sequence number here.
   */
  if (tx_last_seq_ > kRekeyPacketCount || rx_last_seq_ > kRekeyPacketCount)
    return true;

  return false;
}

inline void LodpSession::on_rekey_done() {
  SL_ASSERT(state_ == State::kREKEY);

  // Reset the replay protection state
  tx_last_seq_ = 0;
  rx_last_seq_ = 0;
  rx_bitmap_ = 0;

  // Update the statistics
  stats_.generation_id_++;
  stats_.generation_rx_ = 0;
  stats_.generation_tx_ = 0;

  state_ = State::kESTABLISHED;
  endpoint_.callbacks_.on_rekey(*this, kErrorOk);
}

int LodpSession::send_init_packet() {
  SL_ASSERT(peer_identity_key_);
  SL_ASSERT(state_ == State::kINIT);

  // Generate the INIT packet
  ::std::unique_ptr<packet::Envelope> init(new packet::Envelope());  // TODO/Performance: Buffer pool
  init->set_packet_type(packet::Envelope::INIT);
  packet::Init* init_msg = init->mutable_msg_init();
  init_msg->set_intro_siv_key_source(siv_key_source_->data(),
                                     siv_key_source_->length());

  return siv_encrypt_and_xmit(*init);
}

int LodpSession::send_handshake_packet() {
  SL_ASSERT(peer_identity_key_);
  SL_ASSERT(state_ == State::kHANDSHAKE);

  /*
   * The cookie has a finite lifespan, if it's been too long since we received
   * the HANDSHAKE ACK, transition to the INIT state to obtain a fresh cookie
   * instead.
   */
  if (::std::chrono::steady_clock::now() > cookie_expire_time_) {
    /*
     * Discard the stale state, including the ephemeral keys that were generated
     * on the off chance that they are invalid.
     */
    cookie_.reset();
    session_key_.reset();
    session_private_key_.reset();
    state_ = State::kINIT;
    return send_init_packet();
  }

  // Generate the ephemeral Curve25519 keypair
  if (!session_private_key_) {
    session_private_key_.reset(new crypto::Curve25519::PrivateKey(endpoint_.rng_));
    session_key_.reset(new crypto::Curve25519::PublicKey(*session_private_key_));
  }

  // Generate the HANDSHAKE packet
  ::std::unique_ptr<packet::Envelope> hs(new packet::Envelope());  // TODO/Performance: Buffer pool
  hs->set_packet_type(packet::Envelope::HANDSHAKE);
  packet::Handshake* hs_msg = hs->mutable_msg_handshake();
  hs_msg->set_intro_siv_key_source(siv_key_source_->data(),
                                   siv_key_source_->length());
  hs_msg->set_initiator_public_key(session_key_->data(),
                                   session_key_->length());
  hs_msg->set_handshake_cookie(*cookie_);

  return siv_encrypt_and_xmit(*hs);
}

int LodpSession::send_handshake_ack_packet(const ::std::string& siv_key_source) {
  SL_ASSERT(!peer_identity_key_);

  if (!has_cached_state_)
    return kErrorProtocol;
  if (state_ != State::kESTABLISHED)
    return kErrorProtocol;

  // Build a HANDSHAKE ACK packet from the the cached session key/auth
  ::std::unique_ptr<packet::Envelope> hs_ack(new packet::Envelope());  // TODO/Performance: Buffer pool
  hs_ack->set_packet_type(packet::Envelope::HANDSHAKE_ACK);
  packet::HandshakeAck* hs_ack_msg = hs_ack->mutable_msg_handshake_ack();
  hs_ack_msg->set_responder_public_key(session_key_->data(),
                                       session_key_->length());
  hs_ack_msg->set_handshake_auth(auth_->data(), auth_->length());

  pad_packet(*hs_ack);

  // Transmit the packet
  stats_.tx_bytes_ += LodpEndpoint::kMinPacketLength + hs_ack->ByteSize();
  return endpoint_.send_packet(*hs_ack, peer_addr_, siv_key_source);
}

int LodpSession::send_rekey_packet() {
  SL_ASSERT(state_ == State::kREKEY);

  // Generate the new session key
  if (!session_private_key_) {
    session_private_key_.reset(new crypto::Curve25519::PrivateKey(endpoint_.rng_));
    session_key_.reset(new crypto::Curve25519::PublicKey(*session_private_key_));
    has_cached_state_ = true;
  }

  // Generate the REKEY packet
  ::std::unique_ptr<packet::Envelope> rekey(new packet::Envelope()); // TODO/Performace: Buffer pool
  rekey->set_packet_type(packet::Envelope::REKEY);
  packet::Rekey* rekey_msg = rekey->mutable_msg_rekey();
  rekey_msg->set_sequence_number(++tx_last_seq_);
  rekey_msg->set_initiator_public_key(session_key_->data(),
                                      session_key_->length());

  if (!tx_seq_ok())
    return -ECONNABORTED;

  return siv_encrypt_and_xmit(*rekey);
}

int LodpSession::send_rekey_ack_packet() {
  SL_ASSERT(!peer_identity_key_);
  SL_ASSERT(state_ == State::kREKEY);
  SL_ASSERT(has_cached_state_);

  // Build a REKEY ACK packet from the the cached session key/auth
  ::std::unique_ptr<packet::Envelope> rekey_ack(new packet::Envelope());  // TODO/Performance: Buffer pool
  rekey_ack->set_packet_type(packet::Envelope::REKEY_ACK);
  packet::RekeyAck* rekey_ack_msg = rekey_ack->mutable_msg_rekey_ack();
  rekey_ack_msg->set_sequence_number(++tx_last_seq_);
  rekey_ack_msg->set_responder_public_key(session_key_->data(),
                                          session_key_->length());
  rekey_ack_msg->set_handshake_auth(auth_->data(), auth_->length());

  if (!tx_seq_ok())
    return -ECONNABORTED;

  return siv_encrypt_and_xmit(*rekey_ack);
}

void LodpSession::send_shutdown_packet() {
  if (state_ != State::kESTABLISHED && state_ != State::kREKEY)
    return;

  // Build a SHUTDOWN packet
  ::std::unique_ptr<packet::Envelope> shutdown(new packet::Envelope());  // TODO/Performance: Buffer pool
  shutdown->set_packet_type(packet::Envelope::SHUTDOWN);
  packet::Shutdown* shutdown_msg = shutdown->mutable_msg_shutdown();
  shutdown_msg->set_sequence_number(++tx_last_seq_);

  if (!tx_seq_ok())
    return;

  siv_encrypt_and_xmit(*shutdown);
}

int LodpSession::on_data_packet(const packet::Envelope& pkt) {
  if (state_ != State::kESTABLISHED && state_ != State::kREKEY)
    return kErrorProtocol;

  // Validate the packet
  if (!pkt.has_msg_data()) {
    endpoint_.stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }
  if (!pkt.msg_data().has_sequence_number()) {
    endpoint_.stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }
  if (!pkt.msg_data().has_payload()) {
    endpoint_.stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }

  // Verify that the packet is in window
  if (!rx_seq_ok(pkt.msg_data().sequence_number()))
    return kErrorProtocol;

  stats_.generation_rx_++;
  stats_.rx_goodput_bytes_ += pkt.msg_data().payload().length();

  if (state_ != State::kREKEY && should_rekey())
    endpoint_.callbacks_.on_rekey_needed(*this);

  endpoint_.callbacks_.on_recv(*this, pkt.msg_data().payload().data(),
                               pkt.msg_data().payload().length());

  return kErrorOk;
}

int LodpSession::on_init_ack_packet(const packet::Envelope& pkt) {
  if (!peer_identity_key_)
    return kErrorProtocol;
  if (state_ != State::kINIT)
    return kErrorProtocol;

  // Validate the packet
  if (!pkt.has_msg_init_ack()) {
    endpoint_.stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }
  if (!pkt.msg_init_ack().has_handshake_cookie()) {
    endpoint_.stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }

  // Save the handshake cookie (Guess at the expiration time)
  cookie_.reset(new ::std::string(pkt.msg_init_ack().handshake_cookie()));
  cookie_expire_time_ = ::std::chrono::steady_clock::now() +
      ::std::chrono::seconds(LodpEndpoint::kCookieRotateInterval);
  has_cached_state_ = true;

  // Continue the handshake
  state_ = State::kHANDSHAKE;
  return send_handshake_packet();
}

int LodpSession::on_handshake_packet(const packet::Envelope& pkt) {
  if (peer_identity_key_)
    return kErrorProtocol;
  if (state_ != State::kESTABLISHED)
    return kErrorProtocol;
  if (!has_cached_state_)
    return kErrorProtocol;
  if (auth_ == nullptr)
    return kErrorProtocol;

  /*
   * This routine is called after HANDSHAKE packet and cookie is validated but
   * before the cookie is checked for reuse.
   *
   * We will only ever get a handshake packet with an existing TCB if:
   *  1) The HANDSHAKE ACK gets lost and the peer retransmits (most likely).
   *  2) The peer crashes between sending the HANDSHAKE and receiving the
   *     HANDSHAKE ACK, and happens to use the same source port.
   *  3) The peer attempts to open multiple Sessions to the same peer via the
   *     same LodpEndpoint.
   *
   * We handle case 1 by checking to see if the public key in the HANDSHAKE
   * packet we just received is identical to the one used when creating the TCB.
   * Naturally we would be retransmitting in error if the peer happened to have
   * reused the same Curve25519 key pair between multiple Sessions, but that
   * situation is undetectable.
   *
   * There is nothing that can be done about case 2, since LODP does not have
   * anything analagous to TCP's RST, so the HANDSHAKE packet is dropped.
   * Eventually the peer will give up, our side will reap the idle connection,
   * or the peer will retry with a different source port (NB: All of these
   * things are the responsiblity of the application code).
   *
   * As of now, liblodpxx only supports one session between any given
   * LodpEndpoint pairs, so case 3 is handled identically to case 2.
   */
  if (0 == crypto::memequals(peer_session_key_->data(),
                             pkt.msg_handshake().initiator_public_key().data(),
                             peer_session_key_->length()))
    return send_handshake_ack_packet(pkt.msg_handshake().intro_siv_key_source());

  return kErrorProtocol;
}

int LodpSession::on_handshake_ack_packet(const packet::Envelope& pkt) {
  if (!peer_identity_key_)
    return kErrorProtocol;
  if (state_ != State::kHANDSHAKE)
    return kErrorProtocol;

  SL_ASSERT(has_cached_state_);

  // Validate the packet
  if (!pkt.has_msg_handshake_ack()) {
    endpoint_.stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }
  if (!pkt.msg_handshake_ack().has_responder_public_key()) {
    endpoint_.stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }
  if (pkt.msg_handshake_ack().responder_public_key().length() !=
      crypto::Curve25519::PublicKey::kKeyLength) {
    endpoint_.stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }
  if (!pkt.msg_handshake_ack().has_handshake_auth()) {
    endpoint_.stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }
  if (pkt.msg_handshake_ack().handshake_auth().length() !=
      crypto::NtorHandshake::kAuthLength) {
    endpoint_.stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }

  // Complete the ntor handshake
  const crypto::Curve25519::PublicKey peer_public(reinterpret_cast<const
                                                  uint8_t*>(pkt.msg_handshake_ack().responder_public_key().data()),
                                                            pkt.msg_handshake_ack().responder_public_key().length());
  crypto::SecureBuffer shared_secret(crypto::NtorHandshake::kSecretLength, 0);
  const crypto::SecureBuffer peer_auth(reinterpret_cast<const
                                       uint8_t*>(pkt.msg_handshake_ack().handshake_auth().data()),
                                       pkt.msg_handshake_ack().handshake_auth().length());
  if (!endpoint_.ntor_.initiator(peer_public, *peer_identity_key_,
                                 *session_key_, *session_private_key_,
                                 *node_id_, peer_auth, shared_secret)) {
    // Connection failed, mark the Session as invalid
    scrub_handshake_state();
    state_ = State::kERROR;
    endpoint_.callbacks_.on_connect(*this, -ECONNABORTED);
    return -ECONNABORTED;
  }

  // Derive the ephemeral SIV keys
  const auto key = derive_session_siv_key(shared_secret);
  ephemeral_tx_siv_->set_key(key.data(), crypto::SIVBlake2sXChaCha::kKeyLength);
  ephemeral_rx_siv_->set_key(key.data() + crypto::SIVBlake2sXChaCha::kKeyLength,
                             crypto::SIVBlake2sXChaCha::kKeyLength);

  // Finalize the new session
  scrub_handshake_state();
  state_ = State::kESTABLISHED;
  endpoint_.callbacks_.on_connect(*this, kErrorOk);

  return kErrorOk;
}

int LodpSession::on_rekey_packet(const packet::Envelope& pkt) {
  if (peer_identity_key_)
    return kErrorProtocol;
  if (state_ != State::kESTABLISHED && state_ != State::kREKEY)
    return kErrorProtocol;

  // Validate the packet
  if (!pkt.has_msg_rekey()) {
    endpoint_.stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }
  if (!pkt.msg_rekey().has_sequence_number()) {
    endpoint_.stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }
  if (!pkt.msg_rekey().has_initiator_public_key()) {
    endpoint_.stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }
  if (pkt.msg_rekey().initiator_public_key().length() !=
      crypto::Curve25519::PublicKey::kKeyLength) {
    endpoint_.stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }

  // Verify that the packet is in window
  if (!rx_seq_ok(pkt.msg_rekey().sequence_number()))
    return kErrorProtocol;

  /*
   * If this REKEY is a retransmission, validate that the public_key used is
   * identical to the one sent previously, and just retransmit the REKEY ACK.
   */
  if (state_ == State::kREKEY) {
    if (0 == crypto::memequals(peer_session_key_->data(),
                               pkt.msg_rekey().initiator_public_key().data(),
                               peer_session_key_->length()))
      return send_rekey_ack_packet();

    /*
     * Why is the peer sending a REKEY with a different key?  I could be
     * "forgiving" and redo the ntor handshake, but since this behavior is a
     * sign of a bug in my code somewhere, just drop the packet.
     */
    return kErrorProtocol;
  }

  /*
   * Pull out the peer's session key, generate the session keys, and complete
   * the ntor handshake.
   */
  const crypto::Curve25519::PublicKey
      peer_public(reinterpret_cast<const
                  uint8_t*>(pkt.msg_rekey().initiator_public_key().data()),
                            pkt.msg_rekey().initiator_public_key().length());
  const crypto::Curve25519::PrivateKey session_private(endpoint_.rng_);
  const crypto::Curve25519::PublicKey session_public(session_private);
  crypto::SecureBuffer shared_secret(crypto::NtorHandshake::kSecretLength, 0);
  crypto::SecureBuffer auth(crypto::NtorHandshake::kAuthLength, 0);
  if (!endpoint_.ntor_.responder(peer_public, *endpoint_.identity_public_key_,
                                 session_public,
                                 *endpoint_.identity_private_key_,
                                 session_private, *endpoint_.node_id_,
                                 shared_secret, auth)) {
    return kErrorProtocol;
  }

  // Derive the new keys
  has_cached_state_ = true;
  session_key_.reset(new crypto::Curve25519::PublicKey(session_public));
  peer_session_key_.reset(new crypto::Curve25519::PublicKey(peer_public));
  auth_.reset(new crypto::SecureBuffer(auth));

  // Setup the SIV keys based on the Shared Secret
  const auto key = derive_session_siv_key(shared_secret);
  prev_ephemeral_rx_siv_.swap(ephemeral_rx_siv_);
  prev_ephemeral_tx_siv_.swap(ephemeral_tx_siv_);
  ephemeral_rx_siv_.reset(new crypto::SIVBlake2sXChaCha(endpoint_.rng_,
                                                        key.data(),
                                                        crypto::SIVBlake2sXChaCha::kKeyLength));
  ephemeral_tx_siv_.reset(new crypto::SIVBlake2sXChaCha(endpoint_.rng_,
                                                        key.data() + crypto::SIVBlake2sXChaCha::kKeyLength,
                                                        crypto::SIVBlake2sXChaCha::kKeyLength));
  state_ = State::kREKEY;

  return send_rekey_ack_packet();
}

int LodpSession::on_rekey_ack_packet(const packet::Envelope& pkt) {
  if (!peer_identity_key_)
    return kErrorProtocol;
  if (state_ != State::kREKEY)
    return kErrorProtocol;

  SL_ASSERT(has_cached_state_);

  // Validate the packet
  if (!pkt.has_msg_rekey_ack()) {
    endpoint_.stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }
  if (!pkt.msg_rekey_ack().has_sequence_number()) {
    endpoint_.stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }
  if (!pkt.msg_rekey_ack().has_responder_public_key()) {
    endpoint_.stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }
  if (pkt.msg_rekey_ack().responder_public_key().length() !=
      crypto::Curve25519::PublicKey::kKeyLength) {
    endpoint_.stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }
  if (!pkt.msg_rekey_ack().has_handshake_auth()) {
    endpoint_.stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }
  if (pkt.msg_rekey_ack().handshake_auth().length() !=
      crypto::NtorHandshake::kAuthLength) {
    endpoint_.stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }

  // Verify that the packet is in window
  if (!rx_seq_ok(pkt.msg_rekey_ack().sequence_number()))
    return kErrorProtocol;

  // Complete the ntor handshake
  const crypto::Curve25519::PublicKey peer_public(reinterpret_cast<const
                                                  uint8_t*>(pkt.msg_rekey_ack().responder_public_key().data()),
                                                            pkt.msg_rekey_ack().responder_public_key().length());
  crypto::SecureBuffer shared_secret(crypto::NtorHandshake::kSecretLength, 0);
  const crypto::SecureBuffer peer_auth(reinterpret_cast<const
                                       uint8_t*>(pkt.msg_rekey_ack().handshake_auth().data()),
                                       pkt.msg_rekey_ack().handshake_auth().length());
  if (!endpoint_.ntor_.initiator(peer_public, *peer_identity_key_,
                                 *session_key_, *session_private_key_,
                                 *node_id_, peer_auth, shared_secret)) {
    // Rekey failed, mark the Session as invalid
    scrub_handshake_state();
    state_ = State::kERROR;
    endpoint_.callbacks_.on_rekey(*this, -ECONNABORTED);
    return -ECONNABORTED;
  }

  // Derive the ephemeral SIV keys
  const auto key = derive_session_siv_key(shared_secret);
  ephemeral_tx_siv_->set_key(key.data(), crypto::SIVBlake2sXChaCha::kKeyLength);
  ephemeral_rx_siv_->set_key(key.data() + crypto::SIVBlake2sXChaCha::kKeyLength,
                             crypto::SIVBlake2sXChaCha::kKeyLength);

  // Finalize the new keys
  scrub_handshake_state();
  on_rekey_done();

  return kErrorOk;
}

int LodpSession::on_shutdown_packet(const packet::Envelope& pkt) {
  if (state_ != State::kESTABLISHED && state_ != State::kREKEY)
    return kErrorProtocol;

  // Validate the packet
  if (!pkt.has_msg_shutdown()) {
    endpoint_.stats_.rx_bad_packet_format_++;
    return kErrorBadPacketFormat;
  }
  if (!pkt.msg_shutdown().has_sequence_number()) {
    endpoint_.stats_.rx_bad_packet_format_++;
  }

  // Verify that the packet is in window
  if (!rx_seq_ok(pkt.msg_shutdown().sequence_number()))
    return kErrorProtocol;

  return close(false);
}


} // namespace lodp
} // namespace schwanenlied
