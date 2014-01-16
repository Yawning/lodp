/**
 * @file    lodp_endpoint.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   LODP endpoint
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

#ifndef SCHWANENLIED_LODP_LODP_ENDPOINT_H__
#define SCHWANENLIED_LODP_LODP_ENDPOINT_H__

#include <array>
#include <chrono>
#include <unordered_map>
#include <memory>

#include "schwanenlied/common.h"
#include "schwanenlied/bloom_filter.h"
#include "schwanenlied/ip_address.h"
#include "schwanenlied/crypto/blake2s.h"
#include "schwanenlied/crypto/curve25519.h"
#include "schwanenlied/crypto/ntor.h"
#include "schwanenlied/crypto/random.h"
#include "schwanenlied/crypto/siphash.h"
#include "schwanenlied/crypto/siv_blake2s_xchacha.h"
#include "schwanenlied/crypto/utils.h"
#include "schwanenlied/lodp/lodp_errors.h"
#include "schwanenlied/lodp/lodp_session.h"

// Autogenerated Protocol Buffers Header
#include "lodp.pb.h"

namespace schwanenlied {
namespace lodp {

/**
 * The LODP Endpoint/Session Callbacks
 *
 * To allow easy use with any networking library, the LodpEndpoint and
 * LodpSession interacts with the application code via a series of callbacks.
 * On LodpEndpoint construction, a LodpCallbacks instance is passed in that will
 * be used to signify events.
 *
 * Unless noted otherwise calling back into LodpEndpoint/LodpSession is allowed.
 */
class LodpCallbacks {
 public:
  /**
   * Send a datagram
   *
   * @warning After returning from this callback, the memory backing buf **WILL
   * BE DEALLOCATED**.  If it is not possible to send data immediately the
   * application is responsible for copying it elsewhere if it does not wish to
   * drop the packet.
   *
   * @param[in] endpoint  The LodpEndpoint that wishes to send a packet
   * @param[in] buf       The packet to send
   * @param[in] buf_len   The length of the packet
   * @param[in] addr      The destination address/port
   * @param[in] addr_len  The length of the sockaddr
   *
   * @returns Return value is ignored and propagated back to the application
   */
  virtual int sendto(LodpEndpoint& endpoint,
                     const void* buf,
                     const size_t buf_len,
                     const struct sockaddr *addr,
                     const socklen_t addr_len) = 0;

  /**
   * Set the pad size to be added to an outgoing packet
   *
   * @param[in] session   The LodpSession that is sending the packet
   * @param[in] available The amount of space available for padding
   *
   * @returns The amount of padding to add in bytes
   */
  virtual size_t pad_size(const LodpSession& session,
                          const size_t available) = 0;

  /**
   * Incoming connection (pre-HANDSHAKE ACK) callback
   *
   * This provides the application the opportunity to accept or reject a
   * connection before the HANDSHAKE ACK packet is sent.
   *
   * Applications **SHOULD NOT** call back into LodpEndpoint from this routine
   * beyond LodpEndpoint::context().
   *
   * @param[in] endpoint  The LodpEndpoint that received the incoming connection
   * @param[in] addr      The remote address/port
   * @param[in] addr_len  The length of the sockaddr
   *
   * @returns true - Accept the connection
   * @returns false - Reject the connection
   */
  virtual bool should_accept(const LodpEndpoint& endpoint,
                             const struct sockaddr* addr,
                             const socklen_t addr_len) = 0;

  /**
   * Incoming connection (post-HANDSHAKE ACK) callback
   *
   * This callback notifies the application that a new LodpSession was
   * establised with the given LodpEndpoint as the responder.
   *
   * @param[in] endpoint  The LodpEndpoint that received the incoming connection
   * @param[in] session   The newly created LodpSession
   * @param[in] addr      The remote address/port
   * @param[in] addr_len  The length of the sockaddr
   */
  virtual void on_accept(LodpEndpoint& endpoint,
                         LodpSession* session,
                         const struct sockaddr* addr,
                         const socklen_t addr_len) = 0;

  /**
   * Outgoing connection completion callback
   *
   * If the status value is not kErrorOK, the only safe thing to do with the
   * LodpSession is to call LodpSession::close().
   *
   * @param[in] session   The LodpSession that the connection attempt was being
   *                      made on
   * @param[in] status    The status of the connection attempt
   */
  virtual void on_connect(LodpSession& session,
                          const int status) = 0;

  /**
   * Incoming data callback
   *
   * @warning After returning from this callback, the memory backing buf **WILL
   * BE DEALLOCATED**.
   *
   * @param[in] session The LodpSession that received the data
   * @param[in] buf     The data payload
   * @param[in] buf_len The length of the payload
   */
  virtual void on_recv(LodpSession& session,
                       const void* buf,
                       const size_t buf_len) = 0;

  /**
   * Rekey needed callback
   *
   * This callback notifies the application that enough of the sequence number
   * space has been consumed to the point where the Initiator **MUST REKEY**
   * according to the spec.  This is called both for the Initiator and
   * Responder, despite the fact that the rekey is Initiator driven.
   *
   * @warning Do **NOT** call LodpSession::close() from within this callback.
   *
   * @param[in] session The LodpSession that should LodpSession::rekey() from
   *                    the Initiator
   */
  virtual void on_rekey_needed(LodpSession& session) = 0;

  /**
   * Rekey completion callback
   *
   * This callback notifies the application that a rekey operation has
   * completed.
   *
   * If the status value is not kErrorOK, the only safe thing to do with the
   * LodpSession is to call LodpSession::close().
   *
   * @param[in] session   The LodpSession that the rekey attempt was being made
   *                      on
   * @param[in] status    The status of the connection attempt
   */
  virtual void on_rekey(LodpSession& session,
                        const int status) = 0;

  /**
   * LodpSession teardown callback.
   *
   * This callback signifies that a LodpSession has been closed and gives the
   * application the last opportunity to interact with the LodpSession object.
   *
   * It is recommended that interaction with the LodpSession object from within
   * the callback is minimalzed.
   *
   * @warning After returning from this callback the LodpSession object **WILL BE
   * DEALLOCATED**.
   *
   * @param[in] session The LodpSession that has been closed
   */
  virtual void on_close(const LodpSession& session) = 0;

  // XXX: Logging
};

/**
 * The LODP Endpoint
 *
 * A LodpEndpoint is what handles handshaking, the first step of inbound packet
 * processing and LodpSession management.  The LodpEndpoint is what holds the
 * Identity Key for peers that able to connect and so forth.
 *
 * The interface is designed for people that are familiar with the common event
 * driven network programming libraries in mind (LodpCallbacks to handle various
 * events, with the user calling on_packet() to process incoming packets
 * destined for the LodpEndpoint.
 *
 * @todo Use schwanenlied::Timer for cookie rotation
 */
class LodpEndpoint {
 public:
  /** LodpEndpoint statistics */
  struct Stats {
    /** @{ */
    uint64_t tx_bytes_;             /**< Total bytes sent */
    uint64_t rx_bytes_;             /**< Total bytes received */
    /** @} */

    // Receive statistics (# of packets)
    /** @{ */
    uint64_t rx_undersized_;        /**< Undersized packets */
    uint64_t rx_oversized_;         /**< Oversized packets */
    uint64_t rx_decrypt_failed_;    /**< Packets we failed to decrypt */
    uint64_t rx_invalid_envelope_;  /**< Protobuf deserialization error */
    uint64_t rx_bad_packet_format_; /**< Packet format error */
    uint64_t rx_init_replays_;      /**< Replayed INIT packets */
    uint64_t rx_invalid_cookie_;    /**< Invalid HANDSHAKE cookies */
    uint64_t rx_cookie_replays_;    /**< Replayed handshake cookies */
    uint64_t rx_handshake_failed_;  /**< Failed ntor handshakes */
    /** @} */
  };

  /**
   * Create a initiator (client) only LodpEndpoint.
   *
   * This endpoint is not able to accept incoming connections due to the lack of
   * a node id and Identity Key.
   *
   * @param[in] rng           The crypto::Random instance to be used for SIV
   *                          generation, and when creating random keys
   * @param[in] callbacks     The LodpCallbacks object to use to signal events
   * @param[in] ctxt          The LodpEndpoint user context handle
   * @param[in] safe_logging  Sanitize IP addresses when logging
   */
  LodpEndpoint(const crypto::Random& rng,
               LodpCallbacks& callbacks,
               void *ctxt,
               const bool safe_logging);

  /**
   * Create a responder (client + server) LodpEndpoint.
   *
   * This endpoint is both able to accept incoming connections and connect to
   * other peers.  Unless the first capability is actually required, this should
   * not be used.
   *
   * @param[in] rng           The crypto::Random instance to be used for SIV
   *                          generation, and when creating random keys
   * @param[in] callbacks     The LodpCallbacks object to use to signal events
   * @param[in] ctxt          The LodpEndpoint user context handle
   * @param[in] safe_logging  Sanitize IP addresses when logging
   * @param[in] private_key   The crypto::Curve25519::PrivateKey to be used as
   *                          the endpoint's Identity Key.
   * @param[in] node_id       The ID of the endpoint (for crypto::NtorHandshake)
   * @param[in] node_id_len   The length of the node_id
   */
  LodpEndpoint(const crypto::Random& rng,
               LodpCallbacks& callbacks,
               void *ctxt,
               const bool safe_logging,
               const crypto::Curve25519::PrivateKey& private_key,
               const uint8_t* node_id,
               const size_t node_id_len);

  ~LodpEndpoint();

  /** @{ */
  /** Get the user defined context handle */
  void* context() const { return ctxt_; }
  /** Set the user defined context handle */
  void set_context(void *ctxt) { ctxt_ = ctxt; }
  /** @} */

  /** @{ */
  /** Get the current LodpEndpoint Stats */
  const struct Stats& stats() const { return stats_; }
  /** @} */

  /** @{ */
  /**
   * Get an existing LodpSession
   *
   * @param[in] addr          The remote LodpEndpoint's IP address/port
   *
   * @returns nullptr - No LodpSession currently exists to the remote peer
   * @returns (a pointer to the LodpSession)
   */
  LodpSession* session(const IPAddress& addr) const {
    auto got = session_table_.find(addr);
    if (got != session_table_.end())
      return got->second.get();
    return nullptr;
  }

  /**
   * Get a existing LodpSession
   *
   * This is a convenience wrapper for people that do not want to use IPAddress.
   *
   * @sa session()
   *
   * @param[in] addr          The remote LodpEndpoint's IP address/port
   * @param[in] addr_len      The length of the sockaddr
   *
   * @returns nullptr - No LodpSession currently exists to the remote peer
   * @returns (a pointer to the LodpSession)
   */
  inline LodpSession* session(const struct sockaddr* addr,
                              const socklen_t addr_len) const {
    if (!IPAddress::is_sockaddr_valid(addr, addr_len))
      return nullptr;

    const IPAddress peer_addr(hash_, addr, addr_len, safe_logging_);
    return session(peer_addr);
  }
  /** @} */

  /** @{ */
  /**
   * Connect to a remote peer
   *
   * This allocates a new session object and prepares to connect to the remote
   * peer.  Once this object has successfully returned, the caller is
   * responsible for driving the handshake process forward by invoking
   * LodpSession::handshake() (on it's own connect() does not generate any
   * network traffic).
   *
   * It is important to keep in mind that despite obtaining a pointer to a
   * LodpSession object, the LodpEndpoint maintains ownership of said object.
   * The caller **MUST NOT** delete the object (destroying the LodpEndpoint or
   * LodpSession::close() will clean up LodpSession objects).
   *
   * @param[in] ctxt          The LodpSession user context handle
   * @param[in] public_key    The remote LodpEndpoint's Identity
   *                          crypto::Curve25519::PublicKey
   * @param[in] node_id       The ID of the remote LodpEndpoint (for
   *                          crypto::NtorHandshake)
   * @param[in] node_id_len   The length of node_id
   * @param[in] addr          The remote LodpEndpoint's IP address/port
   * @param[out] session      On successful return, set the pointer to the newly
   *                          created LodpSession.
   * @returns kErrorOk      - Sucesss
   * @returns kErrorInval   - Any of the parameters are invalid
   * @returns kErrorIsConn  - A LodpSession already exists to the remote LodpEndpoint
   */
  int connect(void* ctxt,
              const crypto::Curve25519::PublicKey& public_key,
              const uint8_t* node_id,
              const size_t node_id_len,
              const IPAddress& addr,
              LodpSession*& session);

  /**
   * Connect to a remote peer given a sockaddr
   *
   * This is a convenience wrapper for people that do not want to use IPAddress.
   *
   * @sa connect()
   *
   * @param[in] ctxt          The LodpSession user context handle
   * @param[in] public_key    The remote LodpEndpoint's Identity
   *                          crypto::Curve25519::PublicKey
   * @param[in] node_id       The ID of the remote LodpEndpoint (for
   *                          crypto::NtorHandshake)
   * @param[in] node_id_len   The length of node_id
   * @param[in] addr          The remote LodpEndpoint's IP address/port
   * @param[in] addr_len      The length of the sockaddr
   * @param[out] session      On successful return, set the pointer to the newly
   *                          created LodpSession.
   * @returns kErrorOk       - Sucesss
   * @returns kErrorInval    - Any of the parameters are invalid
   * @returns kErrorAFNoSupport - The address family is not supported
   * @returns kErrorIsConn   - A LodpSession already exists to the remote LodpEndpoint
   */
  inline int connect(void* ctxt,
                     const crypto::Curve25519::PublicKey& public_key,
                     const uint8_t* node_id,
                     const size_t node_id_len,
                     const struct sockaddr *addr,
                     const socklen_t addr_len,
                     LodpSession*& session) {
    if (!IPAddress::is_sockaddr_valid(addr, addr_len))
      return kErrorAFNoSupport;

    const IPAddress dst_addr(hash_, addr, addr_len, safe_logging_);
    return connect(ctxt, public_key, node_id, node_id_len, dst_addr, session);
  }
  /** @} */

  /** @{ */
  /**
   * Process a incoming packet
   *
   * This routine is called to process a incomming packet.
   *
   * @note The return value is informative and in a lot of cases will propagate
   * what is returned from the user defined callback.  Even if a error code from
   * errors.h is returned, it is safe to process further packets.
   *
   * @param[in] buf   A pointer to a buffer containing the incoming packet
   * @param[in] buf_len The length of the incoming packet
   * @param[in] addr    The source IP address/port of the incoming packet
   *
   * @returns kErrorOK - Success
   * @returns (User specified value) - The packet triggered a callback
   * @returns (Error codes from errors.h) - The packet processing triggered an
   *          error.
   */
  int on_packet(const uint8_t* buf,
                const size_t buf_len,
                const IPAddress& addr);

  /** @{ */
  /**
   * Process a incoming packet
   *
   * This is a convenience wrapper for people that do not want to use IPAddress.
   *
   * @sa on_packet()
   *
   * @param[in] buf       A pointer to a buffer containing the incoming packet
   * @param[in] buf_len   The length of the incoming packet
   * @param[in] addr      The source IP address/port of the incoming packet
   * @param[in] addr_len  The length of the sockaddr
   *
   * @returns kErrorOK          - Success
   * @returns kErrorAFNoSupport - The address family is not supported
   * @returns (User specified value) - The packet triggered a callback
   * @returns (Error codes from errors.h) - The packet processing triggered an
   *          error.
   */
  inline int on_packet(const uint8_t* buf,
                       const size_t buf_len,
                       const struct sockaddr *addr,
                       const socklen_t addr_len) {
    if (!IPAddress::is_sockaddr_valid(addr, addr_len))
      return kErrorAFNoSupport;

    const IPAddress src_addr(hash_, addr, addr_len, safe_logging_);
    return on_packet(buf, buf_len, src_addr);
  }
  /** @} */

 private:
  LodpEndpoint() = delete;
  LodpEndpoint(const LodpEndpoint&) = delete;
  void operator=(const LodpEndpoint&) = delete;

  // Implementation specifc constants
  /** @{ */
  /** The size of the init replay BloomFilter (18232 entries) */
  static const size_t kInitFilterSize = 18;
  /** The size of the cookie replay BloomFilter (1139 entries) */
  static const size_t kCookieFilterSize = 14;
  /** The frequency at which the cookie generation key is changed (sec) */
  static const int kCookieRotateInterval = 30;
  /** The time past the cookie generation time that a cookie is valid (sec) */
  static const int kCookieGraceInterval = 30 * 2;
  /** @} */

  // Protocol constants
  /** @{ */
  /** The minimum length a packet must be to bother trial decryption */
  static const size_t kMinPacketLength = crypto::SIVBlake2sXChaCha::kSIVLength +
      crypto::SIVBlake2sXChaCha::kNonceLength;
  /** The length of the initiator key material transmitted in INIT/HANDSHAKE */
  static const size_t kSIVSourceLength = crypto::Blake2s::kKeyLength;
  /** The length of the cookie transmitted in INIT ACK/HANDSHAKE ACK */
  static const size_t kCookieLength = crypto::Blake2s::kDigestLength;
  /** @} */

  // INIT ACK cookie generation/HANDSHAKE cookie validation
  /** @{ */
  /**
   * Rotate the key used in cookie generation if needed
   */
  void rotate_cookie();

  /**
   * Given a INIT or HANDSHAKE packet, calculate (*but not validate*) a cookie
   *
   * @param[in] hash    The crypto::Blake2s instance to use when calculating the
   *                    cookie
   * @param[in] addr    The source address of the packet
   * @param[in] pkt     The packet
   * @param[out] cookie The buffer in which the cookie should be stored
   */
  void generate_cookie(crypto::Blake2s& hash,
                       const IPAddress& addr,
                       const packet::Envelope& pkt,
                       ::std::array<uint8_t, kCookieLength>& cookie);

  /**
   * Given a INIT or HANDSHAKE packet, validate the cookie
   *
   * @param[in] addr    The source address of the packet
   * @param[in] pkt     The packet
   *
   * @returns true - The cookie is valid
   * @returns false - The cookie is invalid
   */
  bool validate_cookie(const IPAddress& addr, const packet::Envelope& pkt);
  /** @} */

  // Packet RX/TX
  /** @{ */
  /**
   * Validate and process a inbound INIT packet
   *
   * Unlike every other packet type this routine examines the raw ciphertext of
   * the packet to detect if the INIT packet is a replay (A bloom filter is
   * examined to see if the nonce has been seen before).
   *
   * If the packet is valid, this will invoke the user's sendto callback to
   * transmit a INIT ACK packet.
   *
   * @param[in] pkt         The INIT packet to process
   * @param[in] addr        The source address of the packet
   * @param[in] ciphertext  The raw ciphertext of the packet
   * @param[in] len         The length of the raw ciphertext
   *
   * @returns kErrorBadPacketFormat - The INIT packet is malformed
   * @returns kErrorInitReplayed    - The INIT packet is a replay
   * @returns (User specified value) - The value returned from the sendto
   *                                   callback
   */
  int on_init_packet(const packet::Envelope& pkt,
                     const IPAddress& addr,
                     const uint8_t* ciphertext,
                     const size_t len);

  /**
   * Validate and process a inbound HANDSHAKE packet
   *
   * This routine takes a pointer to a LodpSession object because it is possible
   * to receive HANDSHAKE packets despite there being an existing LodpSession.
   *
   * @param[in] pkt   The HANDSHAKE packet to process
   * @param[in] addr  The source address of the packet
   * @param[in] tcb   The existing session if any
   *
   * @returns kErrorConnRefused     - The user refuses the incoming connection
   * @returns kErrorBadPacketFormat - The INIT packet is malformed
   * @returns kErrorInvalidCookie   - The cookie is invalid
   * @returns kErrorCookieReplayed  - The cookie has been used previously
   * @returns kErrorHandshakeFailed - The crypto::NtorHandshake fails
   * @returns kErrorProtocol - The existing LodpSession is in a state that does
   *                           not allow transmitting a HANDSHAKE ACK
   * @returns (User specified value) - The value returned from the sendto
   *          callback.
   */
  int on_handshake_packet(const packet::Envelope& pkt,
                          const IPAddress& addr,
                          LodpSession* tcb);

  /**
   * Encrypt and transmit a packet, given KDF material
   *
   * INIT ACK and HANDSHAKE ACK packets are encrypted using a ephemeral key
   * derived from material transmitted in the INIT/HANDSHAKE packets.  This
   * routine will invoke the KDF, Encrypt and Transmit such packets.
   *
   * @param[in] pkt             The INIT ACK/HANDSHAKE ACK packet to transmit
   * @param[in] addr            The destination address of the packet
   * @param[in] siv_key_source  The material passed to the KDF to derive the key
   *
   * @returns (User specified value) - The value returned from the sendto
   *          callback.
   */
  int send_packet(const packet::Envelope& pkt,
                  const IPAddress& addr,
                  const ::std::string& siv_key_source);
  /** @} */

  // User config/callbacks
  /** @{ */
  LodpCallbacks& callbacks_;  /**< Callbacks for this LodpEndpoint and LodpSession */
  void* ctxt_;                /**< The LodpEndpoint user context handle */
  const bool safe_logging_;   /**< Sanitize IP addresses when logging? */
  /** @} */

  // Generic crypto
  /** @{ */
  /** The crypto::Random instance used to generate SIVs */
  const crypto::Random& rng_;
  /** The crypto::SipHash instance used for IPAddress */
  const crypto::SipHash hash_;
  /** The crypto::NtorHandshake instance used to complete handshakes */
  crypto::NtorHandshake ntor_;
  /** @} */

  // Responder specific state
  /** @{ */
  /** Is the endpoint capable of being a responder? */
  const bool is_listening_;
  /** The crypto::NtorHandshake ID associated with this LodpEndpoint */
  ::std::unique_ptr<const crypto::SecureBuffer> node_id_;
  /** The long term LodpEndpoint Identity crypto::Curve25519::PrivateKey */
  ::std::unique_ptr<const crypto::Curve25519::PrivateKey> identity_private_key_;
  /** The long term LodpEndpoint Identity crypto::Curve25519::PublicKey */
  ::std::unique_ptr<const crypto::Curve25519::PublicKey> identity_public_key_;
  /** The crypto::SIVBlake2sXChaCha instance keyed with the Introduction key */
  ::std::unique_ptr<crypto::SIVBlake2sXChaCha> introduction_siv_;

  /**
   * The crypto::SIVBlake2sXChaCha instance used when sending INIT ACK/HANDSHAKE
   * ACK packets.
   */
  ::std::unique_ptr<crypto::SIVBlake2sXChaCha> ephemeral_tx_siv_;
  /** @} */

  // Responder handshake replay protection
  /** @{ */
  /** The INIT replay detection BloomFilter */
  ::std::unique_ptr<BloomFilter> init_filter_;
  /** The cookie replay detection BloomFilter */
  ::std::unique_ptr<BloomFilter> cookie_filter_;
  /** The crypto::Blake2s instance keyed with the most recent cookie key */
  ::std::unique_ptr<crypto::Blake2s> cookie_;
  /** The crypto::Blake2s instance keyed with the previous cookie key */
  ::std::unique_ptr<crypto::Blake2s> prev_cookie_;
  /** The next cookie rotation time */
  ::std::chrono::steady_clock::time_point cookie_rotate_time_;
  /** The cookie expiration time */
  ::std::chrono::steady_clock::time_point cookie_expire_time_;
  /** @} */

  /** @{ */
  /**
   * The session table
   *
   * When a LodpSession is removed from this table (via LodpSession::close()),
   * the resources associated with the session are released.
   */
  ::std::unordered_map<IPAddress, ::std::unique_ptr<LodpSession>> session_table_;
  /** @} */

  /** @{ */
  struct Stats stats_;    /**< Various LodpEndpoint statistics */
  /** @} */

  /** LodpSession is tightly coupled with LodpEndpoint */
  friend LodpSession;
};

crypto::SecureBuffer derive_intro_siv_key(const crypto::Curve25519::PublicKey&
                                          public_key);
crypto::SecureBuffer derive_initiator_siv_key(const crypto::SecureBuffer&
                                              key_source);
crypto::SecureBuffer derive_initiator_siv_key(const ::std::string &key_source);

} // namespace lodp
} // namespace schwanenlied

#endif // SCHWANENLIED_LODP_LODP_ENDPOINT_H__
