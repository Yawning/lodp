/*
 * lodp_pkt.c: LODP Packet Processing
 *
 * Copyright (c) 2013, Yawning Angel <yawning at schwanenlied dot me>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
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

#include <stdlib.h>
#include <time.h>
#include <assert.h>

#include "lodp.h"
#include "lodp_crypto.h"
#include "lodp_impl.h"
#include "lodp_pkt.h"


#define COOKIE_LEN			LODP_MAC_DIGEST_LEN
#define COOKIE_ROTATE_INTERVAL		30
#define COOKIE_GRACE_WINDOW		30

typedef struct {
	uint8_t bytes[COOKIE_LEN];
} lodp_cookie;


#define REKEY_TIME_MIN		5                       /* 5 sec */
#define REKEY_PACKET_COUNT	0x80000000              /* 2^31 packets */
#define REKEY_PACKET_RESP_COUNT	0xfffffbff              /* 2^32 - 1 - 1024 packets */


#if (COOKIE_LEN > PKT_COOKIE_LEN_MAX)
#error Expecting cookies that we create to be shorter than the length.
#endif


/* Packet/session related helpers */
static int siv_encrypt(lodp_endpoint *ep, const lodp_session *session,
    const lodp_siv_key *key, lodp_buf **cciphertext, lodp_buf *plaintext,
    uint16_t pad_clamp);
static int siv_decrypt(lodp_endpoint *ep, const lodp_siv_key *key,
    lodp_buf *plaintext, const uint8_t *ciphertext, size_t len);
static int generate_cookie(lodp_cookie *cookie, int prev_key, lodp_endpoint *ep,
    const lodp_pkt_raw *pkt, const struct sockaddr *addr, socklen_t addr_len);
static int ntor_handshake(lodp_session *session, lodp_siv_key *init_key,
    lodp_siv_key *resp_key, const lodp_ecdh_public_key *pub_key);

static inline int session_sendto(lodp_session *session, const lodp_buf *buf);
static inline int session_tx_seq_ok(lodp_session *session);
static inline int session_rx_seq_ok(lodp_session *session, uint32_t seq);
static inline int session_should_rekey(const lodp_session *session);
static inline void session_on_rekey(lodp_session *session);


/* Packet type specific handler routines */
static int on_init_pkt(lodp_endpoint *ep, const lodp_pkt_init *init_pkt,
    const uint8_t *ciphertext, size_t len, const struct sockaddr *addr,
    socklen_t addr_len);
static int on_handshake_pkt(lodp_endpoint *ep, lodp_session *session,
    const lodp_pkt_handshake *hs_pkt, const struct sockaddr *addr,
    socklen_t addr_len);
static int on_rekey_pkt(lodp_session *session, const lodp_pkt_rekey *rk_pkt);
static int on_data_pkt(lodp_session *session, const lodp_pkt_data *pkt);
static int on_init_ack_pkt(lodp_session *session, const lodp_pkt_init_ack *pkt);
static int on_handshake_ack_pkt(lodp_session *session, const
    lodp_pkt_handshake_ack *pkt);
static int on_rekey_ack_pkt(lodp_session *session, const lodp_pkt_rekey_ack
    *pkt);


int
lodp_on_incoming_pkt(lodp_endpoint *ep, lodp_session *session,
    const uint8_t *ciphertext, size_t len, const struct sockaddr *addr,
    socklen_t addr_len)
{
	lodp_hdr *hdr;
	lodp_buf *buf;
	int used_session_keys;
	int ret;

	assert(NULL != ep);
	assert(NULL != ciphertext);
	assert(NULL != addr);
	assert(addr_len > 0);

	buf = lodp_buf_alloc();
	if (NULL == buf) {
		lodp_log(ep, LODP_LOG_ERROR,
		    "on_packet(): Failed to allocate packet buffer");
		return (LODP_ERR_NOBUFS);
	}

	/*
	 * SIV Decrypt
	 *
	 * Note:
	 * Before calling this routine, we validiated the buffer length to
	 * ensure that at a minimum, the IV/MAC and 4 byte common packet
	 * Type/Flags/Length header is present.
	 */

	used_session_keys = 0;
	if (NULL != session) {
		/* Try the session keys first */
		ret = siv_decrypt(ep, &session->rx_key, buf, ciphertext, len);
		if (!ret) {
			used_session_keys = 1;
			goto siv_decrypt_ok;
		} else if (LODP_ERR_INVALID_MAC != ret)
			goto siv_decrypt_fail;

		/*
		 * If this is the responder, and we have a REKEY ACK in flight,
		 * try the new session keys
		 */
		if ((!session->is_initiator) && (STATE_REKEY == session->state)) {
			assert(NULL != session->handshake);
			ret = siv_decrypt(ep, &session->handshake->rx_rekey_key,
				buf, ciphertext, len);
			if (!ret) {
				used_session_keys = 1;
				session_on_rekey(session);
				lodp_handshake_free(session);
				goto siv_decrypt_ok;
			} else if (LODP_ERR_INVALID_MAC != ret)
				goto siv_decrypt_fail;
		}

		/*
		 * Invalid MAC, this could be a retransmited HANDSHAKE packet,
		 * so try the endpoint keys before giving up.
		 */
	}
	if (!ep->has_intro_keys) {
		lodp_log_addr(ep, LODP_LOG_DEBUG, addr,
		    "_on_incoming_pkt(): Packet from unknown peer");
		ep->stats.rx_invalid_mac++;
		ret = LODP_ERR_INVALID_MAC;
		goto out;
	}

	ret = siv_decrypt(ep, &ep->intro_siv_key, buf, ciphertext, len);
	if (ret) {
siv_decrypt_fail:
		if (LODP_ERR_INVALID_MAC == ret) {
			lodp_log_addr(ep, LODP_LOG_DEBUG, addr,
			    "_on_incoming_pkt(): Invalid MAC");
			ep->stats.rx_invalid_mac++;
		} else
			lodp_log_addr(ep, LODP_LOG_DEBUG, addr,
			    "_on_incoming_pkt(): SIV Decrypt failure (%d)",
			    ret);

		goto out;
	}

siv_decrypt_ok:

	/*
	 * Do the remaining packet type agnostic sanity checking
	 *
	 * Note:
	 * All that needs to be done here is to fixup pkt->length to host byte
	 * order and ensure that pkt->length >= 4 (TLV header is *always*
	 * included in the length) and pkt->length <= buf->len -
	 * PKT_TAG_LEN (The buffer we received is actually has all of
	 * the payload).
	 */

	hdr = (lodp_hdr *)buf->data;
	hdr->length = ntohs(hdr->length);
	if (hdr->length < PKT_TLV_LEN) {
		lodp_log_addr(ep, LODP_LOG_DEBUG, addr,
		    "_on_incoming_pkt(): Header length undersized (%d)",
		    hdr->length);
		ep->stats.rx_invalid_hdr++;
		ret = LODP_ERR_BAD_PACKET;
		goto out;
	}

	if (hdr->length > buf->len - PKT_TAG_LEN) {
		lodp_log_addr(ep, LODP_LOG_DEBUG, addr,
		    "_on_incoming_pkt(): Header length oversized (%d)",
		    hdr->length);
		ep->stats.rx_invalid_hdr++;
		ret = LODP_ERR_BAD_PACKET;
		goto out;
	}

	/*
	 * Actually handle the packet
	 *
	 * At this point, the packet is "tenatively" valid in that it had a
	 * valid MAC, was encrypted with a key that we understand, and the
	 * length is "valid" (May be incorrect for the specific packet type,
	 * but at least that much data is actually present).
	 */

	if (NULL != session) {
		/*
		 * It's possible to get HANDSHAKE packets even though a session
		 * already exists if the HANDSHAKE ACK got lost.  This is only
		 * valid if said packet was encrypted/MACed with the endpoint
		 * keys.
		 */

		session->stats.rx_bytes += buf->len;

		if (!used_session_keys) {
			if (PKT_HANDSHAKE != hdr->type) {
				lodp_log_session(session, LODP_LOG_DEBUG,
				    "_on_incoming_pkt(): Unexpected packet type when expecting HANDSHAKE (%x)",
				    hdr->type);
				ep->stats.rx_invalid_state++;
				ret = LODP_ERR_BAD_PACKET;
				goto out;
			}

			if (session->is_initiator) {
				lodp_log_session(session, LODP_LOG_DEBUG,
				    "_on_incoming_pkt(): HANDSHAKE when session is initiator");
				ep->stats.rx_invalid_state++;
				ret = LODP_ERR_NOT_RESPONDER;
				goto out;
			}

			ret = on_handshake_pkt(ep, session, (lodp_pkt_handshake *)hdr,
			       addr, addr_len);
			goto out;
		}

		/* Packets for an existing session */
		switch (hdr->type)
		{
		case PKT_DATA:
			ret = on_data_pkt(session, (lodp_pkt_data *)hdr);
			break;

		case PKT_INIT_ACK:
			ret = on_init_ack_pkt(session, (lodp_pkt_init_ack *)hdr);
			break;

		case PKT_HANDSHAKE_ACK:
			ret = on_handshake_ack_pkt(session, (lodp_pkt_handshake_ack *)hdr);
			break;

		case PKT_REKEY:
			ret = on_rekey_pkt(session, (lodp_pkt_rekey *)hdr);
			break;

		case PKT_REKEY_ACK:
			ret = on_rekey_ack_pkt(session, (lodp_pkt_rekey_ack *)hdr);
			break;

		default:
unknown_pkt_type:
			/* I-it's not like I decrypted that packet for you or anything... baka. */
			lodp_log_session(session, LODP_LOG_DEBUG,
			    "_on_incoming_pkt(): Unexpected packet type (%x)",
			    hdr->type);
			ep->stats.rx_invalid_state++;
			ret = LODP_ERR_BAD_PACKET;
			break;
		}
	} else {
		/* Responder handshake related packets */
		assert(ep->has_intro_keys);
		switch (hdr->type)
		{
		case PKT_INIT:
			ret = on_init_pkt(ep, (lodp_pkt_init *)hdr, ciphertext, len, addr, addr_len);
			break;

		case PKT_HANDSHAKE:
			ret = on_handshake_pkt(ep, session, (lodp_pkt_handshake *)hdr,
			       addr, addr_len);
			break;

		default:
			goto unknown_pkt_type;
		}
	}

out:
	lodp_buf_free(buf);
	return (ret);
}


int
lodp_send_data_pkt(lodp_session *session, const uint8_t *payload, size_t len)
{
	lodp_pkt_data *pkt;
	lodp_buf *ciphertext;
	lodp_buf *buf;
	int ret;

	assert(NULL != session);
	assert(STATE_ESTABLISHED == session->state);

	if (PKT_DATA_LEN + len > LODP_MSS) {
		lodp_log_session(session, LODP_LOG_ERROR,
		    "_send_data_pkt(): Payload too large (%d)",
		    len);
		return (LODP_ERR_MSGSIZE);
	}

	/* Check to see if we should be rekeying instead */
	if (session_should_rekey(session)) {
		lodp_log_session(session, LODP_LOG_WARN,
		    "_send_data_pkt(): Must rekey");
		return (LODP_ERR_MUST_REKEY);
	}

	buf = lodp_buf_alloc();
	if (NULL == buf) {
		lodp_log_session(session, LODP_LOG_ERROR,
		    "_send_data_pkt(): OOM allocating packet buffer");
		return (LODP_ERR_NOBUFS);
	}

	buf->len = PKT_DATA_LEN + len;
	assert(buf->len < LODP_MSS);

	pkt = (lodp_pkt_data *)buf->data;
	pkt->hdr.type = PKT_DATA;
	pkt->hdr.flags = 0;
	pkt->hdr.length = htons(PKT_HDR_DATA_LEN + len);
	pkt->sequence_number = htonl(++session->tx_last_seq);
	memcpy(pkt->data, payload, len);

	ret = session_tx_seq_ok(session);
	if (ret)
		goto out;

	session->stats.gen_tx_packets++;
	session->stats.tx_payload_bytes += len;

	ret = siv_encrypt(session->ep, session, &session->tx_key, &ciphertext,
	    buf, 0);
	if (ret)
		goto out;
	ret = session_sendto(session, ciphertext);
	lodp_buf_free(ciphertext);

out:
	lodp_buf_free(buf);
	return (ret);
}


int
lodp_send_init_pkt(lodp_session *session)
{
	lodp_pkt_init *pkt;
	lodp_buf *ciphertext;
	lodp_buf *buf;
	int ret;

	assert(NULL != session);
	assert(NULL != session->handshake);
	assert(session->is_initiator);
	assert(STATE_INIT == session->state);

	buf = lodp_buf_alloc();
	if (NULL == buf) {
		lodp_log_session(session, LODP_LOG_ERROR,
		    "_send_init_pkt(): OOM allocating packet buffer");
		return (LODP_ERR_NOBUFS);
	}

	buf->len = PKT_INIT_LEN;
	assert(buf->len < LODP_MSS);

	pkt = (lodp_pkt_init *)buf->data;
	pkt->hdr.type = PKT_INIT;
	pkt->hdr.flags = 0;
	pkt->hdr.length = htons(PKT_HDR_INIT_LEN);
	memcpy(pkt->intro_key_src, session->handshake->intro_key_src,
	    sizeof(pkt->intro_key_src));

	ret = siv_encrypt(session->ep, session, &session->tx_key, &ciphertext,
	    buf, 0);
	if (ret)
		goto out;
	ret = session_sendto(session, ciphertext);
	lodp_buf_free(ciphertext);

out:
	lodp_buf_free(buf);
	return (ret);
}


int
lodp_send_init_ack_pkt(lodp_endpoint *ep, const lodp_pkt_init *init_pkt, const
    lodp_siv_key *key, const struct sockaddr *addr, socklen_t addr_len)
{
	lodp_pkt_init_ack *pkt;
	lodp_buf *ciphertext;
	lodp_buf *buf;
	int ret;

	assert(NULL != ep);
	assert(NULL != init_pkt);
	assert(NULL != key);
	assert(NULL != addr);

	/* Generate the INIT ACK */
	buf = lodp_buf_alloc();
	if (NULL == buf) {
		lodp_log(ep, LODP_LOG_ERROR,
		    "_send_init_ack_pkt(): OOM allocating packet buffer");
		return (LODP_ERR_NOBUFS);
	}

	buf->len = PKT_INIT_ACK_LEN + COOKIE_LEN;
	assert(buf->len < LODP_MSS);

	pkt = (lodp_pkt_init_ack *)buf->data;
	pkt->hdr.type = PKT_INIT_ACK;
	pkt->hdr.flags = 0;
	pkt->hdr.length = htons(PKT_HDR_INIT_ACK_LEN + COOKIE_LEN);
	ret = generate_cookie((lodp_cookie *)pkt->cookie, 0, ep,
		(lodp_pkt_raw *)init_pkt, addr, addr_len);
	if (ret)
		goto out;

	/*
	 * Limit the gains to be had by trying to use INIT packets with a
	 * spoofed return address to mount an amplification attack.
	 *
	 * TODO:
	 * Investigate if it's acceptable to clamp the size of the INIT ACK to
	 * the INIT that triggered it's transmission.  Assuming someone sends a
	 * INIT with 0 padding, the INIT ACKS generated would not be padded at
	 * all, which seems suboptiomal.
	 *
	 * We currently make a tradeoff to limit the maximum amount of padding
	 * added to a INIT ACK instead to something "sensible".
	 */

	ret = siv_encrypt(ep, NULL, key, &ciphertext, buf, PKT_INIT_ACK_LEN +
		PKT_COOKIE_LEN_MAX);
	if (ret)
		goto out;
	ep->stats.tx_bytes += buf->len;
	ret = ep->callbacks.sendto_fn(ep, ciphertext->data, ciphertext->len, addr,
		addr_len);
	lodp_buf_free(ciphertext);

out:
	lodp_buf_free(buf);
	return (ret);
}


int
lodp_send_handshake_pkt(lodp_session *session)
{
	lodp_pkt_handshake *pkt;
	lodp_buf *ciphertext;
	lodp_buf *buf;
	lodp_handshake_data *hs;
	time_t now = time(NULL);
	int ret;

	assert(NULL != session);
	assert(NULL != session->handshake);
	assert(session->is_initiator);
	assert(STATE_HANDSHAKE == session->state);

	hs = session->handshake;

	/*
	 * If it has been long enough that the cookie expired, it is neccecary
	 * to send an INIT packet instead
	 */

	if ((hs->cookie_time + COOKIE_ROTATE_INTERVAL < now) &&
	    (NULL != hs->cookie)) {
		lodp_log_session(session, LODP_LOG_WARN,
		    "_send_handshake_pkt(): Cookie expired, falling back to INIT");
		session->state = STATE_INIT;
		lodp_memwipe(hs->cookie, hs->cookie_len);
		free(hs->cookie);
		hs->cookie = NULL;
		hs->cookie_len = 0;
		return (lodp_send_init_pkt(session));
	}

	buf = lodp_buf_alloc();
	if (NULL == buf) {
		lodp_log_session(session, LODP_LOG_ERROR,
		    "_send_handshake_pkt(): OOM allocating packet buffer");
		return (LODP_ERR_NOBUFS);
	}

	buf->len = PKT_HANDSHAKE_LEN + hs->cookie_len;
	assert(buf->len < LODP_MSS);

	pkt = (lodp_pkt_handshake *)buf->data;
	pkt->hdr.type = PKT_HANDSHAKE;
	pkt->hdr.flags = 0;
	pkt->hdr.length = htons(PKT_HDR_HANDSHAKE_LEN + hs->cookie_len);
	memcpy(pkt->intro_key_src, hs->intro_key_src,
	    sizeof(pkt->intro_key_src));
	lodp_ecdh_pack_pubkey(pkt->public_key,
	    &hs->session_keypair.public_key,
	    sizeof(pkt->public_key));
	memcpy(pkt->cookie, hs->cookie, hs->cookie_len);

	ret = siv_encrypt(session->ep, session, &session->tx_key, &ciphertext,
	    buf, 0);
	if (ret)
		goto out;
	ret = session_sendto(session, ciphertext);
	lodp_buf_free(ciphertext);

out:
	lodp_buf_free(buf);
	return (0);
}


int
lodp_send_handshake_ack_pkt(lodp_session *session, const lodp_siv_key *key)
{
	lodp_pkt_handshake_ack *pkt;
	lodp_buf *ciphertext;
	lodp_buf *buf;
	int ret;

	assert(NULL != session);
	assert(NULL != session->handshake);
	assert(NULL != key);
	assert(!session->is_initiator);
	assert(!session->seen_peer_data);
	assert(STATE_ESTABLISHED == session->state);

	buf = lodp_buf_alloc();
	if (NULL == buf) {
		lodp_log_session(session, LODP_LOG_ERROR,
		    "_send_handshake_ack_pkt(): OOM allocating packet buffer");
		return (LODP_ERR_NOBUFS);
	}

	buf->len = PKT_HANDSHAKE_ACK_LEN;
	assert(buf->len < LODP_MSS);

	pkt = (lodp_pkt_handshake_ack *)buf->data;
	pkt->hdr.type = PKT_HANDSHAKE_ACK;
	pkt->hdr.flags = 0;
	pkt->hdr.length = htons(PKT_HDR_HANDSHAKE_ACK_LEN);
	lodp_ecdh_pack_pubkey(pkt->public_key,
	    &session->handshake->session_keypair.public_key,
	    sizeof(pkt->public_key));
	memcpy(pkt->digest, session->handshake->session_secret_verifier,
	    LODP_MAC_DIGEST_LEN);

	ret = siv_encrypt(session->ep, NULL, key, &ciphertext, buf, 0);
	if (ret)
		goto out;
	ret = session_sendto(session, ciphertext);
	lodp_buf_free(ciphertext);

out:
	lodp_buf_free(buf);
	return (ret);
}


int
lodp_send_rekey_pkt(lodp_session *session)
{
	lodp_pkt_rekey *pkt;
	lodp_buf *ciphertext;
	lodp_buf *buf;
	int ret;

	assert(NULL != session);
	assert(NULL != session->handshake);
	assert(session->is_initiator);
	assert(STATE_REKEY == session->state);

	buf = lodp_buf_alloc();
	if (NULL == buf) {
		lodp_log_session(session, LODP_LOG_ERROR,
		    "_send_rekey_pkt(): OOM allocating packet buffer");
		return (LODP_ERR_NOBUFS);
	}

	buf->len = PKT_REKEY_LEN;
	assert(buf->len < LODP_MSS);

	pkt = (lodp_pkt_rekey *)buf->data;
	pkt->hdr.type = PKT_REKEY;
	pkt->hdr.flags = 0;
	pkt->hdr.length = htons(PKT_HDR_REKEY_LEN);
	pkt->sequence_number = htonl(++session->tx_last_seq);
	lodp_ecdh_pack_pubkey(pkt->public_key,
	    &session->handshake->session_keypair.public_key,
	    sizeof(pkt->public_key));

	ret = session_tx_seq_ok(session);
	if (ret)
		goto out;

	ret = siv_encrypt(session->ep, session, &session->tx_key, &ciphertext,
	    buf, 0);
	if (ret)
		goto out;
	ret = session_sendto(session, ciphertext);
	lodp_buf_free(ciphertext);

out:
	lodp_buf_free(buf);
	return (ret);
}


int
lodp_send_rekey_ack_pkt(lodp_session *session)
{
	lodp_pkt_rekey_ack *pkt;
	lodp_buf *ciphertext;
	lodp_buf *buf;
	int ret;

	assert(NULL != session);
	assert(NULL != session->handshake);
	assert(!session->is_initiator);
	assert(STATE_REKEY == session->state);

	buf = lodp_buf_alloc();
	if (NULL == buf) {
		lodp_log_session(session, LODP_LOG_ERROR,
		    "_send_rekey_ack_pkt(): OOM allocating packet buffer");
		return (LODP_ERR_NOBUFS);
	}

	buf->len = PKT_REKEY_ACK_LEN;
	assert(buf->len < LODP_MSS);

	pkt = (lodp_pkt_rekey_ack *)buf->data;
	pkt->hdr.type = PKT_REKEY_ACK;
	pkt->hdr.flags = 0;
	pkt->hdr.length = htons(PKT_HDR_REKEY_ACK_LEN);
	pkt->sequence_number = htonl(++session->tx_last_seq);
	lodp_ecdh_pack_pubkey(pkt->public_key,
	    &session->handshake->session_keypair.public_key,
	    sizeof(pkt->public_key));
	memcpy(pkt->digest, session->handshake->session_secret_verifier,
	    LODP_MAC_DIGEST_LEN);

	ret = session_tx_seq_ok(session);
	if (ret)
		goto out;

	ret = siv_encrypt(session->ep, session, &session->tx_key, &ciphertext, buf, 0);
	if (ret)
		goto out;
	ret = session_sendto(session, ciphertext);
	lodp_buf_free(ciphertext);

out:
	lodp_buf_free(buf);
	return (ret);
}


void
lodp_rotate_cookie_key(lodp_endpoint *ep)
{
	time_t now = time(NULL);

	assert(NULL != ep);

	lodp_log(ep, LODP_LOG_DEBUG, "_rotate_cookie_key(): Rotating cookie key");

	memcpy(&ep->prev_cookie_key, &ep->cookie_key,
	    sizeof(ep->prev_cookie_key));
	lodp_rand_bytes(&ep->cookie_key, sizeof(ep->cookie_key));

	ep->cookie_rotate_time = now;
	ep->cookie_expire_time = now + COOKIE_GRACE_WINDOW;
}


static int
siv_encrypt(lodp_endpoint *ep, const lodp_session *session,
    const lodp_siv_key *key, lodp_buf **cciphertext, lodp_buf *plaintext,
    uint16_t pad_clamp)
{
	lodp_buf *ciphertext;
	lodp_hdr *hdr;
	int ret;

	assert(NULL != ep);
	assert(NULL != key);
	assert(NULL != plaintext);

	ciphertext = lodp_buf_alloc();
	if (ciphertext == NULL) {
		lodp_log(ep, LODP_LOG_ERROR,
		    "_siv_encrypt(): Failed to allocate packet buffer");
		return (LODP_ERR_NOBUFS);
	}

	hdr = (lodp_hdr *)plaintext->data;

	/*
	 * Optionally allow the user to insert randomized padding here with a
	 * with a callback.
	 */
	if (NULL != ep->callbacks.pre_encrypt_fn) {
		if ((0 == pad_clamp) || (pad_clamp > LODP_MSS))
			pad_clamp = LODP_MSS;

		ret = ep->callbacks.pre_encrypt_fn(ep, session, plaintext->len,
			pad_clamp);
		if (ret > 0) {
			lodp_log(ep, LODP_LOG_DEBUG,
			    "_siv_encrypt(): %d (+ %d) bytes",
			    plaintext->len, ret);
			if (ret + plaintext->len > pad_clamp)
				ret = pad_clamp - plaintext->len;
			lodp_rand_bytes(((void *)hdr) + plaintext->len, ret);
			plaintext->len += ret;
		}
	}

	ciphertext->len = plaintext->len;
	ret = lodp_siv_encrypt(ciphertext->data, key, plaintext->data +
		LODP_SIV_TAG_LEN, ciphertext->len, plaintext->len - LODP_SIV_TAG_LEN);
	if (!ret) 
		*cciphertext = ciphertext;

	return (ret);
}


static int
siv_decrypt(lodp_endpoint *ep, const lodp_siv_key *key,
    lodp_buf *plaintext, const uint8_t *ciphertext, size_t len)
{
	int ret;

	assert(NULL != ep);
	assert(NULL != key);
	assert(NULL != ciphertext);
	assert(NULL != plaintext);
	assert(len > sizeof(lodp_hdr));

	/* By the time this routine is called, len is somewhat validated */
	ret = lodp_siv_decrypt(plaintext->data + LODP_SIV_TAG_LEN, key,
		ciphertext, len - LODP_SIV_TAG_LEN, len);
	if (ret)
		return (LODP_ERR_INVALID_MAC);

#ifdef TINFOIL
	/* Check for possible IV duplication */
	if (lodp_bf_a2(ep->iv_filter, ciphertext, LODP_SIV_TAG_LEN)) {
		ep->stats.rx_duplicate_iv++;
		return (LODP_ERR_DUP_IV);
	}
#endif
	plaintext->len = len;

	return (LODP_ERR_OK);
}


static int
generate_cookie(lodp_cookie *cookie, int prev_key, lodp_endpoint *ep,
    const lodp_pkt_raw *pkt, const struct sockaddr *addr,
    socklen_t addr_len)
{
	uint8_t blob[16 + 2 + LODP_SIV_KEY_LEN];
	uint8_t *p;
	time_t now = time(NULL);
	int ret;

	assert(NULL != cookie);
	assert(NULL != ep);
	assert(NULL != pkt);
	assert(NULL != addr);

	/* If the cookie key rotation time is up, rotate the key */
	if (now > ep->cookie_rotate_time + COOKIE_ROTATE_INTERVAL)
		lodp_rotate_cookie_key(ep);

	if ((PKT_INIT != pkt->hdr.type) && (PKT_HANDSHAKE != pkt->hdr.type))
		return (LODP_ERR_BAD_PACKET);

	/*
	 * Generate a cookie - OM NOM NOM
	 *
	 * This is swiped shamelessly from the DTLS RFC.  Cookies are a hash of
	 * the peer's source IP/Port combined with the immutable contents of
	 * the INIT packet.  Replay attacks are mitigated by rotating the hash
	 * key once every 30 seconds.
	 *
	 * Note:
	 * Checking for cookie reuse would be a good idea, though care must be
	 * taken to only consider cookies as "used" for connections that we
	 * have seen positive proof of the fact that the peer has completed a
	 * handshake.
	 *
	 * blob = Peer IP | Peer Port |  Peer SIV Key
	 * cookie = BLAKE2s(endpoint_cookie_key, blob);
	 */

	p = blob;
	if (AF_INET == addr->sa_family) {
		struct sockaddr_in *addr_v4 = (struct sockaddr_in *)addr;
		memcpy(p, &addr_v4->sin_addr.s_addr, 4);
		p += 4;
		memcpy(p, &addr_v4->sin_port, 2);
		p += 2;
	} else if (AF_INET6 == addr->sa_family) {
		struct sockaddr_in6 *addr_v6 = (struct sockaddr_in6 *)addr;
		memcpy(p, &addr_v6->sin6_addr.s6_addr, 16);
		p += 16;
		memcpy(p, &addr_v6->sin6_port, 2);
		p += 2;
	} else
		return (LODP_ERR_AFNOTSUPPORT);

	/* Both the INIT and HANDSHAKE packets put the key in the same place */
	if (pkt->hdr.length < 4 + LODP_SIV_SRC_LEN)
		return (LODP_ERR_BAD_PACKET);

	memcpy(p, pkt->payload, LODP_SIV_SRC_LEN);
	p += LODP_SIV_SRC_LEN;

	if (prev_key)
		ret = lodp_mac(cookie->bytes, blob, &ep->prev_cookie_key,
			COOKIE_LEN, p - blob);
	else
		ret = lodp_mac(cookie->bytes, blob, &ep->cookie_key,
			COOKIE_LEN, p - blob);
	lodp_memwipe(blob, sizeof(blob));
	return (ret);
}


static int
ntor_handshake(lodp_session *session, lodp_siv_key *init_key,
    lodp_siv_key *resp_key, const lodp_ecdh_public_key *pub_key)
{
	lodp_handshake_data *hs;
	uint8_t shared_secret[LODP_MAC_DIGEST_LEN];
	int ret;

	assert(NULL != session->handshake);

	hs = session->handshake;

	if (session->is_initiator) {
		/*
		 * Initiator:
		 *  * X -> hs->session_keypair.public_key
		 *  * x -> hs->session_keypair.private_key
		 *  * Y -> pub_key
		 *  * B -> session->remote_public_key
		 */
		ret = lodp_ntor(shared_secret,
			hs->session_secret_verifier,
			&hs->session_keypair.public_key,        /* X */
			&hs->session_keypair.private_key,       /* x */
			pub_key,                                /* Y */
			NULL,                                   /* y */
			&session->remote_public_key,            /* B */
			NULL,                                   /* b */
			session->responder_node_id,
			session->responder_node_id_len,
			sizeof(shared_secret),
			sizeof(hs->session_secret_verifier));
	} else {
		/*
		 * Responder:
		 *  * X-> pub_key
		 *  * Y -> hs->session_keypair.public_key
		 *  * y -> hs->session_keypair.private_key
		 *  * B -> ep->identity_keypair.public_key
		 *  * b -> ep->identity_keypair.private_key
		 */
		ret = lodp_ntor(shared_secret,
			hs->session_secret_verifier,
			pub_key,                                        /* X */
			NULL,                                           /* x */
			&hs->session_keypair.public_key,                /* Y */
			&hs->session_keypair.private_key,               /* y */
			&session->ep->identity_keypair.public_key,      /* B */
			&session->ep->identity_keypair.private_key,     /* b */
			session->ep->node_id,
			session->ep->node_id_len,
			sizeof(shared_secret),
			sizeof(hs->session_secret_verifier));
	}
	if (ret) {
out_err:
		lodp_memwipe(hs->session_secret_verifier,
		    sizeof(hs->session_secret_verifier));
		goto out;
	}

	ret = lodp_derive_sessionkeys(init_key, resp_key, shared_secret,
		sizeof(shared_secret));
	if (ret)
		goto out_err;

out:
	lodp_memwipe(shared_secret, sizeof(shared_secret));
	return ((LODP_ERR_OK == ret) ? ret : LODP_ERR_BAD_HANDSHAKE);
}


static inline int
session_sendto(lodp_session *session, const lodp_buf *buf)
{
	int ret;

	assert(NULL != session);
	assert(NULL != buf);

	session->ep->stats.tx_bytes += buf->len;
	session->stats.tx_bytes += buf->len;

	ret = session->ep->callbacks.sendto_fn(session->ep, buf->data,
		buf->len, (struct sockaddr *)&session->peer_addr,
		session->peer_addr_len);

	return (ret);
}


static inline int
session_tx_seq_ok(lodp_session *session)
{
	assert(NULL != session);

	/*
	 * If the sequence number is 0, then something went horribly wrong and
	 * the session wasn't rekeyed as it should have been.
	 *
	 * Note:
	 * It's also possible that this is the approximately 3 billionth rekey
	 * retransmission, but most likely the initiator in this connection is
	 * fucking broken and doesn't support rekeying.
	 */
	if (0 == session->tx_last_seq) {
		lodp_log_session(session, LODP_LOG_ERROR,
		    "_tx_seq_ok(): Sequence space exhausted");
		session->state = STATE_ERROR;
		return (LODP_ERR_CONNABORTED);
	}

	return (0);
}


static inline int
session_rx_seq_ok(lodp_session *session, uint32_t seq)
{
	uint32_t diff;

	assert(NULL != session);

	/*
	 * Guard against replay attacks on DATA/REKEY/REKEY ACK packets
	 *
	 * We implement the sliding window scheme as proposed in  RFC2401, with
	 * a 64 bit bitmap.  Note that this limits the number of packets that
	 * anyone can send on a given session without rekeying to 2^32, but
	 * the rekey algorithm kicks in before then.
	 */

	if (0 == seq) {
		session->ep->stats.rx_invalid_seq_nr++;
		return (LODP_ERR_BAD_SEQUENCE_NR);
	}

	if (seq > session->rx_last_seq) {
		diff = seq - session->rx_last_seq;
		if (diff < sizeof(session->rx_bitmap * 8)) {
			/* In the window */
			session->rx_bitmap <<= diff;
			session->rx_bitmap |= 1;
		} else {
			/* To the right of window */
			session->rx_bitmap = 1;
		}
		session->rx_last_seq = seq;
	} else {
		diff = session->rx_last_seq - seq;

		/* To the left of the windw */
		if (diff > sizeof(session->rx_bitmap) * 8) {
			session->ep->stats.rx_invalid_seq_nr++;
			return (LODP_ERR_BAD_SEQUENCE_NR);
		}

		/* Seen in the bitmap */
		if (session->rx_bitmap & ((uint64_t)1 << diff)) {
			session->ep->stats.rx_invalid_seq_nr++;
			return (LODP_ERR_BAD_SEQUENCE_NR);
		}

		session->rx_bitmap |= ((uint64_t)1 << diff);
	}

	return (LODP_ERR_OK);
}


static inline int
session_should_rekey(const lodp_session *session)
{
	if (STATE_ESTABLISHED != session->state)
		return (0);

	if (!session->is_initiator) {
		/*
		 * Allow sending as much as we want, but hold 1024 packets in
		 * reserve to have enough sequence number space to send REKEY
		 * ACKs (Clients really should have REKEYed way way way before
		 * this point though.
		 */
		if (session->stats.gen_tx_packets > REKEY_PACKET_RESP_COUNT)
			return (1);
	} else {
		/* Rekey whenever we send or receive enough packets */
		if ((session->stats.gen_tx_packets > REKEY_PACKET_COUNT) ||
		    (session->stats.gen_rx_packets > REKEY_PACKET_COUNT))
			return (1);
	}

	return (LODP_ERR_OK);
}


static inline void
session_on_rekey(lodp_session *session)
{
	assert(NULL != session);
	assert(NULL != session->handshake);
	assert(STATE_REKEY == session->state);

	/* Reset the various bits of bookkeeping. */
	session->tx_last_seq = 0;
	session->rx_last_seq = 0;
	session->rx_bitmap = 0;

	session->stats.gen_id++;
	session->stats.gen_tx_packets = 0;
	session->stats.gen_rx_packets = 0;
	session->stats.gen_time = time(NULL);

	/* Move the new keys over */
	memcpy(&session->tx_key, &session->handshake->tx_rekey_key,
	    sizeof(session->tx_key));
	memcpy(&session->rx_key, &session->handshake->rx_rekey_key,
	    sizeof(session->rx_key));

	/* Back to the established state */
	session->state = STATE_ESTABLISHED;

	lodp_log_session(session, LODP_LOG_DEBUG,
	    "_session_on_rekey(): Rekeying complete");
}


static int
on_init_pkt(lodp_endpoint *ep, const lodp_pkt_init *init_pkt,
    const uint8_t *ciphertext, size_t len, const struct sockaddr *addr,
    socklen_t addr_len)
{
	lodp_siv_key key;
	int ret;

	assert(NULL != ep);
	assert(NULL != init_pkt);
	assert(NULL != addr);

	/* Validate the INIT packet */
	if (PKT_HDR_INIT_LEN != init_pkt->hdr.length) {
		lodp_log_addr(ep, LODP_LOG_DEBUG, addr,
		    "_on_init_pkt(): Unexpected payload length (%d)",
		    init_pkt->hdr.length);
		return (LODP_ERR_BAD_PACKET);
	}

	/* Defend against INIT packet replay attacks */
	if (lodp_bf_a2(ep->init_filter, ciphertext, len)) {
		lodp_log_addr(ep, LODP_LOG_WARN, addr,
		    "_on_init_pkt(): INIT replay detected");
		ep->stats.rx_replayed_init++;
		return (LODP_ERR_DUP_INIT);
	}

	/* Pull out the peer's keys */
	ret = lodp_derive_init_introkey(&key, init_pkt->intro_key_src,
		sizeof(init_pkt->intro_key_src));
	if (ret) {
		lodp_log_addr(ep, LODP_LOG_ERROR, addr,
		    "_on_init_pkt(): Failed to derive peer key (%d)",
		    ret);
		goto out;
	}

	ret = lodp_send_init_ack_pkt(ep, init_pkt, &key, addr, addr_len);

out:
	lodp_memwipe(&key, sizeof(key));
	return (ret);
}


static int
on_handshake_pkt(lodp_endpoint *ep, lodp_session *session, const
    lodp_pkt_handshake *hs_pkt, const struct sockaddr *addr, socklen_t addr_len)
{
	lodp_ecdh_public_key pub_key;
	lodp_siv_key key;
	lodp_cookie cookie;
	time_t now = time(NULL);
	int should_callback;
	int ret;

	assert(NULL != ep);
	assert(NULL != hs_pkt);
	assert(NULL != addr);

	/* Validate the HANDSHAKE packet */
	if (PKT_HDR_HANDSHAKE_LEN + COOKIE_LEN != hs_pkt->hdr.length) {
		lodp_log_addr(ep, LODP_LOG_DEBUG, addr,
		    "_on_handshake_pkt(): Unexpected payload length (%d)",
		    hs_pkt->hdr.length);
		return (LODP_ERR_BAD_PACKET);
	}

	/* Validate the cookie */
	ret = generate_cookie(&cookie, 0, ep, (lodp_pkt_raw *)hs_pkt, addr,
		addr_len);
	if (ret) {
		lodp_log_addr(ep, LODP_LOG_WARN, addr,
		    "_on_handshake_pkt(): Failed to calculate cookie (%d)",
		    ret);
		goto out;
	}
	if (lodp_memeq(cookie.bytes, hs_pkt->cookie, COOKIE_LEN)) {
		/* If not match, check the previous cookie if not stale */
		if (now > ep->cookie_expire_time) {
bad_cookie:
			lodp_log_addr(ep, LODP_LOG_DEBUG, addr,
			    "_on_handshake_pkt(): Invalid cookie (%d)",
			    ret);
			ret = LODP_ERR_INVALID_COOKIE;
			ep->stats.rx_invalid_cookie++;
			goto out;
		}
		ret = generate_cookie(&cookie, 1, ep, (lodp_pkt_raw *)hs_pkt,
			addr, addr_len);
		if (ret) {
			lodp_log_addr(ep, LODP_LOG_WARN, addr,
			    "_on_handshake_pkt(): Failed to calculate cookie (%d)",
			    ret);
			goto out;
		}
		if (lodp_memeq(cookie.bytes, hs_pkt->cookie, COOKIE_LEN))
			goto bad_cookie;
	}

	/* Check for cookie reuse */
	if (lodp_bf_a2_test(ep->cookie_filter, cookie.bytes, COOKIE_LEN)) {
		lodp_log_addr(ep, LODP_LOG_WARN, addr,
		    "_on_handshake_pkt(): HANDSHAKE cookie replay detected (%d)",
		    ret);
		ep->stats.rx_duplicate_cookie++;
		ret = LODP_ERR_DUP_COOKIE;
		goto out;
	}

	/* Pull out the peer's keys */
	ret = lodp_derive_init_introkey(&key, hs_pkt->intro_key_src,
		sizeof(hs_pkt->intro_key_src));
	if (ret) {
		lodp_log_addr(ep, LODP_LOG_ERROR, addr,
		    "_on_handshake_pkt(): Failed to derive peer key (%d)",
		    ret);
		goto out;
	}
	lodp_ecdh_unpack_pubkey(&pub_key, hs_pkt->public_key,
	    sizeof(hs_pkt->public_key));

	/*
	 * If a session exists, a few things can have happened:
	 *  1) The HANDSHAKE_ACK got lost.
	 *  2) The one end crashed and is reusing the source port.
	 *     (Eg: RFC 793 "Half-Open Connections and Other Anomalies")
	 *  3) The client software is too damn lazy to implement their own
	 *     multiplexing and is wanting liblodp to do so.
	 *
	 * We detect 1, and retrasmit the HANDSHAKE_ACK.
	 *
	 * We ignore 2/3, on the assumption that the user implements timeouts
	 * on the responder side and will eventually kill off the stale session.
	 *
	 * I *could* go and add the notion of a RST I suppose, but that will not
	 * be a 0.0.1 feature.
	 *
	 * Case 3 is a WONTFIX on the assumpion that sockets client side are
	 * numerous.  Yes, I know Windows is brain damaged and one of the
	 * benefits of UDP is using 1 socket.  Write a proper upper layer that
	 * does multiplexing.
	 *
	 * Note:
	 * This case is explicitly not checked in the INIT handler because not
	 * doing so gives more time for either side to detect the condition and
	 * recover (It's a single packet, and cookie generation is dirt cheap).
	 */

	if (NULL != session) {
		/* Responder side TCBs start in the ESTABLISHED state */
		assert(!session->is_initiator);
		assert(STATE_ESTABLISHED != session->state);

		/*
		 * If we have not seen any payload from the user so far, the
		 * HANDSHAKE ACK got lost.  Retransmit it based off the cached
		 * shared secret/verifier.  There is no need to invoke the user
		 * callback a second time.
		 *
		 * If the protocol layered on top of LODP is of the "Server
		 * Talks First" variant, then the server potentially has
		 * transmited payload here, and wasted bandwidth, but there's
		 * nothing that can be done about that.
		 */

		if (!session->seen_peer_data) {
			lodp_log_session(session, LODP_LOG_DEBUG,
			    "_on_handshake_pkt(): Received retransmitted HANDSHAKE, resending ACK");
			should_callback = 1;
			goto do_xmit;
		}

		/*
		 * If there was payload received, then the peer is trying to
		 * open another connection reusing the source address (or
		 * someone is replaying a HANDSHAKE packet within it's window).
		 *
		 * Till there is a notion of a RST type packet, flat out ignore
		 * this and hope that the peer will go away + timeouts kick in
		 * and our upper layer expires the current session.
		 */

		ret = LODP_ERR_BAD_PACKET;
		goto out_wipe;
	} else
		should_callback = 0;

	/* Generate a TCB */
	ret = lodp_session_init(&session, NULL, ep, addr, addr_len,
		hs_pkt->public_key, sizeof(hs_pkt->public_key), NULL, 0, 0);
	if (ret)
		goto out_wipe;

	/* Save the cookie */
	session->handshake->cookie = calloc(1, COOKIE_LEN);
	if (NULL == session->handshake->cookie) {
		lodp_log_session(session, LODP_LOG_ERROR,
		    "_on_handshake_pkt(): OOM saving cookie");
		ret = LODP_ERR_NOBUFS;
		lodp_session_destroy(session);
		goto out_wipe;
	}
	session->handshake->cookie_len = COOKIE_LEN;
	memcpy(session->handshake->cookie, cookie.bytes, COOKIE_LEN);

	/* Complete our side of the modified ntor handshake */
	ret = ntor_handshake(session, &session->rx_key, &session->tx_key,
		&pub_key);
	if (ret) {
		lodp_session_destroy(session);
		goto out_wipe;
	}

do_xmit:
	ret = lodp_send_handshake_ack_pkt(session, &key);

	/* Inform the user of a incoming connection */
	if (should_callback)
		session->ep->callbacks.on_accept_fn(ep, session, addr,
		    addr_len);

out_wipe:
	lodp_memwipe(&key, sizeof(key));
	lodp_memwipe(&pub_key, sizeof(pub_key));
out:
	lodp_memwipe(&cookie, sizeof(cookie));
	return (ret);
}


static int
on_rekey_pkt(lodp_session *session, const lodp_pkt_rekey *rk_pkt)
{
	lodp_ecdh_public_key pub_key;
	time_t now = time(NULL);
	int ret = 0;

	assert(NULL != session);
	assert(NULL != rk_pkt);
	assert(PKT_REKEY == rk_pkt->hdr.type);

	if (session->is_initiator) {
		lodp_log_session(session, LODP_LOG_DEBUG,
		    "_on_rekey_pkt(): Received REKEY from responder");
		session->ep->stats.rx_invalid_state++;
		return (LODP_ERR_BAD_PACKET);
	}

	if ((STATE_ESTABLISHED != session->state) && (STATE_REKEY !=
	    session->state)) {
		lodp_log_session(session, LODP_LOG_DEBUG,
		    "_on_rekey_pkt(): Received REKEY in unexpected state (%d)",
		    session->state);
		session->ep->stats.rx_invalid_state++;
		return (LODP_ERR_BAD_PACKET);
	}

	/* Validate the REKEY packet */
	if (PKT_HDR_REKEY_LEN != rk_pkt->hdr.length) {
		lodp_log_session(session, LODP_LOG_DEBUG,
		    "_on_rekey_pkt(): Unexpected payload length (%d)",
		    rk_pkt->hdr.length);
		return (LODP_ERR_BAD_PACKET);
	}

	/* Validate the sequence number */
	ret = session_rx_seq_ok(session, ntohl(rk_pkt->sequence_number));
	if (ret)
		goto out;

	/*
	 * Limit the rekey interval to something sane so that a broken or evil
	 * client can't force us to spend a stupid amount of time doing ECDH
	 * math.
	 */
	if (now < session->stats.gen_time + REKEY_TIME_MIN) {
		lodp_log_session(session, LODP_LOG_WARN,
		    "_on_rekey_pkt(): Overaggressive rekeying by peer (%ld sec since last)",
		    now - session->stats.gen_time);
		return (LODP_ERR_BAD_PACKET);
	}

	/* Extract the peer's new public key */
	lodp_ecdh_unpack_pubkey(&pub_key, rk_pkt->public_key,
	    sizeof(rk_pkt->public_key));

	/*
	 * Detect if the REKEY we just received is a retransmission due to a
	 * REKEY ACK being lost.
	 */
	if (STATE_REKEY == session->state) {
		assert(NULL != session->handshake);

		if (lodp_memeq(pub_key.public_key,
		    session->remote_public_key.public_key,
		    sizeof(session->remote_public_key.public_key))) {
			/*
			 * That's odd, the peer wants to REKEY based off a
			 * different public key, when there's a REKEY ACK in
			 * flight.  Just drop the connection.
			 */
			lodp_log_session(session, LODP_LOG_WARN,
			    "_on_rekey_pkt(): Peer attempted to rekey while rekeying");
			ret = LODP_ERR_CONNABORTED;
			session->state = STATE_ERROR;
			goto out;
		}

		/* Retransmit the REKEY ACK from the cache */
		goto do_xmit;
	}

	/* This shouldn't happen...  */
	if (NULL != session->handshake)
		lodp_handshake_free(session);

	session->state = STATE_REKEY;

	ret = lodp_handshake_init(session);
	if (ret) {
		lodp_log_session(session, LODP_LOG_ERROR,
		    "_ok_rekey_pkt(): Failed to initialize handshake state (%d)",
		    ret);
		ret = LODP_ERR_CONNABORTED;
		session->state = STATE_ERROR;
		goto out;
	}

	/* Ntor handshake */
	ret = ntor_handshake(session, &session->handshake->rx_rekey_key,
		&session->handshake->tx_rekey_key, &pub_key);
	if (ret) {
		/* Failure to rekey is fatal for the connection */
		session->state = STATE_ERROR;
		goto out;
	}

	/* Stash the public key in the TCB */
	memcpy(&session->remote_public_key, &pub_key,
	    sizeof(session->remote_public_key));

do_xmit:
	ret = lodp_send_rekey_ack_pkt(session);

out:
	lodp_memwipe(&pub_key, sizeof(pub_key));
	return (ret);
}


static int
on_data_pkt(lodp_session *session, const lodp_pkt_data *pkt)
{
	const uint8_t *payload;
	uint16_t payload_len;
	int ret;

	assert(NULL != session);
	assert(NULL != pkt);
	assert(PKT_DATA == pkt->hdr.type);

	if ((STATE_ESTABLISHED != session->state) && (STATE_REKEY !=
	    session->state)) {
		lodp_log_session(session, LODP_LOG_DEBUG,
		    "_on_data_pkt(): Received DATA in unexpected state (%d)",
		    session->state);
		session->ep->stats.rx_invalid_state++;
		return (LODP_ERR_BAD_PACKET);
	}

	/*
	 * If this is the first DATA packet we received, there is session state
	 * that needs to be initialized.
	 */

	if (!session->seen_peer_data) {
		session->seen_peer_data = 1;

		/*
		 * If this is the responder, then it is safe to jettison the
		 * handshake data, as the peer has clearly received the
		 * HANDSHAKE ACK.
		 */
		if ((!session->is_initiator) && (NULL != session->handshake)) {
			lodp_bf_a2(session->ep->cookie_filter,
			    session->handshake->cookie,
			    session->handshake->cookie_len);
			lodp_handshake_free(session);
		}
	}

	/* Validate the sequence number */
	ret = session_rx_seq_ok(session, ntohl(pkt->sequence_number));
	if (ret)
		goto out;

	/*
	 * Note:
	 * The packet header including the length is already known to be valid
	 * at this point.  No further validation neccecary since we support
	 * payloads ranging from 0 bytes up to the maximum.
	 */

	payload = pkt->data;
	payload_len = pkt->hdr.length - PKT_HDR_DATA_LEN;

	session->stats.gen_rx_packets++;
	session->stats.rx_payload_bytes += payload_len;

	ret = session->ep->callbacks.on_recv_fn(session, payload, payload_len);

out:
	return (ret);
}


static int
on_init_ack_pkt(lodp_session *session, const lodp_pkt_init_ack *pkt)
{
	uint8_t *cookie;
	size_t cookie_len;

	assert(NULL != session);
	assert(NULL != pkt);
	assert(PKT_INIT_ACK == pkt->hdr.type);

	/* INIT ACK when in invalid states is silently dropped */
	if ((!session->is_initiator) || (STATE_INIT != session->state)) {
		lodp_log_session(session, LODP_LOG_DEBUG,
		    "_on_init_ack_pkt(): Received INIT ACK in unexpected state (%d)",
		    session->state);
		session->ep->stats.rx_invalid_state++;
		return (LODP_ERR_BAD_PACKET);
	}

	assert(NULL != session->handshake);

	/*
	 * Save the cookie
	 *
	 * Note:
	 * Yes, this is a malloc in the critical path.  While it is possible to
	 * assume that the peer is using the liblodp cookie format and include
	 * a static cookie field in the TCB, this will break with non-liblodp
	 * implementations and isn't future proof.
	 */

	cookie_len = pkt->hdr.length - PKT_HDR_INIT_ACK_LEN;
	if ((0 == cookie_len) || (cookie_len > PKT_COOKIE_LEN_MAX)) {
		lodp_log_session(session, LODP_LOG_DEBUG,
		    "_on_init_ack_pkt(): Unexpected cookie length (%d)",
		    cookie_len);
		return (LODP_ERR_BAD_PACKET);
	}

	cookie = calloc(1, cookie_len);
	if (NULL == cookie) {
		lodp_log_session(session, LODP_LOG_ERROR,
		    "_on_init_ack_pkt(): OOM saving cookie");
		session->state = STATE_ERROR;
		session->ep->callbacks.on_connect_fn(session, LODP_ERR_NOBUFS);
		return (LODP_ERR_NOBUFS);
	}
	memcpy(cookie, pkt->cookie, cookie_len);

	session->handshake->cookie = cookie;
	session->handshake->cookie_len = cookie_len;
	session->handshake->cookie_time = time(NULL);

	/* Send a HANDSHAKE */
	session->state = STATE_HANDSHAKE;
	return (lodp_handshake(session));
}


static int
on_handshake_ack_pkt(lodp_session *session, const lodp_pkt_handshake_ack *pkt)
{
	lodp_ecdh_public_key pub_key;
	int ret;

	assert(NULL != session);
	assert(NULL != pkt);
	assert(PKT_HANDSHAKE_ACK == pkt->hdr.type);

	/* HANDSHAKE ACK when in invalid states is silently dropped */
	if ((!session->is_initiator) || (STATE_HANDSHAKE != session->state)) {
		lodp_log_session(session, LODP_LOG_DEBUG,
		    "_on_handshake_ack_pkt(): Received HANDSHAKE ACK in unexpected state (%d)",
		    session->state);
		session->ep->stats.rx_invalid_state++;
		return (LODP_ERR_BAD_PACKET);
	}

	assert(NULL != session->handshake);

	/* Validate the HANDSHAKE ACK */
	if (PKT_HDR_HANDSHAKE_ACK_LEN != pkt->hdr.length) {
		lodp_log_session(session, LODP_LOG_DEBUG,
		    "_on_handshake_ack_pkt(): Unexpected payload length (%d)",
		    pkt->hdr.length);
		return (LODP_ERR_BAD_PACKET);
	}

	/* Pull out the responder's public key */
	lodp_ecdh_unpack_pubkey(&pub_key, pkt->public_key,
	    sizeof(pkt->public_key));

	/* Complete our side of the modified ntor handshake */
	ret = ntor_handshake(session, &session->tx_key, &session->rx_key,
		&pub_key);
	if (ret) {
		session->state = STATE_ERROR;
		goto out;
	}

	/* Confirm that the correct shared secret was derived */
	if (lodp_memeq(pkt->digest, session->handshake->session_secret_verifier,
	    sizeof(pkt->digest))) {
		session->state = STATE_ERROR;
		ret = LODP_ERR_BAD_HANDSHAKE;
		goto out;
	}

	/* Inform the user that the connection is established */
	session->state = STATE_ESTABLISHED;

out:
	lodp_handshake_free(session);
	session->ep->callbacks.on_connect_fn(session, ret);
	lodp_memwipe(&pub_key, sizeof(pub_key));
	return (ret);
}


static int
on_rekey_ack_pkt(lodp_session *session, const lodp_pkt_rekey_ack *pkt)
{
	lodp_ecdh_public_key pub_key;
	int ret;

	assert(NULL != session);
	assert(NULL != pkt);
	assert(PKT_REKEY_ACK == pkt->hdr.type);

	/* REKEY ACK when in invalid states is silently dropped */
	if ((!session->is_initiator) || (STATE_REKEY != session->state)) {
		lodp_log_session(session, LODP_LOG_DEBUG,
		    "_on_init_ack_pkt(): Received REKEY ACK in unexpected state (%d)",
		    session->state);
		session->ep->stats.rx_invalid_state++;
		return (LODP_ERR_BAD_PACKET);
	}

	assert(NULL != session->handshake);

	/* Validate the REKEY ACK */
	if (PKT_HDR_REKEY_ACK_LEN != pkt->hdr.length)
		return (LODP_ERR_BAD_PACKET);

	/* Validate the sequence number */
	ret = session_rx_seq_ok(session, ntohl(pkt->sequence_number));
	if (ret) {
		session->state = STATE_ERROR;
		goto out;
	}

	/* Pull out the responder's public key */
	lodp_ecdh_unpack_pubkey(&pub_key, pkt->public_key,
	    sizeof(pkt->public_key));

	/* Complete our side of the modified ntor handshake */
	ret = ntor_handshake(session, &session->handshake->tx_rekey_key,
		&session->handshake->rx_rekey_key, &pub_key);
	if (ret) {
		session->state = STATE_ERROR;
		goto out;
	}

	/* Confirm that the correct shared secret was derived */
	if (lodp_memeq(pkt->digest, session->handshake->session_secret_verifier,
	    sizeof(pkt->digest))) {
		session->state = STATE_ERROR;
		ret = LODP_ERR_BAD_HANDSHAKE;
		goto out;
	}

	session_on_rekey(session);
out:
	lodp_handshake_free(session);
	session->ep->callbacks.on_rekey_fn(session, ret);
	lodp_memwipe(&pub_key, sizeof(pub_key));
	return (ret);
}
