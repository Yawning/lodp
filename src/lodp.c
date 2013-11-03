/*
 * lodp.c: LODP Public Interfaces implementation
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


#if (LODP_PUBLIC_KEY_LEN != LODP_ECDH_PUBLIC_KEY_LEN)
#error Expecting the user exposed public key length to match internal one.
#endif

#if (LODP_PRIVATE_KEY_LEN != LODP_ECDH_PRIVATE_KEY_LEN)
#error Expecting the user exposed public key length to match internal one.
#endif


static inline int session_cmp(struct lodp_session_s *e1, struct lodp_session_s
    *e2);
static inline lodp_session *session_find(lodp_endpoint *ep, const struct
    sockaddr *addr, socklen_t addr_len);
static void free_endpoint(lodp_endpoint *ep);
static void free_session(lodp_session *session);


RB_GENERATE(lodp_ep_sessions, lodp_session_s, entry, session_cmp);


int
lodp_init(void)
{
	int ret;

	/* Initialize the cryptography */
	ret = lodp_crypto_init();
	if (ret)
		return (ret);

	/* Intialize the global state */
	return (lodp_bufpool_init());
}


void
lodp_term(void)
{
	/*
	 * Destroy the global state
	 *
	 * Note: If this is called with endpoints/sessions still present, the
	 * calling code will break in hillarious ways.
	 */
	lodp_bufpool_free();
	lodp_crypto_term();
}


lodp_endpoint *
lodp_endpoint_bind(void *ctxt, const lodp_callbacks *callbacks,
    const uint8_t *priv_key, size_t priv_key_len, int unsafe_logging)
{
	lodp_endpoint *ep;

	/* Make sure that callbacks are set */
	if (NULL == callbacks)
		return (NULL);

	if ((NULL == callbacks->sendto_fn) || (NULL == callbacks->on_recv_fn) ||
	    (NULL == callbacks->on_close_fn) || (NULL == callbacks->on_rekey_fn))
		return (NULL);

	if ((NULL == priv_key) && (NULL == callbacks->on_connect_fn))
		return (NULL);

	if ((NULL != priv_key) && (NULL == callbacks->on_accept_fn))
		return (NULL);

	ep = calloc(1, sizeof(*ep));
	if (NULL == ep)
		return (NULL);

	ep->ctxt = ctxt;
	ep->use_unsafe_logging = unsafe_logging;
	memcpy(&ep->callbacks, callbacks, sizeof(ep->callbacks));
#ifdef TINFOIL
	ep->iv_filter = lodp_bf_init(500000, 0.01); /* 875175 entires */
	if (NULL == ep->iv_filter) {
		free_endpoint(ep);
		return (NULL);
	}
#endif
	RB_INIT(&ep->sessions);

	/* Outgoing only endpoints don't need further initialization */
	if (NULL == priv_key) {
		lodp_log(ep, LODP_LOG_INFO, "Client Endpoint Bound", ep);
		return (ep);
	}

	/* Endpoint that supports incoming connections */
	ep->has_intro_keys = 1;

	/* Initialize Curve25519 keys */
	if (lodp_gen_keypair(&ep->intro_ecdh_keypair, priv_key, priv_key_len)) {
		free_endpoint(ep);
		return (NULL);
	}

	/* Initialize Intro (Stegonographic) MAC/Symetric keys */
	if (lodp_derive_introkeys(&ep->intro_sym_keys,
	    &ep->intro_ecdh_keypair.public_key)) {
		free_endpoint(ep);
		return (NULL);
	}

	/* Generate random secrets for the cookie */
	lodp_rotate_cookie_key(ep);
	memcpy(&ep->prev_cookie_key, &ep->cookie_key, sizeof(ep->prev_cookie_key));

	/* Initialize the INIT replay filter */
	ep->init_filter = lodp_bf_init(16384, 0.001); /* 18232 entries */
	if (NULL == ep->init_filter) {
		free_endpoint(ep);
		return (NULL);
	}

#ifdef TINFOIL
	/* Initialize the cookie replay filter */
	ep->cookie_filter = lodp_bf_init(1024, 0.001); /* 1139 entries */
	if (NULL == ep->cookie_filter) {
		free_endpoint(ep);
		return (NULL);
	}
#endif

	lodp_log(ep, LODP_LOG_INFO, "Server Endpoint Bound", ep);

	return (ep);
}


int
lodp_endpoint_set_context(lodp_endpoint *ep, void *ctxt)
{
	if (NULL == ep)
		return (LODP_ERR_INVAL);

	ep->ctxt = ctxt;
	return (0);
}


int
lodp_endpoint_get_context(const lodp_endpoint *ep, void **ctxt)
{
	if ((NULL == ep) || (NULL == ctxt))
		return (LODP_ERR_INVAL);

	*ctxt = ep->ctxt;
	return (0);
}


ssize_t
lodp_endpoint_get_mss(const lodp_endpoint *ep)
{
	if (NULL == ep)
		return (LODP_ERR_INVAL);

	/* Return the maximum amount of payload that can be sent/received */
	return (LODP_MSS - PKT_DATA_LEN);
}


int
lodp_generate_keypair(uint8_t *pub_key, size_t *pub_key_len, uint8_t *priv_key,
    size_t *priv_key_len)
{
	lodp_ecdh_keypair keypair;
	int ret;

	if ((NULL == pub_key_len) || (NULL == priv_key_len))
		return (LODP_ERR_INVAL);

	if ((*pub_key_len >= LODP_PUBLIC_KEY_LEN) && (*priv_key_len >=
	    LODP_PRIVATE_KEY_LEN) && (NULL != pub_key) && (NULL !=
	    priv_key)) {
		ret = lodp_gen_keypair(&keypair, NULL, 0);
		if (!ret) {
			memcpy(pub_key, keypair.public_key.public_key,
			    LODP_PUBLIC_KEY_LEN);
			memcpy(priv_key, keypair.private_key.private_key,
			    LODP_PRIVATE_KEY_LEN);
		}
		lodp_memwipe(&keypair, sizeof(keypair));
	} else
		ret = LODP_ERR_NOBUFS;

	*pub_key_len = LODP_PUBLIC_KEY_LEN;
	*priv_key_len = LODP_PRIVATE_KEY_LEN;

	return (ret);
}


void
lodp_endpoint_unbind(lodp_endpoint *ep)
{
	lodp_session *session, *tmp;

	assert(NULL != ep);

	for (session = RB_MIN(lodp_ep_sessions, &ep->sessions); session != NULL;
	    session = tmp) {
		tmp = RB_NEXT(lodp_ep_sessions, &ep->sessions, session);
		lodp_close(session);
	}

	lodp_log(ep, LODP_LOG_INFO, "Endpoint Unbound", ep);

	free_endpoint(ep);
}


int
lodp_endpoint_on_packet(lodp_endpoint *ep, const uint8_t *buf, size_t len,
    const struct sockaddr *addr, socklen_t addr_len)
{
	lodp_session *session;
	lodp_buf *pkt;
	int ret;

	if ((NULL == ep) || (NULL == buf) || (NULL == addr))
		return (LODP_ERR_INVAL);

	/*
	 * Validate the packet size, and ignore under/oversized packets.
	 *
	 * Note:
	 * This lets us skip checking for the presence of the MAC/IV and TLV
	 * header in the various inbound packet processing routines since at
	 * least that much is guaranteed to be present in our inbound buffer.
	 *
	 * The Length field in the TLV header may be invalid, but it's not
	 * possible to validate that until after the packet's MAC has been
	 * validated and it has been decrypted.
	 */

	if ((len < PKT_HDR_LEN) || (len > LODP_MSS))
		return (LODP_ERR_BAD_PACKET);

	/* Copy the packet and process it */
	pkt = lodp_buf_alloc();
	if (NULL == pkt)
		return (LODP_ERR_NOBUFS);

	memcpy(pkt->ciphertext, buf, len);
	pkt->len = len;
	session = session_find(ep, addr, addr_len);
	ret = lodp_on_incoming_pkt(ep, session, pkt, addr, addr_len);
	lodp_buf_free(pkt);

	return (ret);
}


lodp_session *
lodp_connect(const void *ctxt, lodp_endpoint *ep, const struct sockaddr
    *addr, size_t addr_len, const uint8_t *pub_key,
    size_t pub_key_len)
{
	if ((NULL == ep) || (NULL == addr) || (NULL == pub_key))
		return (NULL);

	if (LODP_ECDH_PUBLIC_KEY_LEN != pub_key_len)
		return (NULL);

	if (addr_len > sizeof(struct sockaddr_storage))
		return (NULL);

	if ((AF_INET != addr->sa_family) && (AF_INET6 != addr->sa_family))
		return (NULL);

	return (lodp_session_init(ctxt, ep, addr, addr_len, pub_key, pub_key_len,
	       1));
}


lodp_session *
lodp_session_init(const void *ctxt, lodp_endpoint *ep, const struct sockaddr
    *addr, size_t addr_len, const uint8_t *pub_key, size_t
    pub_key_len, int is_initiator)
{
	lodp_session *session;

	assert(NULL != ep);
	assert(NULL != addr);
	assert(NULL != pub_key);

	/*
	 * Check for a existing connection to this peer on the same
	 * endpoint
	 */
	session = session_find(ep, addr, addr_len);
	if (NULL != session)
		return (NULL);

	session = calloc(1, sizeof(*session));
	if (NULL == session)
		return (NULL);

	session->ctxt = (void *)ctxt;
	session->ep = ep;
	memcpy(&session->peer_addr, addr, addr_len);
	session->peer_addr_len = addr_len;
	session->peer_addr_hash = lodp_hash(&session->peer_addr, addr_len);
	lodp_straddr((struct sockaddr *)&session->peer_addr, session->peer_addr_str,
	    sizeof(session->peer_addr_str), ep->use_unsafe_logging);

	/* Generate the Ephemeral Curve25519 keypair */
	if (lodp_gen_keypair(&session->session_ecdh_keypair, NULL, 0)) {
		free_session(session);
		return (NULL);
	}

	/* Store the peer's public key */
	if (lodp_gen_pubkey(&session->remote_public_key, pub_key, pub_key_len)) {
		free_session(session);
		return (NULL);
	}

	if (!is_initiator) {
		/*
		 * The rest of the things are taken care of by the handshake
		 * code
		 */
		session->state = STATE_ESTABLISHED;
		goto add_and_return;
	}

	session->state = STATE_INIT;
	session->is_initiator = 1;

	/* Derive the remote peer's intro keys */
	if (lodp_derive_introkeys(&session->tx_key,
	    &session->remote_public_key)) {
		free_session(session);
		return (NULL);
	}

	/* Generate temporary stegonographic keys for the handshake */
	lodp_rand_bytes(&session->rx_key.mac_key, sizeof(session->rx_key.mac_key));
	lodp_rand_bytes(&session->rx_key.bulk_key, sizeof(session->rx_key.bulk_key));

	lodp_session_log(session, LODP_LOG_INFO, "Client Session Initialized");

add_and_return:
	RB_INSERT(lodp_ep_sessions, &ep->sessions, session);
	return (session);
}


void
lodp_session_destroy(lodp_session *session)
{
	assert(NULL != session);
	assert(NULL != session->ep);

	RB_REMOVE(lodp_ep_sessions, &session->ep->sessions, session);
	free_session(session);
}


int
lodp_session_set_context(lodp_session *session, void *ctxt)
{
	if (NULL == session)
		return (LODP_ERR_INVAL);

	session->ctxt = ctxt;
	return (0);
}


int
lodp_session_get_context(const lodp_session *session, void **ctxt)
{
	if ((NULL == session) || (NULL == ctxt))
		return (LODP_ERR_INVAL);

	*ctxt = session->ctxt;
	return (0);
}


int
lodp_session_get_stats(const lodp_session *session, lodp_session_stats *stats)
{
	if ((NULL == session) || (NULL == stats))
		return (LODP_ERR_INVAL);

	memcpy(stats, &session->stats, sizeof(*stats));

	return (0);
}


int
lodp_handshake(lodp_session *session)
{
	if (NULL == session)
		return (LODP_ERR_INVAL);

	if (!session->is_initiator)
		return (LODP_ERR_NOT_INITIATOR);

	/*
	 * Note:
	 * It is up to the caller to rate limit this.  Poorly implemented code
	 * will spam the fuck out of various handshake packets but that's
	 * not my problem.
	 */

	switch (session->state)
	{
	case STATE_INIT:
		return (lodp_send_init_pkt(session));

	case STATE_HANDSHAKE:
		return (lodp_send_handshake_pkt(session));

	case STATE_ESTABLISHED:
	case STATE_REKEY:
		return (LODP_ERR_ISCONN);

	default:
		return (LODP_ERR_INVAL);
	}

	/* NOTREACHED */
	assert(0);
}


int
lodp_send(lodp_session *session, const void *buf, size_t len)
{
	if ((NULL == session) || ((buf == NULL) && (0 != len)))
		return (LODP_ERR_INVAL);

	if (STATE_REKEY == session->state)
		return ((session->is_initiator) ? LODP_ERR_MUST_REKEY :
		       LODP_ERR_AGAIN);

	if (STATE_ESTABLISHED != session->state)
		return (LODP_ERR_NOTCONN);

	return (lodp_send_data_pkt(session, buf, len));
}


int
lodp_rekey(lodp_session *session)
{
	if (NULL == session)
		return (LODP_ERR_INVAL);

	/* LODP rekeying is always initiator driven */
	if (!session->is_initiator) {
		/* XXX: Allow the app to retransmit REKEY ACKs? */
		return (LODP_ERR_NOT_INITIATOR);
	}

	/* Generate the new curve25519 keypair */
	if (STATE_ESTABLISHED == session->state) {
		/* If this fails, try again? */
		if (lodp_gen_keypair(&session->session_ecdh_keypair, NULL, 0))
			return (LODP_ERR_AGAIN);

		session->state = STATE_REKEY;
	}

	if (STATE_REKEY != session->state)
		return (LODP_ERR_NOTCONN);

	return (lodp_send_rekey_pkt(session));
}


void
lodp_close(lodp_session *session)
{
	assert(NULL != session);

	session->ep->callbacks.on_close_fn(session);

	lodp_session_log(session, LODP_LOG_INFO, "Session Closed");

	lodp_session_destroy(session);
}


static inline int
session_cmp(struct lodp_session_s *e1, struct lodp_session_s *e2)
{
	if (e1->peer_addr_len != e2->peer_addr_len)
		return ((e1->peer_addr_len > e2->peer_addr_len) ? 1 : -1);

	/*
	 * Envisioning a world where IPv6 is popular, use the hash of the
	 * address/port as the key of the tree, and then memcmp on collision.
	 *
	 * Slightly slower for IPv4, faster for IPv6.  Makes it harder for
	 * someone with a gigantic amount of IP addresses (huge botnet?) to mess
	 * up my tree too.
	 */

	if (e1->peer_addr_hash == e2->peer_addr_hash)
		return (memcmp(&e1->peer_addr, &e2->peer_addr, e1->peer_addr_len));

	return ((e1->peer_addr_hash > e2->peer_addr_hash) ? 1 : -1);
}


static inline lodp_session *
session_find(lodp_endpoint *ep, const struct sockaddr *addr,
    socklen_t addr_len)
{
	lodp_session find;

	memset(&find, 0, sizeof(find));
	memcpy(&find.peer_addr, addr, addr_len);
	find.peer_addr_len = addr_len;
	find.peer_addr_hash = lodp_hash(addr, addr_len);

	return (RB_FIND(lodp_ep_sessions, &ep->sessions, &find));
}


static void
free_endpoint(lodp_endpoint *ep)
{
	assert(NULL != ep);
	assert(RB_EMPTY(&ep->sessions));

	if (NULL != ep->init_filter)
		lodp_bf_free(ep->init_filter);
#ifdef TINFOIL
	if (NULL != ep->iv_filter)
		lodp_bf_free(ep->iv_filter);
	if (NULL != ep->cookie_filter)
		lodp_bf_free(ep->cookie_filter);
#endif

	lodp_memwipe(ep, sizeof(*ep));
	free(ep);
}


static void
free_session(lodp_session *session)
{
	assert(NULL != session);

	if (NULL != session->cookie) {
		lodp_memwipe(session->cookie, session->cookie_len);
		free(session->cookie);
	}

	lodp_memwipe(session, sizeof(*session));
	free(session);
}
