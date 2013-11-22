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
lodp_init(int unsafe_logging, lodp_log_level log_level)
{
	int ret;

	/* Initialize the cryptography */
	ret = lodp_crypto_init();
	if (ret)
		return (ret);

	/* Initialize the buffer pool */
	ret = lodp_bufpool_init();
	if (ret)
		return (ret);

	/* Initialize the logging code */
	ret = lodp_log_init(unsafe_logging, log_level);

	return (ret);
}


void
lodp_term(void)
{
	/*
	 * Destroy the global state
	 *
	 * Note:
	 * If this is called with endpoints/sessions still present, the
	 * calling code will break in hillarious ways.
	 */

	lodp_bufpool_free();
	lodp_crypto_term();
}


int
lodp_endpoint_bind(lodp_endpoint **eep, const void *ctxt,
    const lodp_callbacks *callbacks)
{
	lodp_endpoint *ep;

	if ((NULL == callbacks) || (NULL == eep))
		return (LODP_ERR_INVAL);

	/* A certain number of callbacks are mandetory */
	if ((NULL == callbacks->sendto_fn) || (NULL == callbacks->on_recv_fn) ||
	    (NULL == callbacks->on_close_fn) || (NULL == callbacks->on_rekey_fn))
		return (LODP_ERR_INVAL);

	ep = calloc(1, sizeof(*ep));
	if (NULL == ep)
		return (LODP_ERR_NOBUFS);

	ep->ctxt = (void *)ctxt;
	memcpy(&ep->callbacks, callbacks, sizeof(ep->callbacks));
#ifdef TINFOIL
	ep->iv_filter = lodp_bf_init(23, 0.01); /* 875175 entries */
	if (NULL == ep->iv_filter) {
		free_endpoint(ep);
		return (LODP_ERR_NOBUFS);
	}
#endif
	RB_INIT(&ep->sessions);

	lodp_log(ep, LODP_LOG_INFO, "bind(): Bound");

	*eep = ep;

	return (LODP_ERR_OK);
}


int
lodp_endpoint_listen(lodp_endpoint *ep, const uint8_t *priv_key,
    size_t priv_key_len, const uint8_t *node_id, size_t node_id_len)
{
	int ret;

	if ((NULL == ep) || (NULL == priv_key) || (NULL == node_id))
		return (LODP_ERR_INVAL);

	if (NULL == ep->callbacks.on_accept_fn) {
		lodp_log(ep, LODP_LOG_ERROR, "listen(): on_accept_fn == NULL");
		return (LODP_ERR_BADFD);
	}

	if ((0 == node_id_len) || (node_id_len > LODP_NODE_ID_LEN_MAX)) {
		lodp_log(ep, LODP_LOG_ERROR,
		    "listen(): Invalid Node ID length (%d)", node_id_len);
		return (LODP_ERR_INVAL);
	}

	/* Endpoint that supports incoming connections */
	ep->has_intro_keys = 1;

	/* Save the node id */
	ep->node_id = calloc(1, node_id_len);
	if (NULL == ep->node_id) {
		lodp_log(ep, LODP_LOG_ERROR, "listen(): OOM saving node_id");
		free_endpoint(ep);
		return (LODP_ERR_NOBUFS);
	}
	ep->node_id_len = node_id_len;
	memcpy(ep->node_id, node_id, node_id_len);

	/* Initialize Curve25519 keys */
	ret = lodp_ecdh_gen_keypair(&ep->identity_keypair, priv_key,
		priv_key_len);
	if (ret) {
		lodp_log(ep, LODP_LOG_ERROR,
		    "listen(): Failed to initalize Host key (%d)", ret);
		free_endpoint(ep);
		return (ret);
	}

	/* Initialize Introductory SIV key */
	ret = lodp_derive_resp_introkey(&ep->intro_siv_key,
		&ep->identity_keypair.public_key);
	if (ret) {
		lodp_log(ep, LODP_LOG_ERROR,
		    "listen(): Failed to derive Introductory SIV key (%d)",
		    ret);
		free_endpoint(ep);
		return (ret);
	}

	/* Generate random secrets for the cookie */
	lodp_rotate_cookie_key(ep);
	memcpy(&ep->prev_cookie_key, &ep->cookie_key,
	    sizeof(ep->prev_cookie_key));

	/* Initialize the INIT replay filter */
	ep->init_filter = lodp_bf_init(18, 0.001); /* 18232 entries */
	if (NULL == ep->init_filter) {
		lodp_log(ep, LODP_LOG_ERROR,
		    "listen(): OOM allocating init_filter");
		free_endpoint(ep);
		return (LODP_ERR_NOBUFS);
	}

	/* Initialize the cookie replay filter */
	ep->cookie_filter = lodp_bf_init(14, 0.001); /* 1139 entries */
	if (NULL == ep->cookie_filter) {
		lodp_log(ep, LODP_LOG_ERROR,
		    "listen(): OOM allocating cookie_filter");
		free_endpoint(ep);
		return (LODP_ERR_NOBUFS);
	}

	lodp_log(ep, LODP_LOG_INFO, "listen(): Listening");

	return (LODP_ERR_OK);
}


int
lodp_endpoint_set_context(lodp_endpoint *ep, void *ctxt)
{
	if (NULL == ep)
		return (LODP_ERR_INVAL);

	ep->ctxt = ctxt;
	return (LODP_ERR_OK);
}


int
lodp_endpoint_get_context(const lodp_endpoint *ep, void **ctxt)
{
	if ((NULL == ep) || (NULL == ctxt))
		return (LODP_ERR_INVAL);

	*ctxt = ep->ctxt;
	return (LODP_ERR_OK);
}


int
lodp_endpoint_get_stats(const lodp_endpoint *ep, lodp_endpoint_stats *stats)
{
	if ((NULL == ep) || (NULL == stats))
		return (LODP_ERR_INVAL);

	memcpy(stats, &ep->stats, sizeof(*ep));

	return (LODP_ERR_OK);
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

	if ((*pub_key_len >= LODP_PUBLIC_KEY_LEN) &&
	    (*priv_key_len >= LODP_PRIVATE_KEY_LEN) && (NULL != pub_key) &&
	    (NULL != priv_key)) {
		ret = lodp_ecdh_gen_keypair(&keypair, NULL, 0);
		if (!ret) {
			lodp_ecdh_pack_pubkey(pub_key, &keypair.public_key,
			    LODP_PUBLIC_KEY_LEN);
			lodp_ecdh_pack_privkey(priv_key, &keypair.private_key,
			    LODP_PRIVATE_KEY_LEN);
		}
		lodp_memwipe(&keypair, sizeof(keypair));
	} else
		ret = LODP_ERR_NOBUFS;

	*pub_key_len = LODP_PUBLIC_KEY_LEN;
	*priv_key_len = LODP_PRIVATE_KEY_LEN;

	return (ret);
}


int
lodp_endpoint_unbind(lodp_endpoint *ep)
{
	lodp_session *session, *tmp;

	if (NULL == ep)
		return (LODP_ERR_INVAL);

	for (session = RB_MIN(lodp_ep_sessions, &ep->sessions); session != NULL;
	    session = tmp) {
		tmp = RB_NEXT(lodp_ep_sessions, &ep->sessions, session);
		lodp_close(session);
	}

	lodp_log(ep, LODP_LOG_INFO, "unbind(): Unbound");

	free_endpoint(ep);

	return (LODP_ERR_OK);
}


int
lodp_endpoint_on_packet(lodp_endpoint *ep, const uint8_t *buf, size_t len,
    const struct sockaddr *addr, socklen_t addr_len)
{
	lodp_session *session;
	int ret;

	if ((NULL == ep) || (NULL == buf) || (NULL == addr))
		return (LODP_ERR_INVAL);

	ep->stats.rx_bytes += len;

	/*
	 * Validate the packet size, and ignore under/oversized packets.
	 *
	 * The Length field in the TLV header may be invalid, but it's not
	 * possible to validate that until after the packet has been
	 * decrypted/authenticated.
	 */

	if (len < PKT_HDR_LEN) {
		lodp_log_addr(ep, LODP_LOG_DEBUG, addr,
		    "on_packet(): Packet too short %d bytes", len);
		ep->stats.rx_undersized++;
		return (LODP_ERR_BAD_PACKET);
	}

	if (len > LODP_MSS) {
		lodp_log_addr(ep, LODP_LOG_DEBUG, addr,
		    "on_packet(): Packet too large %d bytes ", len);
		ep->stats.rx_oversized++;
		return (LODP_ERR_BAD_PACKET);
	}

	lodp_log_addr(ep, LODP_LOG_DEBUG, addr, "on_packet(): %d bytes", len);

	session = session_find(ep, addr, addr_len);
	ret = lodp_on_incoming_pkt(ep, session, buf, len, addr, addr_len);

	return (ret);
}


int
lodp_connect(lodp_session **ssession, const void *ctxt, lodp_endpoint *ep,
    const struct sockaddr *addr, socklen_t addr_len, const uint8_t *pub_key,
    size_t pub_key_len, const uint8_t *node_id, size_t node_id_len)
{
	lodp_session *session;
	int ret;

	if ((NULL == ep) || (NULL == addr) || (NULL == pub_key) ||
	    (NULL == node_id))
		return (LODP_ERR_INVAL);

	if (NULL == ep->callbacks.on_connect_fn) {
		lodp_log(ep, LODP_LOG_ERROR,
		    "connect(): on_connect_fn == NULL");
		return (LODP_ERR_BADFD);
	}

	if (LODP_ECDH_PUBLIC_KEY_LEN != pub_key_len)
		return (LODP_ERR_INVAL);

	if ((0 == node_id_len) || (node_id_len > LODP_NODE_ID_LEN_MAX)) {
		lodp_log(ep, LODP_LOG_ERROR,
		    "connect(): Invalid Node ID length (%d)", node_id_len);
		return (LODP_ERR_INVAL);
	}

	if ((addr_len > sizeof(struct sockaddr_storage)) ||
	    ((AF_INET != addr->sa_family) && (AF_INET6 != addr->sa_family)))
		return (LODP_ERR_AFNOTSUPPORT);

	ret = lodp_session_init(&session, ctxt, ep, addr, addr_len, pub_key,
		pub_key_len, node_id, node_id_len, 1);
	if (LODP_ERR_OK == ret) {
		*ssession = session;
		lodp_log(ep, LODP_LOG_INFO, "connect(): Connecting to peer");
	}

	return (ret);
}


int
lodp_session_init(lodp_session **ssession, const void *ctxt, lodp_endpoint *ep,
    const struct sockaddr *addr, size_t addr_len, const uint8_t *pub_key,
    size_t pub_key_len, const uint8_t *node_id, size_t node_id_len,
    int is_initiator)
{
	lodp_session *session;
	int ret;

	assert(NULL != ep);
	assert(NULL != addr);
	assert(NULL != pub_key);

	/*
	 * Check for a existing connection to this peer on the same
	 * endpoint
	 */
	session = session_find(ep, addr, addr_len);
	if (NULL != session) {
		lodp_log(ep, LODP_LOG_ERROR,
		    "_session_init(): Already have a connection to the peer");
		return (LODP_ERR_ISCONN);
	}

	session = calloc(1, sizeof(*session));
	if (NULL == session) {
		lodp_log(ep, LODP_LOG_ERROR,
		    "_session_init(): OOM allocating tcb");
		return (LODP_ERR_NOBUFS);
	}

	session->ctxt = (void *)ctxt;
	session->ep = ep;
	session->stats.gen_time = time(NULL);
	memcpy(&session->peer_addr, addr, addr_len);
	session->peer_addr_len = addr_len;
	session->peer_addr_hash = lodp_hash(&session->peer_addr, addr_len);
	lodp_straddr((struct sockaddr *)&session->peer_addr,
	    session->peer_addr_str, sizeof(session->peer_addr_str));

	ret = lodp_handshake_init(session);
	if (ret) {
		lodp_log(ep, LODP_LOG_ERROR,
		    "_session_init(): Failed to initialize handshake state (%d)",
		    ret);
		free_session(session);
		return (ret);
	}

	/* Store the peer's public key */
	lodp_ecdh_unpack_pubkey(&session->remote_public_key, pub_key,
	    pub_key_len);

	if (!is_initiator) {
		/* Responder side is done */
		session->state = STATE_ESTABLISHED;
		goto add_and_return;
	}

	/* Save the Responder's node id used in the ntor handshake */
	assert(NULL != node_id);
	assert(0 != node_id_len);
	assert(node_id_len <= LODP_NODE_ID_LEN_MAX);

	session->responder_node_id = calloc(1, node_id_len);
	if (NULL == session->responder_node_id) {
		lodp_log(ep, LODP_LOG_ERROR, "connect(): OOM saving node_id");
		free_session(session);
		return (LODP_ERR_NOBUFS);
	}
	session->responder_node_id_len = node_id_len;
	memcpy(session->responder_node_id, node_id, node_id_len);

	session->state = STATE_INIT;
	session->is_initiator = 1;

	/* Derive the remote peer's introdutory SIV key */
	ret = lodp_derive_resp_introkey(&session->tx_key,
		&session->remote_public_key);
	if (ret) {
		lodp_log(ep, LODP_LOG_ERROR,
		    "connect(): Failed to derive peer Introductory SIV key (%d)",
		    ret);
		free_session(session);
		return (ret);
	}

	/* Generate a temporary SIV key for the handshake */
	lodp_rand_bytes(session->handshake->intro_key_src,
	    sizeof(session->handshake->intro_key_src));
	ret = lodp_derive_init_introkey(&session->rx_key,
		session->handshake->intro_key_src,
		sizeof(session->handshake->intro_key_src));
	if (ret) {
		lodp_log(ep, LODP_LOG_ERROR,
		    "connect(): Failed to derive self Introductory SIV key (%d)",
		    ret);
		free_session(session);
		return (ret);
	}

add_and_return:
	RB_INSERT(lodp_ep_sessions, &ep->sessions, session);
	*ssession = session;
	return (LODP_ERR_OK);
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
	return (LODP_ERR_OK);
}


int
lodp_session_get_context(const lodp_session *session, void **ctxt)
{
	if ((NULL == session) || (NULL == ctxt))
		return (LODP_ERR_INVAL);

	*ctxt = session->ctxt;
	return (LODP_ERR_OK);
}


int
lodp_session_get_stats(const lodp_session *session, lodp_session_stats *stats)
{
	if ((NULL == session) || (NULL == stats))
		return (LODP_ERR_INVAL);

	memcpy(stats, &session->stats, sizeof(*stats));

	return (LODP_ERR_OK);
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
	int ret;

	if (NULL == session)
		return (LODP_ERR_INVAL);

	/* LODP rekeying is always initiator driven */
	if (!session->is_initiator) {
		/* XXX: Allow the app to retransmit REKEY ACKs? */
		return (LODP_ERR_NOT_INITIATOR);
	}

	/* Generate the new curve25519 keypair */
	if (STATE_ESTABLISHED == session->state) {
		assert(NULL == session->handshake);

		ret = lodp_handshake_init(session);
		if (ret) {
			lodp_log_session(session, LODP_LOG_ERROR,
			    "rekey(): Failed to initialize handshake state (%d)",
			    ret);
			return (ret);
		}

		session->state = STATE_REKEY;
	} else if (STATE_REKEY != session->state)
		return (LODP_ERR_NOTCONN);

	return (lodp_send_rekey_pkt(session));
}


int
lodp_close(lodp_session *session)
{
	if (NULL == session)
		return (LODP_ERR_INVAL);

	session->ep->callbacks.on_close_fn(session);

	lodp_log_session(session, LODP_LOG_INFO, "close(): Closed");

	lodp_session_destroy(session);

	return (LODP_ERR_OK);
}


int
lodp_handshake_init(lodp_session *session)
{
	int ret;

	assert(NULL != session);
	assert(NULL == session->handshake);

	session->handshake = calloc(1, sizeof(*session->handshake));
	if (NULL == session->handshake) {
		lodp_log(session->ep, LODP_LOG_ERROR,
		    "_handshake_init(): OOM allocating handshake state (%p)",
		    session);
		return (LODP_ERR_NOBUFS);
	}

	/* Generate the Ephemeral Curve25519 keypair */
	ret = lodp_ecdh_gen_keypair(&session->handshake->session_keypair,
		NULL, 0);
	if (ret) {
		lodp_log(session->ep, LODP_LOG_ERROR,
		    "_handshake_init(): Failed to generate session key (%d)",
		    ret);
		lodp_handshake_free(session);
		return (ret);
	}

	return (LODP_ERR_OK);
}


void
lodp_handshake_free(lodp_session *session)
{
	lodp_handshake_data *hs;

	assert(NULL != session);
	assert(NULL != session->handshake);

	hs = session->handshake;
	if (NULL != hs->cookie) {
		lodp_memwipe(hs->cookie, hs->cookie_len);
		free(session->handshake->cookie);
		hs->cookie = NULL;
	}

	lodp_memwipe(hs, sizeof(*hs));
	free(hs);
	session->handshake = NULL;
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
session_find(lodp_endpoint *ep, const struct sockaddr *addr, socklen_t addr_len)
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

	if (NULL != ep->node_id)
		free(ep->node_id);
	if (NULL != ep->init_filter)
		lodp_bf_free(ep->init_filter);
#ifdef TINFOIL
	if (NULL != ep->iv_filter)
		lodp_bf_free(ep->iv_filter);
#endif
	if (NULL != ep->cookie_filter)
		lodp_bf_free(ep->cookie_filter);

	lodp_memwipe(ep, sizeof(*ep));
	free(ep);
}


static void
free_session(lodp_session *session)
{
	assert(NULL != session);

	if (NULL != session->responder_node_id)
		free(session->responder_node_id);
	if (NULL != session->handshake)
		lodp_handshake_free(session);

	lodp_memwipe(session, sizeof(*session));
	free(session);
}
