/*
 * lodp_impl.h: LODP Implementation
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


#include <sys/tree.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <stdint.h>

#include "lodp.h"
#include "lodp_crypto.h"

#ifndef _LODP_IMPL_H_
#define _LODP_IMPL_H_


/* Endpoint */
struct lodp_endpoint_s {
	void *			ctxt;           /* User opaque handle */
	lodp_callbacks		callbacks;      /* User callbacks */

	/* Keys used for session initialization */
	lodp_ecdh_keypair	intro_ecdh_keypair;
	lodp_symmetric_key	intro_sym_keys;

	/* Replay protection */
	lodp_mac_key		cookie_key;             /* Cookie key */
	lodp_mac_key		prev_cookie_key;        /* Last cookie key */
	time_t			cookie_rotate_time;     /* Cookie rotate time */
	time_t			cookie_expire_time;     /* Cookie expire time */
	/* XXX: Add a bloom filter or something to detect IV replay */

	/* Endpoint configuration */
	int			has_intro_keys;

	/* Connection table */
	RB_HEAD(lodp_ep_sessions, lodp_session_s) sessions;
};


/* Session TCB */
typedef enum {
	STATE_INVALID = 0,
	STATE_INIT,             /* Initiator: INIT sent */
	STATE_HANDSHAKE,        /* Initiator: HANDSHAKE sent */
	STATE_ESTABLISHED,      /* Handshake completed */
	/* XXX: Rekeying */
	STATE_ERROR             /* TCB is fucked */
} lodp_session_state;

struct lodp_session_s {
	void *			ctxt; /* User opaque handle */

	lodp_endpoint *		ep;
	lodp_session_state	state;
	int			is_initiator;
	int			seen_peer_data;

	/* Session initialization */
	lodp_ecdh_public_key	remote_public_key;
	uint8_t *		cookie;
	uint16_t		cookie_len;

	/* Ephemeral Session Keys */
	lodp_ecdh_keypair	session_ecdh_keypair;
	lodp_ecdh_shared_secret session_secret;
	uint8_t			session_secret_verifier[LODP_MAC_DIGEST_LEN];
	lodp_symmetric_key	tx_key;
	lodp_symmetric_key	rx_key;
	/* XXX: Need an additional set of keys for rekeying */

	/* Connection Table */
	struct sockaddr_storage peer_addr;
	socklen_t		peer_addr_len;
	uint64_t		peer_addr_hash;
	RB_ENTRY(lodp_session_s) entry;
};


lodp_session *lodp_session_init(const void *ctxt, lodp_endpoint *ep,
    const struct sockaddr *addr, size_t addr_len,
    const uint8_t *pub_key, size_t pub_key_len, int is_initiator);
void lodp_session_destroy(lodp_session *session);


/*
 * Buffer management
 *
 * This is simplified by using a buffer pool, maintaining individual buffers
 * that contain both the plaintext and the ciphertext.  This does end up
 * limiting the MSS to a compile time constant.
 *
 * Unless explicitly disabled, the code will insert canary's after the buffers
 * to attempt to detect runtime data corruption.
 *
 * Note:
 * The 64 buffers preallocated is probably overkill due to the design of the
 * current codebase.  In theory, there should only be 2 buffers outstanding
 * since I require the user to copy the data out in each callback.  Either relax
 * this restriction or actually only allocate 2.
 */
#define BUFPOOL_INCR	64			/* Buffer pool base/increase */
#define LODP_MSS	(1280 - 8 - 40)		/* IPv6 MSS - UDP header */


typedef struct lodp_buf_s {
	uint8_t		plaintext[LODP_MSS] __attribute__ ((aligned(__BIGGEST_ALIGNMENT__)));
#ifndef NDEBUG
	uint32_t	pt_canary;
#endif
	uint8_t		ciphertext[LODP_MSS] __attribute__ ((aligned(__BIGGEST_ALIGNMENT__)));
#ifndef NDEBUG
	uint32_t	ct_canary;
#endif
	uint16_t	len;
	SLIST_ENTRY(lodp_buf_s) entry;
} lodp_buf;


int lodp_bufpool_init(void);
lodp_buf *lodp_buf_alloc(void);
void lodp_buf_free(lodp_buf *buf);
void lodp_bufpool_free(void);


#endif
