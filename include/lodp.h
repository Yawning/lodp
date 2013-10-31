/*
 * lodp.h: LODP Public Interfaces
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


#include <netinet/in.h>
#include <stdint.h>

#ifndef _LODP_H_
#define _LODP_H_


/*
 * WARNING:
 *
 * Everything needed to use LODP in an application is provided via interfaces
 * from this file.
 *
 * If you decide to poke at liblodp internals by including other header files or
 * messing with the opaque endpoint/session handles directly, things will break,
 * and I will cackle with glee.
 */

/*
 * Various lengths.  Needs to be kept in sync with lodp_crypto.h, but don't want
 * to expose that to the user.
 */


#define LODP_PRIVATE_KEY_LEN	32
#define LODP_PUBLIC_KEY_LEN	32


/* Error codes */
#define LODP_ERR		0x00100000
#define LODP_ERR_INVAL		(-(LODP_ERR | 1))       /* Invalid arguments */
#define LODP_ERR_NOBUFS		(-(LODP_ERR | 2))       /* Out of memory */
#define LODP_ERR_AGAIN		(-(LODP_ERR | 3))       /* Would block */
#define LODP_ERR_ISCONN		(-(LODP_ERR | 4))       /* Already connected */
#define LODP_ERR_NOTCONN	(-(LODP_ERR | 5))       /* Not connected */
#define LODP_ERR_MSGSIZE	(-(LODP_ERR | 6))       /* Message too big */
#define LODP_ERR_AFNOTSUPPORT	(-(LODP_ERR | 7))       /* Address family */

#define LODP_ERR_NOT_INITIATOR	(-(LODP_ERR | 10))
#define LODP_ERR_NOT_RESPONDER	(-(LODP_ERR | 11))
#define LODP_ERR_INVALID_MAC	(-(LODP_ERR | 12))      /* Bad MAC on packet */
#define LODP_ERR_BAD_PACKET	(-(LODP_ERR | 13))      /* Malformed packet */
#define LODP_ERR_INVALID_COOKIE	(-(LODP_ERR | 14))      /* Expired cookie */
#define LODP_ERR_DUP_COOKIE	(-(LODP_ERR | 15))	/* Reused cookie */
#define LODP_ERR_BAD_HANDSHAKE	(-(LODP_ERR | 15))      /* Handshake failure */
#define LODP_ERR_BAD_PUBKEY	(-(LODP_ERR | 16))      /* Bad ECDH key */


/* Opaque handles for endpoints/connections */
typedef struct lodp_endpoint_s		lodp_endpoint;  /* Endpoint */
typedef struct lodp_session_s		lodp_session;   /* Session */


/* Log level passed to the logging callback */
typedef enum {
	LODP_LOG_INFO,  /* informational message */
	LODP_LOG_ERROR, /* error condition */
	LODP_LOG_DEBUG, /* debug-level messages */
} lodp_log_level;


/* Callbacks */
typedef struct {
	/*
	 * Routine invoked by liblodp to do logging.
	 *
	 * void log(const lodp_endpoint *endpoint, lodp_log_level leve,
	 *    const char *msg);
	 *
	 * Keep in mind that liblodp will sanitize logs by default and that
	 * logging incurs additional overhead.
	 */
	void (*log_fn)(const lodp_endpoint *, lodp_log_level, const
	    char *);

	/*
	 * Routine invoked by liblodp to do outgoing socket I/O.
	 *
	 * int sendto(const lodp_endpoint *endpoint, const void *buf,
	 *     size_t len, const struct sockaddr *addr, socklen_t addr_len);
	 *
	 * It is assumed that the I/O call is non-blocking.  The value returned
	 * from this routine will get propagated back to the return value of
	 * the liblodp API that caused the socket I/O to be invoked.  Invoking
	 * any liblodp routines from within the sendto callback is NOT supported.
	 */
	int (*sendto_fn)(const lodp_endpoint *, const void *, size_t,
	    const struct sockaddr *, socklen_t);

	/*
	 * Routine invoked whenever a connection initiated from the current
	 * host finishes handshaking (Successfully or not).
	 *
	 * void on_connect(const lodp_session *session, int status);
	 *
	 * Status of 0 is a success, anything else is a error condition.  It is
	 * safe to call lodp_close(session) in the callback.
	 */
	void (*on_connect_fn)(const lodp_session *, int);

	/*
	 * Routine invoked whenever a connection initiated by a remote host
	 * finishes handshaking.
	 *
	 * void on_accept_fn(const lodp_endpoint *endpoint,
	 *     lodp_session *session, const struct sockaddr *addr,
	 *     socklen_t addr_len);
	 *
	 * If you decide to close the session before returing from the callback
	 * keep in mind that LODP already has sent the HANDSHAKE ACK at this
	 * point, so the peer may end up sending data to you.  That said, the
	 * behavior is safe.
	 */
	void (*on_accept_fn)(const lodp_endpoint *, lodp_session *,
	    const struct sockaddr *, socklen_t);

	/*
	 * Routine invoked whenever data arives on a existing connection.
	 *
	 * int on_recv(const lodp_session *session, const void *buf,
	 *    size_t len);
	 *
	 * liblodp owns buf, and it will go away shortly after the return from
	 * this callback.  Do not keep a pointer to it.
	 *
	 * The value returned from this routine will get propagated back to the
	 * return value of lodp_endpoint_on_packet().
	 */
	int (*on_recv_fn)(const lodp_session *, const void *, size_t);

	/*
	 * Routine invoked whenever a heartbeat ACK arrives on a existng
	 * connection.
	 *
	 * void on_heartbeat_ack(const lodp_session *session, const void *buf,
	 *     size_t len);
	 *
	 * It is the application's responsibility to handle the HEARTBEAT ACK
	 * payload, and liblodp explicitly does not check to see if the
	 * HEARTBEAT ACK was generated in response to HEARTBEAT that it actually
	 * sent or not (The spec suggests sending a payload that allows
	 * verification of this in the HEARTBEAT packet).
	 *
	 * Note:
	 * This function may be NULL, if HEARTBEAT packets are not used.
	 */
	void (*on_heartbeat_ack_fn)(const lodp_session *, const void *,
	    size_t);

	/*
	 * Routine invoked whenever a session is closed.
	 *
	 * void on_close(const lodp_session *session);
	 *
	 * After returning from this point, things will break if you touch
	 * session again.  Also LODP does not have explicit termination, so
	 * hopefully you informed the peer that you are closing the connection
	 * before you did so as further packets received from the session will
	 * be ignored.
	 */
	void (*on_close_fn)(const lodp_session *);

	/*
	 * Routine invoked by liblodp before each packet is finalized to allow
	 * random padding to be inserted.
	 *
	 * int pre_encrypt(const lodp_endpoint *endpoint,
	 *     const lodp_session *session,  size_t current_length,
	 *     size_t mss);
	 *
	 * Return the size of the random padding to be appended in bytes.  If
	 * the amount of padding requested is too large, then it will be shrunk
	 * down to the MSS (current_length + ret <= mss).
	 */
	int (*pre_encrypt_fn)(const lodp_endpoint *, const lodp_session *,
	    size_t, size_t);
} lodp_callbacks;


int lodp_init(void);
void lodp_term(void);

int lodp_generate_keypair(uint8_t *pub_key, size_t *pub_key_len, uint8_t *
    priv_key, size_t *priv_key_len);

lodp_endpoint *lodp_endpoint_bind(void *ctxt, const lodp_callbacks
    *callbacks, const uint8_t *priv_key, size_t priv_key_len, int unsafe_logging);
void lodp_endpoint_set_context(lodp_endpoint *ep, void *ctxt);
void *lodp_endpoint_get_context(const lodp_endpoint *ep);
size_t lodp_endpoint_get_mss(const lodp_endpoint *ep);
void lodp_endpoint_unbind(lodp_endpoint *ep);
int lodp_endpoint_on_packet(lodp_endpoint *ep, const uint8_t *buf, size_t len,
    const struct sockaddr *addr, socklen_t addr_len);

lodp_session *lodp_connect(const void *ctxt, lodp_endpoint *ep, const struct
    sockaddr *addr, size_t addr_len, const uint8_t *pub_key, size_t
    pub_key_len);
void lodp_session_set_context(lodp_session *session, void *ctxt);
void *lodp_session_get_context(lodp_session *session);
int lodp_handshake(lodp_session *session);
int lodp_send(lodp_session *session, const void *buf, size_t len);
int lodp_heartbeat(lodp_session *session, const void *buf, size_t len);
void lodp_close(lodp_session *session);


#endif
