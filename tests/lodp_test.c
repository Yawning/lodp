/*
 * lodp_test.c: LODP Integration Test
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ottery.h>
#include <unistd.h>

#include <assert.h>

#include "lodp.h"

#define YAWNING    1    /* Maintainer mode, peeks into the opaque handles for
			   debugging purposes. */

#ifdef YAWNING
/* Include LODP internal stuff for debugging purposes */
#include "lodp_impl.h"
#endif


/*
 * This is a simple test case that creates both a server and a client endpoint
 * and rigs the callbacks to implement a simple loopback interface so that the
 * basic functionality can be tested without the network coming into play.
 */


static void log_fn(const lodp_endpoint *ep, lodp_log_level level, const char
    *buf);
static int pre_encrypt(const lodp_endpoint *ep, const lodp_session *session,
    size_t len, size_t mss);


/* Server side goo */
static int s_sendto_fn(const lodp_endpoint *ep, const void *buf, size_t len,
    const struct sockaddr *addr, socklen_t addr_len);
static void s_on_connect_fn(const lodp_session *session, int status);
static void s_on_accept_fn(const lodp_endpoint *ep, lodp_session
    *session, const struct sockaddr *addr, socklen_t addr_len);
static int s_on_recv_fn(const lodp_session *session, const void *buf,
    size_t len);
static void s_on_rekey_fn(const lodp_session *session, int status);
static void s_on_close_fn(const lodp_session *session);

static lodp_callbacks s_test_cbs =
{
	&log_fn,
	&s_sendto_fn,
	&s_on_connect_fn,
	&s_on_accept_fn,
	&s_on_recv_fn,
	&s_on_rekey_fn,
	&s_on_close_fn,
	&pre_encrypt
};

static lodp_endpoint *server_ep;
static lodp_session *server_session;
static struct sockaddr_in server_addr;
static uint8_t server_priv_key[LODP_PRIVATE_KEY_LEN];
static uint8_t server_pub_key[LODP_PUBLIC_KEY_LEN];
static int server_connected;


/* Client side goo */
static int c_sendto_fn(const lodp_endpoint *ep, const void *buf,
    size_t len, const struct sockaddr *addr, socklen_t addr_len);
static void c_on_connect_fn(const lodp_session *session, int status);
static void c_on_accept_fn(const lodp_endpoint *ep, lodp_session *session,
    const struct sockaddr *addr, socklen_t addr_len);
static int c_on_recv_fn(const lodp_session *session, const void *buf, size_t
    len);
static void c_on_rekey_fn(const lodp_session *session, int status);
static void c_on_close_fn(const lodp_session *session);

static lodp_callbacks c_test_cbs =
{
	&log_fn,
	&c_sendto_fn,
	&c_on_connect_fn,
	&c_on_accept_fn,
	&c_on_recv_fn,
	&c_on_rekey_fn,
	&c_on_close_fn,
	&pre_encrypt
};

static lodp_endpoint *client_ep;
static lodp_session *client_session;
static struct sockaddr_in client_addr;
static int client_connected;


int
main(int argc, char *argv[])
{
	uint8_t *test_payload;
	int ret, i;
	size_t pub_len, priv_len;
	size_t len;


	/* Setup some fake addresses */
	memset(&server_addr, 1, sizeof(server_addr));
	memset(&client_addr, 1, sizeof(client_addr));

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(6969);
	server_addr.sin_addr.s_addr = htonl(0x7f000001);        /* 127.0.0.1 */

	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(2323);
	client_addr.sin_addr.s_addr = htonl(0x7f000001);        /* 127.0.0.1 */

	ret = lodp_init();
	if (ret) {
		fprintf(stderr, "lodp_init(): %d\n", ret);
		goto out;
	}

	/* Generate a keypair */
	pub_len = LODP_PUBLIC_KEY_LEN;
	priv_len = LODP_PRIVATE_KEY_LEN;
	ret = lodp_generate_keypair(server_pub_key, &pub_len, server_priv_key,
		&priv_len);
	if (ret) {
		fprintf(stderr, "ERROR: Failed to generate ecdh keypair (%d)\n",
		    ret);
		goto out;
	}

	/* Set up the server endpoint */
	server_ep = lodp_endpoint_bind(NULL, &s_test_cbs, server_priv_key,
		sizeof(server_priv_key), 1);
	if (NULL == server_ep) {
		fprintf(stderr, "ERROR: Failed to initialize server endpoint\n");
		goto out;
	}

	/* Set up the client endpoint */
	client_ep = lodp_endpoint_bind(NULL, &c_test_cbs, NULL, 0, 1);
	if (NULL == client_ep) {
		fprintf(stderr, "ERROR: Failed to initialize client endpoint\n");
		goto out_serv;
	}

	/*
	 * Connect (Client->Server)
	 */
	client_session = lodp_connect(NULL, client_ep, (struct sockaddr *)
		&server_addr, sizeof(server_addr), server_pub_key,
		sizeof(server_pub_key));
	if (NULL == client_session) {
		fprintf(stderr, "ERROR: Failed to connect to server\n");
		goto out_client;
	}

#ifdef YAWNING
	if (memcmp(server_pub_key,
	    client_session->remote_public_key.public_key,
	    sizeof(server_pub_key))) {
		fprintf(stderr, "ERROR: Public key mismatch???\n");
		goto out_client;
	}
	if (memcmp(&server_ep->intro_sym_keys, &client_session->tx_key,
	    sizeof(lodp_symmetric_key))) {
		fprintf(stderr, "ERROR: Intro key mismatch???\n");
		goto out_client;
	}
#endif

	/*
	 * Handshake.  As there is no loss and the server is guaranteed to be
	 * able to accept our connection, this should succeed in one shot due to
	 * reenrant invocation of all my callbacks.
	 */
	for (i = 0; (i < 3) && (!client_connected); i++) {
		ret = lodp_handshake(client_session);
		fprintf(stdout, "Handshake: Client->Server (%d): %d\n", i, ret);
	}
	assert(client_connected);

	/*
	 * Try sending some data, server will echo.
	 */
	len = 1024;
	test_payload = calloc(1, len);
	assert(NULL != test_payload);
	for (i = 0; i < len; i++) {
		test_payload[i] = i & 0xFF;
	}

	for (i = 0; i < 10; i++) {
		ret = lodp_send(client_session, test_payload, len);
		if (ret) {
			fprintf(stdout, "Send: ERROR: Failed to send to server (%d)\n",
			    ret);
		}
	}

	sleep(3);
	/* Try rekeying */
	ret = lodp_rekey(client_session);
	if (ret) {
		fprintf(stdout, "Rekey: ERROR: Failed %d", ret);
	}
	sleep(10);
	ret = lodp_rekey(client_session);
	if (ret) {
		fprintf(stdout, "Rekey: 2nd attemt Failed ? %d\n", ret);
	}

	for (i = 0; i < 10; i++) {
		ret = lodp_send(client_session, test_payload, len);
		if (ret) {
			fprintf(stdout, "Send: ERROR: Failed to send to server (%d)\n",
			    ret);
		}
	}

	free(test_payload);

	lodp_close(client_session);


out_client:
	lodp_endpoint_unbind(client_ep);
out_serv:
	lodp_endpoint_unbind(server_ep);
out:
	lodp_term();

	return (0);
}


static void
log_fn(const lodp_endpoint *ep, lodp_log_level level, const char *buf)
{
	if (ep == server_ep) {
		fprintf(stdout, "[%d]: Server: %s\n", level, buf);
	} else if (ep == client_ep) {
		fprintf(stdout, "[%d]: Client: %s\n", level, buf);
	} else {
		fprintf(stdout, "[%d]: Unknown: %s\n", level, buf);
	}
}


static int
pre_encrypt(const lodp_endpoint *ep, const lodp_session *session, size_t len,
    size_t mss)
{
	int range = mss - len;

	return (ottery_rand_range(range));
}


/* All the server callbacks. */
static int
s_sendto_fn(const lodp_endpoint *ep, const void *buf, size_t len, const struct
    sockaddr *addr, socklen_t addr_len)
{
	struct sockaddr_in *v4addr;
	int ret;

	fprintf(stdout, "Server: sendto(Client), %p, %tu\n", buf, len);

	assert(server_ep == ep);
	assert(addr->sa_family == AF_INET);

	/* Make sure they aren't crossing the streams */
	v4addr = (struct sockaddr_in *)addr;
	assert(v4addr->sin_port == client_addr.sin_port);
	assert(v4addr->sin_addr.s_addr == client_addr.sin_addr.s_addr);

	ret = lodp_endpoint_on_packet(client_ep, buf, len, (struct sockaddr *)
		&server_addr, sizeof(server_addr));
	fprintf(stdout, "Loopback: Server->Client, %d\n", ret);

	return (0);
}


static void
s_on_connect_fn(const lodp_session *session, int status)
{
	/* This should *NEVER* be called */
	fprintf(stderr, "Server: In on_connect_fn????\n");
	assert(0);
}


static void
s_on_accept_fn(const lodp_endpoint *ep, lodp_session *session, const struct
    sockaddr *addr, socklen_t addr_len)
{
	struct sockaddr_in *v4addr;

	assert(server_ep == ep);

	/* Make sure they aren't crossing the streams */
	v4addr = (struct sockaddr_in *)addr;
	assert(v4addr->sin_port == client_addr.sin_port);
	assert(v4addr->sin_addr.s_addr == client_addr.sin_addr.s_addr);

	server_session = session;
	server_connected = 1;
	fprintf(stdout, "Server: onAccept(Client), %p\n", session);
}


static int
s_on_recv_fn(const lodp_session *session, const void *buf, size_t len)
{
	int ret;

	fprintf(stdout, "Server: Rx Data %p, %p %tu\n", session, buf, len);
	ret = lodp_send((lodp_session *)session, (void *)buf, len);
	fprintf(stdout, "Server: Echoing Received buffer (%d)", ret);

	return (0);
}

static void
s_on_rekey_fn(const lodp_session *session, int status)
{
	/* This should *NEVER* be called */
	fprintf(stderr, "Server: In on_rekey_fn????\n");
	assert(0);
}


static void
s_on_close_fn(const lodp_session *session)
{
	fprintf(stdout, "Server: Session closed (%p)\n", session);
}


/* All the client callbacks */
static int
c_sendto_fn(const lodp_endpoint *ep, const void *buf, size_t len, const struct
    sockaddr *addr, socklen_t addr_len)
{
	struct sockaddr_in *v4addr;
	int ret;

	fprintf(stdout, "Client: sendto(Server), %p, %tu\n", buf, len);

	assert(client_ep == ep);
	assert(addr->sa_family == AF_INET);

	/* Make sure they aren't crossing the streams */
	v4addr = (struct sockaddr_in *)addr;
	assert(v4addr->sin_port == server_addr.sin_port);
	assert(v4addr->sin_addr.s_addr == server_addr.sin_addr.s_addr);

	ret = lodp_endpoint_on_packet(server_ep, buf, len, (struct sockaddr *)&client_addr,
		sizeof(client_addr));
	fprintf(stdout, "Loopback: Client->Server, %d\n", ret);

	return (0);
}


static void
c_on_connect_fn(const lodp_session *session, int status)
{
	/* Nothing to do yet */
	assert(session == client_session);

	fprintf(stdout, "Client: onConnect(Server), %p %d\n", session, status);
	if (!status)
		client_connected = 1;
}


static void
c_on_accept_fn(const lodp_endpoint *ep, lodp_session *session, const struct
    sockaddr *addr, socklen_t addr_len)
{
	/* This should *NEVER* be called */
	fprintf(stderr, "Client: In on_accept_fn????\n");
	assert(0);
}


static int
c_on_recv_fn(const lodp_session *session, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t i;

	fprintf(stdout, "Client: Rx Data %p, %p %tu\n", session, buf, len);

	for (i = 0; i < len; i++) {
		if (p[i] != (i & 0xFF)) {
			fprintf(stdout, " * Echoed data mismatch at offset %ld",
			    i);
		}
	}

	return (0);
}


static void
c_on_rekey_fn(const lodp_session *session, int status)
{
	fprintf(stdout, "Client: Session rekeyed (%p) %d\n", session, status);
}


static void
c_on_close_fn(const lodp_session *session)
{
	fprintf(stdout, "Client: Session closed (%p)\n", session);
}
