/*
 * lodp_impl.c: LODP Internal Routines
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
#include <arpa/inet.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <assert.h>

#include "lodp.h"
#include "lodp_crypto.h"
#include "lodp_impl.h"


typedef struct lodp_bufpool_s {
	SLIST_HEAD(lodp_bufpool_list, lodp_buf_s) head;
	size_t	nr_allocated;
	size_t	nr_available;
} lodp_bufpool;


#ifndef NDEBUG
#define BUFPOOL_PRE_MAGIC	0xdeadbabe
#define BUFPOOL_POST_MAGIC	0xbabedead
#endif

#define MAX_LOG_LEN		256


static lodp_bufpool bufpool;
static int bufpool_initialized;

static int logging_unsafe;
static lodp_log_level log_level;


static int bufpool_grow(lodp_bufpool *pool);


int
lodp_bufpool_init(void)
{
	assert(0 == bufpool_initialized);

	if (bufpool_initialized)
		return (LODP_ERR_INVAL);

	bufpool.nr_allocated = 0;
	bufpool.nr_available = 0;
	SLIST_INIT(&bufpool.head);

	bufpool_initialized = 1;

	return (bufpool_grow(&bufpool));
}


lodp_buf *
lodp_buf_alloc(void)
{
	lodp_buf *buf = NULL;

	assert(bufpool_initialized);

	if (((bufpool.nr_available) == 0) || (SLIST_EMPTY(&bufpool.head))) {
		assert(0 == bufpool.nr_available);
		assert(SLIST_EMPTY(&bufpool.head));
		bufpool_grow(&bufpool);
	}

	buf = SLIST_FIRST(&bufpool.head);
	if (NULL != buf) {
#ifndef NDEBUG
		assert(BUFPOOL_PRE_MAGIC == buf->pre_canary);
		assert(BUFPOOL_POST_MAGIC == buf->post_canary);
#endif
		SLIST_REMOVE_HEAD(&bufpool.head, entry);
		bufpool.nr_available--;
	}

	return (buf);
}


void
lodp_buf_free(lodp_buf *buf)
{
	assert(bufpool_initialized);
	assert(NULL != buf);
#ifndef NDEBUG
	assert(BUFPOOL_PRE_MAGIC == buf->pre_canary);
	assert(BUFPOOL_POST_MAGIC == buf->post_canary);
#endif

	lodp_memwipe(buf, sizeof(*buf));
#ifndef NDEBUG
	buf->pre_canary = BUFPOOL_PRE_MAGIC;
	buf->post_canary = BUFPOOL_POST_MAGIC;
#endif
	SLIST_INSERT_HEAD(&bufpool.head, buf, entry);
	bufpool.nr_available++;
}


void
lodp_bufpool_free(void)
{
	lodp_buf *buf;

	assert(bufpool_initialized);
	assert(bufpool.nr_available == bufpool.nr_allocated);

	while (!SLIST_EMPTY(&bufpool.head)) {
		buf = SLIST_FIRST(&bufpool.head);
		SLIST_REMOVE_HEAD(&bufpool.head, entry);
		free(buf);
	}
}


static int
bufpool_grow(lodp_bufpool *pool)
{
	lodp_buf *buf;
	int i;

	assert(NULL != pool);

	for (i = 0; i < BUFPOOL_INCR; i++) {
		buf = calloc(1, sizeof(*buf));
		if (NULL == buf)
			return (LODP_ERR_NOBUFS);

#ifndef NDEBUG
		buf->pre_canary = BUFPOOL_PRE_MAGIC;
		buf->post_canary = BUFPOOL_POST_MAGIC;
#endif
		SLIST_INSERT_HEAD(&pool->head, buf, entry);
		pool->nr_allocated++;
		pool->nr_available++;
	}

	return (LODP_ERR_OK);
}


int
lodp_log_init(int unsafe_logging, lodp_log_level level)
{
	logging_unsafe = unsafe_logging;
	log_level = level;

	return (LODP_ERR_OK);
}


void
lodp_log(const lodp_endpoint *ep, lodp_log_level level, const char *fmt, ...)
{
	char msg[MAX_LOG_LEN];
	va_list args;
	int ret;

	if ((NULL == ep->callbacks.log_fn) || (level > log_level))
		return;

	/*
	 * Prefix the log message with useful information
	 * "EndpointHandle - "
	 */

	ret = snprintf(msg, sizeof(msg), "%p - ", ep);
	assert(ret >= 0);

	va_start(args, fmt);
	ret = vsnprintf(msg + ret, sizeof(msg) - ret, fmt, args);
	if (ret >= 0)
		ep->callbacks.log_fn(ep, level, msg);
	lodp_memwipe(msg, sizeof(msg));
	va_end(args);
}


void
lodp_log_addr(const lodp_endpoint *ep, lodp_log_level level, const struct sockaddr
    *addr, const char *fmt, ...)
{
	char addrstr[LODP_ADDRSTRLEN];
	char msg[MAX_LOG_LEN];
	va_list args;
	int ret;

	if ((NULL == ep->callbacks.log_fn) || (level > log_level))
		return;

	/*
	 * Prefix the log message with useful information
	 * "EndpointHandle - (Addr:Port): "
	 */

	lodp_straddr(addr, addrstr, sizeof(addrstr));
	ret = snprintf(msg, sizeof(msg), "%p - (%s): ", ep, addrstr);
	assert(ret >= 0);

	va_start(args, fmt);
	ret = vsnprintf(msg + ret, sizeof(msg) - ret, fmt, args);
	if (ret >= 0)
		ep->callbacks.log_fn(ep, level, msg);
	lodp_memwipe(msg, sizeof(msg));
	va_end(args);
}


void
lodp_log_session(const lodp_session *session, lodp_log_level level, const char
    *fmt, ...)
{
	char msg[MAX_LOG_LEN];
	va_list args;
	int ret;

	if ((NULL == session->ep->callbacks.log_fn) || (level > log_level))
		return;

	/*
	 * Prefix the log message with useful information
	 * "SesssionHandle (PeerAddr:Port): SessionState - "
	 */

	ret = snprintf(msg, sizeof(msg), "%p (%s): %d - ", session,
		session->peer_addr_str, session->state);
	assert(ret >= 0);

	/* Append the log message */
	va_start(args, fmt);
	ret = vsnprintf(msg + ret, sizeof(msg) - ret, fmt, args);
	if (ret >= 0)
		session->ep->callbacks.log_fn(session->ep, level, msg);
	va_end(args);
}


void
lodp_straddr(const struct sockaddr *addr, char *buf, size_t len)
{
	char addrstr[INET6_ADDRSTRLEN];
	uint16_t port;

	assert(NULL != addr);
	assert(NULL != buf);
	assert(LODP_ADDRSTRLEN == len);

	if (!logging_unsafe) {
		snprintf(buf, len, "[scrubbed]");
		return;
	} else if (AF_INET == addr->sa_family) {
		struct sockaddr_in *v4addr = (struct sockaddr_in *)addr;
		inet_ntop(AF_INET, &v4addr->sin_addr, addrstr, sizeof(addrstr));
		port = ntohs(v4addr->sin_port);
		snprintf(buf, len, "%s:%d", addrstr, port);
	} else if (AF_INET6 == addr->sa_family) {
		struct sockaddr_in6 *v6addr = (struct sockaddr_in6 *)addr;
		inet_ntop(AF_INET6, &v6addr->sin6_addr, addrstr, sizeof(addrstr));
		port = ntohs(v6addr->sin6_port);
		snprintf(buf, len, "[%s]:%d", addrstr, port);
	} else
		snprintf(buf, len, "<Unknown Addr Type>");
}
