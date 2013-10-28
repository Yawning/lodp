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
#define BUFPOOL_PT_MAGIC	0xdeadbabe
#define BUFPOOL_CT_MAGIC	0xbabedead
#endif


static lodp_bufpool bufpool;
static int bufpool_initialized;


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
		assert(BUFPOOL_PT_MAGIC == buf->pt_canary);
		assert(BUFPOOL_CT_MAGIC == buf->ct_canary);
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
	assert(BUFPOOL_PT_MAGIC == buf->pt_canary);
	assert(BUFPOOL_CT_MAGIC == buf->ct_canary);
#endif

	lodp_memwipe(buf, sizeof(*buf));
#ifndef NDEBUG
	buf->pt_canary = BUFPOOL_PT_MAGIC;
	buf->ct_canary = BUFPOOL_CT_MAGIC;
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
		buf->pt_canary = BUFPOOL_PT_MAGIC;
		buf->ct_canary = BUFPOOL_CT_MAGIC;
#endif
		SLIST_INSERT_HEAD(&pool->head, buf, entry);
		pool->nr_allocated++;
		pool->nr_available++;
	}

	return (0);
}
