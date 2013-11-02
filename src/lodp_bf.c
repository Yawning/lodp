/*
 * lodp_bf.c: Bloom Filter implementation
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


#include <math.h>
#include <stdlib.h>
#include <alloca.h>
#include <assert.h>


#include "lodp_crypto.h"
#include "lodp_bf.h"


static inline int next_power_2(uint32_t value);
static inline void get_hashes(uint32_t *hashes, const void *buf, size_t len, int
    k);
static inline int in_cache(const uint8_t *cache, const uint32_t *hashes, int k,
    uint32_t mask);
static inline void add_cache(uint8_t *cache, const uint32_t *hashes, int k,
    uint32_t mask);
static inline void flip_cache(lodp_bf *bf, const uint32_t *hashes);


struct lodp_bf_s {
	uint8_t *	active_1;
	uint8_t *	active_2;
	size_t		cache_len;
	size_t		nr_a1_entries_max;
	size_t		nr_a1_entries;  /* Number of elements in A1 */
	uint32_t	mask;           /* Mask applied to hash output */
	int		k;              /* Number of hash functions */
};


lodp_bf *
lodp_bf_init(size_t n, double p)
{
	static const double ln_2 = 0.69314718055994529;
	static const double ln_2_sq = 0.48045301391820139;
	lodp_bf *bf;
	int k;
	double m;
	double nn;
	double ln_p;

	bf = calloc(sizeof(*bf), 1);
	if (NULL == bf)
		return (NULL);

	/*
	 * From https://en.wikipedia.org/wiki/Bloom_filter:
	 *  m = - n * ln(p) / (ln(2) ^ 2)
	 *  n = - m * (ln(2) ^ 2) / ln(p)
	 *  k = m/n * ln(2)
	 */

	ln_p = log(p);	/* Need libm just for this call. :( */
	m = -1.0d * n * ln_p / ln_2_sq;
	m = 1 << next_power_2((uint32_t)m);
	nn = -1.0d * m * ln_2_sq / ln_p;
	k = (int)((m * ln_2 / nn) + 0.5);

	bf->k = (k > 2) ? k : 2; /* Minimum of 2 hashes */
	bf->mask = (int)m - 1;
	bf->cache_len = (int)m >> 3;
	bf->nr_a1_entries_max = nn;
	bf->active_1 = calloc(bf->cache_len, 1);
	bf->active_2 = calloc(bf->cache_len, 1);

	if ((NULL == bf->active_1) || (NULL == bf->active_2)) {
		lodp_bf_free(bf);
		return (NULL);
	}

	return (bf);
}


int
lodp_bf_a2(lodp_bf *bf, const void *buf, size_t len)
{
	uint32_t *hashes;
	int ret;

	hashes = alloca(bf->k * sizeof(uint32_t));
	get_hashes(hashes, buf, len, bf->k);

	/* Straight forward "from-the-paper" implementation of A2Buffering */

	/* if x is n the active1 cache then */
	if (in_cache(bf->active_1, hashes, bf->k, bf->mask))
		return (1);     /* result := true */

	/* if x is in the active2 cache then */
	if (in_cache(bf->active_2, hashes, bf->k, bf->mask))
		ret = 2;        /* result := true */
	else
		ret = 0;        /* result := false */

	/* insert x into active1 */
	add_cache(bf->active_1, hashes, bf->k, bf->mask);

	/* if the active1 is full then */
	if (++bf->nr_a1_entries > bf->nr_a1_entries_max)
		flip_cache(bf, hashes);

	return (ret);
}


int
lodp_bf_a2_test(lodp_bf *bf, const void *buf, size_t len)
{
	uint32_t *hashes;

	hashes = alloca(bf->k * sizeof(uint32_t));
	get_hashes(hashes, buf, len, bf->k);

	if (in_cache(bf->active_1, hashes, bf->k, bf->mask))
		return (1);

	if (in_cache(bf->active_2, hashes, bf->k, bf->mask)) {
		/*
		 * Yes, despite this being a "Test" routine there's sideffects,
		 * but said sideeffects only occur when there's a cache hit in
		 * the active_2 buffer.
		 */
		add_cache(bf->active_1, hashes, bf->k, bf->mask);
		if (++bf->nr_a1_entries > bf->nr_a1_entries_max)
			flip_cache(bf, hashes);
		return (2);
	}

	return (0);
}


void
lodp_bf_free(lodp_bf *bf)
{
	assert(NULL != bf);
	if (NULL != bf->active_1)
		free(bf->active_1);
	if (NULL != bf->active_2)
		free(bf->active_2);
	free(bf);
}


static inline
int next_power_2(uint32_t value)
{
	int i = 0;

	while (value >>= 1)
		i++;

	return (i + 1);
}


static inline void
get_hashes(uint32_t *hashes, const void *buf, size_t len, int k)
{
	uint64_t base_hash;
	int i;

	/*
	 * According to Kirsch and Mitzenmacher with a suitably good PRF only
	 * two calls to a hash algorithm are needed.
	 *
	 * We take this one step further and use a single invocation of
	 * SipHash-2-4 to generate the two hashes that the rest of the hashes
	 * are derived from.
	 *
	 * See:
	 * "Less Hashing, Same Performance: Building a Better Bloom Filter"
	 */

	base_hash = lodp_hash(buf, len);
	hashes[0] = (uint32_t)(base_hash & 0xffffffff);
	hashes[1] = (uint32_t)(base_hash >> 32);
	for (i = 2; i < k; i++) {
		hashes[i] = hashes[0] + i * hashes[1];
	}
}


static inline int
in_cache(const uint8_t *cache, const uint32_t *hashes, int k, uint32_t mask)
{
	int i;

	for (i = 0; i < k; i++) {
		uint32_t idx = hashes[i] & mask;
		if (0 == (cache[idx/8] & (1 << (idx & 7))))
			return (0);
	}

	return (1);
}


static inline void
add_cache(uint8_t *cache, const uint32_t *hashes, int k, uint32_t mask)
{
	int i;

	for (i = 0; i < k; i++) {
		uint32_t idx = hashes[i] & mask;
		cache[idx/8] |= (1 << (idx & 7));
	}
}


static inline void
flip_cache(lodp_bf *bf, const uint32_t *hashes)
{
	uint8_t *tmp;

	/* flush active2 */
	memset(bf->active_2, 0, bf->cache_len);

	/* switch active1 and 2 */
	tmp = bf->active_2;
	bf->active_2 = bf->active_1;
	bf->active_1 = tmp;

	/* insert x into active1 */
	add_cache(bf->active_1, hashes, bf->k, bf->mask);
	bf->nr_a1_entries = 1;
}
