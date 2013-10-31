/*
 * lodp_bf.h: Bloom Filter implementation
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


#include <stdint.h>


#ifndef _LODP_BF_H_
#define _LODP_BF_H_


/*
 * This is a Bloom Filter implementation tailored for dynamic datasets.
 *
 * Underneath the hood, it implements active-active buffering (A2 buffering) as
 * presented in "Aging Bloom Filter with Two Active Buffers for Dynamic Sets" by
 * MyungKeun Yoon.
 *
 * It requires that the lodp_crypto module has been initialized before it will
 * work as it uses liblodp's SipHash implementation to generate hashes, however
 * removing this dependency is trivial (Edit lodp_bf.c:get_hashes().
 *
 * Note that lodp_bf_init() assumes the user has a rough idea of how much memory
 * a filter with n entries at a p false positive rate will comsume as it does
 * nothing to prevent the allocation of gigantic filters.
 *
 * lodp_bf_a2(): Test-And-Set
 * lodp_bf_a2_test: Test
 */


typedef struct lodp_bf_s   lodp_bf;


lodp_bf *lodp_bf_init(size_t n, double p);
int lodp_bf_a2(lodp_bf *bf, const void *buf, size_t len);
int lodp_bf_a2_test(lodp_bf *bf, const void *buf, size_t len);
void lodp_bf_term(lodp_bf *bf);


#endif
