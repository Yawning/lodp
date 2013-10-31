/*
 * lodp_bf_test.c: LODP Bloom Filter Test
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

#include <assert.h>

#include "lodp_crypto.h"
#include "lodp_bf.h"

int
main(int argc, char *argv[])
{
	FILE *fp;
	lodp_bf *bf;
	char buf[128], *s;
	int ret;

	fp = fopen("/usr/share/dict/cracklib-small", "r");
	if (NULL == fp) {
		perror("fopen");
		return (-1);
	}

	lodp_crypto_init();

	bf = lodp_bf_init(20000, 0.001);
	if (NULL == bf)
		goto out;

	while (NULL != (s = fgets(buf, sizeof(buf), fp))) {
		/* Kill the newline */
		size_t l = strlen(s);
		s[l - 1] = '\0';
		ret = lodp_bf_a2(bf, s, l);
		if (ret) {
			fprintf(stdout, "False positive: [%s]\n", s);
		}
	}

	/* Check something that should be in a2 */
	{
		const char test[] = "10th";
		ret = lodp_bf_a2(bf, test, sizeof(test));
		fprintf(stdout, "Test 1 (Should hit a2): %d\n", ret);
	}

	/* Check again, it should be present now */
	{
		const char test[] = "10th";
		ret = lodp_bf_a2(bf, test, sizeof(test));
		fprintf(stdout, "Test 2 (Should hit): %d\n", ret);
	}

	/* Check for something towards the end of my test file  */
	{
		const char test[] = "wrote";
		ret = lodp_bf_a2(bf, test, sizeof(test));
		fprintf(stdout, "Test 3 (Should hit): %d\n", ret);
	}

	/* Check for something that should miss */
	{
		const char test[] = "NotInDictionary";
		ret = lodp_bf_a2(bf, test, sizeof(test));
		fprintf(stdout, "Test 4 (Should miss): %d\n", ret);
	}

	/* Check again (A1 hit) */
	{
		const char test[] = "NotInDictionary";
		ret = lodp_bf_a2(bf, test, sizeof(test));
		fprintf(stdout, "Test 5 (Should hit): %d\n", ret);
	}

	lodp_bf_term(bf);

out:
	fclose(fp);
	lodp_crypto_term();
	return (0);
}
