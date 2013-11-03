/*
 * lodp_crypto.c: LODP Cryptography routines
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

#include <string.h>
#include <stdlib.h>
#include <alloca.h>
#include <assert.h>

#include <ottery.h>

#include "blake2.h"
#include "chacha.h"
#include "siphash.h"

#include "lodp.h"
#include "lodp_crypto.h"


extern int curve25519_donna(uint8_t *mypublic, const uint8_t *secret, const
    uint8_t *basepoint);

static int curve25519_generate_pubkey(lodp_ecdh_keypair *keypair);
static int lodp_extract(uint8_t *prk, const uint8_t *salt, const uint8_t *ikm,
    size_t prk_len, size_t salt_len, size_t ikm_len);
static int lodp_expand(uint8_t *okm, const uint8_t *prk, const uint8_t *info,
    size_t okm_len, size_t prk_len, size_t info_len);


static int is_initialized;
static lodp_hash_key hash_key;


int
lodp_crypto_init(void)
{
	int ret;

	/* Initialize the CSPRNG */
	ret = ottery_init(NULL);
	if (ret)
		return (-1);

	/* Sigh, lodp_rand_bytes asserts on this, so set it early */
	is_initialized = 1;

	/* Initialize the hash function key */
	lodp_rand_bytes(hash_key.hash_key, sizeof(hash_key.hash_key));

	return (0);
}


void
lodp_crypto_term(void)
{
	assert(is_initialized);

	lodp_memwipe(&hash_key, sizeof(hash_key));
	ottery_wipe();
}


int
lodp_gen_keypair(lodp_ecdh_keypair *keypair, const uint8_t *buf, size_t len)
{
	int ret = 0;
	int i;

	assert(NULL != keypair);

	assert(is_initialized);

	if (NULL == buf) {
		for (i = 0; i < 3; i++) {
#ifdef TINFOIL
			uint8_t tmp[LODP_ECDH_PRIVATE_KEY_LEN];

			lodp_rand_bytes(tmp, sizeof(tmp));
			ret = blake2s(keypair->private_key.private_key, tmp,
			    NULL, LODP_ECDH_PRIVATE_KEY_LEN, sizeof(tmp), 0);
			lodp_memwipe(tmp, sizeof(tmp));
			if (ret)
				goto out;

#else
			lodp_rand_bytes(keypair->private_key.private_key,
			    LODP_ECDH_PRIVATE_KEY_LEN);
#endif

			ret = curve25519_generate_pubkey(keypair);
			if (ret)
				goto out;
			if (!(ret = lodp_ecdh_validate_pubkey(&keypair->public_key)))
				break;
		}
	} else {
		if (LODP_ECDH_PRIVATE_KEY_LEN != len)
			return (LODP_ERR_INVAL);

		memcpy(keypair->private_key.private_key, buf, len);

		ret = curve25519_generate_pubkey(keypair);
	}
out:
	return (ret);
}


int
lodp_gen_pubkey(lodp_ecdh_public_key *pub_key, const uint8_t *buf, size_t len)
{
	assert(NULL != pub_key);
	assert(NULL != buf);
	assert(LODP_ECDH_PUBLIC_KEY_LEN == len);

	assert(is_initialized);

	memcpy(pub_key->public_key, buf, LODP_ECDH_PUBLIC_KEY_LEN);

	return (0);
}


int
lodp_ecdh_validate_pubkey(const lodp_ecdh_public_key *pub_key)
{
	const uint8_t infpoint[LODP_ECDH_PUBLIC_KEY_LEN] = { 0 };

	assert(NULL != pub_key);

	assert(is_initialized);

	/*
	 * Horrific things happen with the ntor handshake variant that we use
	 * if the point at infinity is selected as the public key.
	 */

	if (!lodp_memeq(pub_key->public_key, infpoint, LODP_ECDH_PUBLIC_KEY_LEN))
		return (LODP_ERR_BAD_PUBKEY);

	return (0);
}


void
lodp_ecdh(lodp_ecdh_shared_secret *secret, const lodp_ecdh_private_key
    *private_key, const lodp_ecdh_public_key *public_key)
{
	assert(NULL != secret);
	assert(NULL != private_key);
	assert(NULL != public_key);

	assert(is_initialized);

	curve25519_donna(secret->secret, private_key->private_key,
	    public_key->public_key);
}


int
lodp_mac(uint8_t *digest, uint8_t *buf, const lodp_mac_key *key, size_t
    digest_len, size_t len)
{
	assert(NULL != digest);
	assert(NULL != buf);
	assert(NULL != key);
	assert(LODP_MAC_DIGEST_LEN == digest_len);

	assert(is_initialized);

	if (blake2s(digest, buf, key->mac_key, digest_len, len,
	    LODP_MAC_KEY_LEN))
		return (LODP_ERR_INVAL);

	return (0);
}


int
lodp_encrypt(uint8_t *ciphertext, const lodp_bulk_key *key, const uint8_t *iv,
    const uint8_t *plaintext, size_t len)
{
	assert(NULL != ciphertext);
	assert(NULL != key);
	assert(NULL != iv);
	assert(NULL != plaintext);
	assert(len > 0);

	assert(is_initialized);

	xchacha((chacha_key *)key, (chacha_iv24 *)iv, plaintext, ciphertext,
	    len, 20);

	return (0);
}


int
lodp_decrypt(uint8_t *plaintext, const lodp_bulk_key *key, const uint8_t *iv,
    const uint8_t *ciphertext, size_t len)
{
	return (lodp_encrypt(plaintext, key, iv, ciphertext, len));
}


int
lodp_derive_introkeys(lodp_symmetric_key *sym_key, const lodp_ecdh_public_key
    *pub_key)
{
	static const uint8_t salt[] = {
		'L', 'O', 'D', 'P', '-', 'I', 'n', 't', 'r', 'o',
		'-', 'B', 'L', 'A', 'K', 'E', '2', 's'
	};
	uint8_t prk[LODP_MAC_DIGEST_LEN];
	uint8_t okm[LODP_MAC_KEY_LEN + LODP_BULK_KEY_LEN];
	int ret = LODP_ERR_INVAL;

	assert(NULL != sym_key);
	assert(NULL != pub_key);

	assert(is_initialized);

	/*
	 * Salt = "LODP-Intro-BLAKE2s"
	 * PRK = LODP-Extract(Salt, PublicCurve25519Key)
	 * IntroKey = LODP-Expand(PRK, Salt, 64)
	 * IntroMacKey = IntroKey[0:31]
	 * IntroXChaChaKey = IntroKey[32:63]
	 */

	if (lodp_extract(prk, salt, pub_key->public_key, sizeof(prk),
	    sizeof(salt), LODP_ECDH_PUBLIC_KEY_LEN))
		goto out;
	if (lodp_expand(okm, prk, salt, sizeof(okm), sizeof(prk), sizeof(salt)))
		goto out;
	memcpy(sym_key->mac_key.mac_key, okm, LODP_MAC_KEY_LEN);
	memcpy(sym_key->bulk_key.bulk_key, okm + LODP_MAC_KEY_LEN,
	    LODP_BULK_KEY_LEN);
	ret = 0;

out:
	lodp_memwipe(prk, sizeof(prk));
	lodp_memwipe(okm, sizeof(okm));
	return (ret);
}


int
lodp_derive_sessionkeys(lodp_symmetric_key *init_key, lodp_symmetric_key
    *resp_key, const lodp_ecdh_shared_secret *secret)
{
	static const uint8_t salt[] = {
		'L', 'O', 'D', 'P', '-', 'S', 'e', 's', 's', 'i',
		'o', 'n', '-', 'B', 'L', 'A', 'K', 'E', '2', 's'
	};
	const uint8_t *prk, *p;
	uint8_t okm[2 * (LODP_MAC_KEY_LEN + LODP_BULK_KEY_LEN)];
	int ret = LODP_ERR_INVAL;

	assert(NULL != init_key);
	assert(NULL != resp_key);
	assert(NULL != secret);

	assert(is_initialized);

	/*
	 * Salt = "LODP-Session-BLAKE2s
	 * PRK = SharedSecret
	 * SessionKey = LODP-Expand(PRK, Salt, 128)
	 * InitiatorMacKey = SessionKey[0:31] (Client->Server)
	 * InitiatorXChaChaKey = SessionKey[32:63]
	 * ResponderMacKey = SessionKey[64:95] (Server->Client)
	 * ResponderXChaChaKey = SessionKey[96:127]
	 */

	prk = secret->secret;
	if (lodp_expand(okm, prk, salt, sizeof(okm), sizeof(secret->secret),
	    sizeof(salt)))
		goto out;
	p = okm;
	memcpy(init_key->mac_key.mac_key, p, LODP_MAC_KEY_LEN);
	p += LODP_MAC_KEY_LEN;
	memcpy(init_key->bulk_key.bulk_key, p, LODP_BULK_KEY_LEN);
	p += LODP_BULK_KEY_LEN;
	memcpy(resp_key->mac_key.mac_key, p, LODP_MAC_KEY_LEN);
	p += LODP_MAC_KEY_LEN;
	memcpy(resp_key->bulk_key.bulk_key, p, LODP_BULK_KEY_LEN);
	p += LODP_BULK_KEY_LEN;
	ret = 0;

out:
	lodp_memwipe(okm, sizeof(okm));
	return (ret);
}


uint64_t
lodp_hash(const void *buf, size_t len)
{
	assert(is_initialized);
	return (siphash(hash_key.hash_key, buf, len));
}


void
lodp_rand_bytes(void *s, size_t n)
{
	assert(is_initialized);
	ottery_rand_bytes(s, n);
}


void *
lodp_memwipe(void *s, size_t n)
{
	volatile uint8_t *p = s;

	while (n--)
		*p++ = 0;

	return (s);
}


int
lodp_memeq(const void *s1, const void *s2, size_t n)
{
	const uint8_t *a = s1;
	const uint8_t *b = s2;
	size_t i;
	int ret = 0;

	/*
	 * Note: This doesn't actually obey memcmp semantics
	 * as far as return values go, and merely provides a constant
	 * time method of comparing two buffers.
	 */

	for (i = 0; i < n; i++)
		ret |= a[i] ^ b[i];

	return (ret);
}


static int
curve25519_generate_pubkey(lodp_ecdh_keypair *keypair)
{
	const uint8_t basepoint[32] = { 9 };

	/*
	 * Ensure that the private key is well formed
	 *
	 * Note: curve25519-donna also will do this for us, but that's
	 * possibly implementation dependent.
	 */

	keypair->private_key.private_key[0] &= 248;
	keypair->private_key.private_key[31] &= 127;
	keypair->private_key.private_key[31] |= 64;

	/* Derive the public key */
	curve25519_donna(keypair->public_key.public_key,
	    keypair->private_key.private_key, basepoint);

	return (0);
}


static int
lodp_extract(uint8_t *prk, const uint8_t *salt, const uint8_t *ikm,
    size_t prk_len, size_t salt_len, size_t ikm_len)
{
	if (blake2s(prk, ikm, salt, prk_len, ikm_len, salt_len))
		return (LODP_ERR_INVAL);

	return (0);
}


static int
lodp_expand(uint8_t *okm, const uint8_t *prk, const uint8_t *info,
    size_t okm_len, size_t prk_len, size_t info_len)
{
	blake2s_state state;
	uint8_t T[BLAKE2S_OUTBYTES] = { 0 };
	uint8_t *p;
	size_t N;
	uint8_t i;
	int ret = LODP_ERR_INVAL;

	N = (okm_len + BLAKE2S_OUTBYTES - 1) / BLAKE2S_OUTBYTES;
	if (N > 255)
		return (LODP_ERR_INVAL);

	p = okm;
	for (i = 1; i <= N; i++) {
		size_t to_copy = (okm_len > sizeof(T)) ? sizeof(T) : okm_len;
		if (blake2s_init_key(&state, sizeof(T), prk, prk_len))
			goto out;
		if (i > 1)
			if (blake2s_update(&state, T, sizeof(T)))
				goto out;
		if (blake2s_update(&state, info, info_len))
			goto out;
		if (blake2s_update(&state, &i, sizeof(i)))
			goto out;
		if (blake2s_final(&state, T, sizeof(T)))
			goto out;
		memcpy(p, T, to_copy);
		p += to_copy;
		okm_len -= to_copy;
	}
	ret = 0;

out:
	lodp_memwipe(&state, sizeof(state));
	lodp_memwipe(T, sizeof(T));
	return (ret);
}
