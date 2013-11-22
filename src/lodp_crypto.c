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

#include <stdio.h>

#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <ottery.h>

#include "blake2.h"
#include "chacha.h"
#include "siphash.h"

#include "lodp.h"
#include "lodp_crypto.h"


extern int curve25519_donna(uint8_t *mypublic, const uint8_t *secret, const
    uint8_t *basepoint);

static void curve25519_generate_pubkey(lodp_ecdh_keypair *keypair);
static int curve25519_validate_secret(lodp_ecdh_shared_secret *secret);
static int lodp_extract(uint8_t *prk, const uint8_t *salt, const uint8_t *ikm,
    size_t prk_len, size_t salt_len, size_t ikm_len);
static int lodp_expand(uint8_t *okm, const uint8_t *prk, const uint8_t *info,
    size_t okm_len, size_t prk_len, size_t info_len);


/* NTOR constants */
static const uint8_t NTOR_PROTOID[] =
{
	'l', 'o', 'd', 'p', '-', 'n', 't', 'o', 'r', '-', '1'
};

static const uint8_t NTOR_RESPONDER[] =
{
	'R', 'e', 's', 'p', 'o', 'n', 'd', 'e', 'r'
};

static const lodp_mac_key NTOR_T_KEY =
{
	{
		'l', 'o', 'd', 'p', '-', 'n', 't', 'o', 'r', '-',
		'1', ':', 'k', 'e', 'y', '_', 'e', 'x', 't', 'r',
		'a', 'c', 't', 0
	}
};

static const lodp_mac_key NTOR_T_VERIFY =
{
	{
		'l', 'o', 'd', 'p', '-', 'n', 't', 'o', 'r', '-',
		'1', ':', 'k', 'e', 'y', '_', 'v', 'e', 'r', 'i',
		'f', 'y', 0
	}
};

static const lodp_mac_key NTOR_T_MAC =
{
	{
		'l', 'o', 'd', 'p', '-', 'n', 't', 'o', 'r', '-',
		'1', ':', 'm', 'a', 'c', 0
	}
};

#define NTOR_SECRET_INPUT_LEN_MAX			   \
	(LODP_ECDH_SECRET_LEN * 2 + LODP_NODE_ID_LEN_MAX + \
	LODP_ECDH_PUBLIC_KEY_LEN * 3 + sizeof(NTOR_PROTOID))

#define NTOR_AUTH_INPUT_LEN_MAX				      \
	(LODP_MAC_DIGEST_LEN + LODP_NODE_ID_LEN_MAX +	      \
	LODP_ECDH_PUBLIC_KEY_LEN * 3 + sizeof(NTOR_PROTOID) + \
	sizeof(NTOR_RESPONDER))


/* LODP-KDF constants */
static const uint8_t KDF_INTRO_SALT[] =
{
	'L', 'O', 'D', 'P', '-', 'I', 'n', 't', 'r', 'o',
	'-', 'B', 'L', 'A', 'K', 'E', '2', 's'
};

static const uint8_t KDF_SESSION_SALT[] =
{
	'L', 'O', 'D', 'P', '-', 'S', 'e', 's', 's', 'i',
	'o', 'n', '-', 'B', 'L', 'A', 'K', 'E', '2', 's'
};


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

	/* Validate that the XChaCha/20 implementaion works */
	ret = chacha_check_validity();
	if (!ret)
		return (-1);

	/* Sigh, lodp_rand_bytes asserts on this, so set it early */
	is_initialized = 1;

	/* Initialize the hash function key */
	lodp_rand_bytes(hash_key.hash_key, sizeof(hash_key.hash_key));

	return (LODP_ERR_OK);
}


void
lodp_crypto_term(void)
{
	assert(is_initialized);

	lodp_memwipe(&hash_key, sizeof(hash_key));
	ottery_wipe();

	is_initialized = 0;
}


int
lodp_ecdh_gen_keypair(lodp_ecdh_keypair *keypair, const uint8_t *buf,
    size_t len)
{
	int ret;

	assert(NULL != keypair);
	assert(is_initialized);

	if (NULL == buf) {
#ifdef TINFOIL

		/*
		 * Tor does something like this out of mistrust of the
		 * PRNG, but it's relegated to a TINFOIL option since
		 * bad things will happen in general if the PRNG is
		 * weak.
		 */
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

		curve25519_generate_pubkey(keypair);
		ret = lodp_ecdh_validate_pubkey(&keypair->public_key);
	} else {
		if (LODP_ECDH_PRIVATE_KEY_LEN != len)
			return (LODP_ERR_INVAL);

		memcpy(keypair->private_key.private_key, buf, len);

		curve25519_generate_pubkey(keypair);
		ret = LODP_ERR_OK;
	}
out:
	return (ret);
}


void
lodp_ecdh_pack_pubkey(uint8_t *buf, const lodp_ecdh_public_key *pub_key,
    size_t len)
{
	assert(NULL != pub_key);
	assert(NULL != buf);
	assert(LODP_ECDH_PUBLIC_KEY_LEN == len);
	assert(is_initialized);

	memcpy(buf, pub_key->public_key, LODP_ECDH_PUBLIC_KEY_LEN);
}


void
lodp_ecdh_pack_privkey(uint8_t *buf, const lodp_ecdh_private_key *priv_key,
    size_t len)
{
	assert(NULL != priv_key);
	assert(NULL != buf);
	assert(LODP_ECDH_PRIVATE_KEY_LEN == len);
	assert(is_initialized);

	memcpy(buf, priv_key->private_key, LODP_ECDH_PRIVATE_KEY_LEN);
}


void
lodp_ecdh_unpack_pubkey(lodp_ecdh_public_key *pub_key, const uint8_t *buf,
    size_t len)
{
	assert(NULL != pub_key);
	assert(NULL != buf);
	assert(LODP_ECDH_PUBLIC_KEY_LEN == len);
	assert(is_initialized);

	memcpy(pub_key->public_key, buf, LODP_ECDH_PUBLIC_KEY_LEN);
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

	return (LODP_ERR_OK);
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
lodp_mac(uint8_t *digest, const uint8_t *buf, const lodp_mac_key *key, size_t
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

	return (LODP_ERR_OK);
}


int
lodp_ntor(uint8_t *shared_secret, uint8_t *auth,
    const lodp_ecdh_public_key *X, const lodp_ecdh_private_key *x,
    const lodp_ecdh_public_key *Y, const lodp_ecdh_private_key *y,
    const lodp_ecdh_public_key *B, const lodp_ecdh_private_key *b,
    const uint8_t *node_id, size_t node_id_len,
    size_t shared_secret_len, size_t auth_len)
{
	struct {
		lodp_ecdh_shared_secret secret;
		uint8_t			verify[LODP_MAC_DIGEST_LEN];
		uint8_t			secret_input[NTOR_SECRET_INPUT_LEN_MAX];
		uint8_t			auth_input[NTOR_AUTH_INPUT_LEN_MAX];
	} s;
	uint8_t *p;
	uint8_t *tmp;
	size_t secret_input_len;
	size_t auth_input_len;
	int ret;

	assert(NULL != shared_secret);
	assert(NULL != auth);
	assert(NULL != node_id);
	assert(NULL != B);
	assert(NULL != X);
	assert(NULL != Y);
	assert(node_id_len > 0);
	assert(node_id_len <= LODP_NODE_ID_LEN_MAX);
	assert(LODP_MAC_DIGEST_LEN == shared_secret_len);
	assert(LODP_MAC_DIGEST_LEN == auth_len);
	assert(is_initialized);

	/*
	 * WARNING: Here be dragons
	 *
	 * This is an implementation of the Tor project's ntor handshake, with
	 * minor differences:
	 *  * As handshake failures do not result in any response traffic that
	 *    leaks timing information, so only the successful path is constant
	 *    time (NB: This assumes that node ID length is constant).
	 *  * Instead of HMAC-SHA256, use BLAKE2s.
	 *  * Instead of HKDF-HMAC-SHA256, use lopd_expand.
	 *  * Change the personalization to differentiate it from standard ntor.
	 */

	secret_input_len = LODP_ECDH_SECRET_LEN * 2 + node_id_len +
	    LODP_ECDH_PUBLIC_KEY_LEN * 3 + sizeof(NTOR_PROTOID);
	auth_input_len = sizeof(s.verify) + node_id_len +
	    LODP_ECDH_PUBLIC_KEY_LEN * 3 + sizeof(NTOR_PROTOID) +
	    sizeof(NTOR_RESPONDER);
	p = s.secret_input;

	assert(secret_input_len <= sizeof(s.secret_input));
	assert(auth_input_len <= sizeof(s.auth_input));

	if (NULL != b) {
		/*
		 * Responder:
		 * SecretInput = EXP(X,y) | EXP(X,b) | ID | B | X | Y | PROTOID
		 */

		assert(NULL != y);
		assert(NULL != b);

		lodp_ecdh(&s.secret, y, X);
		if (curve25519_validate_secret(&s.secret))
			goto out;
		memcpy(p, s.secret.secret, LODP_ECDH_SECRET_LEN);
		p += LODP_ECDH_SECRET_LEN;
		lodp_ecdh(&s.secret, b, X);
		if (curve25519_validate_secret(&s.secret))
			goto out;
		memcpy(p, s.secret.secret, LODP_ECDH_SECRET_LEN);
		p += LODP_ECDH_SECRET_LEN;
	} else {
		/*
		 * Initiator:
		 * SecretInput = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
		 */

		assert(NULL != x);

		lodp_ecdh(&s.secret, x, Y);
		if (curve25519_validate_secret(&s.secret))
			goto out;
		memcpy(p, s.secret.secret, LODP_ECDH_SECRET_LEN);
		p += LODP_ECDH_SECRET_LEN;
		lodp_ecdh(&s.secret, x, B);
		if (curve25519_validate_secret(&s.secret))
			goto out;
		memcpy(p, s.secret.secret, LODP_ECDH_SECRET_LEN);
		p += LODP_ECDH_SECRET_LEN;
	}

	tmp = p;
	memcpy(p, node_id, node_id_len);
	p += node_id_len;
	memcpy(p, B->public_key, LODP_ECDH_PUBLIC_KEY_LEN);
	p += LODP_ECDH_PUBLIC_KEY_LEN;
	memcpy(p, X->public_key, LODP_ECDH_PUBLIC_KEY_LEN);
	p += LODP_ECDH_PUBLIC_KEY_LEN;
	memcpy(p, Y->public_key, LODP_ECDH_PUBLIC_KEY_LEN);
	p += LODP_ECDH_PUBLIC_KEY_LEN;
	memcpy(p, NTOR_PROTOID, sizeof(NTOR_PROTOID));
	p += sizeof(NTOR_PROTOID);
	assert(p - secret_input_len == s.secret_input);

	/* SharedSecret = H(SecretInput, t_key) */
	ret = lodp_mac(shared_secret, s.secret_input, &NTOR_T_KEY,
		shared_secret_len, secret_input_len);
	if (ret)
		goto out;

	/* Verify = H(SecretInput, t_key) */
	ret = lodp_mac(s.verify, s.secret_input, &NTOR_T_VERIFY, sizeof(s.verify),
		secret_input_len);
	if (ret)
		goto out;

	/* AuthInput = Verify | ID | B | Y | X | PROTOID | "Responder" */
	memcpy(s.auth_input, s.verify, sizeof(s.verify));
	memcpy(s.auth_input + sizeof(s.verify), tmp, p - tmp);
	p = s.auth_input + sizeof(s.verify) + (p - tmp);
	memcpy(p, NTOR_RESPONDER, sizeof(NTOR_RESPONDER));
#ifndef NDEBUG
	p += sizeof(NTOR_RESPONDER);
	assert(p - auth_input_len == s.auth_input);
#endif

	/* Auth = H(AuthInput, t_mac) */
	ret = lodp_mac(auth, s.auth_input, &NTOR_T_MAC, auth_len, auth_input_len);
	if (ret)
		goto out;

out:
	lodp_memwipe(&s, sizeof(s));
	return ((LODP_ERR_OK == ret) ? ret : LODP_ERR_BAD_HANDSHAKE);
}


int
lodp_siv_encrypt(uint8_t *ciphertext, const lodp_siv_key *key, const
    uint8_t *plaintext, size_t ct_len, size_t pt_len)
{
	blake2s_state state;
	int ret;

	assert(NULL != ciphertext);
	assert(NULL != key);
	assert(NULL != plaintext);
	assert(pt_len > 0);
	assert(is_initialized);

	if (ct_len != pt_len + LODP_SIV_TAG_LEN)
		return (LODP_ERR_INVAL);

	ret = LODP_ERR_INVAL;
	if (blake2s_init_key(&state, LODP_SIV_IV_LEN, key->mac_key.mac_key,
	    LODP_MAC_KEY_LEN))
		goto out;

	/* Generate the Associated Data (random 16 byte nonce) */
	lodp_rand_bytes(ciphertext + LODP_SIV_IV_LEN, LODP_SIV_NONCE_LEN);

	/* Generate the Synthetic IV */
	blake2s_update(&state, ciphertext + LODP_SIV_IV_LEN,
	    LODP_SIV_NONCE_LEN);
	blake2s_update(&state, plaintext, pt_len);
	blake2s_final(&state, ciphertext, LODP_SIV_IV_LEN);

	/* Do the bulk encryption */
	xchacha((chacha_key *)&key->stream_key, (chacha_iv24 *)ciphertext,
	    plaintext, ciphertext + LODP_SIV_TAG_LEN, pt_len, 20);
	ret = LODP_ERR_OK;

out:
	lodp_memwipe(&state, sizeof(state));
	return (ret);
}


int
lodp_siv_encrypt_data(uint8_t *ciphertext, const lodp_siv_key *key,
    const uint8_t *pkt, const uint8_t *data, size_t ct_len, size_t hdr_len,
    size_t data_len, size_t pad_len)
{
	struct {
		blake2s_state	iv_state;
		chacha_state	state;
	} s;
	uint8_t *p;
	int ret;

	assert(NULL != ciphertext);
	assert(NULL != key);
	assert(NULL != pkt);
	assert(NULL != data);
	assert(hdr_len > 0);
	assert(is_initialized);

	if (ct_len != hdr_len + LODP_SIV_TAG_LEN + data_len + pad_len)
		return (LODP_ERR_INVAL);

	/*
	 * Getto scatter/gather variant of lodp_siv_encrypt() specifically for
	 * handling DATA packets.
	 *
	 * Having this routine lets us save a memcpy() in the outgoing DATA
	 * packet path.
	 *
	 * We assume that pkt looks like:
	 *    header[hdr_len] (Will be 8 bytes for DATA)
	 *    skip[data_len]
	 *    padding[pad_len]
	 *
	 * We weave in data[data_len] instead of processing skip, to arrive at
	 * the correct packet.
	 */

	ret = LODP_ERR_INVAL;
	if (blake2s_init_key(&s.iv_state, LODP_SIV_IV_LEN, key->mac_key.mac_key,
	    LODP_MAC_KEY_LEN))
		goto out;

	/* Generate the Associated Data (random 16 byte nonce) */
	lodp_rand_bytes(ciphertext + LODP_SIV_IV_LEN, LODP_SIV_NONCE_LEN);

	/* Generate the Synthetic IV */
	blake2s_update(&s.iv_state, ciphertext + LODP_SIV_IV_LEN,
	    LODP_SIV_NONCE_LEN);
	blake2s_update(&s.iv_state, pkt, hdr_len);
	blake2s_update(&s.iv_state, data, data_len);
	blake2s_update(&s.iv_state, pkt + hdr_len + data_len, pad_len);
	blake2s_final(&s.iv_state, ciphertext, LODP_SIV_IV_LEN);

	/* Do the bulk encryption */
	xchacha_init(&s.state, (chacha_key *)&key->stream_key,
	    (chacha_iv24 *)ciphertext, 20);
	p = ciphertext + LODP_SIV_TAG_LEN;
	p += chacha_update(&s.state, pkt, p, hdr_len);
	if (data_len > 0)
		p += chacha_update(&s.state, data, p, data_len);
	if (pad_len > 0)
		p += chacha_update(&s.state, pkt + hdr_len + data_len, p, pad_len);
	p += chacha_final(&s.state, p);
	ret = LODP_ERR_OK;

out:
	lodp_memwipe(&s, sizeof(s));
	return (ret);
}


int
lodp_siv_decrypt(uint8_t *plaintext, const lodp_siv_key *key, const uint8_t
    *ciphertext, size_t pt_len, size_t ct_len)
{
	struct {
		blake2s_state	state;
		uint8_t		siv_cmp[LODP_SIV_IV_LEN];
	} s;
	int ret;

	assert(NULL != plaintext);
	assert(NULL != ciphertext);
	assert(NULL != key);
	assert(pt_len > 0);
	assert(is_initialized);

	if (ct_len != pt_len + LODP_SIV_TAG_LEN)
		return (LODP_ERR_INVAL);

	if (blake2s_init_key(&s.state, LODP_SIV_IV_LEN, key->mac_key.mac_key,
	    LODP_MAC_KEY_LEN)) {
		lodp_memwipe(&s, sizeof(s));
		return (LODP_ERR_INVAL);
	}

	/* Decrypt first */
	xchacha((chacha_key *)&key->stream_key, (chacha_iv24 *)ciphertext,
	    ciphertext + LODP_SIV_TAG_LEN, plaintext, pt_len, 20);

	/*
	 * Authenticate the AD + plaintext by calculating the SIV and comparing
	 * it with the one that was used in the decryption.
	 */

	blake2s_update(&s.state, ciphertext + LODP_SIV_IV_LEN,
	    LODP_SIV_NONCE_LEN);
	blake2s_update(&s.state, plaintext, pt_len);
	blake2s_final(&s.state, s.siv_cmp, sizeof(s.siv_cmp));
	ret = lodp_memeq(s.siv_cmp, ciphertext, LODP_SIV_IV_LEN);

	lodp_memwipe(&s, sizeof(s));
	return ((ret == 0) ? LODP_ERR_OK : LODP_ERR_INVALID_MAC);
}


int
lodp_derive_resp_introkey(lodp_siv_key *siv_key, const lodp_ecdh_public_key
    *pub_key)
{
	return (lodp_derive_init_introkey(siv_key, pub_key->public_key,
	       LODP_ECDH_PUBLIC_KEY_LEN));
}


int
lodp_derive_init_introkey(lodp_siv_key *siv_key, const uint8_t *src, size_t len)
{
	struct {
		uint8_t prk[LODP_MAC_DIGEST_LEN];
		uint8_t okm[LODP_SIV_KEY_LEN];
	} s;
	int ret;

	assert(NULL != siv_key);
	assert(NULL != src);
	assert(LODP_SIV_SRC_LEN == len);
	assert(is_initialized);

	/*
	 * Salt = "LODP-Intro-BLAKE2s"
	 * PRK = LODP-Extract(Salt, SourceMaterial)
	 * IntroductorySIVKey = LODP-Expand(PRK, Salt, 64)
	 */

	ret = lodp_extract(s.prk, KDF_INTRO_SALT, src, sizeof(s.prk),
		sizeof(KDF_INTRO_SALT), len);
	if (ret)
		goto out;
	ret = lodp_expand(s.okm, s.prk, KDF_INTRO_SALT, sizeof(s.okm),
		sizeof(s.prk), sizeof(KDF_INTRO_SALT));
	if (ret)
		goto out;
	memcpy(siv_key->mac_key.mac_key, s.okm, LODP_MAC_KEY_LEN);
	memcpy(siv_key->stream_key.stream_key, s.okm + LODP_MAC_KEY_LEN,
	    LODP_STREAM_KEY_LEN);

out:
	lodp_memwipe(&s, sizeof(s));
	return (ret);
}


int
lodp_derive_sessionkeys(lodp_siv_key *init_key, lodp_siv_key *resp_key,
    const uint8_t *shared_secret, size_t shared_secret_len)
{
	uint8_t okm[LODP_SIV_KEY_LEN * 2];
	const uint8_t *p;
	int ret;

	assert(NULL != init_key);
	assert(NULL != resp_key);
	assert(NULL != shared_secret);
	assert(LODP_MAC_DIGEST_LEN == shared_secret_len);
	assert(is_initialized);

	/*
	 * Salt = "LODP-Session-BLAKE2s
	 * PRK = SharedSecret
	 * SessionKey = LODP-Expand(PRK, Salt, 128)
	 * InitiatorSIVKey = leftmost(SessionKey, LODP_SIV_KEY_LEN)
	 * ResponderSIVKey = rightmost(SessionKey, LODP_SIV_KEY_LEN)
	 */

	ret = lodp_expand(okm, shared_secret, KDF_SESSION_SALT, sizeof(okm),
		shared_secret_len, sizeof(KDF_SESSION_SALT));
	if (ret)
		goto out;
	p = okm;
	memcpy(init_key->mac_key.mac_key, p, LODP_MAC_KEY_LEN);
	p += LODP_MAC_KEY_LEN;
	memcpy(init_key->stream_key.stream_key, p, LODP_STREAM_KEY_LEN);
	p += LODP_STREAM_KEY_LEN;
	memcpy(resp_key->mac_key.mac_key, p, LODP_MAC_KEY_LEN);
	p += LODP_MAC_KEY_LEN;
	memcpy(resp_key->stream_key.stream_key, p, LODP_STREAM_KEY_LEN);
#ifndef NDEBUG
	p += LODP_STREAM_KEY_LEN;
	assert(p - sizeof(okm) == okm);
#endif

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

	for (i = 0; i < n; i++)
		ret |= a[i] ^ b[i];

	return (ret);
}


static void
curve25519_generate_pubkey(lodp_ecdh_keypair *keypair)
{
	const uint8_t basepoint[32] = { 9 };

	/*
	 * Ensure that the private key is well formed
	 *
	 * Note:
	 * curve25519-donna also will do this for us, but that's possibly
	 * implementation dependent.
	 */

	keypair->private_key.private_key[0] &= 248;
	keypair->private_key.private_key[31] &= 127;
	keypair->private_key.private_key[31] |= 64;

	/* Derive the public key */
	curve25519_donna(keypair->public_key.public_key,
	    keypair->private_key.private_key, basepoint);
}


static int
curve25519_validate_secret(lodp_ecdh_shared_secret *secret)
{
	const uint8_t infpoint[LODP_ECDH_PUBLIC_KEY_LEN] = { 0 };

	assert(NULL != secret);
	return (!lodp_memeq(secret->secret, infpoint, LODP_ECDH_SECRET_LEN));
}


static int
lodp_extract(uint8_t *prk, const uint8_t *salt, const uint8_t *ikm,
    size_t prk_len, size_t salt_len, size_t ikm_len)
{
	if (blake2s(prk, ikm, salt, prk_len, ikm_len, salt_len))
		return (LODP_ERR_INVAL);

	return (LODP_ERR_OK);
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
	int ret;

	N = (okm_len + BLAKE2S_OUTBYTES - 1) / BLAKE2S_OUTBYTES;
	if (N > 255)
		return (LODP_ERR_INVAL);

	ret = LODP_ERR_INVAL;
	p = okm;
	for (i = 1; i <= N; i++) {
		size_t to_copy = (okm_len > sizeof(T)) ? sizeof(T) : okm_len;
		if (blake2s_init_key(&state, sizeof(T), prk, prk_len))
			goto out;
		if (i > 1)
			blake2s_update(&state, T, sizeof(T));
		blake2s_update(&state, info, info_len);
		blake2s_update(&state, &i, sizeof(i));
		blake2s_final(&state, T, sizeof(T));
		memcpy(p, T, to_copy);
		p += to_copy;
		okm_len -= to_copy;
	}
	ret = LODP_ERR_OK;

out:
	lodp_memwipe(&state, sizeof(state));
	lodp_memwipe(T, sizeof(T));
	return (ret);
}
