/*
 * lodp_crypto.h: LODP Cryptography
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

#ifndef _LODP_CRYPTO_H_
#define _LODP_CRYPTO_H_


/* Initialization/Termination */
int lodp_crypto_init(void);
void lodp_crypto_term(void);


/* ECDH (Curve25519) */
#define LODP_ECDH_PUBLIC_KEY_LEN	32
#define LODP_ECDH_PRIVATE_KEY_LEN	32
#define LODP_ECDH_SECRET_LEN		32


typedef struct {
	uint8_t public_key[LODP_ECDH_PUBLIC_KEY_LEN];
} lodp_ecdh_public_key;

typedef struct {
	uint8_t private_key[LODP_ECDH_PRIVATE_KEY_LEN];
} lodp_ecdh_private_key;

typedef struct {
	uint8_t secret[LODP_ECDH_SECRET_LEN];
} lodp_ecdh_shared_secret;

typedef struct {
	lodp_ecdh_public_key	public_key;
	lodp_ecdh_private_key	private_key;
} lodp_ecdh_keypair;


int lodp_gen_keypair(lodp_ecdh_keypair *keypair, const uint8_t *buf,
    size_t len);
int lodp_gen_pubkey(lodp_ecdh_public_key *pub_key, const uint8_t *buf,
    size_t len);
int lodp_ecdh_validate_pubkey(const lodp_ecdh_public_key *pub_key);
void lodp_ecdh(lodp_ecdh_shared_secret *secret, const lodp_ecdh_private_key
    *private_key, const lodp_ecdh_public_key *public_key);


/* MAC and bulk crypto (BLAKE2s/XChaCha) */
#define LODP_MAC_KEY_LEN	32
#define LODP_MAC_DIGEST_LEN	32
#define LODP_BULK_KEY_LEN	32
#define LODP_BULK_IV_LEN	24


typedef struct {
	uint8_t mac_key[LODP_MAC_KEY_LEN];
} lodp_mac_key;

typedef struct {
	uint8_t bulk_key[LODP_BULK_KEY_LEN];
} lodp_bulk_key;

typedef struct {
	lodp_mac_key	mac_key;
	lodp_bulk_key	bulk_key;
} lodp_symmetric_key;


int lodp_mac(uint8_t *digest, const uint8_t *buf, const lodp_mac_key *key,
    size_t digest_len, size_t len);
int lodp_encrypt(uint8_t *ciphertext, const lodp_bulk_key *key, const uint8_t
    *iv, const uint8_t *plaintext, size_t len);
int lodp_decrypt(uint8_t *plaintext, const lodp_bulk_key *key, const uint8_t
    *iv, const uint8_t *ciphertext, size_t len);


/* LODP specific KDF/Handshake */
int lodp_derive_introkeys(lodp_symmetric_key *sym_key, const
    lodp_ecdh_public_key *pub_key);
int lodp_derive_sessionkeys(lodp_symmetric_key *init_key, lodp_symmetric_key
    *resp_key, const uint8_t *shared_secret, size_t shared_secret_len);
int lodp_ntor(uint8_t *shared_secret, uint8_t *auth,
    const lodp_ecdh_public_key *X, const lodp_ecdh_private_key *x,
    const lodp_ecdh_public_key *Y, const lodp_ecdh_private_key *y,
    const lodp_ecdh_public_key *B, const lodp_ecdh_private_key *b,
    const uint8_t *node_id, size_t node_id_len,
    size_t shared_secret_len, size_t auth_len);


/* Utility Routines */
#define LODP_HASH_KEY_LEN    16


typedef struct {
	uint8_t hash_key[LODP_HASH_KEY_LEN];
} lodp_hash_key;


uint64_t lodp_hash(const void *buf, size_t len);
void lodp_rand_bytes(void *s, size_t n);
void *lodp_memwipe(void *s, size_t n);
int lodp_memeq(const void *s1, const void *s2, size_t n);


#endif
