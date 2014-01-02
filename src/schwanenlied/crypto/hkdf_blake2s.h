/**
 * @file    hkdf_blake2s.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   HKDF-BLAKE2s
 */

/*
 * Copyright (c) 2013, Yawning Angel <yawning at schwanenlied dot me>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
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

#ifndef SCHWANENLIED_CRYPTO_HKDF_BLAKE2S_H__
#define SCHWANENLIED_CRYPTO_HKDF_BLAKE2S_H__

#include <string>

#include "schwanenlied/common.h"
#include "schwanenlied/crypto/blake2s.h"
#include "schwanenlied/crypto/utils.h"

namespace schwanenlied {
namespace crypto {

/**
 * HMAC-Based Extract-and-Expand Key Derivation Function ([BLAKE2s](@ref crypto::Blake2s))
 *
 * This is a straight forward implementation of
 * [HKDF](http://tools.ietf.org/html/rfc5869) that uses BLAKE2s as the PRF.
 * As BLAKE2s supports keyed digests, the extract/expand routines do not
 * actually use HMAC.
 */
namespace HkdfBlake2s {

/**
 * HKDF-BLAKE2s-Extract
 *
 *     Let H(t, x) be BLAKE2s with key t, and message x.
 *
 *     HDKF-BLAKE2s-Extract(salt, IKM) -> PRK
 *
 *         PRK = H(salt, IKM)
 *
 * @param[in] salt      A pointer to the salt
 * @param[in] salt_len  The size of the salt
 * @param[in] ikm       The initial keying material to extract
 *
 * @returns The extracted key material
 */
SecureBuffer extract(const uint8_t* salt,
                     const size_t salt_len,
                     const SecureBuffer& ikm);

/**
 * HKDF-BLAKE2s-Expand
 *
 *     Let H(t, x) be BLAKE2s with key t, and message x.
 *
 *     HKDF-BLAKE2s-Expand(PRK, info, L) -> OKM
 *
 *         N = ceil(L/HashLen)
 *
 *         T = T(1) | T(2) | T(3) | ... | T(N)
 *
 *         OKM = first L octets of T
 *
 *         T(0) = empty string (zero length)
 *
 *         T(1) = H(PRK, T(0) | info | 0x01)
 *
 *         T(2) = H(PRK, T(1) | info | 0x02)
 *
 *         T(3) = H(PRK, T(2) | info | 0x03)
 *
 *         ...
 *
 *         T(N) = H(PRK, T(N - 1) | info | N)
 *
 * @param[in] prk       The pseudorandom key to expand
 * @param[in] info      A pointer to the info
 * @param[in] info_len  The size of the info
 * @param[in] len       The desired size of the expanded key material
 *
 * @returns The expanded key material
 */
SecureBuffer expand(const SecureBuffer& prk,
                    const uint8_t* info,
                    const size_t info_len,
                    const size_t len);

} // namespace HkdfBlake2s

} // namespace crypto
} // namespace schwanenlied

#endif // SCHWANENLIED_CRYPTO_HKDF_BLAKE2S_H__
