/**
 * @file    random.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   C++ wrapper around libottery
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

#ifndef SCHWANENLIED_CRYPTO_RANDOM_H__
#define SCHWANENLIED_CRYPTO_RANDOM_H__

#include <ottery_st.h>

#include "schwanenlied/common.h"

namespace schwanenlied {
namespace crypto {

/**
 * A C++ wrapper around [libottery](https://github.com/nmathewson/libottery),
 * a cryptographic PRNG.
 *
 * In theory this wrapper is unneccecary but this allows developers to switch
 * out the PRNG as needed.
 *
 * @todo This probably is better off as an abstract base class.
 */
class Random {
 public:
  /**
   * Construct the CSPRNG instance.
   *
   * The first time this is called it will explicitly initialize libottery.
   *
   * @warning If libottery fails to initialize, this will SL_ASSERT().
   */
  Random();

  /**
   * Destroy the PRNG instance.
   */
  ~Random();

  /** @{ */
  /**
   * Fill a buffer with random bytes.
   *
   * @param[out] buf The buffer to fill
   * @param[in]  len The number of random bytes to generate
   */
  void get_bytes(void* buf, const size_t len);

  /**
   * Generate a random 32 bit integer
   *
   * @return A random number between 0 and UINT_MAX inclusive
   */
  uint32_t get_uint32();

  /**
   * Generate a random 32 bit integer with an upper limit
   *
   * @param[in] max The upper limit
   * @return A random number between 0 and max
   */
  uint32_t get_uint32_range(uint32_t max);
  /** @} */

 private:
  Random(const Random&) = delete;
  void operator=(const Random&) = delete;

  struct ottery_state state_;
};

} // namespace crypto
} // namespace schwanenlied

#endif // SCHWANENLIED_CRYPTO_RANDOM_H__
