/**
 * @file    random.cc
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   C++ wrapper around libottery (IMPLEMENTATION)
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

#include <cstdlib>
#include <mutex>

// libottery doesn't do this in the header, though it should
extern "C" {
#include <ottery.h>
}

#include "schwanenlied/crypto/random.h"

namespace schwanenlied {
namespace crypto {

static ::std::once_flag init_rng;

Random::Random() {
  ::std::call_once(init_rng, []() {
    int ret = ::ottery_init(nullptr);
    SL_ASSERT(ret == 0);
  });
}

void Random::get_bytes(void* buf, const size_t len) const {
  ::ottery_rand_bytes(buf, len);
}

uint32_t Random::get_uint32() const {
  return ::ottery_rand_uint32();
}

uint32_t Random::get_uint32_range(uint32_t max) const {
  return ::ottery_rand_range(max);
}

} // namespace crypto
} // namespace schwanenlied
