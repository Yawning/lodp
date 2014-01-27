/**
 * @file   bloom_filter.cc
 * @author Yawning Angel (yawning at schwanenlied dot me)
 * @brief  A SipHash-2-4 based Active-Active Bloom Filter (IMPLEMENTATION)
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

#include <cmath>
#include <cstring>

#include <alloca.h>

#include "schwanenlied/bloom_filter.h"

namespace schwanenlied {

static const double ln_2 = 0.69314718055994529;     // ln(2)
static const double ln_2_sq = 0.48045301391820139;  // ln(2) ^ 2

BloomFilter::BloomFilter(crypto::Random& rng,
                         const size_t m_ln2,
                         const double p) :
    hash_(rng),
    nr_hashes_(0),
    nr_entries_(0),
    nr_entries_max_(0),
    hash_mask_(0) {
  SL_ASSERT(m_ln2 <= kMaxMLn2);

  // Derive the number of entries and number of hashes
  uint32_t m = 1 << m_ln2;
  nr_entries_max_ = calculate_n(m_ln2, p);
  nr_hashes_ = calculate_k(m_ln2, nr_entries_max_);
  if (nr_hashes_ < 2)
    nr_hashes_ = 2; // Use at least 2 hashes
  SL_ASSERT(nr_hashes_ <= kMaxNrHashes);
  hash_mask_ = m - 1;

  active_1_.resize(m >> 3);
  active_2_.resize(m >> 3);
}

bool BloomFilter::test(const void* buf,
                       const size_t len) {
  // Calculate the hashes
  uint32_t *hashes = static_cast<uint32_t*>(alloca(nr_hashes_ * sizeof(uint32_t)));
  get_hashes(hashes, buf, len);

  if (test_cache(active_1_, hashes))
    return true;

  if (test_cache(active_2_, hashes)) {
    /*
     * Yes, despite this being "test" and not "test_and_set", this still will
     * insert the entry into a1, if it is only present in a2 to preserve the
     * A2Buffering semantics.
     */
    add_cache_active_1(hashes);
    if (++nr_entries_ > nr_entries_max_)
      flip_cache(hashes);
    return true;
  }

  return false;
}

bool BloomFilter::test_and_set(const void* buf,
                               const size_t len) {
  // Calculate the hashes
  uint32_t *hashes = static_cast<uint32_t*>(alloca(nr_hashes_ * sizeof(uint32_t)));
  get_hashes(hashes, buf, len);

  // Straight forward "from-the-paper" implementation of A2Buffering

  // if x is in the active1 cache then
  if (test_cache(active_1_, hashes))
    return true;

  // if x is in the active2 cache then
  bool ret = false;
  if (test_cache(active_2_, hashes))
    ret = true; // result := true
  else
    ret = false; // result := false

  // insert x into active1
  add_cache_active_1(hashes);

  // if active1 is full then
  if (++nr_entries_ > nr_entries_max_)
    flip_cache(hashes);

  return ret;
}

const size_t BloomFilter::calculate_n(const size_t m_ln2,
                                      const double p) {
  SL_ASSERT(m_ln2 > 0);
  SL_ASSERT(p > 0.0d);
  SL_ASSERT(p < 1.0d);

  double m = 1 << m_ln2;
  double n = -1.0d * m * ln_2_sq / std::log(p);

  return static_cast<size_t>(n);
}

const size_t BloomFilter::calculate_m(const size_t n,
                                      const double p) {
  SL_ASSERT(n > 0);
  SL_ASSERT(p > 0.0d);
  SL_ASSERT(p < 1.0d);

  double m = -1.0d * n * std::log(p) / ln_2_sq;

  return static_cast<size_t>(std::ceil(std::log2(m)));
}

const int BloomFilter::calculate_k(const size_t m_ln2,
                                   const size_t n) {
  SL_ASSERT(m_ln2 > 0);
  SL_ASSERT(n > 0);

  double m = 1 << m_ln2;
  return static_cast<int>((m * ln_2 / n) + 0.5);
}

const inline void BloomFilter::get_hashes(uint32_t* hashes,
                                          const void* buf,
                                          const size_t len) const {

  SL_ASSERT(nr_hashes_ >= 2);

  /*
   * According to Kirsch and Mitzenmacher with a suitably good PRF only two
   * calls to a hash algorithm are needed.
   *
   * We take this one step further and use a single invocation of SipHash-2-4
   * to generate the two hashes that the rest of the hashes are derived from.
   *
   * See:
   * "Less Hashing, Same Performance: Building a Better Bloom Filter"
   */
  uint64_t base_hash = hash_.digest(static_cast<const uint8_t*>(buf), len);
  hashes[0] = static_cast<uint32_t>(base_hash & 0xffffffff);
  hashes[1] = static_cast<uint32_t>(base_hash >> 32);
  for (int i = 2; i < nr_hashes_; i++)
    hashes[i] = hashes[0] + i * hashes[1];
}

const inline bool BloomFilter::test_cache(const std::vector<uint8_t>& cache,
                                          const uint32_t* hashes) const {
  for (int i = 0; i < nr_hashes_; i++) {
    uint32_t idx = hashes[i] & hash_mask_;
    if (0 == (cache[idx/8] & (1 << (idx & 7))))
      return false;
  }
  return true;
}

inline void BloomFilter::add_cache_active_1(const uint32_t* hashes) {
  for (int i = 0; i < nr_hashes_; i++) {
    uint32_t idx = hashes[i] & hash_mask_;
    active_1_[idx/8] |= (1 << (idx & 7));
  }
}

inline void BloomFilter::flip_cache(const uint32_t* hashes) {
  // flush active2
  ::std::memset(&active_2_[0], 0, active_2_.size());

  // switch active1 and 2
  active_1_.swap(active_2_);

  // insert x into active1
  add_cache_active_1(hashes);
  nr_entries_ = 1;
}

} // namespace schwanenlied
