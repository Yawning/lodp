/**
 * @file   bloom_filter.h
 * @author Yawning Angel (yawning at schwanenlied dot me)
 * @brief  A SipHash-2-4 based Active-Active Bloom Filter
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

#ifndef SCHWANENLIED_BLOOM_FILTER_H__
#define SCHWANENLIED_BLOOM_FILTER_H__

#include <vector>

#include "schwanenlied/common.h"
#include "schwanenlied/crypto/random.h"
#include "schwanenlied/crypto/siphash.h"

namespace schwanenlied {

/**
 * A [SipHash-2-4](@ref crypto::SipHash) based Active-Active Bloom Filter
 *
 * It is designed to be stable over time even when it is filled to max capacity
 * by implementing the active-active buffering (A2 buffering) scheme presented
 * in "Aging Bloom Filter with Two Active Buffers for Dynamic Sets" (MyungKeun
 * Yoon).
 *
 * Internally it attempts to be fast, requiring one SipHash-2-4 invocation per
 * query, though like all Bloom Filters it will do horrific
 * things to the d-cache with a large number of hash functions.
 *
 * Notes:
 * - The A2 Bloom Filter uses 2 caches, so creating a 1 MiB filter for example
 *   actually consumes 2 MiB + alpha of storage.
 * - The limits to the implementation are:
 *   + A maximum cache size of 2 GiB.
 *   + A maximum of 32 hash functions (Could be increased, but storage for the
 *     hashes is allocated on the stack, so potentially unwise).
 * - Despite using SipHash-2-4, neither querying nor adding elements to the
 *   Bloom Filter is constant time.  It does attempt to defend itself against
 *   people feeding crafted data by randomizing the SipHash-2-4 key per
 *   instance and by using a cryptographic PRF.
 */
class BloomFilter {
 public:
  /** The maximum size of the a single Bloom Filter as a power of 2 */
  static const size_t kMaxMLn2 = 31;
  /** The maximum number of hash functions usable by the Bloom Filter */
  static const int kMaxNrHashes = 32;

  /**
   * Create a Bloom Filter with a given cache size and target false postive
   * rate.  The constructor will automatically determine the number of entries
   * that a filter of the requested size can support, and the number of hash
   * functions required to achive the desired false positive rate.
   *
   * @warning If an attempt is made to create a Bloom Filter that exceeds
   * certain rather generous hardcoded limits, this will SL_ASSERT().
   *
   * @param[in] rng   The crypto::Random instance used to key the hash
   * @param[in] m_ln2 The size of an active buffers in bits as a power of 2
   * @param[in] p     The desired false positive rate
   */
  BloomFilter(crypto::Random& rng,
              const size_t m_ln2,
              const double p);

  /** @{ */
  /** Return the size of each cache in bytes. */
  const size_t size() const { return active_1_.size(); }
  /** Return the maximum number of entries per cache */
  const size_t nr_entries_max() const { return nr_entries_max_; }
  /** @} */

  /** @{ */
  /**
   * Test a given buffer for membership.
   *
   * This function will change the internal state of the caches if the queried
   * item is in the A2 cache but not the A1 cache in order to maintain the
   * semantics of the A2 buffering algorithm.
   *
   * @param[in] buf A pointer to the buffer
   * @param[in] len The size of the buffer in bytes
   *
   * @returns true  - The buffer **may** be present
   * @returns false - The buffer it is **not** present
   */
  bool test(const void* buf,
            const size_t len);

  /**
   * Test a given buffer for membership, and add it unconditonally.
   *
   * @param[in] buf A pointer to the buffer
   * @param[in] len The size of the buffer in bytes
   *
   * @returns true  - The buffer **may** be present
   * @returns false - The buffer it is **not** present
   */
  bool test_and_set(const void* buf,
                    const size_t len);
  /** @} */

  /** @{ */
  /**
   * Calculate the number of entries that will fit in a Bloom Filter given size
   * and target false positive rate.
   *
   * @param[in] m_ln2 The size of the Bloom Filter in bits as a power of 2
   * @param[in] p     The desired false positive rate
   *
   * @returns The maximum number of entries that will fit in the Bloom Filter
   */
  static const size_t calculate_n(const size_t m_ln2,
                                  const double p);

  /**
   * Calculate the required size of a Bloom Filter given the number of entries
   * and the target false positive rate.
   *
   * @param[in] n   The number of entries the Bloom Filter must hold
   * @param[in] p   The desired false positive rate
   *
   * @returns The size of the the Bloom Filter in bits as a power of 2
   */
  static const size_t calculate_m(const size_t n,
                                  const double p);

  /**
   * Calculate the number of hash functions needed given a Bloom filter size and
   * the number of entries it needs to contain.
   *
   * @param[in] m_ln2 The size of the Bloom Filter in bits as a power of 2.
   * @param[in] n     The number of entries the Bloom Filter must hold
   *
   * @returns The number of hash functions the Bloom Filter needs to use
   */
  static const int calculate_k(const size_t m_ln2,
                               const size_t n);
  /** @} */

 private:
  BloomFilter() = delete;
  BloomFilter(const BloomFilter&) = delete;
  void operator=(const BloomFilter&) = delete;

  /**
   * Given a pointer to a buffer, calculate the set of hashes used to test for
   * membership.
   *
   * @param[out] hashes The backing store for the hashes
   * @param[in]  buf A pointer to the buffer
   * @param[in]  len The size of the buffer in bytes
   */
  const inline void get_hashes(uint32_t* hashes,
                               const void* buf,
                               const size_t len) const;

  /**
   * Test to see if the cache contains the entry described by a set ofhashes.
   *
   * @param[in] cache The cache to query
   * @param[in] hashes The set of hashes that describe the entry
   *
   * @returns true - The entry **may** be present
   * @returns false - The entry is **not** present
   */
  const inline bool test_cache(const ::std::vector<uint8_t>& cache,
                               const uint32_t* hashes) const;

  /**
   * Insert the entry described by a set of hashes into the Active 1 cache.
   *
   * @param[in] hashes The set of hashes that describes the entry
   */
  inline void add_cache_active_1(const uint32_t* hashes);

  /**
   * Swap the caches, and insert the entry described by a set of hashes into the
   * new Active 1 cache.
   *
   * @param[in] hashes The set of hashes that describes the entry
   */
  inline void flip_cache(const uint32_t* hashes);

  crypto::SipHash hash_;  /**< The crypto::SipHash instance */
  int nr_hashes_;         /**< Number of hash functions used to query ("k") */
  size_t nr_entries_;     /**< Number of entries currently in active_1_ */
  size_t nr_entries_max_; /**< Maximum number of entries in each cache ("n") */
  uint32_t hash_mask_;    /**< Bitmask used to truncate the hash output */
  ::std::vector<uint8_t> active_1_; /**< The "Active 1" cache */
  ::std::vector<uint8_t> active_2_; /**< The "Active 2" cache */
};

} // namespace schwanenlied

#endif // SCHWANENLIED_BLOOM_FILTER_H__
