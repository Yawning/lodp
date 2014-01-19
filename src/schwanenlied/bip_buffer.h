/**
 * @file    bip_buffer.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   Bi-partite Buffer
 */

/*
 * Copyright (c) 2014, Yawning Angel <yawning at schwanenlied dot me>
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

#ifndef SCHWANENLIED_BIP_BUFFER_H__
#define SCHWANENLIED_BIP_BUFFER_H__

#include <memory>

namespace schwanenlied {

/**
 * Bi-partite buffer (2 part ring buffer)
 *
 * This is the buffer datastructure as described by
 * [Simon Cooke](http://www.codeproject.com/Articles/3479/The-Bip-Buffer-The-Circular-Buffer-with-a-Twist).
 *
 * Differences from the original BipBuffer:
 * - This implementation is 64 bit clean
 * - The Bi-partite nature of the buffer can entirely be ignored if
 *   push_back(), pop_front(), and copy() are used exclusively (peek(),
 *   reserve() and commit() require understanding of how a Bip-Buffer works).
 * - The backing store is allocated at object construction time
 */
class BipBuffer {
 public:
  /**
   * Create a BipBuffer with a given size
   *
   * @param[in] sz The size of the BipBuffer
   */
  BipBuffer(const size_t sz);

  ~BipBuffer();

  /** @{ */
  /** Return the amount of data in the BipBuffer */
  const size_t size() const { return a_size_ + b_size_; }
  /** Return the capacity of the BipBuffer */
  const size_t max_size() const { return buffer_size_; }
  /** Return the size of the current reservation */
  const size_t reserve_size() const { return reserve_size_; }
  /** Return if the BipBuffer is empty */
  const bool empty() const { return size() == 0; }
  /** @} */

  /** @{ */
  /** Clear the contents of the BipBuffer */
  void clear();

  /**
   * Obtain a pointer to the head of the data
   *
   * It is important to note that this does not guarantee that all of the data
   * in the buffer is accessable as internally the data may be stored in 2
   * parts.  If access to everything is required, linearize() first.
   *
   * This is equivalent to "GetContiguousBlock()" in the original code.
   *
   * @warning Calls to push_back() or linearize() can invalidate the pointer
   * returned from this routine.
   *
   * @param[out] sz The amount of data accessable
   * @returns nullptr - The buffer is empty
   * @returns A pointer to the head of the data
   */
  const uint8_t* peek(size_t& sz) const;

  /**
   * Append data to the tail of the buffer
   *
   * @warning If the buffer is fragmented in a way that will result in data not
   * fitting (Space behind the "A" buffer is required), then this routine will
   * call linearize().
   *
   * @warning This routine will cause an assertion if it is called with a
   * reservation pending.
   *
   * @param[in] buf The data to append to the buffer
   * @param[in] sz The size of the data to append
   * @returns The amount of data copied into the buffer
   */
  const size_t push_back(const uint8_t* buf,
                         const size_t sz);

  /**
   * Remove data from the head of the buffer
   *
   * @param[in] sz The amount of data to remove
   */
  void pop_front(const size_t sz);

  /**
   * Copy data out of the buffer
   *
   * @param[in] buf The destination
   * @param[in] sz  The amount of data to copy
   * @param[in] offset The offset to copy from
   */
  const void copy(uint8_t* buf,
                  const size_t sz,
                  const size_t offset = 0) const;

  /**
   * Reserve space in the buffer
   *
   * Allocate space at the tail of the buffer for new data.  commit() *MUST* be
   * called after a successful reservation has been made before any of the
   * accesors will use the new allocation.
   *
   * This is equivalent to "Reserve()" in the original code.
   *
   * @param[in] sz The amount of space to reserve
   * @param[out] reserved The amount of space actually reserved
   * @returns nullptr No space available
   * @returns A pointer to the reserved space
   */
  uint8_t* reserve(const size_t sz,
                   size_t& reserved);

  /**
   * Finalize a reservation
   *
   * This informs the BipBuffer that the space allocated by reserve() is
   * actually in use.  It is possible to commit less than the amount of space
   * returned from reserve() (for example if the reservation was not needed, or
   * less space was actually used).
   *
   * This is equivalent to "Commit()" in the original code.
   *
   * @param[in] sz The size of the space to commit
   */
  void commit(const size_t sz);

  /**
   * Linearize the backing store
   *
   * This routine defragments the buffer into one contiguous region starting at
   * at the head of the backing store.  If there is both a "A" and "B" region
   * present, this will invalidate any pointers previously returned from peek(),
   * or reserve().
   *
   * @todo Avoid using a temporary buffer
   */
  void linearize();
  /** @} */

 private:
  BipBuffer() = delete;
  BipBuffer(const BipBuffer&) = delete;
  void operator=(const BipBuffer&) = delete;

  ::std::unique_ptr<uint8_t[]> buffer_; /**< The backing store */
  const size_t buffer_size_;            /**< Size of the backing store */

  size_t a_offset_;       /**< Offset of the "A" buffer */
  size_t a_size_;         /**< Size of the "A" buffer */
  size_t b_size_;         /**< Size of the "B" buffer */
  size_t reserve_offset_; /**< Offset of the reservation */
  size_t reserve_size_;   /**< Size of the reservation */
};

} // namespace schwanenlied

#endif // SCHWANENLIED_BIP_BUFFER_H__
