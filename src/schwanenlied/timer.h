/**
 * @file    timer.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   Asynchronous callback based timer
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

#ifndef SCHWANENLIED_TIMER_H__
#define SCHWANENLIED_TIMER_H__

#include <chrono>
#include <functional>

#include <uv.h>

#include "schwanenlied/common.h"

namespace schwanenlied {

/**
 * Asynchronous callback based timer
 *
 * This provides a simple millisecond resolution timer based on
 * [libuv](https://github.com/joyent/libuv).  It is expected that the
 * application handles running the libuv default event loop, and nothing will
 * happen if the loop is not actually run.
 *
 * @todo Like crypto::Random this may be better off as an abstract base class
 */
class Timer {
 public:
  /**
   * Create a timer with a given callback function.
   *
   * @param[in] callback_fn The function to call when the timer expires
   */
  Timer(const ::std::function<void()> callback_fn);
  
  ~Timer();

  /** @{ */
  /** Return the status of the timer */
  const bool is_active() const;
  /** @} */

  /** @{ */
  /**
   * Start the timer
   *
   * @param[in] delta_t The timer duration in milliseconds
   *
   * @returns true - The timer was schedule successfully
   * @returns false - The timer failed to be scheduled
   */
  bool start(const ::std::chrono::milliseconds& delta_t);

  /** Stop the timer */
  void stop();
  /** @} */

  /** @{ */
  /**
   * Invoke the timer callback function
   *
   * @note This does not change the status of the timer (scheduled/stopped)
   */
  void fire() const {
    callback_fn_();
  }
  /** @} */

 private:
  Timer() = delete;
  Timer(const Timer&) = delete;
  void operator=(const Timer&) = delete;

  const ::std::function<void()> callback_fn_; /**< The timer callback */
  uv_timer_t* timer_handle_; /**< The libuv timer handle */
};

} // namespace schwanenlied

#endif // SCHWANENLIED_TIMER_H__
