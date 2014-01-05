/**
 * @file    timer.cc
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   Asynchronous callback based timer (IMPLEMENTATION)
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

#include <cstdlib>

#include "schwanenlied/timer.h"

namespace schwanenlied {

Timer::Timer(const ::std::function<void()> callback_fn) :
    callback_fn_(callback_fn) {
  SL_ASSERT(callback_fn_);

  timer_handle_ = reinterpret_cast<uv_timer_t*>(::std::calloc(1, sizeof(*timer_handle_)));
  SL_ASSERT(timer_handle_ != nullptr);

  uv_timer_init(uv_default_loop(), timer_handle_);
  timer_handle_->data = this;
}

Timer::~Timer() {
  uv_handle_t* t_handle = reinterpret_cast<uv_handle_t*>(timer_handle_);

  // Stop the timer if it is pending
  if (uv_is_active(t_handle))
    uv_timer_stop(timer_handle_);

  // Handle defered timer cleanup with a lambda
  uv_close_cb close_cb = [](uv_handle_t* handle) {
    free(handle);
  };
  uv_close(t_handle, close_cb);

  timer_handle_ = nullptr;
}

const bool Timer::is_active() const {
  return (0 != uv_is_active(reinterpret_cast<uv_handle_t*>(timer_handle_)));
}

bool Timer::start(const ::std::chrono::milliseconds& delta_t) {
  // Stop the existing timer, if running
  stop();

  // Gratuitous use of yet another lambda to call the timer callback
  uv_timer_cb timer_cb = [](uv_timer_t* handle, int status) {
    // Does status ever hold anything important?
    reinterpret_cast<Timer*>(handle->data)->fire();
  };
  int ret = uv_timer_start(timer_handle_, timer_cb, delta_t.count(), 0);

  return (ret == 0);
}

void Timer::stop() {
  if (uv_is_active(reinterpret_cast<uv_handle_t*>(timer_handle_)))
    uv_timer_stop(timer_handle_);
}

} // namespace schwanenlied
