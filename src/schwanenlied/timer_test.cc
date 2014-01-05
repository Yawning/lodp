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

#include <chrono>

#include "schwanenlied/timer.h"
#include "gtest/gtest.h"

namespace schwanenlied {

class TimerTest : public ::testing::Test {
 public:
  bool timer_fired_ = false;

 protected:
  virtual void SetUp() {};
  virtual void TearDown() {};
};

TEST_F(TimerTest, SmokeTest) {
  const ::std::chrono::milliseconds interval(200);

  Timer t([this]() {
    this->timer_fired_ = true;
    uv_stop(uv_default_loop());          
  });

  ASSERT_TRUE(t.start(interval));
  ASSERT_TRUE(t.is_active());

  // Most overcomplicated sleep implementation ever
  auto start = ::std::chrono::steady_clock::now();
  uv_run(uv_default_loop(), UV_RUN_DEFAULT);

  ASSERT_TRUE(::std::chrono::steady_clock::now() - start > interval);
  ASSERT_TRUE(timer_fired_);
}

} // namespace schwanenlied
