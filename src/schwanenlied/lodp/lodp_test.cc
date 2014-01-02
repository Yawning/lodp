/*
 * lodp_test.cc: Simple LODP functionality test
 *
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

#include <arpa/inet.h>

#include <cstring>

// If you're really anal about valgrind...
//#include <google/protobuf/stubs/common.h>

#include "schwanenlied/lodp/lodp_endpoint.h"
#include "schwanenlied/lodp/lodp_session.h"
#include "gtest/gtest.h"

namespace schwanenlied {
namespace lodp {

class LodpTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    // Initialize the client/server "addresses" (fake)
    ::std::memset(&client_addr_, 0, sizeof(client_addr_));
    client_addr_.sin_family = AF_INET;
    client_addr_.sin_port = htons(6969);
    inet_pton(AF_INET, "127.0.0.1", &client_addr_.sin_addr);

    ::std::memset(&server_addr_, 0, sizeof(server_addr_));
    server_addr_.sin_family = AF_INET;
    server_addr_.sin_port = htons(2323);
    inet_pton(AF_INET, "127.0.0.1", &server_addr_.sin_addr);
  };
  virtual void TearDown() {};

  struct sockaddr_in client_addr_;
  struct sockaddr_in server_addr_;

};

// A callback class that implements a simple loopback interface
// that implements a echo server on the responder end and pushes data
// between two endpoints.
class TestCallbacks : public LodpCallbacks {
 public:
  TestCallbacks() :
      client_endpoint_(nullptr),
      server_endpoint_(nullptr),
      client_session_(nullptr),
      server_session_(nullptr) {}

  int sendto(LodpEndpoint& endpoint,
             const void* buf,
             const size_t buf_len,
             const struct sockaddr* addr,
             const socklen_t addr_len) override;

  size_t pad_size(const LodpSession& session,
                  const size_t available) override;

  bool should_accept(const LodpEndpoint& endpoint,
                     const struct sockaddr* addr,
                     const socklen_t addr_len) override;

  void on_accept(LodpEndpoint& endpoint,
                 LodpSession* session,
                 const struct sockaddr* addr,
                 const socklen_t addr_len) override;

  void on_connect(LodpSession& session,
                  const int status) override;

  void on_recv(LodpSession& session,
               const void* buf,
               const size_t buf_len) override;

  void on_rekey_needed(LodpSession& session) override;

  void on_rekey(LodpSession& session,
                const int status) override;

  void on_close(const LodpSession& session) override;

  LodpEndpoint* client_endpoint_;
  LodpEndpoint* server_endpoint_;
  LodpSession* client_session_;
  LodpSession* server_session_;
};

int TestCallbacks::sendto(LodpEndpoint& endpoint,
                          const void* buf,
                          const size_t buf_len,
                          const struct sockaddr* addr,
                          const socklen_t addr_len) {
  SCOPED_TRACE("sendto() callback");

  if (&endpoint == client_endpoint_) {
    int ret = server_endpoint_->on_packet(reinterpret_cast<const uint8_t*>(buf),
                                          buf_len, addr, addr_len);
    EXPECT_EQ(kErrorOk, ret);
    return ret;
  } else if (&endpoint == server_endpoint_) {
    int ret = client_endpoint_->on_packet(reinterpret_cast<const uint8_t*>(buf),
                                          buf_len, addr, addr_len);
    EXPECT_EQ(kErrorOk, ret);
    return ret;
  } else
    ADD_FAILURE(); // WTF endpoint is this?

  return -1;
}

size_t TestCallbacks::pad_size(const LodpSession& session,
                               const size_t available) {
  SCOPED_TRACE("pad_size() callback");

  // Always pad packets out to the MTU
  return available;
}

bool TestCallbacks::should_accept(const LodpEndpoint& endpoint,
                                  const struct sockaddr* addr,
                                  const socklen_t addr_len)  {
  SCOPED_TRACE("should_accept() callback");
  if (&endpoint == server_endpoint_) {
    EXPECT_EQ(nullptr, server_session_);
    if (server_session_ == nullptr)
      return true;
  } else
    ADD_FAILURE(); // Why is the client here?

  return false;
}

void TestCallbacks::on_accept(LodpEndpoint& endpoint,
                              LodpSession* session,
                              const struct sockaddr* addr,
                              const socklen_t addr_len) {
  SCOPED_TRACE("on_accept() callback");
  if (&endpoint == server_endpoint_) {
    EXPECT_EQ(nullptr, server_session_);
    if (server_session_ == nullptr)
      server_session_ = session;
  } else
    ADD_FAILURE(); // Why is the client here?
}

void TestCallbacks::on_connect(LodpSession& session,
                               const int status) {
  SCOPED_TRACE("on_connect() callback");
  EXPECT_EQ(client_session_, &session);
  EXPECT_EQ(kErrorOk, status);
}

void TestCallbacks::on_recv(LodpSession& session,
                            const void* buf,
                            const size_t buf_len) {
  SCOPED_TRACE("on_recv() callback");

  // The loopback test sends known data, so verify it.
  if (buf_len > 0) {
    const uint8_t* ptr = static_cast<const uint8_t*>(buf);
    for (size_t i = 0; i < buf_len; i++)
      ASSERT_TRUE(ptr[i] == static_cast<uint8_t>(i));
  }

  // The server is a echo server ^_^
  if (&session == server_session_) {
    int ret = server_session_->send(buf, buf_len);
    ASSERT_EQ(kErrorOk, ret);
  }
}

void TestCallbacks::on_rekey_needed(LodpSession& session) {
  SCOPED_TRACE("on_rekey_needed() callback");
}

void TestCallbacks::on_rekey(LodpSession& session,
                             const int status) {
  SCOPED_TRACE("on_rekey() callback");
}

void TestCallbacks::on_close(const LodpSession& session) {
  SCOPED_TRACE("on_close() callback");

  if (&session == client_session_)
    client_session_ = nullptr;
  else if (&session == server_session_)
    server_session_ = nullptr;
  else
    FAIL(); // WTF session is this?
}

// A simple loopback based test that exercises the "successful" codepaths for
// everything
TEST_F(LodpTest, LoopbackTest) {
  crypto::Random rng;
  TestCallbacks cbs;

  // Certain versions of GCC ship ::std::chrono::steady_clock that isn't
  // actually steady.  If the version of libstdc++ that lodpxx is compiled
  // against provides a clock that isn't monotonic, bad things will happen to
  // the internal timer code.  Not sure if this is really my problem when it's a
  // matter of "your STL implementaton isn't up to spec".
  EXPECT_TRUE(::std::chrono::steady_clock::is_steady);

  // Initialize the client endpoint
  cbs.client_endpoint_ = new LodpEndpoint(rng, cbs, nullptr, false);
  ASSERT_NE(nullptr, cbs.client_endpoint_);

  // Initialize the server endpoint
  const uint8_t node_id[] = { 'T', 'e', 's', 't', 'N', 'o', 'd', 'e' };
  crypto::Curve25519::PrivateKey server_priv_key(rng);
  crypto::Curve25519::PublicKey server_pub_key(server_priv_key);
  cbs.server_endpoint_ = new LodpEndpoint(rng, cbs, nullptr, false,
                                          server_priv_key, node_id,
                                          sizeof(node_id));
  ASSERT_NE(nullptr, cbs.server_endpoint_);

  // Client side: Attempt to connect.
  int ret = cbs.client_endpoint_->connect(nullptr, server_pub_key, node_id,
                                          sizeof(node_id),
                                          reinterpret_cast<sockaddr*>(&server_addr_),
                                          sizeof(server_addr_),
                                          cbs.client_session_);
  ASSERT_EQ(kErrorOk, ret);
  ASSERT_NE(nullptr, cbs.client_session_);

  // Handshake
  ret = cbs.client_session_->handshake();
  ASSERT_EQ(kErrorOk, ret);
  ASSERT_NE(nullptr, cbs.server_session_);

  // Excellent, the handshake went through, send a bunch of data
  uint8_t buf[1500] = { 0 };  // This is *always* bigger than the MTU
  for (size_t i = 0; i < sizeof(buf); i++)
    buf[i] = static_cast<uint8_t>(i);
  for (size_t sz = 0; sz < cbs.client_session_->mtu(); sz++) {
    ret = cbs.client_session_->send(buf, sz);
    ASSERT_EQ(kErrorOk, ret);
  }

  // Rekey
  ret = cbs.client_session_->rekey();
  ASSERT_EQ(kErrorOk, ret);

  // Excellent, the rekey apparently worked, send a bunch of data
  for (size_t sz = 0; sz < cbs.client_session_->mtu(); sz++) {
    ret = cbs.client_session_->send(buf, sz);
    ASSERT_EQ(kErrorOk, ret);
  }

  // Validate that all of the data was actually sent
  ASSERT_TRUE(cbs.client_session_->stats().tx_goodput_bytes_ ==
              cbs.client_session_->stats().rx_goodput_bytes_);
  ASSERT_TRUE(cbs.server_session_->stats().tx_goodput_bytes_ ==
              cbs.server_session_->stats().rx_goodput_bytes_);
  ASSERT_TRUE(cbs.client_session_->stats().tx_goodput_bytes_ ==
              cbs.server_session_->stats().tx_goodput_bytes_);

  // Close the client session
  cbs.client_session_->close();
  ASSERT_EQ(nullptr, cbs.client_session_);

  // Ensure that the server received/processed the shutdown, and closed the
  // session.
  //cbs.server_session_->close();
  ASSERT_EQ(nullptr, cbs.server_session_);

  delete cbs.server_endpoint_;
  delete cbs.client_endpoint_;

  // Valgrind will complain about memory being reachable unless the protobuf
  // library is torn down correctly, but we may want to use more protobuf stuff
  // later in another test case.
  //::google::protobuf::ShutdownProtobufLibrary();
}

} // namespace lodp
} // namespace schwanenlied
