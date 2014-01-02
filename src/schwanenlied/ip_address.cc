/**
 * @file  ip_address.cc
 * @author Yawning Angel (yawning at schwanenlied dot me)
 * @brief   A portable IP address/port wrapper (IMPLEMENTATION)
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

#include <cstring>

#include <arpa/inet.h>

#include "schwanenlied/ip_address.h"

namespace schwanenlied {

// Constants stolen from libutp, because they looked into this more than I have
static const size_t kIPv4UdpMTU = 1402;
static const size_t kIPv6UdpMTU = 1232;

IPAddress::IPAddress(const crypto::SipHash& hash,
                     const struct sockaddr* addr,
                     const socklen_t len,
                     const bool safe) :
    safe_(safe),
    version_(0),
    addr_hash_(0),
    addr_(),
    addr_len_(len) {
  SL_ASSERT(addr != nullptr);

  if (addr->sa_family == AF_INET) {
    SL_ASSERT(addr_len_ == sizeof(struct sockaddr_in));
    uint8_t hash_buf[4 + 2];
    const struct sockaddr_in *v4addr = reinterpret_cast<const struct
        sockaddr_in*>(addr);
    ::std::memcpy(hash_buf, &v4addr->sin_addr.s_addr, 4);
    ::std::memcpy(hash_buf + 4, &v4addr->sin_port, 2);
    addr_hash_ = hash.digest(hash_buf, sizeof(hash_buf));
    version_ = 4;
  } else if (addr->sa_family == AF_INET6) {
    SL_ASSERT(addr_len_ == sizeof(struct sockaddr_in6));
    uint8_t hash_buf[16 + 2];
    const struct sockaddr_in6 *v6addr = reinterpret_cast<const struct
        sockaddr_in6*>(addr);
    ::std::memcpy(hash_buf, v6addr->sin6_addr.s6_addr, 16);
    ::std::memcpy(hash_buf + 16, &v6addr->sin6_port, 2);
    addr_hash_ = hash.digest(hash_buf, sizeof(hash_buf));
    version_ = 6;
  } else
    SL_ABORT("Unsupported address type");

  ::std::memcpy(&addr_, addr, addr_len_);
}

bool IPAddress::operator==(const IPAddress& rhs) const {
  if (hash() != rhs.hash())
    return false;

  if (version() != rhs.version())
    return false;

  if (version() == 4) {
    const struct sockaddr_in *v4addr_lhs = reinterpret_cast<const struct
        sockaddr_in*>(sockaddr());
    const struct sockaddr_in *v4addr_rhs = reinterpret_cast<const struct
        sockaddr_in*>(rhs.sockaddr());

    if (v4addr_lhs->sin_port != v4addr_rhs->sin_port)
      return false;

    return v4addr_lhs->sin_addr.s_addr == v4addr_rhs->sin_addr.s_addr;
  } else if (version() == 6) {
    const struct sockaddr_in6 *v6addr_lhs = reinterpret_cast<const struct
        sockaddr_in6*>(sockaddr());
    const struct sockaddr_in6 *v6addr_rhs = reinterpret_cast<const struct
        sockaddr_in6*>(rhs.sockaddr());

    if (v6addr_lhs->sin6_port != v6addr_rhs->sin6_port)
      return false;

    return  (0 == ::std::memcmp(v6addr_lhs->sin6_addr.s6_addr,
                                v6addr_rhs->sin6_addr.s6_addr, 16));
  }

  SL_ABORT("Unsupported address type");
}

bool IPAddress::operator<(const IPAddress& rhs) const {
  if (hash() != rhs.hash())
    return hash() < rhs.hash();

  if (version() != rhs.version())
    return version() < rhs.version();

  if (version() == 4) {
    const struct sockaddr_in *v4addr_lhs = reinterpret_cast<const struct
        sockaddr_in*>(sockaddr());
    const struct sockaddr_in *v4addr_rhs = reinterpret_cast<const struct
        sockaddr_in*>(rhs.sockaddr());

    if (v4addr_lhs->sin_addr.s_addr >= v4addr_rhs->sin_addr.s_addr)
      return false;

    return v4addr_lhs->sin_port < v4addr_rhs->sin_port;
  } else if (version() == 6) {
    const struct sockaddr_in6 *v6addr_lhs = reinterpret_cast<const struct
        sockaddr_in6*>(sockaddr());
    const struct sockaddr_in6 *v6addr_rhs = reinterpret_cast<const struct
        sockaddr_in6*>(rhs.sockaddr());

    if (0 <= ::std::memcmp(v6addr_lhs->sin6_addr.s6_addr,
                           v6addr_rhs->sin6_addr.s6_addr, 16))
      return false;

    return v6addr_lhs->sin6_port < v6addr_rhs->sin6_port;
  }

  SL_ABORT("Unsupported address type");
}

const struct sockaddr* IPAddress::sockaddr() const {
  return reinterpret_cast<const struct sockaddr*>(&addr_);
}

const size_t IPAddress::udp_mtu() const {
  if (version_ == 4) {
    return kIPv4UdpMTU;
  } else if (version_ == 6) {
    return kIPv6UdpMTU;
  }

  SL_ABORT("Unsupported address type");
}

::std::string IPAddress::to_string() const {
  std::string ret;
  char addrstr[INET6_ADDRSTRLEN];
  ret.reserve(INET6_ADDRSTRLEN + 2 + 1 + 5);
  if (version_ == 4) {
    // IPv4 addresses return "xxx.xxx.xxx.xxx:port"
    const struct sockaddr_in* v4addr = reinterpret_cast<const struct
        sockaddr_in*>(&addr_);
    if (!safe_) {
      ::inet_ntop(AF_INET, &v4addr->sin_addr, addrstr, sizeof(addrstr));
      ret = addrstr;
    } else
      ret = "[scrubbed]";
    uint16_t port = ntohs(v4addr->sin_port);
    ret += ':';
    ret += ::std::to_string(port);
  } else if (version_ == 6) {
    // IPv6 addresses return "[<address>]:port"
    const struct sockaddr_in6* v6addr = reinterpret_cast<const struct
        sockaddr_in6*>(&addr_);
    ret = '[';
    if (!safe_) {
      ::inet_ntop(AF_INET6, &v6addr->sin6_addr, addrstr, sizeof(addrstr));
      ret += addrstr;
    } else
      ret += "scrubbed";
    uint16_t port = htons(v6addr->sin6_port);
    ret += "]:";
    ret += ::std::to_string(port);
  } else
    ret = "<Unknown Address Type>";

  return ret;
}

bool IPAddress::is_sockaddr_valid(const struct sockaddr* addr,
                                  const socklen_t addr_len) {
  if (addr->sa_family == AF_INET) {
    return (addr_len == sizeof(struct sockaddr_in));
  } else if (addr->sa_family == AF_INET6) {
    return (addr_len == sizeof(struct sockaddr_in6));
  }

  return false;
}

} // namespace schwanenlied
