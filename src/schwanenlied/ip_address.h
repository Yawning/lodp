/**
 * @file  ip_address.h
 * @author Yawning Angel (yawning at schwanenlied dot me)
 * @brief   A portable IP address/port wrapper
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

#ifndef SCHWANENLIED_IP_ADDRESS_H__
#define SCHWANENLIED_IP_ADDRESS_H__

#include <functional>
#include <string>

#include <netinet/in.h>

#include "schwanenlied/common.h"
#include "schwanenlied/crypto/siphash.h"

namespace schwanenlied {

/**
 * A portable IP address/port wrapper
 *
 * Internally it stores the [SipHash-2-4](@ref crypto::SipHash) digest of the
 * address/port and uses the hash to avoid comparisons.  This is useful when
 * implementing a connection table, and will protect implementations from hash
 * flooding type attacks as long as the SipHash key is changed appropriately
 * (Eg: on application startup).
 *
 * Overloaded operators and a ::std::hash specialization are also provided to
 * allow this object to safely be used as a key in STL containers without
 * worrying about algorithmic complexity attacks.
 *
 * @warning It is important to keep in mind that all instances SHOULD be
 * constructed with the same SipHash instance.
 *
 * The to_string() method is aware of privacy sensitive logging, and will scrub
 * the address (but **NOT** the port) if the object is constructed
 * appropriately.
 */
class IPAddress {
 public:
  /**
   * Create a IP address/port based on a given sockaddr
   *
   * @warning If the address type is unsupported, the library will SL_ABORT()
   *
   * @param[in] hash  The crypto::SipHash instance used for address comparisons
   * @param[in] addr  The struct sockaddr that describes the address and port
   * @param[in] len   The length of addr
   * @param[in] safe  Sanitize the IP address when converting it to a string
   */
  IPAddress(const crypto::SipHash& hash,
            const struct sockaddr* addr,
            const socklen_t len,
            const bool safe = false);
  IPAddress(const IPAddress&) = default;

  /** @{ */
  bool operator==(const IPAddress& rhs) const;
  bool operator!=(const IPAddress& rhs) const { return !(*this == rhs); }
  bool operator<(const IPAddress& rhs) const;
  bool operator>(const IPAddress& rhs) const { return rhs < *this; }
  bool operator<=(const IPAddress& rhs) const { return !(*this > rhs); }
  bool operator>=(const IPAddress& rhs) const { return !(*this < rhs); }
  /** @} */

  /** @{ */
  /** Get a pointer to a struct sockaddr suitable for use with socket calls */
  const struct sockaddr* sockaddr() const;

  /** Get the length of struct sockaddr returned by addr() */
  const socklen_t length() const { return addr_len_; }

  /**
   * Get the IP protocol version of the address
   *
   * @returns 4 - IPv4 address
   * @returns 6 - IPv6 address
   */
  const int version() const { return version_; }

  /** Get the UDP MTU of the address in bytes */
  const size_t udp_mtu() const;

  /** Get a cryptographic hash of the IP/port combination */
  const uint64_t hash() const { return addr_hash_; }

  /**
   * Get a string representation of the IP/port ("safe" addresses scrub)
   *
   * @note This uses inet_ntop() which is missing on certain operating systems.
   * The only one of relevance is sufficiently old versions of Windows (XP and
   * below).
   */
  ::std::string to_string() const;
  /** @} */

  /**
   * Validate a sockaddr and determine if it is possible to construct an
   * IPAddress from it
   *
   * @param[in] addr      The struct sockaddr that describes the address and port
   * @param[in] addr_len  The length of addr
   */
  static bool is_sockaddr_valid(const struct sockaddr* addr,
                                const socklen_t addr_len);

 private:
  IPAddress() = delete;

  const bool safe_;     /**< Sanitize the IP address in to_string() */
  int version_;         /**< IP version of the address */
  uint64_t addr_hash_;  /**< The SipHash-2-4 digest of the address/port */
  struct sockaddr_storage addr_;  /**< A copy of the original sockaddr */
  const socklen_t addr_len_;      /**< The length of the data in addr_ */
};

} // namespace schwanenlied

namespace std {

/**
 * Template specialization for ::schwanenlied::IPAddress
 *
 * This relies on ::schwanenlied::IPAddress::hash(), and will allow  one to
 * safely use ::schwanenlied::IPAddress as keys in the STL's unordered
 * associative containers.
 */
template <>
struct hash<::schwanenlied::IPAddress> {
 public:
  size_t operator()(const schwanenlied::IPAddress& addr) const {
    // The compiler should optimize this branch out
    if (sizeof(size_t) == sizeof(uint64_t)) {
      return addr.hash();
    } else {
      return static_cast<size_t>(addr.hash());
    }
  }
};

} // namespace std

#endif // SCHWANENLIED_IP_ADDRESS_H__
