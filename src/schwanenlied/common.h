/**
 * @file    common.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   Common definitions and includes
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

#ifndef SCHWANENLIED_COMMON_H_
#define SCHWANENLIED_COMMON_H_

#include <cstddef>
#include <cstdint>
#include <iostream>

/**
 * An assert() replacement that will unconditionally be called
 *
 * When the library asserts, it is for something totally fundemental that's a
 * programmer error or the code is in such a messed up state that the only sane
 * thing to do is to exit.  This is used in lieu of throwing exceptions to catch
 * invalid parameters in constructors and thus requires a custom definiton that
 * will be evaluated regardless of NDEBUG being defined.
 */
#define SL_ASSERT(expression)                                           \
do {                                                                    \
  if (!(expression)) {                                                  \
    std::cerr << "Assertion failed: " << #expression << std::endl;      \
    std::cerr << "  in: " << __PRETTY_FUNCTION__ << std::endl;          \
    std::cerr << "  at: " << __FILE__ << ":" << __LINE__ << std::endl;  \
    std::terminate();                                                   \
  }                                                                     \
} while(0)

/**
 * An assert(0) replacement that will give more useful information
 *
 * This is for things like code that should never be reached.
 */
#define SL_ABORT(message)                                               \
do {                                                                    \
  std::cerr << "Internal Error: " << #message << std::endl;             \
  std::cerr << "  in: " << __PRETTY_FUNCTION__ << std::endl;            \
  std::cerr << "  at: " << __FILE__ << ":" << __LINE__ << std::endl;    \
  std::terminate();                                                     \
} while(0)

/** @{ */

/**
 * The base offset of all the common error codes
 *
 * All of the code shifts the errors returned to a hopefully unused portion of
 * the return code space so that the application can propagate return values
 * back via callbacks without ambiguity.
 */
const int kErrorOffset = 0x0010000;

/** Success */
const int kErrorOk = 0;

/** Invalid argument */
const int kErrorInval = -(kErrorOffset | 1);
/** Address family not supported */
const int kErrorAFNoSupport = -(kErrorOffset | 2);
/** Session in a bad state */
const int kErrorBadFD = -(kErrorOffset | 3);
/** Message too long */
const int kErrorMsgSize = -(kErrorOffset | 4);
/** No remaining descriptors */
const int kErrorNFile = -(kErrorOffset | 5);
/** Resource temporarily unavailable */
const int kErrorAgain = -(kErrorOffset | 6);

/** Is connected */
const int kErrorIsConn = -(kErrorOffset | 10);
/** Is not connected */
const int kErrorNotConn = -(kErrorOffset | 11);
/** Connection aborted */
const int kErrorConnAborted = -(kErrorOffset | 12);
/** Connection refused */
const int kErrorConnRefused = -(kErrorOffset | 13);
/** @} */

#ifdef DOXYGEN
/*
 * Doxygen related stuff
 */
/** schwanenlied.me */
namespace schwanenlied {

/** Cryptography modules */
namespace crypto {}

/** LODP modules */
namespace lodp {
/** LODP packets (Autogenerated) */
namespace packet {}
} // namespace lodp

/** NQTCP modules */
namespace nqtcp {
/** NQTCP packet (Autogenerated) */
namespace packet {}
} // namespace nqtcp

} // namespace schwanenlied
#endif // DOXYGEN

#endif // SCHWANENLIED_COMMON_H_
