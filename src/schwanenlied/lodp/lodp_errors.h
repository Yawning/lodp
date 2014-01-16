/**
 * @file    lodp_errors.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   LODP error codes
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

#ifndef SCHWANENLIED_LODP_ERROR_H__
#define SCHWANENLIED_LODP_ERROR_H__

namespace schwanenlied {
namespace lodp {

/**
 * The base offset of all LODP specific errors
 *
 * The LODP code shifts all of it's own errors into a unused portion of the int
 * return code space since it allows the application to propagate return values
 * back to the calling code from the callbacks.
 */
const int kErrorOffset = 0x0020000;

/** @{ */
/** Session is not the initiator */
const int kErrorNotInitiator = -(kErrorOffset | 1);
/** Session is not the responder */
const int kErrorNotResponder = -(kErrorOffset | 2);
/** Session must rekey */
const int kErrorMustRekey = -(kErrorOffset | 3);
/** @} */

/** @{ */
/** Packet too small */
const int kErrorUndersizedPacket = -(kErrorOffset | 10);
/** Packet too big */
const int kErrorOversizedPacket = -(kErrorOffset | 11);
/** Failed to decrypt packet  */
const int kErrorDecryptionFailure = -(kErrorOffset | 12);
/** Packet is not a protobuf */
const int kErrorInvalidEnvelope = -(kErrorOffset | 13);
/** Bad packet format */
const int kErrorBadPacketFormat = -(kErrorOffset | 14);
/** @} */

/** @{ */
/** Protocol error */
const int kErrorProtocol = -(kErrorOffset | 20);
/** Received a replayed INIT packet */
const int kErrorInitReplayed = -(kErrorOffset | 21);
/** Received a invalid cookie in a HANDSHAKE packet */
const int kErrorInvalidCookie = -(kErrorOffset | 22);
/** Received a replayed HANDSHAKE packet */
const int kErrorCookieReplayed = -(kErrorOffset | 23);
/** ntor handshake failed */
const int kErrorHandshakeFailed = -(kErrorOffset | 24);
/** @} */

} // namespace lodp
} // namespace schwanenlied

#endif // SCHWANENLIED_LODP_ERROR_H__
