/* ed25519.h -- Ed25519 (RFC 8032) and X25519 (RFC 7748).
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NOT PRODUCTION CRYPTO.  This code is not constant-time, has no blinding,
 * no side-channel hardening and no secret-memory wiping.  The scalar
 * multiplication branches on the bits of the private scalar, so anything
 * that can measure how long ed25519_sign() takes, or watch its cache
 * footprint, can recover the private key.  Do not use it to protect
 * anything.  It exists to be *correct* against the published vectors.
 * See README.md, which says this first and at greater length.
 */
#ifndef ED25519_H
#define ED25519_H

#include <stddef.h>
#include <stdint.h>

/* SHA-512 (FIPS 180-4).  Needed by Ed25519 itself and exposed because the
 * RFC 8032 section 7.1 vectors include one whose message is a SHA-512
 * digest.  VENDORED from the sibling ../sha2 -- see ed25519.c. */
void ed25519_sha512(const void *data, size_t len, unsigned char out[64]);

#endif /* ED25519_H */
