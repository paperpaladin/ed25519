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

/* Ed25519, RFC 8032.  A secret key is a 32-byte seed; the public key is
 * derived from it, and ed25519_sign takes only the seed so a public key
 * that does not match cannot be passed in. */
#define ED25519_SEED_BYTES       32
#define ED25519_PUBLIC_KEY_BYTES 32
#define ED25519_SIGNATURE_BYTES  64

void ed25519_keygen(const unsigned char seed[32], unsigned char pk[32]);

void ed25519_sign(unsigned char sig[64], const void *msg, size_t len,
		  const unsigned char seed[32]);

/* 0 if the signature is good, -1 otherwise.  Refuses an unreduced S and
 * any non-canonical point encoding, and uses the cofactorless equation
 * [S]B == R + [k]A that RFC 8032 5.1.7 specifies.
 *
 * THE CALLER MUST CHECK THE LENGTH.  This reads exactly 64 bytes and has
 * no way to know how many were offered, so a signature that arrived
 * truncated, padded, or with anything appended is this function's caller's
 * problem -- it will happily verify the first 64 bytes of a 96-byte blob
 * and report success.  Project Wycheproof devotes twelve vectors to that
 * shape, every one of them expected to be rejected, and all twelve are
 * rejected by length before reaching here. */
int ed25519_verify(const unsigned char sig[64], const void *msg, size_t len,
		   const unsigned char pk[32]);

/* X25519, RFC 7748.  Defined on every 32-byte string: there is no input
 * validation and none is required -- half of all u values put the point on
 * the twist rather than on Curve25519 and the result is still safe to use.
 *
 * x25519_base is x25519 against u = 9, RFC 7748's generator.
 *
 * Callers doing Diffie-Hellman may want to reject an all-zero output,
 * which happens exactly when the peer sent a low-order point.  RFC 7748
 * makes that check optional for X25519 and it is not done here. */
#define X25519_KEY_BYTES 32

void x25519(unsigned char out[32], const unsigned char k[32],
	    const unsigned char u[32]);

void x25519_base(unsigned char out[32], const unsigned char k[32]);

#endif /* ED25519_H */
