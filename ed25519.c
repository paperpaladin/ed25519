/* ed25519.c -- Ed25519 (RFC 8032) and X25519 (RFC 7748) in one C11 file.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NOT PRODUCTION CRYPTO: not constant-time, no blinding, no hardening, no
 * memory wiping.  See ed25519.h and README.md.
 */
#include "ed25519.h"
#include <string.h>

/* ===================================================================== *
 * SHA-512 -- VENDORED, not reimplemented.
 *
 * Lifted from the sibling project ../sha2 (sha2.c, GPL-3.0-or-later, same
 * repo collection) and stripped to SHA-512 alone: the 32-bit core, the
 * truncated variants, HMAC and PBKDF2 do not come along.  Over there it is
 * checked against the NIST CAVP byte vectors and against CPython hashlib,
 * GNU coreutils and openssl over every message length from 0 to 2048; the
 * same code here is checked again against hashlib by t/diff.py, so the
 * vendored copy carries its own oracle on this side of the fence.
 *
 * The one change from the original: a single 64-bit byte counter instead of
 * sha2.c's 128-bit one, since the high half is unreachable without 2^61
 * bytes of message, and a const-context final() is not needed here.
 * ===================================================================== */

static const uint64_t K512[80] = {
	0x428a2f98d728ae22ull, 0x7137449123ef65cdull,
	0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
	0x3956c25bf348b538ull, 0x59f111f1b605d019ull,
	0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
	0xd807aa98a3030242ull, 0x12835b0145706fbeull,
	0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
	0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull,
	0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
	0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull,
	0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
	0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull,
	0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
	0x983e5152ee66dfabull, 0xa831c66d2db43210ull,
	0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
	0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull,
	0x06ca6351e003826full, 0x142929670a0e6e70ull,
	0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull,
	0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
	0x650a73548baf63deull, 0x766a0abb3c77b2a8ull,
	0x81c2c92e47edaee6ull, 0x92722c851482353bull,
	0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull,
	0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
	0xd192e819d6ef5218ull, 0xd69906245565a910ull,
	0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
	0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull,
	0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
	0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull,
	0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
	0x748f82ee5defb2fcull, 0x78a5636f43172f60ull,
	0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
	0x90befffa23631e28ull, 0xa4506cebde82bde9ull,
	0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
	0xca273eceea26619cull, 0xd186b8c721c0c207ull,
	0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
	0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull,
	0x113f9804bef90daeull, 0x1b710b35131c471bull,
	0x28db77f523047d84ull, 0x32caab7b40c72493ull,
	0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
	0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull,
	0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull,
};

#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

static uint64_t ld64be(const unsigned char *p)
{
	uint64_t v = 0;
	for (int i = 0; i < 8; i++)
		v = v << 8 | p[i];
	return v;
}

/* FIPS 180-4 section 6.4.2.  nblk whole 128-byte blocks. */
static void compress512(uint64_t *h, const unsigned char *p, size_t nblk)
{
	while (nblk--) {
		uint64_t w[80], a = h[0], b = h[1], c = h[2], d = h[3];
		uint64_t e = h[4], f = h[5], g = h[6], hh = h[7];
		for (int t = 0; t < 16; t++)
			w[t] = ld64be(p + 8 * t);
		for (int t = 16; t < 80; t++) {
			uint64_t x = w[t - 15], y = w[t - 2];
			uint64_t s0 = ROR64(x, 1) ^ ROR64(x, 8) ^ (x >> 7);
			uint64_t s1 = ROR64(y, 19) ^ ROR64(y, 61) ^ (y >> 6);
			w[t] = w[t - 16] + s0 + w[t - 7] + s1;
		}
		for (int t = 0; t < 80; t++) {
			uint64_t S1 = ROR64(e, 14) ^ ROR64(e, 18) ^ ROR64(e, 41);
			uint64_t t1 = hh + S1 + CH(e, f, g) + K512[t] + w[t];
			uint64_t S0 = ROR64(a, 28) ^ ROR64(a, 34) ^ ROR64(a, 39);
			uint64_t t2 = S0 + MAJ(a, b, c);
			hh = g; g = f; f = e; e = d + t1;
			d = c; c = b; b = a; a = t1 + t2;
		}
		h[0] += a; h[1] += b; h[2] += c; h[3] += d;
		h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
		p += 128;
	}
}

struct sha512 {
	uint64_t h[8];
	uint64_t n;			/* message bytes so far */
	unsigned char buf[128];
	unsigned blen;
};

static void sha512_init(struct sha512 *c)
{
	static const uint64_t iv[8] = {
		0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull,
		0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
		0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
		0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull,
	};
	memcpy(c->h, iv, sizeof iv);
	c->n = 0;
	c->blen = 0;
}

static void sha512_update(struct sha512 *c, const void *data, size_t len)
{
	const unsigned char *p = data;

	c->n += len;
	if (c->blen) {
		size_t want = 128 - c->blen;
		if (len < want) {
			memcpy(c->buf + c->blen, p, len);
			c->blen += (unsigned)len;
			return;
		}
		memcpy(c->buf + c->blen, p, want);
		compress512(c->h, c->buf, 1);
		c->blen = 0;
		p += want;
		len -= want;
	}
	if (len >= 128) {
		size_t nblk = len / 128;
		compress512(c->h, p, nblk);
		p += nblk * 128;
		len -= nblk * 128;
	}
	memcpy(c->buf, p, len);
	c->blen = (unsigned)len;
}

static void sha512_final(struct sha512 *c, unsigned char out[64])
{
	uint64_t bitlo = c->n << 3, bithi = c->n >> 61;

	c->buf[c->blen++] = 0x80;
	if (c->blen > 112) {
		memset(c->buf + c->blen, 0, 128 - c->blen);
		compress512(c->h, c->buf, 1);
		c->blen = 0;
	}
	memset(c->buf + c->blen, 0, 112 - c->blen);
	for (int i = 0; i < 8; i++) {
		c->buf[112 + i] = (unsigned char)(bithi >> (56 - 8 * i));
		c->buf[120 + i] = (unsigned char)(bitlo >> (56 - 8 * i));
	}
	compress512(c->h, c->buf, 1);
	for (int i = 0; i < 64; i++)
		out[i] = (unsigned char)(c->h[i / 8] >> (56 - 8 * (i % 8)));
}

void ed25519_sha512(const void *data, size_t len, unsigned char out[64])
{
	struct sha512 c;
	sha512_init(&c);
	sha512_update(&c, data, len);
	sha512_final(&c, out);
}

/* ===================================================================== *
 * CLI.  Everything is driven through this: there is no separate C test
 * program.  `ed25519 OP ARGS...` does one operation; `ed25519 run` reads
 * one such command per line from stdin and prints one result line per
 * command, which is what lets t/diff.py push tens of thousands of
 * operations through a single process.
 * ===================================================================== */
#ifdef ED25519_CLI
#include <stdio.h>
#include <stdlib.h>

#define BLOBMAX (64 * 1024)
#define LINEMAX (4 * BLOBMAX + 64)

static int unhex1(int ch)
{
	if (ch >= '0' && ch <= '9') return ch - '0';
	if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
	if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
	return -1;
}

/* "-" means the empty string, because an empty argv token cannot survive
 * whitespace splitting.  Returns the byte count, or -1. */
static long unhex(const char *s, unsigned char *out, size_t cap)
{
	size_t n = strlen(s), i;
	if (n == 1 && s[0] == '-')
		return 0;
	if (n % 2 || n / 2 > cap)
		return -1;
	for (i = 0; i < n; i += 2) {
		int hi = unhex1(s[i]), lo = unhex1(s[i + 1]);
		if (hi < 0 || lo < 0)
			return -1;
		out[i / 2] = (unsigned char)(hi << 4 | lo);
	}
	return (long)(n / 2);
}

static void puthex(const unsigned char *p, size_t n)
{
	static const char d[] = "0123456789abcdef";
	for (size_t i = 0; i < n; i++) {
		putchar(d[p[i] >> 4]);
		putchar(d[p[i] & 15]);
	}
}

/* One command.  Always prints exactly one line. */
static void docmd(int argc, char **argv)
{
	static unsigned char a[BLOBMAX];
	long na;

	if (argc < 1) {
		puts("ERR noop");
		return;
	}
	if (!strcmp(argv[0], "sha512") && argc == 2) {
		unsigned char h[64];
		if ((na = unhex(argv[1], a, sizeof a)) < 0) {
			puts("ERR hex");
			return;
		}
		ed25519_sha512(a, (size_t)na, h);
		puthex(h, 64);
		putchar('\n');
		return;
	}
	puts("ERR unknown");
}

int main(int argc, char **argv)
{
	static char line[LINEMAX];

	if (argc == 2 && !strcmp(argv[1], "run")) {
		while (fgets(line, sizeof line, stdin)) {
			char *tok[8];
			int n = 0;
			char *p = line, *q;
			while (n < 8 && (q = strtok(p, " \t\r\n")) != NULL) {
				tok[n++] = q;
				p = NULL;
			}
			if (n == 0)
				continue;
			docmd(n, tok);
		}
		return ferror(stdin) ? 1 : 0;
	}
	if (argc >= 2) {
		docmd(argc - 1, argv + 1);
		return 0;
	}
	fprintf(stderr, "usage: %s OP ARGS... | %s run\n", argv[0], argv[0]);
	return 2;
}
#endif /* ED25519_CLI */
