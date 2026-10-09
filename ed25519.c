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
 * Field arithmetic mod p = 2^255 - 19.
 *
 * Five 64-bit limbs in radix 2^51, little-endian: the value is
 * f[0] + f[1]*2^51 + ... + f[4]*2^204.  The representation is redundant --
 * a field element has many limb encodings -- and the invariant maintained
 * everywhere below is that every limb is < 2^51 + 2^13 on entry to and exit
 * from every operation.  That bound is what makes the products fit:
 * (2^51+2^13)^2 * 19 * 5 < 2^109, well inside an unsigned __int128, and the
 * final carry 19*(t4 >> 51) < 2^62 fits a uint64_t.  fe_add and fe_sub
 * carry on the way out rather than leaving slack for a later operation to
 * absorb, which costs a few instructions and removes the whole class of
 * "limb grew too big three operations ago" bug.
 *
 * ../bigint next door does arbitrary-precision integers; none of it is
 * reusable here.  This is fixed-width arithmetic in a single modulus whose
 * shape (2^255 - 19, so 2^255 == 19) is the entire reason the code looks
 * like this.  Sharing a general bignum would have been slower and would
 * have had nothing to say about the carry bounds above.
 * ===================================================================== */

__extension__ typedef unsigned __int128 fe_u128;	/* -Wpedantic */

typedef uint64_t fe[5];

#define MASK51 0x7ffffffffffffull

/* p - 2 and (p - 5)/8, little-endian, as exponents for fe_pow. */
static const unsigned char FE_PM2[32] = {
	0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
};
static const unsigned char FE_PM5D8[32] = {
	0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f,
};

static void fe_0(fe h) { h[0] = h[1] = h[2] = h[3] = h[4] = 0; }
static void fe_1(fe h) { fe_0(h); h[0] = 1; }
static void fe_copy(fe h, const fe f) { memcpy(h, f, 5 * sizeof *h); }

/* One carry pass, wrap first.  Taking 2^255 == 19 before the chain rather
 * than after is what makes two passes provably enough to get every limb
 * strictly below 2^51: after this, limbs 0..3 are masked and only limb 4
 * can have grown, and by at most 1. */
static void fe_carry_pass(fe h)
{
	uint64_t c;
	c = h[4] >> 51; h[4] &= MASK51; h[0] += 19 * c;
	c = h[0] >> 51; h[0] &= MASK51; h[1] += c;
	c = h[1] >> 51; h[1] &= MASK51; h[2] += c;
	c = h[2] >> 51; h[2] &= MASK51; h[3] += c;
	c = h[3] >> 51; h[3] &= MASK51; h[4] += c;
}

static void fe_add(fe h, const fe f, const fe g)
{
	for (int i = 0; i < 5; i++)
		h[i] = f[i] + g[i];
	fe_carry_pass(h);
}

static void fe_sub(fe h, const fe f, const fe g)
{
	/* 2p, so the subtraction cannot go negative: g's limbs are below
	 * 2^51 + 2^13 and every limb of 2p is above that. */
	static const uint64_t twop[5] = {
		0xfffffffffffdaull, 0xffffffffffffeull, 0xffffffffffffeull,
		0xffffffffffffeull, 0xffffffffffffeull,
	};
	for (int i = 0; i < 5; i++)
		h[i] = f[i] + twop[i] - g[i];
	fe_carry_pass(h);
}

static void fe_neg(fe h, const fe f)
{
	fe z;
	fe_0(z);
	fe_sub(h, z, f);
}

static void fe_mul(fe h, const fe f, const fe g)
{
	fe_u128 t[5] = { 0, 0, 0, 0, 0 };
	uint64_t c = 0;
	int i, j;

	/* Schoolbook, with the top half folded down by 2^255 == 19.  Written
	 * as a loop rather than the usual 25 unrolled lines: gcc unrolls it
	 * anyway, and the unrolled form is where a transposed index hides.
	 * shortcut: no Karatsuba, no dedicated squaring -- fe_sq below just
	 * calls this.  A squaring that exploits the symmetry is about 30%
	 * fewer multiplies, which matters only if signing speed does. */
	for (i = 0; i < 5; i++)
		for (j = 0; j < 5; j++) {
			fe_u128 pr = (fe_u128)f[i] * g[j];
			if (i + j >= 5)
				t[i + j - 5] += 19 * pr;
			else
				t[i + j] += pr;
		}
	for (i = 0; i < 5; i++) {
		t[i] += c;
		h[i] = (uint64_t)t[i] & MASK51;
		c = (uint64_t)(t[i] >> 51);
	}
	h[0] += 19 * c;
	c = h[0] >> 51; h[0] &= MASK51; h[1] += c;
	c = h[1] >> 51; h[1] &= MASK51; h[2] += c;
}

static void fe_sq(fe h, const fe f) { fe_mul(h, f, f); }

static void fe_muls(fe h, const fe f, uint64_t s)
{
	fe c;
	fe_0(c);
	c[0] = s;
	fe_mul(h, f, c);
}

/* Canonical 32-byte little-endian encoding: the unique representative in
 * [0, p). */
static void fe_tobytes(unsigned char s[32], const fe f)
{
	fe t;
	uint64_t c, q;
	int i, j;

	fe_copy(t, f);
	fe_carry_pass(t);
	fe_carry_pass(t);	/* now every limb < 2^51, so t < 2^255 */

	/* q = 1 iff t + 19 >= 2^255, i.e. iff t >= p.  Then subtract p by
	 * adding 19 and dropping bit 255. */
	q = (t[0] + 19) >> 51;
	q = (t[1] + q) >> 51;
	q = (t[2] + q) >> 51;
	q = (t[3] + q) >> 51;
	q = (t[4] + q) >> 51;
	t[0] += 19 * q;
	c = t[0] >> 51; t[0] &= MASK51; t[1] += c;
	c = t[1] >> 51; t[1] &= MASK51; t[2] += c;
	c = t[2] >> 51; t[2] &= MASK51; t[3] += c;
	c = t[3] >> 51; t[3] &= MASK51; t[4] += c;
	t[4] &= MASK51;

	/* shortcut: a bit at a time, 256 iterations of nothing.  Five shifts
	 * and masks would do it, and that is exactly where an off-by-one in
	 * a limb boundary hides; this version has no boundaries to get
	 * wrong.  Not on any hot path -- it runs twice per signature. */
	for (i = 0; i < 32; i++) {
		unsigned v = 0;
		for (j = 0; j < 8; j++) {
			int bit = 8 * i + j;
			if (bit < 255)
				v |= (unsigned)((t[bit / 51] >> (bit % 51)) & 1)
				     << j;
		}
		s[i] = (unsigned char)v;
	}
}

/* Decode 32 bytes little-endian, ignoring bit 255 as RFC 7748 and RFC 8032
 * both require.  A non-canonical input (>= p) decodes to its own value mod
 * p without complaint; callers that must reject one re-encode and compare,
 * which is what fe_iscanon does. */
static void fe_frombytes(fe h, const unsigned char s[32])
{
	fe_0(h);
	for (int bit = 0; bit < 255; bit++)
		if ((s[bit / 8] >> (bit % 8)) & 1)
			h[bit / 51] |= (uint64_t)1 << (bit % 51);
}

static int fe_iscanon(const unsigned char s[32])
{
	unsigned char r[32];
	fe t;
	fe_frombytes(t, s);
	fe_tobytes(r, t);
	return memcmp(r, s, 32) == 0;
}

static int fe_isnonzero(const fe f)
{
	unsigned char s[32];
	unsigned char acc = 0;
	fe_tobytes(s, f);
	for (int i = 0; i < 32; i++)
		acc |= s[i];
	return acc != 0;
}

static int fe_isnegative(const fe f)
{
	unsigned char s[32];
	fe_tobytes(s, f);
	return s[0] & 1;
}

static int fe_eq(const fe f, const fe g)
{
	unsigned char a[32], b[32];
	fe_tobytes(a, f);
	fe_tobytes(b, g);
	return memcmp(a, b, 32) == 0;
}

/* h = f^e, e little-endian over nbits bits, square and multiply from the
 * top.  shortcut: the textbook ladder, 254 squarings and 254 conditional
 * multiplies for an inversion where the standard addition chain uses 254
 * squarings and 11 multiplies.  It is also, and this is the reason, the
 * version whose correctness is obvious by inspection; the exponent is a
 * constant in the table above and is checked against p - 2 in Python. */
static void fe_pow(fe h, const fe f, const unsigned char *e, int nbits)
{
	fe r, b;
	fe_1(r);
	fe_copy(b, f);
	for (int i = nbits - 1; i >= 0; i--) {
		fe_sq(r, r);
		if ((e[i / 8] >> (i % 8)) & 1)
			fe_mul(r, r, b);
	}
	fe_copy(h, r);
}

static void fe_invert(fe h, const fe f) { fe_pow(h, f, FE_PM2, 255); }

/* f^((p-5)/8), the exponent RFC 8032 section 5.1.1 uses to build a square
 * root: for p == 5 mod 8, if x is a square then x^((p-5)/8) * x is a square
 * root of x up to a factor of sqrt(-1). */
static void fe_pow22523(fe h, const fe f) { fe_pow(h, f, FE_PM5D8, 252); }


/* ===================================================================== *
 * Scalars mod L, the order of the base point.
 *
 *   L = 2^252 + 27742317777372353535851937790883648493
 *
 * Two things need this: reducing a 64-byte SHA-512 digest into a scalar,
 * and computing S = (r + k*a) mod L when signing.  Both are little-endian
 * byte strings in and out, because that is what RFC 8032 puts on the wire;
 * there is no limb representation here at all.
 * ===================================================================== */

static const unsigned char SC_L[32] = {
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
};

/* 1 iff s >= L, reading s as 32 bytes little-endian.  This is the
 * malleability check RFC 8032 section 5.1.7 requires of a verifier: a
 * signature carrying S + L verifies under the group equation just as well
 * as one carrying S, so a verifier that does not refuse it hands an
 * attacker a second valid signature for free. */
static int sc_geq_l(const unsigned char s[32])
{
	for (int i = 31; i >= 0; i--)
		if (s[i] != SC_L[i])
			return s[i] > SC_L[i];
	return 1;			/* exactly L, which is also >= L */
}

static void sc_sub_l(unsigned char s[32])
{
	int borrow = 0;
	for (int i = 0; i < 32; i++) {
		int v = (int)s[i] - (int)SC_L[i] - borrow;
		borrow = v < 0;
		s[i] = (unsigned char)(v & 0xff);
	}
}

/* out = in mod L, in little-endian, any length.
 *
 * Long division, one bit at a time, from the top: r = 2r + bit, then
 * subtract L if it fits.  r stays below L < 2^253, so 2r + 1 < 2^254 and
 * the 32-byte accumulator never overflows -- that is the only bound this
 * needs, and it is the reason the loop is this short.
 *
 * shortcut: 8*len iterations each walking 32 bytes.  About 25 us for a
 * 64-byte digest, against the ~1 ms a signature already spends in the
 * scalar multiplication, so it is under 3% of signing and invisible in
 * verification.  The fast way is Barrett reduction over 21-bit limbs, which
 * is what ref10's sc_reduce does in 200 lines of derived constants; those
 * constants are the kind of thing that is wrong in one limb and passes
 * every test that does not happen to carry into it.  This version has no
 * constants beyond L itself.
 */
static void sc_reduce(unsigned char out[32], const unsigned char *in,
		      size_t len)
{
	unsigned char r[32];
	size_t bit;

	memset(r, 0, 32);
	for (bit = 8 * len; bit-- > 0;) {
		unsigned c = (unsigned)(in[bit / 8] >> (bit % 8)) & 1;
		for (int i = 0; i < 32; i++) {
			unsigned v = (unsigned)r[i] << 1 | c;
			r[i] = (unsigned char)v;
			c = v >> 8;
		}
		if (sc_geq_l(r))
			sc_sub_l(r);
	}
	memcpy(out, r, 32);
}

/* out = a*b + c mod L.  The product is formed in full at 64 bytes and then
 * reduced, rather than reduced as it goes: 64 bytes is small, and a partial
 * product that is "nearly reduced" is where an off-by-one lives. */
static void sc_muladd(unsigned char out[32], const unsigned char a[32],
		      const unsigned char b[32], const unsigned char c[32])
{
	uint32_t t[64];
	unsigned char p[64];
	unsigned carry = 0;
	int i, j;

	for (i = 0; i < 64; i++)
		t[i] = 0;
	for (i = 0; i < 32; i++)
		for (j = 0; j < 32; j++)
			t[i + j] += (uint32_t)a[i] * b[j];
	/* Each t[k] sums at most 32 products of two bytes: under 2^21, so
	 * nothing has overflowed and the carries can all be taken at the
	 * end. */
	for (i = 0; i < 64; i++) {
		uint32_t v = t[i] + carry + (i < 32 ? c[i] : 0u);
		p[i] = (unsigned char)(v & 0xff);
		carry = v >> 8;
	}
	sc_reduce(out, p, 64);
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

static int arg32(const char *s, unsigned char out[32])
{
	return unhex(s, out, 32) == 32;
}

/* `fe OP A [B]` -- one field operation on canonical 32-byte little-endian
 * hex, printing the canonical encoding of the result, or 0/1 for the
 * predicates.  This is the whole surface t/diff.py needs to difference the
 * field against Python's integers, which is the cheapest oracle in the
 * repo: Python has arbitrary precision and `% (2**255 - 19)`. */
static void cmd_fe(int argc, char **argv)
{
	unsigned char ab[32], bb[32], rb[32];
	fe x, y, r;
	const char *op = argv[1];

	if (!arg32(argv[2], ab)) {
		puts("ERR hex");
		return;
	}
	fe_frombytes(x, ab);
	if (!strcmp(op, "muls") && argc == 4) {
		fe_muls(r, x, strtoull(argv[3], NULL, 10));
		fe_tobytes(rb, r);
		puthex(rb, 32);
		putchar('\n');
		return;
	}
	fe_0(y);
	if (argc >= 4) {
		if (!arg32(argv[3], bb)) {
			puts("ERR hex");
			return;
		}
		fe_frombytes(y, bb);
	}
	if (!strcmp(op, "iscanon")) {
		puts(fe_iscanon(ab) ? "1" : "0");
		return;
	}
	if (!strcmp(op, "isneg")) {
		puts(fe_isnegative(x) ? "1" : "0");
		return;
	}
	if (!strcmp(op, "nonzero")) {
		puts(fe_isnonzero(x) ? "1" : "0");
		return;
	}
	if (!strcmp(op, "eq")) {
		puts(fe_eq(x, y) ? "1" : "0");
		return;
	}
	if (!strcmp(op, "add"))		 fe_add(r, x, y);
	else if (!strcmp(op, "sub"))	 fe_sub(r, x, y);
	else if (!strcmp(op, "mul"))	 fe_mul(r, x, y);
	else if (!strcmp(op, "sq"))	 fe_sq(r, x);
	else if (!strcmp(op, "neg"))	 fe_neg(r, x);
	else if (!strcmp(op, "inv"))	 fe_invert(r, x);
	else if (!strcmp(op, "p22523"))	 fe_pow22523(r, x);
	else if (!strcmp(op, "canon"))	 fe_copy(r, x);
	else {
		puts("ERR fe op");
		return;
	}
	fe_tobytes(rb, r);
	puthex(rb, 32);
	putchar('\n');
}

/* `sc reduce X` / `sc muladd A B C` / `sc ltl S` -- scalar arithmetic mod
 * L, again with Python's integers as the oracle. */
static void cmd_sc(int argc, char **argv)
{
	static unsigned char big[64];
	unsigned char a[32], b[32], c[32], r[32];
	long n;

	if (!strcmp(argv[1], "reduce") && argc == 3) {
		if ((n = unhex(argv[2], big, sizeof big)) < 0) {
			puts("ERR hex");
			return;
		}
		sc_reduce(r, big, (size_t)n);
	} else if (!strcmp(argv[1], "muladd") && argc == 5) {
		if (!arg32(argv[2], a) || !arg32(argv[3], b) ||
		    !arg32(argv[4], c)) {
			puts("ERR hex");
			return;
		}
		sc_muladd(r, a, b, c);
	} else if (!strcmp(argv[1], "ltl") && argc == 3) {
		if (!arg32(argv[2], a)) {
			puts("ERR hex");
			return;
		}
		puts(sc_geq_l(a) ? "0" : "1");
		return;
	} else {
		puts("ERR sc op");
		return;
	}
	puthex(r, 32);
	putchar('\n');
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
	if (!strcmp(argv[0], "sc") && argc >= 3) {
		cmd_sc(argc, argv);
		return;
	}
	if (!strcmp(argv[0], "fe") && argc >= 3) {
		cmd_fe(argc, argv);
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
