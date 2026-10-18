#!/usr/bin/env python3
"""t/diff.py -- every oracle that needs more than shell.

SPDX-License-Identifier: GPL-3.0-or-later

Usage: t/diff.py ./ed25519 SECTION [SECTION...]

Each section prints "ok - ..." / "not ok - ..." lines; t/run.sh counts them.
Python stdlib only: hashlib for SHA-512, and plain integers for the field and
scalar arithmetic, which are the cheapest independent oracle available for
arithmetic mod 2^255-19 and mod L.
"""
import hashlib
import os
import random
import subprocess
import sys

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493

FAILED = 0


SKIPPED = 0


def skip(msg):
    """Neither a pass nor a failure.

    The Wycheproof vectors are not in the repository, so on a machine
    without them this section cannot run -- and must not report `ok`.
    t/run.sh counts only lines beginning "ok - " and "not ok - ", so this
    prefix is invisible to both counters and visible to the reader, and
    run.sh prints the skip count in its summary so a missing oracle cannot
    be mistaken for a satisfied one.
    """
    global SKIPPED
    SKIPPED += 1
    print("skip - %s" % msg)


def ok(cond, msg):
    global FAILED
    if cond:
        print("ok - %s" % msg)
    else:
        print("not ok - %s" % msg)
        FAILED += 1
    return cond


def batch(exe, lines):
    """Run one process, feed it `lines` commands, return the result lines."""
    inp = "".join(l + "\n" for l in lines)
    p = subprocess.run([exe, "run"], input=inp, stdout=subprocess.PIPE,
                       universal_newlines=True)
    out = p.stdout.split("\n")
    if out and out[-1] == "":
        out.pop()
    if p.returncode != 0:
        print("not ok - `%s run` exited %d (crash or sanitizer)"
              % (exe, p.returncode))
        global FAILED
        FAILED += 1
    if len(out) != len(lines):
        print("not ok - `%s run` gave %d result lines for %d commands"
              % (exe, len(out), len(lines)))
        FAILED += 1
        out += ["MISSING"] * (len(lines) - len(out))
    return out


def hx(b):
    return b.hex() if b else "-"


# --------------------------------------------------------------- sha512 ---
def sec_sha512(exe):
    """The vendored SHA-512 against CPython hashlib, every length 0..600.

    600 covers five block boundaries and both sides of the 111/112 length
    where the length field stops fitting in the final block -- the place a
    padding bug lives.  Ed25519 hashes 32+64 and 32+32+len bytes, so these
    are the lengths it actually uses.
    """
    rnd = random.Random(1)
    msgs = [bytes(rnd.randrange(256) for _ in range(n)) for n in range(601)]
    msgs += [bytes(rnd.randrange(256) for _ in range(rnd.randrange(5000)))
             for _ in range(200)]
    got = batch(exe, ["sha512 " + hx(m) for m in msgs])
    bad = [i for i, m in enumerate(msgs)
           if got[i] != hashlib.sha512(m).hexdigest()]
    ok(not bad, "SHA-512 == hashlib on %d messages (lengths 0..600 "
       "exhaustive, then random): %d differ" % (len(msgs), len(bad)))


# ------------------------------------------------------------------ fe ---
def le(b):
    return int.from_bytes(b, "little")


def leb(n):
    return (n % 2**256).to_bytes(32, "little")


def fe_inputs():
    """Random values plus every edge the limb layout can have.

    The limbs are radix 2^51, so 2^51, 2^102, 2^153 and 2^204 and their
    neighbours are where a carry is either taken or dropped.  p, p+1, 2^255-1
    and 2^255-19 are where canonicality is decided.  A random sweep alone
    would hit none of them.
    """
    edge = [0, 1, 2, 18, 19, 20,
            P - 2, P - 1, P, P + 1, P + 2,
            2**255 - 1, 2**255 - 2, 2**255 - 19, 2**255 - 20,
            2**254, 2**254 - 1, (P + 1) // 2]
    for k in (51, 102, 153, 204, 255):
        edge += [2**k - 2, 2**k - 1, 2**k, 2**k + 1]
    edge += [(2**51 - 1) * sum(2**(51 * i) for i in range(5)),
             sum(2**(51 * i) for i in range(5))]
    rnd = random.Random(2)
    rand = [rnd.randrange(2**256) for _ in range(2000)]
    rand += [rnd.randrange(2**255) for _ in range(2000)]
    # small and sparse values, which is where a missing fold shows up
    rand += [rnd.randrange(2**20) for _ in range(200)]
    rand += [1 << rnd.randrange(256) for _ in range(200)]
    return [v % 2**256 for v in edge + rand]


def sec_fe(exe):
    vals = fe_inputs()
    hxs = [leb(v).hex() for v in vals]
    # the field value a 32-byte string denotes: bit 255 ignored, then mod p
    red = [(v % 2**255) % P for v in vals]
    n = len(vals)

    cmds, want, names = [], [], []

    def one(cmd, expect, name):
        cmds.append(cmd)
        want.append(expect)
        names.append(name)

    for i in range(n):
        one("fe canon " + hxs[i], leb(red[i]).hex(), "canon")
        one("fe sq " + hxs[i], leb(red[i] * red[i] % P).hex(), "sq")
        one("fe neg " + hxs[i], leb(-red[i] % P).hex(), "neg")
        one("fe inv " + hxs[i], leb(pow(red[i], P - 2, P)).hex(), "inv")
        one("fe p22523 " + hxs[i],
            leb(pow(red[i], (P - 5) // 8, P)).hex(), "p22523")
        one("fe iscanon " + hxs[i], "1" if vals[i] < P else "0", "iscanon")
        one("fe isneg " + hxs[i], str(red[i] & 1), "isneg")
        one("fe nonzero " + hxs[i], "1" if red[i] else "0", "nonzero")
        j = (i * 7 + 3) % n
        one("fe add %s %s" % (hxs[i], hxs[j]),
            leb((red[i] + red[j]) % P).hex(), "add")
        one("fe sub %s %s" % (hxs[i], hxs[j]),
            leb((red[i] - red[j]) % P).hex(), "sub")
        one("fe mul %s %s" % (hxs[i], hxs[j]),
            leb(red[i] * red[j] % P).hex(), "mul")
        one("fe eq %s %s" % (hxs[i], hxs[j]),
            "1" if red[i] == red[j] else "0", "eq")

    got = batch(exe, cmds)
    bad = {}
    for i, g in enumerate(got):
        if g != want[i]:
            bad.setdefault(names[i], []).append(i)
    for nm in ("canon", "add", "sub", "mul", "sq", "neg", "inv", "p22523",
               "iscanon", "isneg", "nonzero", "eq"):
        tot = sum(1 for x in names if x == nm)
        b = bad.get(nm, [])
        msg = "fe %-8s == Python integers mod 2^255-19 on %d inputs" % (nm, tot)
        if b:
            msg += " (first bad: `%s` -> %s, want %s)" % (
                cmds[b[0]], got[b[0]], want[b[0]])
        ok(not b, msg)
    ok(True, "fe: %d operations differenced in one process" % len(cmds))


# ------------------------------------------------------------------ sc ---
def sec_sc(exe):
    """Scalars mod L against Python's integers.

    The interesting inputs are L itself and its small multiples, because a
    reduction that is one conditional subtraction short gets every random
    input right and L+1 wrong -- and L+1 is precisely what the Wycheproof
    malleability cases put in a signature.
    """
    rnd = random.Random(3)
    edge = [0, 1, 2, L - 2, L - 1, L, L + 1, L + 2,
            2 * L, 2 * L + 1, 4 * L, 8 * L, 2**252, 2**253, 2**255,
            2**255 - 19, 2**256 - 1, 2**512 - 1, 2**256]
    small = [v % 2**256 for v in edge]
    wide = edge + [rnd.randrange(2**512) for _ in range(1500)] \
        + [rnd.randrange(2**256) for _ in range(500)] \
        + [k * L + rnd.randrange(3) for k in range(1, 40)]

    cmds, want, names = [], [], []

    def one(c, w, nm):
        cmds.append(c)
        want.append(w)
        names.append(nm)

    for v in wide:
        b = (v % 2**512).to_bytes(64, "little")
        one("sc reduce " + b.hex(), ((v % 2**512) % L).to_bytes(32, "little").hex(),
            "reduce64")
    for v in small:
        b = (v % 2**256).to_bytes(32, "little")
        one("sc reduce " + b.hex(), ((v % 2**256) % L).to_bytes(32, "little").hex(),
            "reduce32")
        one("sc ltl " + b.hex(), "1" if (v % 2**256) < L else "0", "ltl")
    for v in [rnd.randrange(2**256) for _ in range(400)] + small:
        b = (v % 2**256).to_bytes(32, "little")
        one("sc ltl " + b.hex(), "1" if (v % 2**256) < L else "0", "ltl")
    tri = [(rnd.randrange(2**256), rnd.randrange(2**256), rnd.randrange(2**256))
           for _ in range(800)]
    tri += [(L - 1, L - 1, L - 1), (L, L, L), (0, 0, 0), (1, 1, 0),
            (2**256 - 1, 2**256 - 1, 2**256 - 1)]
    for a, b, c in tri:
        one("sc muladd %s %s %s" % (leb(a).hex(), leb(b).hex(), leb(c).hex()),
            ((a * b + c) % L).to_bytes(32, "little").hex(), "muladd")

    got = batch(exe, cmds)
    bad = {}
    for i, g in enumerate(got):
        if g != want[i]:
            bad.setdefault(names[i], []).append(i)
    for nm in ("reduce64", "reduce32", "ltl", "muladd"):
        tot = sum(1 for x in names if x == nm)
        b = bad.get(nm, [])
        msg = "sc %-9s == Python integers mod L on %d inputs" % (nm, tot)
        if b:
            msg += " (first bad: `%s` -> %s, want %s)" % (
                cmds[b[0]], got[b[0]], want[b[0]])
        ok(not b, msg)
    # The one check that needs no reference at all: L is the order, so
    # anything times L is zero and L reduces to zero.
    z = "0" * 64
    g = batch(exe, ["sc reduce " + leb(L).hex(),
                    "sc muladd %s %s %s" % (leb(L).hex(), leb(1).hex(), z)])
    ok(g[0] == z and g[1] == z, "L reduces to 0 and L*1 reduces to 0")


# ----------------------------------------------- a reference in Python ---
# An independent Ed25519, about forty lines, written from the formulas in
# RFC 8032 sections 5.1.3 and 5.1.4 and using Python's integers for the
# field.  It shares no code and no representation with ed25519.c: no limbs,
# no radix, no carry bounds, a different square-root path.  That makes it a
# real second opinion on the group law rather than a restatement of the C.
D = -121665 * pow(121666, P - 2, P) % P
SQRTM1 = pow(2, (P - 1) // 4, P)
BY = 4 * pow(5, P - 2, P) % P


def ref_add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    aa = (y1 - x1) * (y2 - x2) % P
    bb = (y1 + x1) * (y2 + x2) % P
    cc = 2 * D * t1 * t2 % P
    dd = 2 * z1 * z2 % P
    e, f, g, h = bb - aa, dd - cc, dd + cc, bb + aa
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def ref_mul(s, pt):
    r = (0, 1, 1, 0)
    for i in range(255, -1, -1):
        r = ref_add(r, r)
        if (s >> i) & 1:
            r = ref_add(r, pt)
    return r


def ref_encode(pt):
    x, y, z, _ = pt
    zi = pow(z, P - 2, P)
    x, y = x * zi % P, y * zi % P
    return leb(y | (x & 1) << 255)


def ref_decode(b):
    """None if these 32 bytes are not the encoding of a point."""
    y = le(b) % 2**255
    sign = b[31] >> 7
    if y >= P:
        return None
    u, v = (y * y - 1) % P, (D * y * y + 1) % P
    x = u * pow(v, 3, P) % P * pow(u * pow(v, 7, P) % P, (P - 5) // 8, P) % P
    if v * x * x % P != u % P:
        x = x * SQRTM1 % P
        if v * x * x % P != u % P:
            return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = P - x
    return (x, y, 1, x * y % P)


REF_B = ref_decode(ref_encode((0, BY, 1, 0)))


def ref_scalar_base(s):
    return ref_encode(ref_mul(s % (2**256), REF_B))


# ------------------------------------------------------------------ ge ---
def ref_points(n, seed):
    """n distinct curve points, as encodings, from the Python reference."""
    rnd = random.Random(seed)
    out = []
    while len(out) < n:
        b = leb(rnd.randrange(2**256))
        if ref_decode(b) is not None:
            out.append(b)
    return out


def sec_ge(exe):
    # The curve constants against RFC 8032 section 5.1, which prints them.
    want = {
        "d": 37095705934669439343138083508754565189542113879843219016388785533085940283555,
        "sqrtm1": 19681161376707505956807079304988542015446066515923890162744021073123829784752,
        "basex": 15112221349535400772501151409588531511454012693041857206046113283949847762202,
        "basey": 46316835694926478169428394003475163141307993866256225615783033603165251855960,
        "l": 2**252 + 27742317777372353535851937790883648493,
    }
    names = sorted(want)
    got = batch(exe, ["ge const " + n for n in names])
    bad = [n for n, g in zip(names, got)
           if le(bytes.fromhex(g)) != want[n] % 2**256]
    ok(not bad, "curve constants derived from their definitions equal the "
       "values printed in RFC 8032 5.1 (d, sqrt(-1), Bx, By, L): %s"
       % (", ".join(bad) + " differ" if bad else "all 5 match"))
    g = batch(exe, ["ge const base"])
    ok(g[0] == "5866666666666666666666666666666666666666666666666666666666666666",
       "the base point encodes to RFC 8032's 5866...66")

    pts = ref_points(300, 4)
    # The 8 points of order dividing 8, and the two encodings of the
    # identity-adjacent y values; these are the inputs where a formula that
    # is merely "unified for distinct points" falls over.
    special = [leb(0), leb(1), leb(1 | 1 << 255), leb(P - 1), leb(P),
               leb(2**255 - 1),
               bytes.fromhex("0000000000000000000000000000000000000000"
                             "000000000000000000000080"),
               bytes.fromhex("ecffffffffffffffffffffffffffffffffffffff"
                             "ffffffffffffffffffffff7f"),
               bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05"
                             "d3c63339b13802886d53fc05"),
               bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa"
                             "2c39ccc64ec7fd7792ac037a")]
    allpts = special + pts

    cmds, want2 = [], []

    def one(c, w):
        cmds.append(c)
        want2.append(w)

    nvalid = 0
    for b in allpts:
        r = ref_decode(b)
        if r is None:
            one("ge dec " + b.hex(), "ERR dec")
            continue
        nvalid += 1
        one("ge dec " + b.hex(), ref_encode(r).hex())
        one("ge neg " + b.hex(),
            ref_encode((P - r[0], r[1], 1, (P - r[0]) * r[1] % P)).hex())
        one("ge dbl " + b.hex(), ref_encode(ref_add(r, r)).hex())
        one("ge selfadd " + b.hex(), ref_encode(ref_add(r, r)).hex())
        one("ge id " + b.hex(), "1" if r[0] == 0 and r[1] == 1 else "0")
    for i, b in enumerate(allpts):
        c = allpts[(i * 13 + 5) % len(allpts)]
        rb, rc = ref_decode(b), ref_decode(c)
        if rb is None:
            one("ge add %s %s" % (b.hex(), c.hex()), "ERR dec")
        elif rc is None:
            one("ge add %s %s" % (b.hex(), c.hex()), "ERR dec2")
        else:
            one("ge add %s %s" % (b.hex(), c.hex()),
                ref_encode(ref_add(rb, rc)).hex())

    got = batch(exe, cmds)
    bad = [i for i in range(len(cmds)) if got[i] != want2[i]]
    msg = ("group law == the Python reference on %d operations over %d "
           "points (%d of the encodings are not points and must say so)"
           % (len(cmds), nvalid, len(allpts) - nvalid))
    if bad:
        msg += " -- first bad: `%s` -> %s, want %s" % (
            cmds[bad[0]], got[bad[0]], want2[bad[0]])
    ok(not bad, msg)

    # Scalar multiplication: the primitive a signature is built on, and
    # the one this file could already compute before the C could -- ref_mul
    # has been here since the group went in, so the oracle for it existed
    # before the implementation did.
    #
    # Both sides run the full 256 bits of the scalar with no reduction, so
    # scalars at and past L are meaningful inputs rather than errors: the
    # reduction is the caller's job in RFC 8032 and doing it here would
    # hide a scalarmult that silently reduced.
    rnd = random.Random(11)
    sm_cmds, sm_want = [], []
    scalars = ([0, 1, 2, 8, L - 1, L, L + 1, 2**252, 2**255, 2**256 - 1]
               + [rnd.randrange(2**256) for _ in range(40)])
    for sc in scalars:
        one2 = leb(sc).hex()
        sm_cmds.append("ge basemul " + one2)
        sm_want.append(ref_encode(ref_mul(sc % 2**256, REF_B)).hex())
    for b in allpts[:40]:
        r = ref_decode(b)
        sc = leb(rnd.randrange(2**256)).hex()
        if r is None:
            sm_cmds.append("ge mul %s %s" % (b.hex(), sc))
            sm_want.append("ERR dec")
            continue
        w = ref_encode(ref_mul(le(bytes.fromhex(sc)), r)).hex()
        sm_cmds.append("ge mul %s %s" % (b.hex(), sc))
        sm_want.append(w)
        # r and p one object, which a scalarmult that wrote the accumulator
        # before reading the point would get wrong while passing `mul`.
        sm_cmds.append("ge selfmul %s %s" % (b.hex(), sc))
        sm_want.append(w)
    got = batch(exe, sm_cmds)
    bad = [i for i in range(len(sm_cmds)) if got[i] != sm_want[i]]
    msg = ("scalar multiplication == the Python reference on %d products "
           "(%d scalars against the base point, including 0, 1, L-1, L and "
           "2^256-1)" % (len(sm_cmds), len(scalars)))
    if bad:
        msg += " -- first bad: `%s` -> %s, want %s" % (
            sm_cmds[bad[0]], got[bad[0]], sm_want[bad[0]])
    ok(not bad, msg)

    # L*B is the identity, because L is the order of the base point. That is
    # the one fact about scalar multiplication that does not need a
    # reference implementation to state, so it is asserted on its own.
    got = batch(exe, ["ge basemul " + leb(L).hex(),
                      "ge id " + ref_encode(ref_mul(0, REF_B)).hex(),
                      "ge basemul " + leb(L + 1).hex()])
    ok(got[0] == ref_encode((0, 1, 1, 0)).hex(),
       "L*B is the identity, so B has order L")
    ok(got[2] == "5866666666666666666666666666666666666666666666666666666666666666",
       "...and (L+1)*B is B again")

    # The non-canonical y values are exactly y in [p, 2^255): nineteen of
    # them, each with either sign bit.  y = p is the worst one, because it
    # is p + 0 and y = 0 is a real point of order 4 -- so a verifier that
    # reduces mod p instead of refusing gets a point out of it.
    nc = [leb((P + k) | sb << 255) for k in range(19) for sb in (0, 1)]
    got = batch(exe, ["ge dec " + b.hex() for b in nc])
    n = sum(1 for g in got if g == "ERR dec")
    ok(n == len(nc), "every non-canonical y in [p, 2^255) rejected, both "
       "sign bits: %d/%d" % (n, len(nc)))


# ------------------------------------------------------------- sign ---
#
# A second Ed25519, written from RFC 8032's ALGORITHM rather than from its
# test vectors, sharing nothing with the C: Python integers against 51-bit
# limbs, `pow` against fe_pow, and a different group representation.
#
# Written from the algorithm on purpose. Transcribing the RFC's vectors
# would check the C against 7 published values; this checks it against an
# independent implementation over as many keys and messages as there is
# time for, and the vectors then come separately from Wycheproof.

def ref_clamp(h):
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return le(bytes(a))


def ref_keygen(seed):
    return ref_encode(ref_mul(ref_clamp(hashlib.sha512(seed).digest()), REF_B))


def ref_sign(seed, msg):
    h = hashlib.sha512(seed).digest()
    a = ref_clamp(h)
    A = ref_encode(ref_mul(a, REF_B))
    r = le(hashlib.sha512(h[32:] + msg).digest()) % L
    R = ref_encode(ref_mul(r, REF_B))
    k = le(hashlib.sha512(R + A + msg).digest()) % L
    return R + leb((r + k * a) % L)


def ref_verify(pk, msg, sig):
    """Cofactorless, S reduced, canonical encodings only -- as the C is."""
    if len(sig) != 64 or len(pk) != 32:
        return False
    sval = le(sig[32:])
    if sval >= L:
        return False
    A = ref_decode(pk)
    R = ref_decode(sig[:32])
    if A is None or R is None:
        return False
    k = le(hashlib.sha512(sig[:32] + pk + msg).digest()) % L
    return (ref_encode(ref_mul(sval, REF_B))
            == ref_encode(ref_add(R, ref_mul(k, A))))


def sec_sign(exe):
    rnd = random.Random(23)
    # Message lengths that matter: empty (RFC 8032's first vector), one
    # byte, and either side of SHA-512's 128-byte block boundary, where a
    # buffering bug in the hash would show up only here.
    lens = [0, 1, 2, 31, 32, 63, 64, 111, 127, 128, 129, 191, 192, 193, 255,
            256, 257, 1023, 1024]
    cases = []
    for n in lens:
        cases.append((bytes(rnd.randrange(256) for _ in range(32)),
                      bytes(rnd.randrange(256) for _ in range(n))))
    for _ in range(60):
        cases.append((bytes(rnd.randrange(256) for _ in range(32)),
                      bytes(rnd.randrange(256)
                            for _ in range(rnd.randrange(0, 200)))))
    # Seeds that are all-zero and all-ones, because a clamp applied to the
    # wrong half of the digest survives random seeds.
    cases.append((bytes(32), b"abc"))
    cases.append((b"\xff" * 32, b"abc"))

    def mhex(m):
        return m.hex() if m else "-"

    cmds, want = [], []
    for seed, msg in cases:
        cmds.append("keygen " + seed.hex())
        want.append(ref_keygen(seed).hex())
        cmds.append("sign %s %s" % (seed.hex(), mhex(msg)))
        want.append(ref_sign(seed, msg).hex())
    got = batch(exe, cmds)
    bad = [i for i in range(len(cmds)) if got[i] != want[i]]
    msg_ = ("keygen and sign == an independent Python Ed25519 on %d cases "
            "(message lengths 0..1024, including both sides of SHA-512's "
            "128-byte block)" % len(cases))
    if bad:
        msg_ += " -- first bad: `%s` -> %s, want %s" % (
            cmds[bad[0]][:60], got[bad[0]], want[bad[0]])
    ok(not bad, msg_)

    # Verification. A signer that verifies its own output proves nothing,
    # so every signature is also checked against the reference's verdict,
    # and then damaged in each of the ways that matter and checked again.
    cmds, want = [], []
    for seed, msg in cases[:40]:
        pk = ref_keygen(seed)
        sig = ref_sign(seed, msg)
        cmds.append("verify %s %s %s" % (pk.hex(), mhex(msg), sig.hex()))
        want.append("1" if ref_verify(pk, msg, sig) else "0")
        # One flipped bit, in R, in S, in the message, and in the key.
        for label, bad_pk, bad_msg, bad_sig in (
                ("R", pk, msg, bytes([sig[0] ^ 1]) + sig[1:]),
                ("S", pk, msg, sig[:40] + bytes([sig[40] ^ 1]) + sig[41:]),
                ("msg", pk, (msg + b"\x00") if not msg else
                 bytes([msg[0] ^ 1]) + msg[1:], sig),
                ("pk", bytes([pk[0] ^ 1]) + pk[1:], msg, sig)):
            cmds.append("verify %s %s %s"
                        % (bad_pk.hex(), mhex(bad_msg), bad_sig.hex()))
            want.append("1" if ref_verify(bad_pk, bad_msg, bad_sig) else "0")
    got = batch(exe, cmds)
    bad = [i for i in range(len(cmds)) if got[i] != want[i]]
    accepted = sum(1 for w in want if w == "1")
    msg_ = ("verify agrees with the reference on %d signatures, %d good and "
            "%d damaged in R, S, the message or the key"
            % (len(cmds), accepted, len(cmds) - accepted))
    if bad:
        msg_ += " -- first bad: `%s` -> %s, want %s" % (
            cmds[bad[0]][:60], got[bad[0]], want[bad[0]])
    ok(not bad, msg_)

    # Malleability: S + L is the same scalar mod L, so an implementation
    # that reduces S instead of refusing it accepts a second signature for
    # a message it already signed. RFC 8032 requires the refusal.
    cmds = []
    for seed, msg in cases[:25]:
        pk, sig = ref_keygen(seed), ref_sign(seed, msg)
        mal = sig[:32] + leb(le(sig[32:]) + L)
        cmds.append("verify %s %s %s" % (pk.hex(), mhex(msg), mal.hex()))
    got = batch(exe, cmds)
    n = sum(1 for g in got if g == "0")
    ok(n == len(cmds), "S + L is refused rather than reduced, so a "
       "signature cannot be mauled into a second valid one: %d/%d"
       % (n, len(cmds)))


# ----------------------------------------------------------- x25519 ---
#
# Three oracles, and they are NOT equally independent. Saying which is
# which matters more here than anywhere else in this file, because the
# obvious one is the weakest.
#
# 1. THE BIRATIONAL MAP, which is the strong one. Curve25519 and
#    edwards25519 are the same group in different coordinates, and RFC 7748
#    section 4.1 gives the correspondence: u = (1 + y) / (1 - y). So
#    x25519_base(k) can be computed a second way -- take [clamp(k)]B on the
#    EDWARDS curve, with the group law already differenced above, and map
#    the resulting y. That shares no algorithm with the Montgomery ladder:
#    different coordinates, different formula, different number of field
#    operations.
#
# 2. DIFFIE-HELLMAN AGREEMENT, which needs no reference implementation at
#    all. X25519(a, X25519(b, 9)) == X25519(b, X25519(a, 9)), because both
#    are [a*b]G. A metamorphic relation, and the only check here that would
#    still mean something if every reference were wrong the same way.
#
# 3. A Python transcription of the ladder, which is the WEAK one and is
#    included anyway. It is the same algorithm in a different
#    representation, so it differences 51-bit limbs against Python
#    integers -- a real check on the field arithmetic in this context, and
#    no check at all on whether the ladder is the right ladder. If the
#    pseudocode were copied wrongly, this oracle would agree enthusiastically
#    and oracles 1 and 2 would not.

X_A24 = 121665


def ref_x25519(k, u):
    """RFC 7748 section 5, transcribed. The weak oracle -- see above."""
    kc = bytearray(k)
    kc[0] &= 248
    kc[31] &= 127
    kc[31] |= 64
    kk = le(bytes(kc))
    x1 = le(u) % 2**255           # decodeUCoordinate masks bit 255
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        kt = (kk >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % P
        aa = a * a % P
        b = (x2 - z2) % P
        bb = b * b % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        dd = (x3 - z3) % P
        da = dd * a % P
        cb = c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + X_A24 * e) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return leb(x2 * pow(z2, P - 2, P) % P)


def ref_x25519_base_via_edwards(k):
    """x25519_base the other way round: Edwards scalarmult, then the map.

    u = (1 + y) / (1 - y), RFC 7748 section 4.1. Shares no algorithm with
    the Montgomery ladder, which is what makes it worth having.
    """
    kc = bytearray(k)
    kc[0] &= 248
    kc[31] &= 127
    kc[31] |= 64
    x, y, z, _ = ref_mul(le(bytes(kc)), REF_B)
    zi = pow(z, P - 2, P)
    y = y * zi % P
    return leb((1 + y) * pow((1 - y) % P, P - 2, P) % P)


def sec_x25519(exe):
    rnd = random.Random(31)
    keys = [bytes(rnd.randrange(256) for _ in range(32)) for _ in range(40)]
    # Scalars whose clamping matters: all-zero, all-ones, and the two
    # patterns that differ only in the bits the clamp forces.
    keys += [bytes(32), b"\xff" * 32,
             bytes([0xff] + [0] * 31), bytes([0] * 31 + [0xff])]

    # 1. the strong oracle: the same point reached through the other curve.
    cmds = ["x25519base " + k.hex() for k in keys]
    want = [ref_x25519_base_via_edwards(k).hex() for k in keys]
    got = batch(exe, cmds)
    bad = [i for i in range(len(cmds)) if got[i] != want[i]]
    msg = ("x25519_base == [k]B on the EDWARDS curve mapped through "
           "u = (1+y)/(1-y), on %d scalars -- a different curve form, a "
           "different algorithm" % len(keys))
    if bad:
        msg += " -- first bad: `%s` -> %s, want %s" % (
            cmds[bad[0]][:48], got[bad[0]], want[bad[0]])
    ok(not bad, msg)

    # 2. the oracle that needs no reference: both sides are [a*b]G.
    cmds, pairs = [], []
    for i in range(0, 20, 2):
        a, b = keys[i], keys[i + 1]
        pairs.append((a, b))
        cmds.append("x25519base " + a.hex())
        cmds.append("x25519base " + b.hex())
    pub = batch(exe, cmds)
    cmds2 = []
    for n, (a, b) in enumerate(pairs):
        cmds2.append("x25519 %s %s" % (a.hex(), pub[2 * n + 1]))
        cmds2.append("x25519 %s %s" % (b.hex(), pub[2 * n]))
    got = batch(exe, cmds2)
    agree = sum(1 for n in range(len(pairs))
                if got[2 * n] == got[2 * n + 1])
    ok(agree == len(pairs),
       "Diffie-Hellman agrees on %d/%d key pairs, which needs no reference "
       "implementation at all" % (agree, len(pairs)))

    # 3. the weak oracle: same algorithm, different representation.
    cmds, want = [], []
    us = [k for k in keys[:20]]
    us += [bytes(32), bytes([1] + [0] * 31), leb(P - 1), leb(P), leb(P + 1),
           b"\xff" * 32]
    for i, u in enumerate(us):
        k = keys[i % len(keys)]
        cmds.append("x25519 %s %s" % (k.hex(), u.hex()))
        want.append(ref_x25519(k, u).hex())
    got = batch(exe, cmds)
    bad = [i for i in range(len(cmds)) if got[i] != want[i]]
    msg = ("the ladder == the RFC 7748 pseudocode in Python on %d products, "
           "including u = 0, 1, p-1, p and p+1 (same algorithm, so this "
           "checks the limbs and not the ladder)" % len(cmds))
    if bad:
        msg += " -- first bad: `%s` -> %s, want %s" % (
            cmds[bad[0]][:48], got[bad[0]], want[bad[0]])
    ok(not bad, msg)

    # The clamp clears the three low bits, which is why the final
    # conditional swap in RFC 7748's pseudocode can never fire here: the
    # loop's last iteration sets swap to bit 0 of the scalar. Asserted
    # because the code relies on it to call that swap dead, and because a
    # mutation that deletes the swap survives -- correctly, as an
    # equivalent mutant, which is only true while this holds.
    # Through the BINARY, because the first version of this did not touch
    # it: it computed `(k[0] & 248) & 7` in Python and asserted the result
    # was zero, which is true of every byte and would pass with ed25519.c
    # deleted. It was also the assertion the README cited to underwrite the
    # equivalent-mutant claim, so the one thing holding that claim up was a
    # tautology.
    #
    # What has to be true is that the implementation IGNORES the bits the
    # clamp discards. So: flip the three low bits and the top two, and the
    # answer must not move. If it does, the clamp is not doing what the
    # dead closing swap depends on.
    cmds, want = [], []
    for k in keys:
        flipped = bytes([k[0] ^ 0x07]) + k[1:31] + bytes([k[31] ^ 0xc0])
        cmds.append("x25519base " + k.hex())
        cmds.append("x25519base " + flipped.hex())
    got = batch(exe, cmds)
    moved = [i for i in range(0, len(cmds), 2) if got[i] != got[i + 1]]
    ok(not moved, "the clamp discards the three low bits and the top two: "
       "flipping them changes no answer, on %d scalars -- which is what "
       "makes the ladder's closing swap dead code" % len(keys))

    # A low-order u gives an all-zero shared secret. RFC 7748 makes
    # rejecting that optional and this does not reject it, so the value is
    # asserted rather than the refusal -- a caller doing Diffie-Hellman is
    # the one that has to care.
    zero = batch(exe, ["x25519 %s %s" % (keys[0].hex(), bytes(32).hex()),
                       "x25519 %s %s" % (keys[0].hex(),
                                         bytes([1] + [0] * 31).hex())])
    ok(all(z == bytes(32).hex() for z in zero),
       "u = 0 and u = 1 are low order, so the shared secret is all zero "
       "rather than an error -- which RFC 7748 permits and the header says")


# ------------------------------------------------------- wycheproof ---
#
# Published vectors, and the only oracle here that was written by people
# trying to break implementations rather than to describe one. Wycheproof's
# EDDSA set is where the cases nobody thinks of live: signatures with S
# beyond L, non-canonical point encodings, small-order public keys,
# truncated and garbage-appended signatures.
#
# The file is not in the repository -- it is third-party data, it is large,
# and vendoring it would mean this project shipping someone else's test
# suite. Put it at scratch/wp_ed.json (the EDDSA verify set from the
# Project Wycheproof repository, testvectors/ed25519_test.json) and this
# section runs; without it the section SKIPS, loudly, and the skip is
# counted separately from the passes.

WYCHEPROOF_ED = "scratch/wp_ed.json"
WYCHEPROOF_X = "scratch/wp_x.json"


def sec_wycheproof(exe):
    import json
    path = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), WYCHEPROOF_ED)
    if not os.path.exists(path):
        skip("Wycheproof EDDSA vectors absent (%s); put the EDDSA verify "
             "set there to run them" % WYCHEPROOF_ED)
        return
    with open(path) as fh:
        data = json.load(fh)
    if data.get("algorithm") != "EDDSA":
        skip("%s is not the EDDSA set (algorithm=%r) -- the XDH set is a "
             "different file and would silently test nothing"
             % (WYCHEPROOF_ED, data.get("algorithm")))
        return

    cmds, want, meta = [], [], []
    for group in data["testGroups"]:
        pk = group["publicKey"]["pk"]
        for t in group["tests"]:
            expect = "1" if t["result"] == "valid" else "0"
            if len(t["sig"]) != 128:
                # Our CLI takes exactly 64 signature bytes, so a truncated
                # or over-long signature cannot be handed to it at all.
                # That is the right answer -- such a signature is invalid --
                # but it is the harness refusing, not the implementation, so
                # it is recorded rather than counted as a verify result.
                meta.append((t["tcId"], expect, None))
                continue
            cmds.append("verify %s %s %s"
                        % (pk, t["msg"] or "-", t["sig"]))
            want.append(expect)
            meta.append((t["tcId"], expect, len(cmds) - 1))
    got = batch(exe, cmds)
    bad = [i for i in range(len(cmds)) if got[i] != want[i]]
    nvalid = sum(1 for w in want if w == "1")
    byharness = sum(1 for _, _, i in meta if i is None)
    msg = ("%d Wycheproof EDDSA vectors agree (%d valid, %d invalid"
           % (len(cmds), nvalid, len(cmds) - nvalid))
    msg += "; %d more have a signature that is not 64 bytes and are " \
           "rejected by length alone)" % byharness if byharness else ")"
    if bad:
        tc = [m[0] for m in meta if m[2] == bad[0]]
        msg += " -- first bad: tcId %s wanted %s got %s" % (
            tc[0] if tc else "?", want[bad[0]], got[bad[0]])
    ok(not bad, msg)


def sec_wycheproof_x(exe):
    """The XDH set: 518 vectors, every one with an expected shared secret.

    None of them is "invalid": X25519 is defined on every 32-byte string, so
    a twist point or a low-order key has an answer rather than an error.
    254 are marked "acceptable", meaning an implementation may compute the
    secret or refuse -- this one computes, so the expected value applies to
    all 518.
    """
    import json
    path = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), WYCHEPROOF_X)
    if not os.path.exists(path):
        skip("Wycheproof XDH vectors absent (%s)" % WYCHEPROOF_X)
        return
    with open(path) as fh:
        data = json.load(fh)
    if data.get("algorithm") != "XDH":
        skip("%s is not the XDH set (algorithm=%r)"
             % (WYCHEPROOF_X, data.get("algorithm")))
        return
    tests = [t for g in data["testGroups"] for t in g["tests"]]
    cmds = ["x25519 %s %s" % (t["private"], t["public"]) for t in tests]
    got = batch(exe, cmds)
    bad = [i for i in range(len(cmds)) if got[i] != tests[i]["shared"]]
    nacc = sum(1 for t in tests if t["result"] == "acceptable")
    msg = ("%d Wycheproof XDH vectors agree (%d acceptable: twist points, "
           "low-order and non-canonical keys, all with an expected answer)"
           % (len(cmds), nacc))
    if bad:
        msg += " -- first bad: tcId %s (%s) -> %s, want %s" % (
            tests[bad[0]]["tcId"], ",".join(tests[bad[0]].get("flags", [])),
            got[bad[0]], tests[bad[0]]["shared"])
    ok(not bad, msg)


# ---------------------------------------------------------------- wmul ---
def sec_wmul(exe):
    """The windowed base multiplication against the double-and-add.

    PLAN item 08.  `ge wbasemul s` is the new path (a table of [d*16^i]B
    and a constant-time select); `ge basemul s` is the old double-and-add,
    unchanged, and it is the oracle here -- it is itself differenced
    against the Python reference in sec_ge, so agreeing with it is
    agreeing with Python one step removed, and the Python reference is run
    directly on the shorter scalar list below as well.

    The hazard this section is written around: comparing "both methods"
    proves nothing if `ge wbasemul` is quietly the double-and-add too.  So
    every claim is paired with a group-addition count, which is 64 for the
    windowed path and 256 + popcount(s) for the double-and-add, and the
    counts of keygen, sign and verify say which one the LIBRARY calls.
    """
    rnd = random.Random(808)
    scalars = ([0, 1, 2, 8, 15, 16, 17, 255, 2**252, 2**255, 2**255 + 1,
                L - 1, L, L + 1, 2**256 - 1]
               + [rnd.randrange(2**256) for _ in range(40)])

    # 1. Against the double-and-add AND against Python, same scalars.
    cmds = []
    for sc in scalars:
        cmds.append("ge wbasemul " + leb(sc).hex())
        cmds.append("ge basemul " + leb(sc).hex())
    got = batch(exe, cmds)
    bad = [i for i in range(0, len(cmds), 2) if got[i] != got[i + 1]]
    msg = ("the windowed [s]B == the double-and-add [s]B on %d scalars, "
           "including 0, 1, L, 2^255 and 2^256-1" % len(scalars))
    if bad:
        msg += " -- first bad: `%s` -> %s, double-and-add says %s" % (
            cmds[bad[0]], got[bad[0]], got[bad[0] + 1])
    ok(not bad, msg)

    want = [ref_encode(ref_mul(sc, REF_B)).hex() for sc in scalars]
    bad = [j for j, sc in enumerate(scalars) if got[2 * j] != want[j]]
    msg = ("...and == the Python reference on the same %d, so the agreement "
           "above is not two implementations sharing one mistake"
           % len(scalars))
    if bad:
        msg += " -- first bad: s=%d -> %s, want %s" % (
            scalars[bad[0]], got[2 * bad[0]], want[bad[0]])
    ok(not bad, msg)

    # 2. Every entry of every window, which random scalars do not cover:
    #    s = d * 16^i reads table[i][d] and nothing else, so a single
    #    wrong entry is named rather than averaged away.
    cmds, pairs = [], []
    for i in range(64):
        for d in range(16):
            sc = d * 16**i
            cmds.append("ge wbasemul " + leb(sc).hex())
            cmds.append("ge basemul " + leb(sc).hex())
            pairs.append((i, d))
    got = batch(exe, cmds)
    bad = [j for j in range(len(pairs)) if got[2 * j] != got[2 * j + 1]]
    msg = ("every one of the %d table entries [d*16^i]B agrees with the "
           "double-and-add" % len(pairs))
    if bad:
        msg += " -- first bad: i=%d d=%d -> %s, want %s" % (
            pairs[bad[0]][0], pairs[bad[0]][1],
            got[2 * bad[0]], got[2 * bad[0] + 1])
    ok(not bad, msg)

    # 3. WHICH CODE RAN.  Without this the two checks above would pass
    #    with ge_basemult deleted and `ge wbasemul` wired to the
    #    double-and-add: one implementation compared with itself.
    cmds = ["ge adds reset"]
    for sc in scalars:
        cmds += ["ge wbasemul " + leb(sc).hex(), "ge adds reset",
                 "ge basemul " + leb(sc).hex(), "ge adds reset"]
    got = batch(exe, cmds)
    wn = [int(got[2 + 4 * j]) for j in range(len(scalars))]
    dn = [int(got[4 + 4 * j]) for j in range(len(scalars))]
    want_d = [256 + bin(sc).count("1") for sc in scalars]
    ok(set(wn) == {64},
       "the windowed path takes exactly 64 group additions for EVERY one "
       "of the %d scalars, so it is not the double-and-add and its "
       "operation count does not depend on the scalar: counts seen = %s"
       % (len(scalars), sorted(set(wn))))
    ok(dn == want_d and len(set(dn)) > 1,
       "...while the double-and-add takes 256 + popcount(s), %d to %d over "
       "the same scalars -- the two paths are distinguishable, and this is "
       "what stops the comparison above testing one of them twice"
       % (min(dn), max(dn)))

    # 4. The library, not just the CLI op.  keygen is one [a]B and sign is
    #    two, so 64 and 128 additions say the secret scalar now goes
    #    through the windowed path; verify is one [S]B windowed plus one
    #    [k]A by the double-and-add plus the single R + [k]A.
    seed = bytes(range(32))
    msgb = b"\x00"
    pk = ref_keygen(seed)
    sig = ref_sign(seed, msgb)
    k = le(hashlib.sha512(sig[:32] + pk + msgb).digest()) % L
    got = batch(exe, [
        "ge adds reset",
        "keygen " + seed.hex(), "ge adds reset",
        "sign %s %s" % (seed.hex(), msgb.hex()), "ge adds reset",
        "verify %s %s %s" % (pk.hex(), msgb.hex(), sig.hex()),
        "ge adds reset"])
    nkey, nsign, nver = int(got[2]), int(got[4]), int(got[6])
    want_ver = 64 + (256 + bin(k).count("1")) + 1
    ok((nkey, nsign) == (64, 128),
       "keygen is 64 group additions and sign is 128, so the SECRET scalar "
       "goes through the windowed path and never through the branching "
       "double-and-add: got %d and %d" % (nkey, nsign))
    ok(nver == want_ver,
       "verify is 64 for the windowed [S]B plus %d for [k]A by "
       "double-and-add plus 1 for R + [k]A = %d: got %d"
       % (256 + bin(k).count("1"), want_ver, nver))


SECTIONS = {
    "sha512": sec_sha512,
    "fe": sec_fe,
    "sc": sec_sc,
    "ge": sec_ge,
    "wmul": sec_wmul,
    "sign": sec_sign,
    "wycheproof": sec_wycheproof,
    "x25519": sec_x25519,
    "wycheproof_x": sec_wycheproof_x,
}


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    exe = sys.argv[1]
    for name in sys.argv[2:]:
        if name not in SECTIONS:
            sys.exit("no such section: %s" % name)
        SECTIONS[name](exe)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
