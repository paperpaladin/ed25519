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

    # The non-canonical y values are exactly y in [p, 2^255): nineteen of
    # them, each with either sign bit.  y = p is the worst one, because it
    # is p + 0 and y = 0 is a real point of order 4 -- so a verifier that
    # reduces mod p instead of refusing gets a point out of it.
    nc = [leb((P + k) | sb << 255) for k in range(19) for sb in (0, 1)]
    got = batch(exe, ["ge dec " + b.hex() for b in nc])
    n = sum(1 for g in got if g == "ERR dec")
    ok(n == len(nc), "every non-canonical y in [p, 2^255) rejected, both "
       "sign bits: %d/%d" % (n, len(nc)))


SECTIONS = {
    "sha512": sec_sha512,
    "fe": sec_fe,
    "sc": sec_sc,
    "ge": sec_ge,
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
