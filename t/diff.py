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


SECTIONS = {
    "sha512": sec_sha512,
    "fe": sec_fe,
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
