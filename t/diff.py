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


SECTIONS = {
    "sha512": sec_sha512,
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
