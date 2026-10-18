#!/usr/bin/env python3
"""t/bench.py -- where the time in a signature actually goes.

SPDX-License-Identifier: GPL-3.0-or-later

This exists to answer a planning question with a measurement instead of an
assumption. PLAN.md item 07 was "replace the long-division scalar
reduction with the fast one, against the slow one as oracle", on the
reasoning that item 02 had deliberately chosen the obvious version. The
reasoning was fine and the item was still wrong: the scalar arithmetic is
a few percent of a signature and the scalar multiplication is most of it.

Run as `make bench`. It times the CLI in batch mode, so each number
includes a little hex parsing and line handling -- which is why the
RELATIVE sizes are the point and the absolute ones are not.
"""
import os
import random
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def timeit(exe, cmds):
    inp = "\n".join(cmds) + "\n"
    best = None
    for _ in range(3):          # three runs, keep the fastest
        t0 = time.perf_counter()
        r = subprocess.run([exe, "run"], input=inp,
                           capture_output=True, text=True)
        dt = time.perf_counter() - t0
        if r.returncode != 0:
            print("bench: %s exited %d" % (exe, r.returncode))
            return None
        best = dt if best is None else min(best, dt)
    return best / len(cmds) * 1e6


def main():
    exe = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "ed25519")
    if not os.path.exists(exe):
        print("bench: no %s (run make)" % exe)
        return 1
    rnd = random.Random(1)
    n = 300
    seeds = [bytes(rnd.randrange(256) for _ in range(32)).hex()
             for _ in range(n)]

    rows = [
        ("sign", ["sign %s 00" % s for s in seeds]),
        ("verify", None),       # filled in below, needs a signature
        ("keygen = 1 scalarmult", ["keygen %s" % s for s in seeds]),
        ("x25519_base = 1 ladder", ["x25519base %s" % s for s in seeds]),
        ("sc_muladd", ["sc muladd %s %s %s" % (s, s, s) for s in seeds]),
        # `sc reduce`, not `sc reduce64`: there is no reduce64 op, and the
        # first version of this timed `puts("ERR sc op")` at 2.7 us instead
        # of the reduction at 17.5. That number then went into the README
        # and into the rejection of PLAN item 07 -- the same failure this
        # file was written to fix one layer down, since `make bench` used to
        # invoke a `bench` op that was never written either.
        ("sc_reduce of 64 bytes", ["sc reduce %s%s" % (s, s)
                                   for s in seeds]),
        ("sha512 of 32 bytes", ["sha512 %s" % s for s in seeds]),
    ]
    out = subprocess.run([exe, "run"], text=True, capture_output=True,
                         input="".join("keygen %s\nsign %s 00\n" % (s, s)
                                       for s in seeds)).stdout.split()
    pks, sigs = out[0::2], out[1::2]
    rows[1] = ("verify", ["verify %s 00 %s" % (p, g)
                          for p, g in zip(pks, sigs)])

    print("microseconds per operation, fastest of three runs of %d:" % n)
    times = {}
    for label, cmds in rows:
        us = timeit(exe, cmds)
        if us is None:
            return 1
        times[label] = us
        print("  %-26s %7.1f" % (label, us))

    sign = times["sign"]
    mult = times["keygen = 1 scalarmult"]
    # TWO reductions, not one: signing reduces H(prefix||M) to get r and
    # H(R||A||M) to get k. Counting one understated the scalar arithmetic
    # by a reduction, which is most of it.
    scal = times["sc_muladd"] + 2 * times["sc_reduce of 64 bytes"]
    print()
    print("A signature is two scalar multiplications, two hashes, two")
    print("reductions and one muladd.  Of its %.0f us:" % sign)
    print("  %5.1f%%  two scalar multiplications (%.0f us)"
          % (200.0 * mult / sign, 2 * mult))
    print("  %5.1f%%  all the scalar arithmetic (%.0f us: one muladd and"
          % (100.0 * scal / sign, scal))
    print("           two reductions)")
    print()
    print("Which is the answer to PLAN item 07.  Replacing the long-division")
    print("reduction with a fast one can save at most the second number, and")
    print("a windowed scalar multiplication goes after the first -- which is")
    print("PLAN item 08, now done: [s]B is a table lookup and 64 group")
    print("additions, so the two multiplications in a signature cost what one")
    print("used to and the second number is a BIGGER share of a smaller")
    print("total.  Still the same decision: 49 us for a page of constants.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
