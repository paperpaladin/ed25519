# ed25519

**NOT PRODUCTION CRYPTO.** Not constant-time, no blinding, no side-channel
hardening, no secret-memory wiping. The scalar multiplication branches on
the bits of the private scalar, so anything that can measure how long it
runs, or watch its cache footprint, can recover the key. Do not use it to
protect anything.

It exists to be *correct*: Ed25519 (RFC 8032) and X25519 (RFC 7748) built
up from the field arithmetic, with every layer differenced against
something that shares no code with it.

```
$ make test
36 passed, 0 failed
```

## Why every layer has its own oracle

Cryptographic code is the worst case for self-consistent wrongness. An
implementation can be internally coherent, pass its own round-trips, produce
signatures it verifies itself, and still be wrong in a way only another
implementation will reveal. **"Sign, then verify" is not evidence of
anything.**

So each layer is differenced against a *different representation* of the
same mathematics, and every layer is reachable from the command line so it
can be differenced from outside:

| layer | oracle | what it shares with us |
|---|---|---|
| SHA-512 | CPython `hashlib` | nothing |
| field mod 2^255-19 | Python arbitrary-precision integers | nothing: no limbs, no carries |
| scalars mod L | Python integers mod L | nothing |
| the group | 40 lines of Python from RFC 8032 5.1.3 / 5.1.4 | nothing |
| scalar multiplication | the same Python integers | nothing |
| sign and verify | a second Ed25519 in Python, from the RFC's *algorithm* | nothing |
| sign and verify | Project Wycheproof's EDDSA vectors | nothing: written to break implementations |
| X25519 | the *same point* reached through the Edwards curve | nothing: a different curve form |
| X25519 | Diffie-Hellman agreeing with itself | nothing: no reference at all |
| X25519 | Project Wycheproof's XDH vectors | nothing |
| the constants | the values RFC 8032 5.1 prints | they are the document |

```
ok - SHA-512 == hashlib on 801 messages (lengths 0..600 exhaustive, then random): 0 differ
ok - fe: 53280 operations differenced in one process
ok - sc muladd    == Python integers mod L on 805 inputs
ok - curve constants derived from their definitions equal the values printed
     in RFC 8032 5.1 (d, sqrt(-1), Bx, By, L): all 5 match
ok - the base point encodes to RFC 8032's 5866...66
ok - group law == the Python reference on 1848 operations over 307 points
     (3 of the encodings are not points and must say so)
ok - every non-canonical y in [p, 2^255) rejected, both sign bits: 38/38
ok - keygen and sign == an independent Python Ed25519 on 81 cases
     (message lengths 0..1024, including both sides of SHA-512's 128-byte block)
ok - verify agrees with the reference on 200 signatures, 40 good and 160
     damaged in R, S, the message or the key
ok - S + L is refused rather than reduced, so a signature cannot be mauled
     into a second valid one: 25/25
ok - 139 Wycheproof EDDSA vectors agree (88 valid, 51 invalid; 12 more have
     a signature that is not 64 bytes and are rejected by length alone)
```

The constants are the detail worth noticing. They are **derived from their
definitions** in the code and then compared against what the RFC prints, so
a mistyped constant is caught by the document, not by the code
agreeing with itself.

## SHA-512 is vendored, not rewritten

Lifted from the sibling `../sha2` and stripped to SHA-512 alone. A second
hand-written SHA-512 would be a second place to be wrong, and rewriting it
would be busywork with a new bug in it.

The one change: a single 64-bit byte counter instead of `sha2.c`'s 128-bit
one, the high half being unreachable without 2^61 bytes of message.

Over in `../sha2` it is checked against the NIST CAVP vectors, CPython,
coreutils and openssl. Here it is checked against `hashlib` again anyway, so
the vendored copy carries its own oracle on this side of the fence rather
than being trusted because it passed next door.

## X25519, and three oracles that are not equally independent

Curve25519 is the same group as edwards25519 in coordinates that make a
different operation cheap, so X25519 reuses the field arithmetic and
nothing else: the ladder is x-only, needing no point decoding, no square
root and no sign bit.

Which oracle to believe matters more here than anywhere else in this repo,
because the obvious one is the weakest. In order of how little they share
with the code:

The birational map. RFC 7748 section 4.1 gives the correspondence
between the two curve forms, `u = (1 + y) / (1 - y)`. So `x25519_base(k)`
can be computed a second way: take `[clamp(k)]B` on the Edwards curve,
whose group law is already differenced against Python, and map the `y` that
comes out. Different coordinates, different formula, different number of
field operations, and it agrees on all 44 scalars.

Diffie-Hellman agreeing with itself. `X25519(a, X25519(b, 9))` equals
`X25519(b, X25519(a, 9))` because both are `[a*b]G`. This is the only check
here that would still mean something if every reference implementation were
wrong in the same way.

A Python transcription of the ladder. This is the weak one and it is
in the suite anyway, because it is the *same algorithm* in a different
representation, so it differences 51-bit limbs against Python integers. A
real check on the field arithmetic in this context, and no check at all on
whether the ladder is the right ladder, if the pseudocode had been copied
wrongly, this oracle would agree enthusiastically while the two above would
not.

```
ok - x25519_base == [k]B on the EDWARDS curve mapped through u = (1+y)/(1-y),
     on 44 scalars -- a different curve form, a different algorithm
ok - Diffie-Hellman agrees on 10/10 key pairs, which needs no reference
     implementation at all
ok - the ladder == the RFC 7748 pseudocode in Python on 26 products,
     including u = 0, 1, p-1, p and p+1
ok - 518 Wycheproof XDH vectors agree (254 acceptable: twist points,
     low-order and non-canonical keys, all with an expected answer)
```

### There is no input validation, and none is required

Half of all `u` values put the point on the twist, not on
Curve25519, and RFC 7748 defines X25519 on every 32-byte string anyway. The
ladder computes in a group either way and the result is still safe to use.
That is why 221 of Wycheproof's vectors here are twist points marked
`acceptable` with an expected answer, and why none of the 518 is marked
invalid. A low-order `u` gives an all-zero shared secret, not an
error. Rejecting that is optional in RFC 7748, is not done here, and is
called out in the header as the caller's decision.

### A surviving mutant, and the clamp's fault

RFC 7748's pseudocode ends the ladder with a conditional swap. **Deleting
it changes no output.** The loop's last iteration sets the swap flag to bit
0 of the scalar, and `decodeScalar25519` has just cleared the three low
bits, so that swap can never fire.

It is kept. It is what the RFC says, it makes the ladder correct for a
scalar below `2^255` with the clamp removed, and it costs two branches that
are never taken. The mutant is recorded as surviving, not chased.

The suite asserts the premise that makes it equivalent, and **the first
version of that assertion was itself a tautology**, it computed
`(k[0] & 248) & 7` in Python, asserted the answer was zero, and never
touched the binary at all. True of every byte, and it would have passed
with the implementation deleted. It was also the only thing holding up the
equivalent-mutant claim above.

It now goes through the binary the way it should have: flip the three low
bits and the top two of each scalar and require the answer not to move,
which is what "the clamp discards them" actually means. Deleting the low-bit
mask turns it red.

## Three decisions in the signature, not transcription

Most of RFC 8032 is transcription. Three things are choices, and each is a
place an implementation can be wrong while passing its own round trip,
which is why "sign, then verify" proves nothing.

Signing takes only the seed. The usual API hands `sign()` both the
secret scalar and the public key, saving one scalar multiplication per
signature. It also admits a real attack. A caller who passes a public key not
derived from the secret gets a signature that verifies under *that*
key. `A` is recomputed from the seed every time instead. It costs about
half the price of a signature, and the footgun cannot be loaded.

Verification is cofactorless. `[S]B == R + [k]A`, exactly as RFC 8032
section 5.1.7 step 3 writes it: not the cofactored `[8][S]B == [8]R +
[8][k]A` that several implementations use. The two disagree on signatures
with a small-order component, so this is a choice with observable
consequences, not an optimisation.

Non-canonical encodings are refused. Any `y` in `[p, 2^255)` is
rejected, not reduced mod `p` first, for public keys and for `R`.
That is stricter than several widely used libraries, and the difference is
visible in the Wycheproof vectors.

### Malleability

`S` and `S + L` are the same scalar mod `L`, so an implementation that
*reduces* `S` instead of refusing it accepts a second valid signature for a
message it has already signed. This refuses it, and both oracles check that
independently: the differential constructs `S + L` for 25 signatures and
requires a rejection, and Wycheproof's 8 `SignatureMalleability` vectors
require the same. Deleting the one `if` turns both red.

## Scalars by long division, and a planned optimisation that was measured away

Reduction mod `L` the fast way (Barrett, or Montgomery) is a page of
magic constants that cannot be checked by reading. This does long division
instead: slow, and obviously right. The plan said the fast version could
replace it later with this one as its oracle. No other order makes the
replacement checkable.

Then the replacement was measured instead of written:

```
$ make bench
  sign                         462 us
  verify                       494 us
  keygen = 1 scalarmult        217 us
  x25519_base = 1 ladder       163 us
  sc_muladd                     17 us
  sc_reduce of 64 bytes         16 us
  sha512 of 32 bytes             4 us

A signature is two scalar multiplications, two hashes, two
reductions and one muladd.  Of its 462 us:
   94.2%  two scalar multiplications (435 us)
   10.7%  all the scalar arithmetic (49 us: one muladd and
           two reductions)
```

A perfect reduction buys eleven percent of a signature in exchange for a
page of unreadable constants, in a repository whose stated non-goal is
speed. The item is closed as rejected, with the measurement as the reason,
and the thing the measurement points at, a windowed scalar multiplication,
is queued behind "if anything ever needs this faster than 462 us".

### That benchmark was wrong twice, and the second time was mine

The first version of `make bench` ran `./ed25519 bench`, a CLI op that was
never written: it printed `ERR unknown` and exited 0, so the target looked
like it worked. Replacing it introduced the same defect one layer down.
The new script timed `sc reduce64`, also not an op, so the
"2 us" above was the cost of printing `ERR sc op`, not the cost of a
reduction. It also counted one reduction where a signature performs two,
for `r` and for `k`.

So the figure that closed PLAN item 07 was 4.1% when the honest answer is
10.7%, wrong by a factor of nearly three. **The decision survives and the
number did not**, and that is the only reason this is a correction
and not a reopening: 94% against 11% says the same thing 92% against 4% did.


## What does not work

Not constant-time, and that is a stated non-goal, not a to-do.
`ge_scalarmult` skips the addition when the scalar bit is clear, so both
the running time and the cache footprint depend on the private scalar. A
half-hardened implementation invites exactly the use this must not have, so
it is not half-hardened.

The Wycheproof vectors are not in the repository. They are third-party
data, and vendoring them would mean this project shipping someone else's
test suite. Put the EDDSA verify set at `scratch/wp_ed.json` and they run;
without it that section skips, and the skip is counted and printed
separately from the passes:

```
35 passed, 0 failed, 1 SKIPPED
  skipped: Wycheproof EDDSA vectors absent (scratch/wp_ed.json); ...
```

A skipped oracle that reported `ok` would be exactly the kind of test this
project exists not to have. The section also checks the file is the EDDSA
set and skips if it is not, since the XDH set is a different file with the same
shape, and it was sitting in the same directory.

`ed25519_verify` does not check the signature length, because it cannot.
It takes `const unsigned char sig[64]` and has no way to know how many bytes
were offered, so it will verify the first 64 bytes of a 96-byte blob and
report success. Checking the length is the caller's job and the header says
so. Twelve of Wycheproof's vectors are exactly that shape, truncated,
padded, public key appended: all twelve expected to be rejected, and all
twelve rejected on length before they reach the implementation. The suite
records them separately instead of counting them as verify results,
because that is the harness refusing and not the code under test.

**X25519 does no input validation and does not reject an all-zero shared
secret.** Both are permitted by RFC 7748 and both are the caller's
decision. A Diffie-Hellman caller that needs contributory behaviour has to
check the output itself.

Only the pure Ed25519 variant. No Ed25519ph, no Ed25519ctx, no
prehashing, and no batch verification.

One message at a time, in memory. There is no streaming signing API, so
a message has to fit in a buffer.

No other curves, no assembly, no install target, no stable ABI.

## License

GPL-3.0-or-later.
