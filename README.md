# ed25519

**NOT PRODUCTION CRYPTO.** Not constant-time, no blinding, no side-channel
hardening, no secret-memory wiping. Do not use it to protect anything.

Signing is not constant time. `sc_reduce` is long division and subtracts
`L` only when it fits; `sc_geq_l` returns as soon as two bytes differ.
Both run on secret values, so the time a signature takes still depends on
the key. The *multiplication* by the base point no longer does, since
PLAN item 08, and that one narrow claim is spelled out below rather than
rounded up into a claim about the whole thing.

It exists to be *correct*: Ed25519 (RFC 8032) and X25519 (RFC 7748) built
up from the field arithmetic, with every layer differenced against
something that shares no code with it.

```
$ make test
43 passed, 0 failed
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
| the windowed [s]B | the double-and-add it replaced, plus Python | nothing: a table against a bit loop |
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
ok - the windowed [s]B == the double-and-add [s]B on 55 scalars, including
     0, 1, L, 2^255 and 2^256-1
ok - every one of the 1024 table entries [d*16^i]B agrees with the
     double-and-add
ok - the windowed path takes exactly 64 group additions for EVERY one of
     the 55 scalars, and the double-and-add takes 256 + popcount(s)
ok - keygen is 64 group additions and sign is 128, so the SECRET scalar
     goes through the windowed path
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

## A windowed base multiplication, and the only constant-time claim here

A signature is two multiplications by the base point, and `make bench`
said they were most of it. Both are by the *same* point, so the doublings
can be done once at startup instead of 256 times per signature:
`GE_BTAB[i][d]` holds `[d * 16^i]B` for 64 windows of 4 bits, and

```
[s]B = sum over the 64 hex digits d_i of s  of  GE_BTAB[i][d_i]
```

is 64 group additions and no doublings, against the `256 + popcount(s)`
the double-and-add needs. The table costs 1152 additions, once. Signing
went from about 500 us to about 190.

### The table lookup is constant time

A windowed method with `table[digit]` written literally is a cache-timing
oracle on the private key, and it is the usual way this optimisation is
got wrong. `ge_wselect` reads **all sixteen** entries of a window and
picks one arithmetically:

```c
uint64_t m = 0 - (((uint64_t)(i ^ digit) - 1) >> 63);  /* all ones iff i == digit */
fe_cmov(r->X, tab[i].X, m);
```

No branch on the scalar, no load address derived from it, and 64 group
additions whatever the scalar is. That last part is the only piece of it a
machine checks here: the suite counts `ge_add` calls and requires 64 for
every scalar it tries, 64 for `keygen` and 128 for `sign`.

**This does not make signing constant time**, and the operation count is
not a timing measurement. It says the number of group additions does not
depend on the scalar. It says nothing about cache lines, nothing about the
scalar arithmetic that still branches on secrets, and there is no timing
harness in this repository to say more. The claim is about one function
and is deliberately not rounded up.

### A surviving mutant, and why it survives

Replacing the sixteen-entry scan with `*r = tab[digit]` passes the entire
suite. It computes the same function, so no differential oracle can see
it; it is a pure cache-timing defect. The alternative to recording it is
inventing a measurement this repo cannot make honestly, so it is recorded.
Reading the code is the only check on that line.

### How the suite knows the new code ran

This is the trap the section is built around. "Compare the windowed
multiplication against the double-and-add" passes perfectly if
`ge wbasemul` quietly calls the double-and-add: the harness then compares
one implementation with itself and reports agreement on everything.

So `ge_add` counts its calls under `-DED25519_CLI` and `ge adds reset`
reports them. Wiring `ge wbasemul` to the double-and-add fails exactly two
checks, both of them count checks, and every value comparison in the
section still passes. Reverting `keygen` to the double-and-add fails
exactly two more, the same way. Those four are the ones that make the
other three mean something.

Eight of nine planted defects turn the suite red, nine failures each:
reversed nibble order, a table stepping by `8^i`, one window short, every
window built from `B` instead of `[16^i]B`, `fe_cmov` using AND where it
needs XOR, and the select mask off by one. The ninth is the survivor
above.

### [k]A in verify is still the double-and-add

Verification is `[S]B == R + [k]A`. `[S]B` uses the table; `[k]A` does
not, because `A` changes every call, so its table would have to be built
every call, and nothing in verification is secret. The double-and-add is
therefore still live code, still reachable as `ge mul` and `ge basemul`,
and still the oracle for the windowed one.

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
$ make bench                       (before item 08)   (after)
  sign                         462 us               191 us
  verify                       494 us               394 us
  keygen = 1 scalarmult        217 us                89 us
  x25519_base = 1 ladder       163 us               196 us
  sc_muladd                     17 us                19 us
  sc_reduce of 64 bytes         16 us                19 us
  sha512 of 32 bytes             4 us                 4 us
```

The absolute numbers move a few percent between runs on this machine and
the `x25519` and `sc` rows did not change at all; it is the relative sizes
that the measurement is for.

Before item 08, a perfect reduction bought eleven percent of a signature
in exchange for a page of unreadable constants, in a repository whose
stated non-goal is speed. The item was closed as rejected with the
measurement as the reason, and the thing the measurement pointed at, a
windowed scalar multiplication, was queued behind "if anything ever needs
this faster than 462 us".

Item 08 then happened anyway, for the constant-time reason above rather
than the speed, and it moved the arithmetic under item 07's own
conclusion: the scalar arithmetic is now about 29% of a 191 us signature
where it was 11% of a 462 us one. The rejection stands on the absolute
figure, which did not move: 49 us for a page of constants nobody can read.

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

Not constant-time, and that is a stated non-goal, not a to-do. Since item
08 the honest version is narrower and still ends in the same place:

- `ge_basemult`, which is every multiplication a *secret* scalar goes
  through, does not branch on the scalar and does not index its table with
  it.
- `sc_reduce` subtracts `L` when it fits, `sc_geq_l` returns on the first
  differing byte, and `sc_muladd` runs through `sc_reduce`. All three see
  secrets while signing, so the time a signature takes still depends on
  the key.
- Nothing measures any of this. There is no timing harness, so even the
  first bullet is an argument from the code and an operation count.
- No blinding, and no secret-memory wiping: `a`, `prefix`, `r` and `k` are
  left on the stack.

A half-hardened implementation invites exactly the use this must not have,
so the top of this file still says do not use it to protect anything.

The Wycheproof vectors are not in the repository. They are third-party
data, and vendoring them would mean this project shipping someone else's
test suite. Put the EDDSA verify set at `scratch/wp_ed.json` and they run;
without it that section skips, and the skip is counted and printed
separately from the passes:

```
42 passed, 0 failed, 1 SKIPPED
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
