# ed25519

**NOT PRODUCTION CRYPTO.** Not constant-time, no blinding, no side-channel
hardening, no secret-memory wiping. The scalar multiplication branches on
the bits of the private scalar, so anything that can measure how long it
runs, or watch its cache footprint, can recover the key. Do not use it to
protect anything.

It exists to be *correct*: Ed25519 (RFC 8032) built up from the field
arithmetic, with every layer differenced against something that shares no
code with it.

```
$ make test
23 passed, 0 failed
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
```

The constants are the detail worth noticing: they are **derived from their
definitions** in the code and then compared against what the RFC prints, so
a mistyped constant is caught by the document rather than by the code
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

## Scalars by long division, on purpose

Reduction mod L the fast way -- Barrett, or Montgomery -- is a page of magic
constants that cannot be checked by reading. This does long division
instead: slow, and obviously right. The fast version can replace it later
with this one as its oracle, which is the only order that makes the
replacement checkable.

## What does not work

**There is no signing or verification.** `ed25519.h` declares exactly one
function, `ed25519_sha512`. The field, the scalars and the group are
finished and differenced; the thing they were built for is the next planned
item and is not written. The repository name currently overstates what is
here.

**The HEAD commit is a WIP commit.** A session building this repo was cut
off partway through wiring up the Wycheproof vectors, and that commit records
the tree as it stood. It builds and the suite passes; the feature it was in
the middle of is absent.

**No X25519**, despite the file header mentioning RFC 7748. The Wycheproof
XDH vectors are downloaded (518 tests) and nothing reads them.

**No Wycheproof.** 151 EDDSA verify tests sit in `scratch/wp_ed.json`,
which is gitignored, and nothing reads them either. Wycheproof is where the
edge cases live -- small-order points, non-canonical encodings, signatures
with S >= L -- so until it runs, the published-vector coverage is the RFC's
happy path plus whatever the differential harness happens to generate.

**Not constant-time, and that is a stated non-goal rather than a to-do.** A
half-hardened implementation invites exactly the use this must not have.

No other curves, no assembly, no install target, no stable ABI.

## License

GPL-3.0-or-later.
