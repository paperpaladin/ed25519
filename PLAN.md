# ed25519 -- plan

## Contract

Ed25519 (RFC 8032) and X25519 (RFC 7748) in one C11 file, built up from the
field arithmetic rather than wrapped around a library.

**NOT PRODUCTION CRYPTO.** Not constant-time, no blinding, no side-channel
hardening, no secret-memory wiping. The scalar multiplication branches on
the bits of the private scalar, so anything that can measure how long a
signature takes, or watch its cache footprint, can recover the key. This
exists to be *correct* against the published vectors, and the README says so
first.

```
ed25519 fe  OP ...        field arithmetic mod 2^255-19
ed25519 sc  OP ...        scalar arithmetic mod L
ed25519 ge  OP ...        group operations on the curve
```

The CLI exists for the differential harness: every internal layer is
reachable from outside so it can be differenced against an independent
implementation, rather than only the top-level signature being testable.

## Hard invariant

**Every layer is differenced against something that shares no code with it.**

Cryptographic code is the worst case for self-consistent wrongness: an
implementation can be internally coherent, pass its own round-trip tests,
produce signatures it verifies itself, and be wrong in a way only another
implementation will show. "Sign then verify" is not evidence.

So each layer has an oracle built from a different representation:

- the field, against Python's arbitrary-precision integers mod 2^255-19 --
  no limbs, no carries, no shared idea of how a number is stored;
- the scalars, against Python integers mod L;
- the group, against a 40-line Python transcription of RFC 8032 5.1.3 and
  5.1.4 that uses those integers directly;
- SHA-512, against CPython's `hashlib`.

The vendored SHA-512 carries its own oracle on this side of the fence rather
than being trusted because it passed next door.

## Oracle

Ranked by how little of it we control.

1. **RFC 8032 and RFC 7748 themselves**, for the curve constants and the
   test vectors. The constants are *derived from their definitions* in the
   code and then compared against the values the RFC prints -- d,
   sqrt(-1), Bx, By and L -- so a typo in a constant is caught by the
   document rather than by agreement with itself.
2. **CPython `hashlib`**, for the vendored SHA-512, over every message
   length from 0 to 600 and then random lengths.
3. **Python integers**, for the field and the scalars. The cheapest
   independent oracle that exists for arithmetic mod a prime: a different
   representation, a different algorithm, and no shared code.
4. **An independent Ed25519 group in Python**, 40 lines, written from RFC
   8032 5.1.3 and 5.1.4 with no limbs and nothing shared with the C.
5. **Project Wycheproof**, for the edge cases nobody thinks of. Not wired
   up yet; the vectors are downloaded into `scratch/` and the next items
   are what use them.

## Non-goals

Constant time. It is stated as a non-goal rather than attempted badly: a
half-hardened implementation invites exactly the use this must not have.
Making it constant-time would mean a different scalar multiplication, and
the honest version of that claim needs a measurement harness this does not
have.

Being a library anyone depends on. There is no stable ABI, no versioning,
no install target.

Other curves. No P-256, no secp256k1, no Ristretto.

Hardware acceleration, assembly, or anything that makes the arithmetic
harder to difference against Python.

## Commit sequence

- [x] 00 scaffolding, and SHA-512 vendored from `../sha2` rather than
      rewritten
      why: Ed25519 needs SHA-512 and a second hand-written SHA-512 would be
           a second place to be wrong. Vendoring it is honest; rewriting it
           would be busywork with a new bug in it.
      done: stripped to SHA-512 alone, with one change -- a 64-bit byte
            counter instead of a 128-bit one, the high half being
            unreachable without 2^61 bytes of message. Checked again
            against `hashlib` here, so the copy carries its own oracle.
      proves: 801 messages, lengths 0..600 exhaustive then random, 0 differ.
- [x] 01 field arithmetic mod 2^255-19, differenced against Python integers
      why: everything above this is built on it, and a wrong carry shows up
           as a wrong signature ten layers later where it cannot be
           diagnosed.
      proves: 13 operations -- canon, add, sub, mul, sq, neg, inv, p22523,
            iscanon, isneg, nonzero, eq -- over 4440 inputs each, 53280
            operations differenced in one process.
- [x] 02 scalars mod L by long division, because the fast way is all
      constants
      why: Barrett or Montgomery reduction mod L is a page of magic numbers
           that cannot be checked by reading. Long division is slow and
           obviously right, and the fast version can replace it later
           against this one as the oracle.
      proves: reduce64, reduce32, ltl and muladd against Python integers
            mod L, and that L and L*1 both reduce to 0.
- [x] 03 the group, against an independent Python transcription
      why: the group law is where an implementation can be self-consistently
           wrong most easily -- doubling and addition that agree with each
           other and with neither the curve nor anybody else.
      proves: the curve constants derived from their definitions equal the
            values RFC 8032 5.1 prints, all 5 of them; the base point
            encodes to the RFC's 5866...66; the group law matches the
            Python reference over 1848 operations on 307 points, 3 of whose
            encodings are not points and must say so; and every
            non-canonical y in [p, 2^255) is rejected with both sign bits,
            38 of 38.
- [x] 03a scalar multiplication, which the plan did not have
      why: it was not an item, and it should have been. Item 04 is keygen,
           sign and verify, and none of them can be written without s*P --
           which item 03 did not build, because the group law and the
           scalar arithmetic are both complete without it. Found by
           reading the CLI: `ge` had const, dec, id, neg, dbl, add, selfadd
           and eq, and no multiplication, while t/diff.py had had ref_mul
           since the group went in. The oracle existed before the
           implementation; the plan just never named the gap.
      done: double-and-add over the 256 bits of the scalar, most
            significant first, with no reduction -- RFC 8032 makes the
            reduction the caller's job and doing it here would hide a
            scalarmult that silently reduced. This is the function that
            makes the whole repository non-constant-time: the addition is
            skipped when the bit is clear, so the timing and the cache
            footprint both depend on the private scalar.
      proves: 127 products against the Python reference, over 50 scalars
            including 0, 1, 2, 8, L-1, L, L+1, 2^252, 2^255 and 2^256-1,
            and 40 random points with the aliasing path tested separately.
            And L*B is the identity, which is the one fact here that needs
            no reference implementation to state -- so B has order L, and
            (L+1)*B is B again.
      found: the edge-case scalar list is what catches a whole mutation
            class. Dropping the top bit of the scalar -- looping from 254
            rather than 255 -- is invisible to random 256-bit scalars
            often enough to matter, and is caught immediately by the
            2^255 entry. Mutation-tested three ways: reversed bit order
            within each byte, the unexamined top bit, and doubling after
            the add instead of before.

- [ ] 04 keygen, sign and verify, against the RFC 8032 section 7.1 vectors
      why: this is the whole point of the repo and it is not done. There is
           no `ed25519_sign` yet -- `ed25519.h` declares only
           `ed25519_sha512`. The layers below are finished and differenced;
           the thing they were built for is missing.
      note: one of the section 7.1 vectors has a SHA-512 digest as its
            message, which is why `ed25519_sha512` is exported at all.
- [ ] 05 the Wycheproof Ed25519 vectors
      why: THIS IS THE INTERRUPTED FEATURE. `scratch/wp_ed.json` was
           already downloaded when the session building this repo was cut
           off, and the WIP commit at HEAD records the tree mid-change.
           Wycheproof is the set of edge cases nobody thinks of: small-order
           points, non-canonical encodings, signatures with S >= L.
           151 verify tests in the file already downloaded.
      note: the JSON is data, not a build script, so using it is fine. It
            lives in `scratch/`, which is gitignored, so the harness has to
            skip cleanly when it is absent rather than fail.
- [ ] 06 X25519 (RFC 7748), and its own Wycheproof vectors (518 tests,
      already downloaded as `scratch/wp_x.json`)
      why: the header already claims X25519 and nothing implements it. The
           Montgomery ladder shares the field arithmetic already
           differenced above, so the new surface is small.
- [ ] 07 the fast scalar reduction, against the long division as oracle
      why: item 02 deliberately chose the slow obvious version and said the
           fast one could come later measured against it. This is later.

## Open questions

- (Resolved by looking.) `scratch/t.json` and `scratch/wp_x.json` are
  byte-identical: one download was repeated under two names. Both are
  Wycheproof's XDH set, 518 tests, schema `xdh_comp_schema_v1`, so they
  belong to item 06 rather than 05. `scratch/wp_ed.json` is the EDDSA
  verify set, 151 tests, schema `eddsa_verify_schema_v1`, which is item 05's.
  Delete the duplicate before either is wired up, so the harness cannot
  silently run the wrong set.
- Whether to keep the CLI at all once signing exists. It is there so each
  layer can be differenced from outside, which is the hard invariant, so
  probably yes -- but it is also a public surface that is not part of the
  contract.
