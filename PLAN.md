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
ed25519 keygen SEED      the public key for a 32-byte seed
ed25519 sign SEED MSG    a signature, or "-" for an empty message
ed25519 verify PK MSG SIG   1 if the signature is good, 0 if not
ed25519 x25519 K U       X25519, RFC 7748
ed25519 x25519base K     the same against u = 9
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

- [x] 04 keygen, sign and verify
      why: the whole point of the repo, and it was the thing missing. The
           layers below were finished and differenced and `ed25519.h`
           declared one function.
      done: and the oracle is an independent Ed25519 in Python written from
            RFC 8032's ALGORITHM rather than from its vectors. Transcribing
            the section 7.1 vectors would check this against seven
            published values; differencing against a second implementation
            checks it against as many keys and messages as there is time
            for, and the published vectors then come separately from
            Wycheproof, which is item 05.
      proves: keygen and sign agree on 81 cases with message lengths 0 to
            1024 -- including 0, and both sides of SHA-512's 128-byte block
            where a buffering bug would hide. verify agrees on 200
            signatures, 40 good and 160 damaged in R, in S, in the message
            and in the key, because a signer that verifies its own output
            has proved nothing.
      note: three things here are decisions rather than transcription.
            SIGNING TAKES ONLY THE SEED: handing sign() a public key as
            well saves a scalarmult and admits a key-substitution attack,
            so A is recomputed every time. VERIFICATION IS COFACTORLESS,
            [S]B == R + [k]A exactly as 5.1.7 step 3 writes it rather than
            the cofactored form, which disagrees on small-order
            components. NON-CANONICAL ENCODINGS ARE REFUSED rather than
            reduced mod p, which is stricter than several widely used
            libraries.
      note: S and S+L are the same scalar mod L, so refusing an unreduced S
            is what stops a signature being mauled into a second valid one.
            Both oracles check it independently -- the differential builds
            S+L for 25 signatures, and Wycheproof has 8 malleability
            vectors -- and deleting the one `if` turns both red.
      found: the library build had eight unused-function warnings, which
            were the missing feature showing up as dead code: nothing in
            the public API reached the fe, sc or ge layers. Implementing
            this consumed most of them; the four that remain -- fe_muls,
            fe_eq, ge_isidentity, ge_neg -- are reachable only from the
            CLI, which is the differential harness, so they are now
            guarded by ED25519_CLI rather than left to warn. A build that
            always warns is a build whose warnings nobody reads.
- [x] 05 the Wycheproof Ed25519 vectors
      why: THIS WAS THE INTERRUPTED FEATURE. scratch/wp_ed.json was already
           downloaded when the session building this repo was cut off.
           Wycheproof is the set of edge cases nobody thinks of, and the
           only oracle here written by people trying to break
           implementations rather than to describe one.
      done: all 151 agree. 139 go through verify (88 valid, 51 invalid) and
            12 have a signature that is not 64 bytes, which the harness
            rejects by length -- recorded as such rather than counted as a
            verify result, because that is the harness refusing and not the
            implementation.
      note: the file is NOT vendored. It is third-party data and shipping
            it would mean this project carrying someone else's test suite.
            Absent, the section SKIPS -- and the skip is counted and
            printed separately from the passes, because a skipped oracle
            reporting `ok` is exactly the failure this project exists not
            to have. t/run.sh counts only lines beginning "ok - " and
            "not ok - ", so "skip - " is invisible to both.
      note: it also checks the file is the EDDSA set and skips if it is
            not. The XDH set is a different file with the same shape, it
            was sitting in the same directory under two names, and loading
            it would have tested nothing while reporting a pass.
      found: both skip paths were tested by making them happen -- moving
            the file away, and putting the XDH file in its place. An
            untested skip is a test that passes for the wrong reason.
- [x] 06 X25519 (RFC 7748), and its own Wycheproof vectors
      why: the header already claimed X25519 and nothing implemented it.
           The Montgomery ladder shares the field arithmetic already
           differenced, so the new surface was small.
      done: the ladder from RFC 7748 section 5, x-only, so no point
            decoding, no square root and no sign bit. fe_muls stopped being
            harness-only in the process -- the ladder needs a24*E, which is
            exactly what it was for, so its ED25519_CLI guard came off.
      proves: THREE oracles, and they are not equally independent, which is
            the part worth stating:
              the birational map   u = (1+y)/(1-y), so [k]B on the EDWARDS
                                   curve reaches the same point by a
                                   different algorithm. 44 scalars.
              DH agreement         X25519(a, base(b)) == X25519(b, base(a)),
                                   which needs no reference at all.
              the pseudocode       transcribed into Python. The WEAK one:
                                   same algorithm, so it checks the limbs
                                   and not the ladder. In the suite anyway,
                                   and labelled.
            All 518 Wycheproof XDH vectors agree on the first run.
      note: no input validation, and none is required. Half of all u values
            are on the twist, RFC 7748 defines X25519 on every 32-byte
            string, and 221 of Wycheproof's vectors here are twist points
            marked "acceptable" with an expected answer. None of the 518 is
            invalid. A low-order u gives an all-zero secret rather than an
            error; rejecting it is optional and is the caller's decision.
      survived: deleting the ladder's CLOSING conditional swap changes no
            output, and the mutant is equivalent rather than the test being
            weak. The loop's last iteration sets the swap flag to bit 0 of
            the scalar and decodeScalar25519 has just cleared the three low
            bits, so it can never fire. Kept -- it is what the RFC says and
            makes the ladder correct for an unclamped scalar -- and the
            suite now asserts the premise that makes the mutant equivalent,
            because the claim holds only while the clamp does.
      found: three other mutations are caught by all three oracles at once:
            a24 off by one, no clamp, and a ladder one bit short. The
            Edwards-map oracle and Wycheproof both name a first-bad case.
- [x] 07 REJECTED by measurement: the fast scalar reduction is not worth
      writing
      why it was queued: item 02 deliberately chose long division over
           Barrett or Montgomery because the fast way is a page of magic
           constants that cannot be checked by reading, and said the fast
           one could come later with the slow one as its oracle.
      why it is rejected: the reasoning was sound and the item still
           optimised the wrong thing. `make bench` measures where a
           signature's time goes, and the answer is not ambiguous:

             sign                         466 us
             keygen = 1 scalarmult        214 us
             sc_muladd                     17 us
             sc_reduce of 64 bytes          2 us

           A signature is two scalar multiplications plus two hashes plus
           one muladd. The two multiplications are 92% of it and ALL the
           scalar arithmetic is 4%. A perfect reduction saves four percent
           of a signature in exchange for a page of constants nobody can
           read, in a repository whose stated non-goal is speed.
      done: the measurement, not the optimisation. t/bench.py and
            `make bench`, so the claim is reproducible rather than a number
            in a commit message. Item 08 is what the measurement says to do
            instead, if anything.
      found: `make bench` already existed and was broken. It ran
            `./ed25519 bench`, a CLI op that was never written, so it
            printed "ERR unknown" and exited 0 -- a target that looked like
            it worked. Another artefact of the interrupted session.
      found: `make clean` deleted the downloaded test vectors. It did
            `rm -rf scratch`, and scratch/ holds both build output and the
            Wycheproof JSON, so cleaning silently removed the vectors --
            after which the suite skips both Wycheproof sections and still
            reports 0 failed. A clean that quietly reduces what the next
            test run checks is worse than no clean. It now removes the
            binary and the logs and says what it kept.

### Later

- [ ] 08 a windowed scalar multiplication, against the double-and-add
      why: this is where the time is, and item 07 is the measurement that
           says so -- 92% of a signature against the 4% a faster reduction
           could touch. A fixed-window method with a table of multiples of
           the base point is the usual approach. The double-and-add stays
           as its oracle, which is the only order in which the replacement
           is checkable.
      note: only worth doing at all if something needs signing to be
           faster than 466 us. Nothing here does, so this is queued rather
           than next.
- [ ] 09 Ed25519ph and Ed25519ctx
      why: RFC 8032 defines three variants and this implements one. The
           other two change only the dom2 prefix fed to the hash, so the
           surface is small -- and Wycheproof has vectors for them, which
           means the oracle already exists.
- [ ] 10 a streaming signing API
      why: a message currently has to fit in memory. Ed25519 hashes the
           message twice, so streaming needs the caller to present it
           twice or needs the hash state saved -- which is the design
           question, and the reason this is not just a loop.

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
