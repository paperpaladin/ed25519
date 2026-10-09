#!/bin/sh
# t/run.sh -- build and run every oracle, print "N passed, M failed".
# SPDX-License-Identifier: GPL-3.0-or-later
#
# POSIX sh.  This script, not the Makefile, compiles the binary under test,
# so `make test-asan` is the same script with different CFLAGS.
set -u

cd "$(dirname "$0")/.." || exit 1
CC=${CC:-gcc}
CFLAGS=${CFLAGS:--std=c11 -Wall -Wextra -Wpedantic -O2 -g}

mkdir -p scratch		# repo-local: /tmp is shared with other work
OUT=scratch/run.log
: > "$OUT"

say() { printf '%s\n' "$*" | tee -a "$OUT"; }

# shellcheck disable=SC2086
$CC $CFLAGS -DED25519_CLI -o scratch/ed25519 ed25519.c || {
	echo "not ok - compile"
	exit 1
}
E=./scratch/ed25519

# A crash is a failure.  A pipeline's exit status is tee's, so output goes to
# a file first and the status is read from the command itself -- the sibling
# ../sha2 reported "0 failed" through an ASAN abort exactly once by piping a
# test program through tee, and that is not repeated here.
run() {
	label=$1
	shift
	st=0
	"$@" > scratch/last.log 2>&1 || st=$?
	tee -a "$OUT" < scratch/last.log
	[ "$st" = 0 ] ||
		say "not ok - $label exited $st (crash, abort or sanitizer)"
}

printf -- '--- oracle: CPython hashlib (the vendored SHA-512)\n'
run "diff.py sha512" python3 t/diff.py "$E" sha512

printf -- '\n--- oracle: Python integers mod 2^255-19 (the field)\n'
run "diff.py fe" python3 t/diff.py "$E" fe

printf -- '\n--- oracle: Python integers mod L (the scalars)\n'
run "diff.py sc" python3 t/diff.py "$E" sc

printf -- '\n--- oracle: an independent Ed25519 group in Python (40 lines,\n'
printf -- '    RFC 8032 5.1.3 and 5.1.4, no limbs and no shared code)\n'
run "diff.py ge" python3 t/diff.py "$E" ge

printf -- '\n=== oracles\n'
printf -- '  CPython hashlib               ran (no network needed)\n'
printf -- '  Python integers mod p and L   ran (no network needed)\n'
printf -- '  Python reference group        ran (no network needed)\n'

pass=$(grep -c '^ok - ' "$OUT")
fail=$(grep -c '^not ok - ' "$OUT")
printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
