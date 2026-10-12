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

printf -- '\n--- oracle: an independent Ed25519 in Python, written from the\n'
printf -- '    RFC 8032 algorithm rather than from its vectors\n'
run "diff.py sign" python3 t/diff.py "$E" sign

printf -- '\n--- oracle: Project Wycheproof EDDSA vectors, if present\n'
run "diff.py wycheproof" python3 t/diff.py "$E" wycheproof

printf -- '\n=== oracles\n'
printf -- '  CPython hashlib               ran (no network needed)\n'
printf -- '  Python integers mod p and L   ran (no network needed)\n'
printf -- '  Python reference group        ran (no network needed)\n'
printf -- '  An independent Ed25519        ran (no network needed)\n'
if [ -f scratch/wp_ed.json ]; then
	printf -- '  Project Wycheproof EDDSA      ran\n'
else
	printf -- '  Project Wycheproof EDDSA      ABSENT (scratch/wp_ed.json)\n'
fi

pass=$(grep -c '^ok - ' "$OUT")
fail=$(grep -c '^not ok - ' "$OUT")
skipped=$(grep -c '^skip - ' "$OUT")

# A skipped oracle is reported separately and never folded into the pass
# count. An absent third-party vector file is not a reason to fail, and it
# is also not a reason to claim the vectors agreed.
if [ "$skipped" -gt 0 ]; then
	printf '\n%s passed, %s failed, %s SKIPPED\n' "$pass" "$fail" "$skipped"
	grep '^skip - ' "$OUT" | sed 's/^skip - /  skipped: /'
else
	printf '\n%s passed, %s failed\n' "$pass" "$fail"
fi
[ "$fail" -eq 0 ]
