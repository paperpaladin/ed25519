# ed25519 -- SPDX-License-Identifier: GPL-3.0-or-later
#
# t/run.sh compiles the test binaries itself, so test-asan is a CFLAGS
# override and nothing more.  -ffile-prefix-map keeps the build reproducible:
# without it -g writes $(CURDIR) into DWARF .debug_line_str.

# `CC ?= gcc` does not work: make has a built-in default of `cc`, so the
# variable is already set and ?= never fires.
ifeq ($(origin CC),default)
CC := gcc
endif
CFLAGS  ?= -std=c11 -Wall -Wextra -Wpedantic -O2 -g -ffile-prefix-map=$(CURDIR)=.
ASAN     = -std=c11 -Wall -Wextra -Wpedantic -O1 -g \
	   -fsanitize=address,undefined -fno-omit-frame-pointer \
	   -ffile-prefix-map=$(CURDIR)=.

.PHONY: all test test-asan bench clean

all: ed25519.o ed25519

ed25519.o: ed25519.c ed25519.h
	$(CC) $(CFLAGS) -c -o $@ ed25519.c

# The CLI is main() inside ed25519.c behind -DED25519_CLI, so the library
# stays one translation unit and the repo stays at two source files.  The
# tests drive that CLI; there is no separate C test program.
ed25519: ed25519.c ed25519.h
	$(CC) $(CFLAGS) -DED25519_CLI -o $@ ed25519.c

test: all
	CC='$(CC)' CFLAGS='$(CFLAGS)' ./t/run.sh

test-asan:
	CC='$(CC)' CFLAGS='$(ASAN)' UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
		./t/run.sh

bench: all
	./ed25519 bench

clean:
	rm -f ed25519.o ed25519
	rm -rf scratch
