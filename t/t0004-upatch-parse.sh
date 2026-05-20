#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0004 -- the .upatch container parser is the target's trust boundary:
# an attacker can hand it an arbitrary file. It must reject malformed
# input cleanly (non-zero exit, never a crash). Driven through the real
# core binary's read-only `upatch info`; needs no root, kernel, or clang.

cd "$(dirname "$0")"
. ./test-lib.sh

S=../shirudo

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
: > "$WORK/empty"
head -c 8 /dev/urandom > "$WORK/trunc"
head -c 65536 /dev/urandom > "$WORK/garbage"
printf 'SHIRUDO\0not-a-real-header-just-magic-ish' > "$WORK/badmagic"

# Rejected cleanly == non-zero exit and not killed by a signal (>=128,
# e.g. 139 = SIGSEGV). A clean parser error is the only acceptable
# outcome for any of these inputs.
reject() {
	"$S" upatch info "$1" >/dev/null 2>&1
	rc=$?
	[ "$rc" -ne 0 ] && [ "$rc" -lt 128 ]
}

test_expect_success 'empty file rejected, no crash' '
	reject "$WORK/empty"
'

test_expect_success 'truncated file (8 bytes) rejected, no crash' '
	reject "$WORK/trunc"
'

test_expect_success 'random garbage rejected, no crash' '
	reject "$WORK/garbage"
'

test_expect_success 'plausible-magic-but-bogus rejected, no crash' '
	reject "$WORK/badmagic"
'

test_expect_success 'nonexistent file rejected, no crash' '
	reject "$WORK/does-not-exist"
'

test_expect_success 'a directory path rejected, no crash' '
	reject "$WORK"
'

test_done
