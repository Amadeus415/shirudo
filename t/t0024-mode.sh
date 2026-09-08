#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0024 -- strict parsing of the irreversible mode commitment.

cd "$(dirname "$0")"
. ./test-lib.sh

H=helper/test-mode
D=$(python3 -c 'print("ab" * 32)')

test_expect_success 'mode parser accepts the canonical commitment' '
	printf "version=1\\nmode=trusted_root\\ncert_sha256=%s\\n" "$D" |
	./$H | grep -qx "rc=0"
'

test_expect_success 'mode parser rejects an overlong digest' '
	printf "version=1\\nmode=trusted_root\\ncert_sha256=%s0\\n" "$D" |
	./$H | grep -qx "rc=-22"
'

test_expect_success 'mode parser rejects blank and duplicate fields' '
	printf "version=1\\n\\nmode=trusted_root\\ncert_sha256=%s\\n" "$D" |
	./$H | grep -qx "rc=-22" &&
	printf "version=1\\nversion=1\\nmode=trusted_root\\ncert_sha256=%s\\n" "$D" |
	./$H | grep -qx "rc=-22"
'

test_expect_success 'mode parser rejects embedded NUL and trailing data' '
	python3 -c "import sys; d=b\"ab\"*32; sys.stdout.buffer.write(b\"version=1\\nmode=trusted_root\\ncert_sha256=\" + d + b\"\\n\\0ignored\")" |
	./$H | grep -qx "rc=-22"
'

test_done
