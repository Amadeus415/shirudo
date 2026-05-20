#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t/run-tests.sh -- discover and run every tNNNN-*.sh test in this
# directory, prap-style. CI-friendly; sets non-zero exit if any test
# fails.

set -eu

cd "$(dirname "$0")"

fail=0
found=0
for t in t[0-9][0-9][0-9][0-9]-*.sh; do
	[ -e "$t" ] || continue
	found=1
	if sh "$t"; then
		:
	else
		fail=$((fail + 1))
	fi
done

if [ "$found" -eq 0 ]; then
	echo "# no tests yet" >&2
fi

exit "$fail"
