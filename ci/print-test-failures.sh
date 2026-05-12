#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# On test failure, dump every failing test's output so the CI log
# carries enough context to debug from.

. "$(dirname "$0")/lib.sh"

results_dir="t/test-results"
if [ ! -d "$results_dir" ]; then
	log "no t/test-results/ directory; nothing to dump"
	exit 0
fi

for out in "$results_dir"/*.out; do
	[ -e "$out" ] || continue
	# Test was a failure iff a matching .exit file contains non-zero.
	exitfile="${out%.out}.exit"
	if [ -r "$exitfile" ]; then
		ec="$(cat "$exitfile")"
		[ "$ec" = "0" ] && continue
	fi
	log "======= $(basename "$out") ======="
	cat "$out"
done

# Also surface any trash directories with state worth inspecting.
for dir in t/trash\ directory.*; do
	[ -d "$dir" ] || continue
	log "trash directory preserved: $dir"
	ls -la "$dir" || true
done
