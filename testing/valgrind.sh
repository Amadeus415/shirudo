#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# testing/valgrind.sh -- memcheck over the unit tests and over every fuzz
# target's seed corpus, each input once: a read of memory never written,
# or one out of bounds or after a free, in the Rust or in the C it calls,
# which the sanitizers of the fuzz build see only in part. The targets
# are the replay builds of build/fuzz-replay, without libFuzzer. What runs
# Lua is left out: LuaJIT's interpreter reads memory memcheck takes for
# unwritten.
#
#   make -C testing valgrind

set -u

cd "$(dirname "$0")"
lua_fuzzers='decoder'
memcheck='valgrind -q --error-exitcode=99 --track-origins=yes --leak-check=no'
fail=0

listed() {
	case " $2 " in *" $1 "*) return 0 ;; esac
	return 1
}

printf 'valgrind: unit tests\n'
# shellcheck disable=SC2086 # the command and its options
$memcheck ../build/unit/shirudo-unit -q || fail=$((fail + 1))

for d in fuzz/corpus/*/; do
	t=${d%/}
	t=${t##*/}
	listed "$t" "$lua_fuzzers" && continue
	printf 'valgrind: fuzz-%s\n' "$t"
	# shellcheck disable=SC2086
	$memcheck "../build/fuzz-replay/fuzz-$t" "$d" || fail=$((fail + 1))
done
exit "$fail"
