#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0001 -- util/json schema parser: extraction, skipping, bounds,
# and robustness against malformed input.

cd "$(dirname "$0")"
. ./test-lib.sh

H=helper/test-json-parser

# EINVAL=22, E2BIG=7, ENOSPC=28 on Linux.

test_expect_success 'valid event: extracts digest, skips nested set[]' '
	out=$(printf "%s" "{\"schema\":1,\"digest\":\"abcdef\",\"type\":\"init\",\"set\":[{\"name\":\"x\"}]}" | ./$H) &&
	echo "$out" | grep -qx "rc=0" &&
	echo "$out" | grep -q "digest=abcdef" &&
	echo "$out" | grep -q "type=init" &&
	echo "$out" | grep -q "schema=1"
'

test_expect_success 'unknown keys and nested objects are skipped' '
	printf "%s" "{\"a\":{\"b\":[1,2,3]},\"digest\":\"ff\",\"c\":true}" | ./$H | grep -q "digest=ff"
'

test_expect_success 'unterminated string -> EINVAL' '
	printf "%s" "{\"digest\":\"abc" | ./$H | grep -qx "rc=-22"
'

test_expect_success 'trailing garbage -> EINVAL' '
	printf "%s" "{\"digest\":\"a\"}xyz" | ./$H | grep -qx "rc=-22"
'

test_expect_success 'type mismatch (digest as number) -> EINVAL' '
	printf "%s" "{\"digest\":123}" | ./$H | grep -qx "rc=-22"
'

test_expect_success 'over-long string value -> ENOSPC' '
	big=$(printf "%0200d" 0) &&
	printf "%s" "{\"digest\":\"$big\"}" | ./$H | grep -qx "rc=-28"
'

test_expect_success 'over-deep nesting -> E2BIG (no crash)' '
	doc=$(python3 -c "print(\"{\\\"a\\\":\"*40 + \"1\" + \"}\"*40, end=\"\")") &&
	printf "%s" "$doc" | ./$H | grep -qx "rc=-7"
'

test_expect_success 'non-JSON garbage -> clean error, no crash' '
	head -c 4096 /dev/urandom | ./$H >/dev/null 2>&1; rc=$?; [ "$rc" -ne 139 ]
'

test_expect_success 'empty object parses, no fields seen' '
	printf "%s" "{}" | ./$H | grep -qx "rc=0"
'

test_done
