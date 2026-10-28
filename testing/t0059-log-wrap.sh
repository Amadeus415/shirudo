#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0059 -- util/log.c wraps a long message for a terminal: at a word,
# at a clause break when one fills most of the line, under a hanging
# indent, never inside a word, and the words read back unchanged. At
# width 0, what anything but a terminal gets, a message is one line.

cd "$(dirname "$0")"
. ./test-lib.sh

H=./helper/test-log
[ -x "$H" ] || test_skip_all "test-log not built"
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

TEXT="shirudo does not trust this boot's upatch set: keep the eventlog and journal as evidence and handle it as an incident; an upatch load or unload that was cut short leaves the same state"

test_expect_success 'width 0 keeps one line' '
	[ "$("$H" 0 "hint: " 6 "$TEXT")" = "hint: $TEXT" ]
'

test_expect_success 'a message that fits stays one line' '
	[ "$("$H" 80 "hint: " 6 "short text")" = "hint: short text" ]
'

test_expect_success 'a long message wraps under the indent and reads back unchanged' '
	"$H" 80 "hint: " 6 "$TEXT" >"$WORK/wrapped" &&
	python3 - "$WORK/wrapped" "$TEXT" <<"PY"
import sys
lines = open(sys.argv[1]).read().splitlines()
assert len(lines) > 1, lines
assert all(len(line) <= 80 for line in lines), lines
assert lines[0].startswith("hint: ")
assert all(line.startswith(" " * 6) and line[6] != " " for line in lines[1:]), lines
words = " ".join([lines[0][6:]] + [line[6:] for line in lines[1:]])
assert words == sys.argv[2], words
PY
'

test_expect_success 'a clause break that fills most of the line is preferred' '
	"$H" 60 "" 2 "first clause of the message runs on: then a second clause that is long enough" \
		>"$WORK/clause" &&
	head -1 "$WORK/clause" | grep -qx "first clause of the message runs on:"
'

test_expect_success 'a word longer than the line is not cut' '
	long=/var/lib/shirudo/$(printf "%0100d" 0) &&
	"$H" 60 "" 2 "cannot open $long: No such file or directory" >"$WORK/word" &&
	[ "$(sed -n 1p "$WORK/word")" = "cannot open" ] &&
	[ "$(sed -n 2p "$WORK/word")" = "  $long:" ] &&
	[ "$(sed -n 3p "$WORK/word")" = "  No such file or directory" ]
'

test_done
