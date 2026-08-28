#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1102 -- eventlog cap: with eventlog.max_bytes set tiny in
# shirudo.conf, a load refuses with category eventlog_full at pre-flight,
# before the .upatch is even opened (so a nonexistent path still trips
# it). No BPF_PROG_LOAD, no chain extend, no append. Non-destructive.

cd "$(dirname "$0")"
. ./integration-lib.sh
target_guard

BOGUS="/tmp/shirudo-nonexistent-$$.upatch"

CONF=/etc/shirudo/shirudo.conf
SAVED=$(mktemp)
if [ -e "$CONF" ]; then HAD=yes; cp "$CONF" "$SAVED"; else HAD=no; fi
cleanup() {
	if [ "$HAD" = yes ]; then cp "$SAVED" "$CONF"; else rm -f "$CONF"; fi
	rm -f "$SAVED"
}
trap cleanup EXIT
mkdir -p /etc/shirudo
printf 'eventlog.max_bytes = 100\n' > "$CONF"

test_expect_success 'tiny eventlog cap -> category eventlog_full' '
	cat=$($SHIRUDO_BIN upatch load "$BOGUS" --no-precheck --report=- \
	      2>/dev/null | report_field category) &&
	[ "$cat" = "eventlog_full" ]
'

test_done
