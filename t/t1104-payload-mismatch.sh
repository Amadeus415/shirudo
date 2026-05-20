#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1104 -- unload payload_mismatch: a signed UNLOAD directive whose
# expected payload_sha256 does not match the loaded upatch's pin xattr
# is refused with category payload_mismatch and detaches nothing. The
# directive's signature still verifies (operator key); only the payload
# binding is wrong. Non-destructive: the pin survives.

cd "$(dirname "$0")"
. ./integration-lib.sh
integration_guard

UP=$(first_loaded_upatch)
[ -n "$UP" ] || test_skip_all "no upatch currently loaded to target"
[ -x "$SHIRUDO_BUILD_BIN" ] || test_skip_all "shirudo-build not found: $SHIRUDO_BUILD_BIN"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# A deliberately wrong expected payload (all 0xaa, definitely not the
# real digest). build --unload embeds the prebuilt unload template, so
# this needs no clang.
WRONG=$(python3 -c 'print("aa"*32)')
"$SHIRUDO_BUILD_BIN" --unload "$UP" --payload-sha256 "$WRONG" \
	-o "$WORK/unload.upatch" >/dev/null 2>&1 ||
	test_skip_all "build --unload failed"

test_expect_success 'wrong expected payload -> payload_mismatch, pin intact' '
	cat=$($SHIRUDO_BIN upatch unload "$WORK/unload.upatch" --no-precheck \
	      --report=- 2>/dev/null | report_field category) &&
	[ "$cat" = "payload_mismatch" ] &&
	[ -e "/var/lib/shirudo/bpffs/upatches/$UP/link" ]
'

test_done
