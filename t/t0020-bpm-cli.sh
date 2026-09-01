#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ./test-lib.sh

SHIRUDO=../shirudo
BPM_SOURCE_HELPER=helper/test-bpm-source

test_expect_success 'bpm exposes native subcommands to completion' '
	out=$($SHIRUDO bpm --list-cmds) &&
	echo "$out" | grep -qx config &&
	echo "$out" | grep -qx repo &&
	echo "$out" | grep -qx key &&
	echo "$out" | grep -qx install &&
	echo "$out" | grep -qx upgrade
'

test_expect_success 'bpm help describes the target package workflow' '
	out=$($SHIRUDO bpm --help 2>&1) &&
	echo "$out" | grep -q "signed target-local BPM packages" &&
	echo "$out" | grep -q "refresh signed repository indexes"
'

test_expect_success 'bpm rejects an unknown subcommand' '
	! $SHIRUDO bpm not-a-command >/dev/null 2>&1
'

test_expect_success 'bpm parses spaced repository source assignments' '
	out=$($BPM_SOURCE_HELPER) &&
	echo "$out" | grep -qx "endpoint=oci://registry.test:5443" &&
	echo "$out" | grep -qx "key_file=/etc/shirudo/bpm/keys/jbrust.pem"
'

test_done
