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
	echo "$out" | grep -qx pull &&
	echo "$out" | grep -qx install &&
	echo "$out" | grep -qx upgrade
'

test_expect_success 'bpm help describes the target package workflow' '
	out=$($SHIRUDO bpm --help 2>&1) &&
	echo "$out" | grep -q "signed target-local BPM packages" &&
	echo "$out" | grep -q "refresh signed repository indexes" &&
	echo "$out" | grep -q "download an OCI package"
'

test_expect_success 'target bpm does not expose operator-only commands' '
	! $SHIRUDO bpm --list-cmds | grep -qx push &&
	! $SHIRUDO bpm --list-cmds | grep -qx build &&
	! $SHIRUDO bpm push >/dev/null 2>&1 &&
	! $SHIRUDO bpm build >/dev/null 2>&1
'

test_expect_success 'bpm pull validates package references before network access' '
	! $SHIRUDO bpm pull ./package.bee >/dev/null 2>&1 &&
	! $SHIRUDO bpm pull oci://registry.example/repository >/dev/null 2>&1
'

test_expect_success 'bpm pull without a reference prints OCI usage' '
	if out=$($SHIRUDO bpm pull 2>&1); then
		false
	else
		echo "$out" | grep -q "The package reference must start with oci://" &&
		echo "$out" | grep -q "oci://quay.io/namespace/package:tag"
	fi
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
