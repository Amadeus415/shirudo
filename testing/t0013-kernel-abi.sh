#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ./test-lib.sh

H=helper/test-kernel-abi

test_expect_success 'signed-loader kernel ABI validator accepts only its required prefix' '
	"$H"
'

test_done
