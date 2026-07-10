#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0008 -- paged serializer and detailed map JSON output shape.

cd "$(dirname "$0")"
. ./test-lib.sh

H=helper/test-upatch-serializer-pages

[ -x "$H" ] || test_skip_all "serializer pages helper not built"

test_expect_success 'paged serializer JSON exposes pages and one data object' '
	"$H"
'

test_done
