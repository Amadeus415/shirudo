#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1101 -- filesystem-sealing LSM (bpf/seal.c): a non-shirudo process
# cannot modify a labelled file under /var/lib/shirudo, even as root.
# Non-destructive: the seal denies the tamper, so the file survives.

cd "$(dirname "$0")"
. ./integration-lib.sh
integration_guard

CERT=/var/lib/shirudo/keys/cert.der
[ -e "$CERT" ] || test_skip_all "no cert at $CERT"
before=$(sha256sum "$CERT" | cut -d' ' -f1)

test_expect_success 'seal denies a non-shirudo write to a labelled file' '
	! dd if=/dev/zero of=/var/lib/shirudo/keys/cert.der bs=1 count=1 \
	     conv=notrunc 2>/dev/null &&
	[ "$(sha256sum /var/lib/shirudo/keys/cert.der | cut -d" " -f1)" = "$before" ]
'

test_expect_success 'seal denies a non-shirudo setxattr on a labelled file' '
	! python3 -c "import os,sys; os.setxattr(sys.argv[1], \"user.sealprobe\", b\"x\")" \
	    /var/lib/shirudo/keys/cert.der 2>/dev/null
'

test_done
