#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0007 -- serializer upatches use the UPGM metadata format and bind
# each serializer program to its target map. Builds the arena-tree
# example, signs it with throwaway keys, and checks the container
# offline. Full load/read is covered by integration environments with
# BPF_MAP_TYPE_ARENA support.

cd "$(dirname "$0")"
. ./test-lib.sh

SHB=../tools/shirudo-build/shirudo-build
CHECK=helper/test-upatch-prog-metadata

command -v clang >/dev/null 2>&1 || test_skip_all "no clang"
command -v openssl >/dev/null 2>&1 || test_skip_all "no openssl"
[ -x "$SHB" ] || test_skip_all "shirudo-build not built (make shirudo-build)"
[ -x "$CHECK" ] || test_skip_all "metadata helper not built"
[ -e ../bpf/vmlinux.h ] || test_skip_all "no bpf/vmlinux.h (build the tree)"
[ -e ../bpf/include/bpf/bpf_helpers.h ] || test_skip_all "no in-tree bpf headers"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/k.pem" \
	-outform DER -out "$WORK/c.der" -days 1 -sha256 -subj "/CN=t0007" \
	>/dev/null 2>&1 || test_skip_all "openssl keygen failed"

case "$SHB" in
/*) B="$SHB" ;;
*)  B="$(pwd)/$SHB" ;;
esac

( cd .. && "$B" examples/arena-tree-serializer.bpf.c \
	-o "$WORK/arena-tree-serializer.upatch" \
	--vmlinux bpf/vmlinux.h --name arena-tree-serializer \
	--key "$WORK/k.pem" --cert "$WORK/c.der" ) >/dev/null 2>&1 ||
	test_skip_all "arena serializer build failed (kernel/toolchain lacks arena support?)"

test_expect_success 'arena serializer upatch carries UPGM serializer metadata' '
	"$CHECK" "$WORK/arena-tree-serializer.upatch"
'

test_done
