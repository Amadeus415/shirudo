#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ./test-lib.sh

BUILDER=../contrib/build-kernel-package.sh

check_builtin_options() {
	for symbol in "$@"; do
		grep -qx "${symbol}=y" "$BUILDER" &&
		grep -Eq "^[[:space:]]*require_config ${symbol} y$" \
			"$BUILDER" || return 1
	done
}

test_expect_success 'slim kernel enables and validates NitroTPM CRB' '
	check_builtin_options CONFIG_TCG_CRB
'

test_expect_success 'slim kernel enables and validates EC2 network and storage' '
	check_builtin_options CONFIG_NET_VENDOR_AMAZON CONFIG_ENA_ETHERNET \
		CONFIG_BLK_DEV_NVME
'

test_expect_success 'slim kernel enables and validates EFI and initramfs boot' '
	check_builtin_options CONFIG_EFI CONFIG_EFI_STUB \
		CONFIG_BLK_DEV_INITRD CONFIG_RD_GZIP CONFIG_RD_XZ CONFIG_RD_ZSTD
'

test_expect_success 'slim kernel enables and validates snap-packaged SSM support' '
	check_builtin_options CONFIG_BLK_DEV_LOOP CONFIG_MISC_FILESYSTEMS \
		CONFIG_SQUASHFS CONFIG_SQUASHFS_ZLIB CONFIG_SQUASHFS_XZ \
		CONFIG_SQUASHFS_ZSTD
'

test_done
