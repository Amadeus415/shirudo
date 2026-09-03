#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ./test-lib.sh

TARGET=../shirudo-target
OPERATOR=../shirudo

if ! command -v readelf >/dev/null 2>&1 || [ ! -x "$TARGET" ]; then
	test_skip_all 'target static profile has not been built'
fi

test_expect_success 'target binary has no shared TLS closure' '
	test -x "$TARGET" &&
	! readelf -d "$TARGET" | grep -Eq "lib(curl|ssl|crypto|mbedtls|mbedx509|mbedcrypto)\\.so"
'

test_expect_success 'target binary has no OpenSSL or mbedTLS unresolved symbols' '
	! nm -u "$TARGET" | grep -Eq "(^| )(SSL|OPENSSL|EVP_|X509|CMS_|mbedtls_)"
'

test_expect_success 'operator binary retains dynamic TLS libraries' '
	test -x "$OPERATOR" &&
	readelf -d "$OPERATOR" | grep -q "libcurl.so" &&
	readelf -d "$OPERATOR" | grep -q "libssl.so" &&
	readelf -d "$OPERATOR" | grep -q "libcrypto.so"
'

test_done
