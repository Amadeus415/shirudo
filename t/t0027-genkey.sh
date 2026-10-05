#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ./test-lib.sh

SHIRUDO=${SHIRUDO_GENKEY_TEST_BINARY:-../shirudo}
if ! command -v openssl >/dev/null 2>&1 || [ ! -x "$SHIRUDO" ]; then
	test_skip_all 'shirudo and openssl are needed to test generated certificates'
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/shirudo-genkey.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

test_expect_success 'genkey creates a certificate with Authority Key Identifier' '
	"$SHIRUDO" genkey --keys-dir "$tmp/keys" &&
	openssl x509 -inform DER -in "$tmp/keys/cert.der" \
		-noout -ext authorityKeyIdentifier | grep -Eq "([0-9A-F]{2}:){19}[0-9A-F]{2}"
'

test_expect_success 'self-signed certificate authority and subject key identifiers match' '
	subject=$(openssl x509 -inform DER -in "$tmp/keys/cert.der" \
		-noout -ext subjectKeyIdentifier | tail -1 | tr -d "[:space:]") &&
	authority=$(openssl x509 -inform DER -in "$tmp/keys/cert.der" \
		-noout -ext authorityKeyIdentifier | tail -1 | tr -d "[:space:]") &&
	test -n "$subject" && test "$subject" = "$authority"
'

test_done
