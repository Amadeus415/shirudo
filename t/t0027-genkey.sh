#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0027 -- `shirudo genkey`: the default key is ML-DSA-87 (FIPS 204),
# the certificate is self-signed with the same key and carries matching
# subject/authority key identifiers, and `--algorithm rsa-2048` is the
# classical opt-out. The ML-DSA cases need an OpenSSL (>= 3.5) that
# knows the algorithm; they are skipped on older toolchains while the
# RSA cases still run.

cd "$(dirname "$0")"
. ./test-lib.sh

SHIRUDO=${SHIRUDO_GENKEY_TEST_BINARY:-../shirudo}
if ! command -v openssl >/dev/null 2>&1 || [ ! -x "$SHIRUDO" ]; then
	test_skip_all 'shirudo and openssl are needed to test generated certificates'
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/shirudo-genkey.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

have_mldsa=0
if openssl list -public-key-algorithms 2>/dev/null | grep -qi 'ML-DSA'; then
	have_mldsa=1
fi

cert_text() {
	openssl x509 -inform DER -in "$1" -noout -text
}

if [ "$have_mldsa" = 1 ]; then
	test_expect_success 'genkey defaults to an ML-DSA-87 key and certificate' '
		"$SHIRUDO" genkey --keys-dir "$tmp/keys" >"$tmp/genkey.out" 2>&1 &&
		grep -q "ML-DSA-87" "$tmp/genkey.out" &&
		cert_text "$tmp/keys/cert.der" | grep -q "Public Key Algorithm: ML-DSA-87" &&
		cert_text "$tmp/keys/cert.der" | grep -q "Signature Algorithm: ML-DSA-87"
	'

	test_expect_success 'ML-DSA certificate carries an Authority Key Identifier' '
		openssl x509 -inform DER -in "$tmp/keys/cert.der" \
			-noout -ext authorityKeyIdentifier | grep -Eq "([0-9A-F]{2}:){19}[0-9A-F]{2}"
	'

	test_expect_success 'ML-DSA subject and authority key identifiers match' '
		subject=$(openssl x509 -inform DER -in "$tmp/keys/cert.der" \
			-noout -ext subjectKeyIdentifier | tail -1 | tr -d "[:space:]") &&
		authority=$(openssl x509 -inform DER -in "$tmp/keys/cert.der" \
			-noout -ext authorityKeyIdentifier | tail -1 | tr -d "[:space:]") &&
		test -n "$subject" && test "$subject" = "$authority"
	'

	test_expect_success 'ML-DSA private key is a PEM private key the toolchain can read' '
		openssl pkey -in "$tmp/keys/signing_key.pem" -noout -text 2>/dev/null |
			head -1 | grep -qi "ML-DSA-87"
	'

	test_expect_success 'keys reports ML-DSA-87 and a matching key/cert pair' '
		"$SHIRUDO" keys --keys-dir "$tmp/keys" >"$tmp/keys.out" 2>&1 &&
		grep -q "Public-key: *ML-DSA-87" "$tmp/keys.out" &&
		grep -q "Algorithm: *ML-DSA-87" "$tmp/keys.out" &&
		grep -q "signing key matches cert" "$tmp/keys.out"
	'

	test_expect_success 'genkey does not offer the smaller ML-DSA parameter sets' '
		! "$SHIRUDO" genkey --keys-dir "$tmp/keys65" --algorithm ml-dsa-65 >"$tmp/65.out" 2>&1 &&
		grep -q "unknown --algorithm" "$tmp/65.out" &&
		! "$SHIRUDO" genkey --keys-dir "$tmp/keys44" --algorithm ml-dsa-44 >/dev/null 2>&1 &&
		! test -e "$tmp/keys65/signing_key.pem"
	'
else
	test_expect_success 'genkey refuses the ML-DSA default with an upgrade hint on old OpenSSL' '
		! "$SHIRUDO" genkey --keys-dir "$tmp/keys" >"$tmp/genkey.out" 2>&1 &&
		grep -q "OpenSSL 3.5" "$tmp/genkey.out" &&
		! test -e "$tmp/keys/signing_key.pem"
	'
fi

test_expect_success 'genkey --algorithm rsa-2048 produces the classical opt-out' '
	"$SHIRUDO" genkey --keys-dir "$tmp/rsa" --algorithm rsa-2048 >"$tmp/rsa.out" 2>&1 &&
	grep -q "RSA-2048" "$tmp/rsa.out" &&
	cert_text "$tmp/rsa/cert.der" | grep -q "Public Key Algorithm: rsaEncryption" &&
	cert_text "$tmp/rsa/cert.der" | grep -q "Public-Key: (2048 bit)" &&
	cert_text "$tmp/rsa/cert.der" | grep -q "Signature Algorithm: sha256WithRSAEncryption"
'

test_expect_success 'RSA certificate authority and subject key identifiers match' '
	subject=$(openssl x509 -inform DER -in "$tmp/rsa/cert.der" \
		-noout -ext subjectKeyIdentifier | tail -1 | tr -d "[:space:]") &&
	authority=$(openssl x509 -inform DER -in "$tmp/rsa/cert.der" \
		-noout -ext authorityKeyIdentifier | tail -1 | tr -d "[:space:]") &&
	test -n "$subject" && test "$subject" = "$authority"
'

test_expect_success 'genkey rejects an unknown --algorithm' '
	! "$SHIRUDO" genkey --keys-dir "$tmp/bad" --algorithm ed25519 >"$tmp/bad.out" 2>&1 &&
	grep -q "unknown --algorithm" "$tmp/bad.out" &&
	! test -e "$tmp/bad/signing_key.pem"
'

test_expect_success 'genkey refuses to overwrite without --force' '
	! "$SHIRUDO" genkey --keys-dir "$tmp/rsa" --algorithm rsa-2048 >/dev/null 2>&1 &&
	"$SHIRUDO" genkey --keys-dir "$tmp/rsa" --algorithm rsa-2048 --force >/dev/null 2>&1
'

test_done
