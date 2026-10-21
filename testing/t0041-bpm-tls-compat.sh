#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ./test-lib.sh

CLIENT=${SHIRUDO_TEST_BPM_TLS_CLIENT:-./helper/test-bpm-tls}
[ -x "$CLIENT" ] || test_skip_all "test-bpm-tls not built (make test-helpers)"
command -v openssl >/dev/null 2>&1 || test_skip_all "no openssl"
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

WORK=$(mktemp -d)
PIDS=
cleanup() {
	for pid in $PIDS; do
		kill "$pid" 2>/dev/null || :
		wait "$pid" 2>/dev/null || :
	done
	rm -rf "$WORK"
}
trap cleanup EXIT HUP INT TERM

make_cert() {
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		-subj /CN=localhost -addext "subjectAltName=$2" -days 2 \
		-keyout "$WORK/$1.key" -out "$WORK/$1.pem" >/dev/null 2>&1
}
make_cert server 'IP:127.0.0.1,DNS:localhost' || test_skip_all "cannot create test certificate"
make_cert wrong 'DNS:wrong.example' || test_skip_all "cannot create hostname test certificate"

start_server() {
	name=$1
	cert=$2
	shift 2
	python3 ./helper/test-bpm-tls-server.py --cert "$WORK/$cert.pem" \
		--key "$WORK/$cert.key" --ready-file "$WORK/$name.port" "$@" \
		>"$WORK/$name.log" 2>&1 &
	PIDS="$PIDS $!"
	i=0
	while [ ! -s "$WORK/$name.port" ]; do
		i=$((i + 1))
		if [ "$i" -ge 100 ]; then
			cat "$WORK/$name.log" >&2
			return 1
		fi
		sleep .05
	done
}
start_server tls13 server || test_skip_all "TLS 1.3 server unavailable"
start_server tls12 server --tls12 || test_skip_all "TLS 1.2 server unavailable"
start_server wrong wrong || test_skip_all "hostname test server unavailable"
port=$(cat "$WORK/tls13.port")
port12=$(cat "$WORK/tls12.port")
portwrong=$(cat "$WORK/wrong.port")

export BPM_OCI_SCHEME=https BPM_OCI_CA_FILE="$WORK/server.pem"
export REGISTRY_AUTH_FILE="$WORK/no-auth.json" NO_PROXY='*' no_proxy='*'
unset BPM_OCI_USERNAME BPM_OCI_PASSWORD BPM_OCI_BEARER_TOKEN BPM_OCI_TLS_COMPAT

fetch() {
	"$CLIENT" "$@" >"$WORK/client.out" 2>"$WORK/client.err"
}

test_expect_success 'classical-only TLS 1.3 is rejected by default with a protocol error' '
	! fetch "oci://127.0.0.1:$port" /ok &&
	grep -qi "protocol error" "$WORK/client.err"
'
test_expect_success 'an explicitly listed host and port accepts classical TLS 1.3' '
	BPM_OCI_TLS_COMPAT="127.0.0.1:$port" fetch "oci://127.0.0.1:$port" /ok
'
test_expect_success 'a bare host does not match a nonstandard port' '
	! BPM_OCI_TLS_COMPAT=127.0.0.1 fetch "oci://127.0.0.1:$port" /ok
'
test_expect_success 'allowlists match exact hosts, not prefixes or wildcards' '
	! BPM_OCI_TLS_COMPAT="127.0.0.1.evil:$port,*:$port" \
		fetch "oci://127.0.0.1:$port" /ok
'
test_expect_success 'allowlists accept multiple case-insensitive hosts and whitespace' '
	BPM_OCI_TLS_COMPAT="other.example, LOCALHOST:$port ," \
		fetch "oci://localhost:$port" /ok
'
test_expect_success 'TLS 1.2 stays rejected in compatibility mode' '
	! BPM_OCI_TLS_COMPAT="127.0.0.1:$port12" fetch "oci://127.0.0.1:$port12" /ok &&
	grep -qi "protocol error" "$WORK/client.err"
'
test_expect_success 'compatibility does not disable certificate verification' '
	(unset BPM_OCI_CA_FILE
	 ! BPM_OCI_TLS_COMPAT="127.0.0.1:$port" fetch "oci://127.0.0.1:$port" /ok &&
	 grep -qi "permission denied" "$WORK/client.err")
'
test_expect_success 'compatibility does not disable hostname verification' '
	! BPM_OCI_CA_FILE="$WORK/wrong.pem" BPM_OCI_TLS_COMPAT="127.0.0.1:$portwrong" \
		fetch "oci://127.0.0.1:$portwrong" /ok &&
	grep -qi "permission denied" "$WORK/client.err"
'
test_expect_success 'redirect hosts do not inherit compatibility' '
	! BPM_OCI_TLS_COMPAT="127.0.0.1:$port" \
		fetch "oci://127.0.0.1:$port" /redirect "$WORK/download" &&
	grep -qi "protocol error" "$WORK/client.err"
'
test_expect_success 'redirects work when both authorities are explicitly listed' '
	BPM_OCI_TLS_COMPAT="127.0.0.1:$port,localhost:$port" \
		fetch "oci://127.0.0.1:$port" /redirect "$WORK/download" &&
	grep -qx ok "$WORK/download"
'
test_expect_success 'authentication hosts do not inherit compatibility' '
	! BPM_OCI_TLS_COMPAT="127.0.0.1:$port" fetch "oci://127.0.0.1:$port" /auth &&
	grep -qi "protocol error" "$WORK/client.err"
'
test_expect_success 'authentication works when both authorities are explicitly listed' '
	BPM_OCI_TLS_COMPAT="127.0.0.1:$port,localhost:$port" \
		fetch "oci://127.0.0.1:$port" /auth
'

test_done
