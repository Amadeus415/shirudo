#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3111 -- a struct_ops upatch registers a TCP congestion control that a
# connection then runs, and its unload takes the algorithm out again.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-struct-ops
CC=shirudo_test_cc
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PIN="/run/shirudo/bpffs/upatches/$NAME/link"
AVAILABLE=/proc/sys/net/ipv4/tcp_available_congestion_control
WORK=$(mktemp -d)
trap 'if [ -e "$PIN" ]; then "$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 || true; fi; rm -rf "$WORK"' EXIT

for fixture in "$LOAD" "$UNLOAD"; do
	[ -s "$fixture" ] || test_skip_all "missing struct_ops fixture: $fixture"
done

# A loopback connection with the algorithm; exits 2 when it is unknown.
connect_with_cc() {
	python3 - "$CC" <<'PY'
import errno
import socket
import sys

cc = sys.argv[1].encode()
srv = socket.create_server(("127.0.0.1", 0))
cli = socket.socket()
try:
    cli.setsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, cc)
except OSError as e:
    sys.exit(2 if e.errno == errno.ENOENT else 1)
cli.connect(srv.getsockname())
conn, _ = srv.accept()
cli.sendall(b"x" * 65536)
got = 0
while got < 65536:
    got += len(conn.recv(65536))
used = cli.getsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, 16)
sys.exit(0 if used.rstrip(b"\0") == cc else 1)
PY
}

test_expect_success 'the algorithm is unknown before the load' '
	! grep -qw "$CC" "$AVAILABLE" &&
	{ connect_with_cc; [ $? -eq 2 ]; }
'

test_expect_success 'the load links and pins the struct_ops map' '
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null &&
	[ -e "$PIN" ] &&
	grep -qw "$CC" "$AVAILABLE"
'

test_expect_success 'status reports the struct the map fills' '
	"$SHIRUDO_BIN" upatch get "$NAME" --json >"$WORK/get.json" &&
	python3 - "$WORK/get.json" <<'PY'
import json
import sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
assert doc["upatch"]["location"] == "struct_ops/tcp_congestion_ops"
assert not any(m["name"] == "shirudo_test_cc" for m in doc["upatch"]["maps"])
PY
'

test_expect_success 'a connection runs the signed algorithm' '
	connect_with_cc &&
	"$SHIRUDO_BIN" upatch get "$NAME" --json >"$WORK/after.json" &&
	python3 - "$WORK/after.json" <<'PY'
import json
import sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
inits = next(m for m in doc["upatch"]["maps"] if m["name"] == "inits")
assert int(inits["entries"][0]["value"], 0) >= 1
PY
'

test_expect_success 'the unload takes the algorithm out' '
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null &&
	[ ! -e "$PIN" ] &&
	! grep -qw "$CC" "$AVAILABLE" &&
	{ connect_with_cc; [ $? -eq 2 ]; }
'

test_done
