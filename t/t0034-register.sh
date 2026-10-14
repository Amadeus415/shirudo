#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0034 -- the measurement register against a software TPM: binding,
# the anchor, extends, the recreate and replay attacks, a reset, and
# the evidence a verifier accepts or refuses. Needs the libtpms-backed
# helper/tpmsim-cmd; skipped where libtpms is not installed.

cd "$(dirname "$0")"
. ./test-lib.sh

R=helper/test-register
SIM=$(pwd)/helper/tpmsim-cmd
S=../shirudo
[ -x "$SIM" ] || test_skip_all "helper/tpmsim-cmd not built (libtpms-dev missing)"
[ -x "$R" ] || test_skip_all "helper/test-register not built"
[ -x "$S" ] || test_skip_all "shirudo not built"
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
mkdir -p "$WORK/keys"
head -c 700 /dev/urandom >"$WORK/keys/cert.der"
export SHIRUDO_TPM_TCTI="cmd:$SIM $WORK/tpm"
export SHIRUDO_EVENTLOG_PATH="$WORK/eventlog"
export SHIRUDO_KEYS_DIR="$WORK/keys"

py() { python3 -c "$1"; }
sha() { py "import hashlib; print(hashlib.sha256(bytes.fromhex(\"$1\")).hexdigest())"; }
field() { sed -n "s/^$1=//p"; }
Z=0000000000000000000000000000000000000000000000000000000000000000
PAYLOAD=$(py "print(\"ab\"*32)")

test_expect_success 'init binds the register to PCR 15 and anchors its name' '
	init=$($S attest predict --cert="$WORK/keys/cert.der" | sed -n "s/^init_event: //p") &&
	out=$(./$R init "$init") &&
	echo "$out" | grep -qx "rc=0" &&
	echo "$out" | grep -qx "reused=0" &&
	echo "$out" | grep -qx "pcr_before=$Z" &&
	name=$(echo "$out" | field name) &&
	[ "$(echo "$out" | field anchor)" = "nvpcr-init:shirudo:0x1818e00:$name" ] &&
	anchor_digest=$(py "import hashlib; print(hashlib.sha256(b\"nvpcr-init:shirudo:0x1818e00:$name\").hexdigest())") &&
	[ "$(./$R pcr 15)" = "$(sha "$Z$anchor_digest")" ] &&
	[ "$(echo "$out" | field value)" = "$(sha "$Z$init")" ] &&
	echo "$init" >"$WORK/init" && echo "$name" >"$WORK/name"
'

test_expect_success 'status reports the register bound, logged and anchored' '
	./$R status | grep -qx "tpm=1 defined=1 written=1 logged=1 anchored=1" &&
	$S status --json >"$WORK/status.json" &&
	python3 - "$WORK/status.json" <<"PY"
import json, sys
t = json.load(open(sys.argv[1]))["tpm"]
assert t["register_bound"] and t["register_anchored"], t
assert t["chain_matches_eventlog"] is True, t
assert t["pcr"] == 15, t
PY
'

test_expect_success 'a re-run of init reuses the register and adds no event' '
	out=$(./$R init "$(cat "$WORK/init")") &&
	echo "$out" | grep -qx "reused=1" &&
	[ "$(wc -l <"$WORK/eventlog")" = 1 ]
'

test_expect_success 'a load extends through the written branch and replays' '
	before=$(./$R read | field value) &&
	event=$(py "import hashlib; print(hashlib.sha256(b\"shirudo-upatch\\0\" + bytes.fromhex(\"$PAYLOAD\") + b\"foo\").hexdigest())") &&
	out=$(./$R load foo "$PAYLOAD") &&
	echo "$out" | grep -qx "rc=0" &&
	[ "$(echo "$out" | field value)" = "$(sha "$before$event")" ] &&
	./$R status | grep -qx "tpm=1 defined=1 written=1 logged=1 anchored=1"
'

test_expect_success 'the init branch cannot be satisfied after the anchor' '
	./$R first-write "$PAYLOAD" | grep -qx "rc=-13"
'

test_expect_success 'evidence verifies against the pinned key and predicted state' '
	nonce=0102030405060708090a0b0c0d0e0f10 &&
	./$R evidence $nonce >"$WORK/evidence.json" &&
	ak=$(py "import json; print(json.load(open(\"$WORK/evidence.json\"))[\"ak\"][\"name\"])") &&
	echo "$ak" >"$WORK/ak" &&
	value=$(./$R read | field value) &&
	$S attest verify --evidence="$WORK/evidence.json" --nonce=$nonce \
		--ak-name="$ak" --expect-chain="$value" --strict-anchor \
		>"$WORK/report" &&
	grep -qx "verdict: ok" "$WORK/report" &&
	! grep -q "^FAIL" "$WORK/report"
'

test_expect_success 'verify computes the state from cert and set, flags runtime events' '
	nonce=0102030405060708090a0b0c0d0e0f10 &&
	$S attest verify --evidence="$WORK/evidence.json" --nonce=$nonce \
		--ak-name="$(cat "$WORK/ak")" --cert="$WORK/keys/cert.der" \
		>"$WORK/report3"; rc=$? &&
	[ "$rc" = 1 ] &&
	grep -q "^ok:   state: init event covers" "$WORK/report3" &&
	grep -q "^FAIL: state: 1 event after boot" "$WORK/report3" &&
	$S attest verify --evidence="$WORK/evidence.json" --nonce=$nonce \
		--ak-name="$(cat "$WORK/ak")" --cert="$WORK/keys/cert.der" \
		--allow-runtime-events | grep -qx "verdict: ok"
'

test_expect_success 'predict reproduces the register after the load' '
	value=$(./$R read | field value) &&
	$S attest predict --cert="$WORK/keys/cert.der" --event="load:foo=$PAYLOAD" |
		grep -qx "register_after_events: $value"
'

test_expect_success 'a wrong nonce, a wrong key name or a tampered value fails' '
	nonce=0102030405060708090a0b0c0d0e0f10 &&
	value=$(./$R read | field value) &&
	ak=$(cat "$WORK/ak") &&
	! $S attest verify --evidence="$WORK/evidence.json" --nonce=ffff \
		--ak-name="$ak" --expect-chain="$value" >/dev/null &&
	! $S attest verify --evidence="$WORK/evidence.json" --nonce=$nonce \
		--ak-name="000b$(py "print(\"00\"*32)")" --expect-chain="$value" >/dev/null &&
	sed "s/\"value\":\"$value\"/\"value\":\"$Z\"/" "$WORK/evidence.json" >"$WORK/tampered.json" &&
	! $S attest verify --evidence="$WORK/tampered.json" --nonce=$nonce \
		--ak-name="$ak" --expect-chain="$value" >"$WORK/report4" &&
	grep -q "^FAIL: register: certified contents" "$WORK/report4"
'

test_expect_success 'a recreated index is unwritable and no longer anchored' '
	out=$(./$R recreate) &&
	echo "$out" | grep -qx "rc=0" &&
	echo "$out" | grep -qx "written=0" &&
	[ "$(echo "$out" | field name)" != "$(cat "$WORK/name")" ] &&
	./$R extend-raw "$PAYLOAD" | grep -qx "rc=-19" &&
	./$R first-write "$PAYLOAD" | grep -qx "rc=-13" &&
	./$R status | grep -qx "tpm=1 defined=1 written=0 logged=1 anchored=0"
'

test_expect_success 'init refuses a second binding before the next TPM reset' '
	./$R init "$(cat "$WORK/init")" | grep -qx "rc=-17" &&
	[ "$(wc -l <"$WORK/eventlog")" = 2 ] &&
	./$R status | grep -qx "rebound=0"
'

test_expect_success 'a TPM reset clears the register; init binds it again' '
	rm -f "$WORK/tpm/volatile" &&
	./$R read | grep -qx "rc=-19" &&
	out=$(./$R init "$(cat "$WORK/init")") &&
	echo "$out" | grep -qx "rc=0" &&
	echo "$out" | grep -qx "reused=0" &&
	[ "$(echo "$out" | field name)" = "$(cat "$WORK/name")" ] &&
	[ "$(echo "$out" | field value)" = "$(sha "$Z$(cat "$WORK/init")")" ] &&
	./$R status | grep -qx "tpm=1 defined=1 written=1 logged=1 anchored=1" &&
	./$R status | grep -qx "rebound=0" &&
	python3 - "$WORK/eventlog" <<"PY"
import json, sys
inits = [json.loads(l) for l in open(sys.argv[1]) if json.loads(l)["type"] == "init"]
assert len(inits) == 2, inits
assert inits[0]["tpm_reset_count"] != inits[1]["tpm_reset_count"], inits
PY
'

test_expect_success 'after the reset the evidence matches the set at boot' '
	nonce=cafe &&
	./$R evidence $nonce >"$WORK/evidence2.json" &&
	$S attest verify --evidence="$WORK/evidence2.json" --nonce=$nonce \
		--ak-name="$(cat "$WORK/ak")" --cert="$WORK/keys/cert.der" \
		--strict-anchor >"$WORK/report6" &&
	grep -qx "verdict: ok" "$WORK/report6" &&
	grep -q "^ok:   eventlog: one init record for this TPM reset (2 this boot)" "$WORK/report6" &&
	grep -q "^ok:   register: init record is of the TPM" "$WORK/report6" &&
	grep -q "^ok:   quote and certification are of one TPM reset" "$WORK/report6"
'

test_expect_success 'a second init record for one TPM reset fails status and verify' '
	nonce=f00d &&
	cp "$WORK/eventlog" "$WORK/eventlog.orig" &&
	tail -n 1 "$WORK/eventlog" >>"$WORK/eventlog" &&
	./$R status | grep -qx "rebound=1" &&
	$S status --json >"$WORK/status2.json" &&
	python3 - "$WORK/status2.json" <<"PY"
import json, sys
t = json.load(open(sys.argv[1]))["tpm"]
assert t["register_rebound"] is True, t
assert t["init_records"] == 3, t
assert t["chain_matches_eventlog"] is False, t
PY
	./$R evidence $nonce >"$WORK/evidence3.json" &&
	$S attest verify --evidence="$WORK/evidence3.json" --nonce=$nonce \
		--ak-name="$(cat "$WORK/ak")" --cert="$WORK/keys/cert.der" \
		>"$WORK/report7"; rc=$? &&
	[ "$rc" = 1 ] &&
	grep -q "^FAIL: eventlog: one init record for this TPM reset" "$WORK/report7" &&
	cp "$WORK/eventlog.orig" "$WORK/eventlog" &&
	./$R status | grep -qx "rebound=0"
'

test_expect_success 'an init record of another TPM reset fails verification' '
	nonce=cafe &&
	sed "s/\"tpm_reset_count\":[0-9]*/\"tpm_reset_count\":4000000000/g" \
		"$WORK/evidence2.json" >"$WORK/evidence4.json" &&
	$S attest verify --evidence="$WORK/evidence4.json" --nonce=$nonce \
		--ak-name="$(cat "$WORK/ak")" --cert="$WORK/keys/cert.der" \
		>"$WORK/report8"; rc=$? &&
	[ "$rc" = 1 ] &&
	grep -q "^FAIL: register: init record is of the TPM" "$WORK/report8"
'

test_done
