#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1118 -- pull a signed BPM tree from the fixture OCI registry, select one
# operation, skip another by selector, and fetch only the selected upatch.

cd "$(dirname "$0")"
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
REGISTRY="$FIXTURES/tree-oci"
MATCH_PIN=/var/lib/shirudo/bpffs/upatches/shirudo-test-tree-match/link
MATCH_CACHE=/var/lib/shirudo/bpm/upatch-tree/artifacts
TREE_CONFIG=/etc/shirudo/bpm/upatch-tree.conf
LABELS=/etc/shirudo/node.labels
WORK=$(mktemp -d)
SERVER_PID=

for fixture in \
	"$REGISTRY/shirudo/upatch-tree/manifests/stable" \
	"$FIXTURES/shirudo-test-tree-match.upatch" \
	"$FIXTURES/shirudo-test-tree-skip.upatch" \
	"$FIXTURES/cert.der" \
	"./helper/test-oci-registry.py"
do
	[ -s "$fixture" ] || test_skip_all "missing tree fixture: $fixture"
done

[ ! -e "$TREE_CONFIG" ] || test_skip_all "tree config already exists"
[ ! -e /var/lib/shirudo/bpm/upatch-tree ] ||
	test_skip_all "tree state already exists"
[ ! -e "$LABELS" ] || test_skip_all "node labels already exist"

cleanup()
{
	if [ -n "$SERVER_PID" ]; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	if [ -e "$MATCH_PIN" ]; then
		"$SHIRUDO_BIN" upatch unload \
			"$FIXTURES/shirudo-test-tree-match.unload.upatch" \
			--no-precheck >/dev/null 2>&1 || true
	fi
	rm -f "$TREE_CONFIG" "$LABELS"
	rm -rf /var/lib/shirudo/bpm/upatch-tree
	rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p /etc/shirudo/bpm
printf 'env=tree-test\n' >"$LABELS"
printf '%s\n' \
	'endpoint = oci://127.0.0.1:5443/shirudo/upatch-tree' \
	'reference = stable' >"$TREE_CONFIG"

python3 ./helper/test-oci-registry.py \
	--root "$REGISTRY" --port 5443 --log "$WORK/requests.log" \
	--ready-file "$WORK/ready" &
SERVER_PID=$!
for _ in 1 2 3 4 5; do
	[ -e "$WORK/ready" ] && break
	sleep 1
done
[ -e "$WORK/ready" ] || exit 1

if ! BPM_OCI_SCHEME=http "$SHIRUDO_BIN" bpm tree sync \
	--report "$WORK/report.json" >/dev/null; then
	cat "$WORK/requests.log" >&2
	exit 1
fi

[ "$(report_field selected <"$WORK/report.json")" = 1 ]
[ "$(report_field skipped <"$WORK/report.json")" = 1 ]
[ "$(report_field applied <"$WORK/report.json")" = 1 ]
[ "$(report_field last_seq <"$WORK/report.json")" = 2 ]
[ -e "$MATCH_PIN" ]
[ "$(find "$MATCH_CACHE" -name '*.upatch' -type f | wc -l)" = 1 ]
grep -q '/v2/shirudo/upatch-tree/manifests/stable' "$WORK/requests.log"
grep -q '/v2/shirudo/tree-match/manifests/sha256:' "$WORK/requests.log"
grep -q '/v2/shirudo/tree-match/blobs/sha256:' "$WORK/requests.log"
! grep -q '/v2/shirudo/tree-skip/' "$WORK/requests.log"

test_done
