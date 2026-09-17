#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1119 -- apply an initial BPM tree publication, update it with one appended
# operation, and verify the second sync resumes at the stored cursor.

cd "$(dirname "$0")"
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
REGISTRY="$FIXTURES/tree-oci"
TREE_REPO="$REGISTRY/shirudo/upatch-tree-sequential"
MATCH_PIN=/var/lib/shirudo/bpffs/upatches/shirudo-test-tree-match/link
SKIP_PIN=/var/lib/shirudo/bpffs/upatches/shirudo-test-tree-skip/link
TREE_CONFIG=/etc/shirudo/bpm/upatch-tree.conf
LABELS=/etc/shirudo/node.labels
WORK=$(mktemp -d)
SERVER_PID=

for fixture in \
	"$TREE_REPO/manifests/stable" \
	"$TREE_REPO/manifests/updated" \
	"$FIXTURES/shirudo-test-tree-match.upatch" \
	"$FIXTURES/shirudo-test-tree-match.unload.upatch" \
	"$FIXTURES/shirudo-test-tree-skip.upatch" \
	"$FIXTURES/shirudo-test-tree-skip.unload.upatch" \
	"$FIXTURES/cert.der" \
	"./helper/test-oci-registry.py"
do
	[ -s "$fixture" ] || test_skip_all "missing sequential tree fixture: $fixture"
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
	if [ -e "$SKIP_PIN" ]; then
		"$SHIRUDO_BIN" upatch unload \
			"$FIXTURES/shirudo-test-tree-skip.unload.upatch" \
			--no-precheck >/dev/null 2>&1 || true
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
	'endpoint = oci://127.0.0.1:5443/shirudo/upatch-tree-sequential' \
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
	--report "$WORK/first-report.json" >/dev/null; then
	cat "$WORK/requests.log" >&2
	exit 1
fi

[ "$(report_field selected <"$WORK/first-report.json")" = 1 ]
[ "$(report_field skipped <"$WORK/first-report.json")" = 0 ]
[ "$(report_field applied <"$WORK/first-report.json")" = 1 ]
[ "$(report_field last_seq <"$WORK/first-report.json")" = 1 ]
[ -e "$MATCH_PIN" ]
[ ! -e "$SKIP_PIN" ]
grep -q '/v2/shirudo/tree-match/manifests/sha256:' "$WORK/requests.log"
grep -q '/v2/shirudo/tree-match/blobs/sha256:' "$WORK/requests.log"
! grep -q '/v2/shirudo/tree-skip/' "$WORK/requests.log"

# Replace the tag with the signed publication containing the appended seq=2
# operation, while retaining the same configured reference and tree ID.
cp "$TREE_REPO/manifests/updated" "$TREE_REPO/manifests/stable"
: >"$WORK/requests.log"

if ! BPM_OCI_SCHEME=http "$SHIRUDO_BIN" bpm tree sync \
	--report "$WORK/second-report.json" >/dev/null; then
	cat "$WORK/requests.log" >&2
	exit 1
fi

[ "$(report_field selected <"$WORK/second-report.json")" = 1 ]
[ "$(report_field skipped <"$WORK/second-report.json")" = 0 ]
[ "$(report_field applied <"$WORK/second-report.json")" = 1 ]
[ "$(report_field last_seq <"$WORK/second-report.json")" = 2 ]
[ -e "$MATCH_PIN" ]
[ -e "$SKIP_PIN" ]
! grep -q '/v2/shirudo/tree-match/' "$WORK/requests.log"
grep -q '/v2/shirudo/tree-skip/manifests/sha256:' "$WORK/requests.log"
grep -q '/v2/shirudo/tree-skip/blobs/sha256:' "$WORK/requests.log"

test_done
