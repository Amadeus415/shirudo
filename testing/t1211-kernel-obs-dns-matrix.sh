#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=kernel-obs
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PIN="/run/shirudo/bpffs/upatches/$NAME/link_0"
RUNNER=./helper/test-dns-prog-run
WORK=$(mktemp -d)

cleanup()
{
	if [ -e "$PIN" ] || [ -e "/run/shirudo/bpffs/upatches/$NAME/link" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
	rm -f "/var/lib/shirudo/upatches/$NAME.upatch"
	rm -rf "$WORK"
}
trap cleanup EXIT

save_failure()
{
	cat "$WORK/matrix.log" >&2 2>/dev/null || true
	if [ -d /mnt/shirudo-out ]; then
		mkdir -p /mnt/shirudo-out/dns-matrix
		cp -a "$WORK/." /mnt/shirudo-out/dns-matrix/
	fi
	return 1
}

load_observability()
{
	if "$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck --report=- \
		>"$WORK/load.log" 2>&1; then
		return 0
	fi
	cat "$WORK/load.log" >&2
	if [ -d /mnt/shirudo-out ]; then
		cp "$WORK/load.log" /mnt/shirudo-out/dns-matrix-load.log
	fi
	return 1
}

[ -s "$LOAD" ] || test_skip_all "missing kernel-obs fixture"
[ -s "$UNLOAD" ] || test_skip_all "missing kernel-obs unload fixture"

test_expect_success 'DNS matrix helper and generator are available' '
	[ -x "$RUNNER" ] &&
	python3 dns_obs_matrix.py --self-test >"$WORK/self-test.log" 2>&1
'

test_expect_success 'kernel-obs DNS programs load for packet tests' '
	load_observability &&
	[ -e "/run/shirudo/bpffs/upatches/$NAME/serializers/dns" ]
'

test_expect_success 'DNS UDP deterministic packet matrix passes' '
	python3 dns_obs_matrix.py --deterministic --known-gaps \
		--runner "$RUNNER" --shirudo "$SHIRUDO_BIN" --upatch "$NAME" \
		--work "$WORK" >"$WORK/matrix.log" 2>&1 || save_failure
'

if [ -s "$WORK/matrix.log" ]; then
	sed 's/^/# dns-matrix: /' "$WORK/matrix.log"
fi

if [ "${TEST_VM_DNS_FUZZ:-0}" = 1 ]; then
	test_expect_success 'DNS UDP seeded mutation fuzz run passes' '
		python3 dns_obs_matrix.py --fuzz \
			--runner "$RUNNER" --work "$WORK" \
			--seed "${TEST_VM_DNS_FUZZ_SEED:-0x53484952}" \
			--cases "${TEST_VM_DNS_FUZZ_CASES:-5000}" \
			>"$WORK/fuzz.log" 2>&1 || save_failure
	'
	if [ -s "$WORK/fuzz.log" ]; then
		sed 's/^/# dns-fuzz: /' "$WORK/fuzz.log"
	fi
fi

test_done
