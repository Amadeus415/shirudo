#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR_INPUT="${TEST_VM_WORK_DIR:-$REPO_ROOT/build/test-vm}"
if [[ "$WORK_DIR_INPUT" == /* ]]; then
	WORK_DIR="$WORK_DIR_INPUT"
else
	WORK_DIR="$REPO_ROOT/$WORK_DIR_INPUT"
fi

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
OUTPUT_INPUT="${BENCHMARK_OUTPUT_DIR:-$REPO_ROOT/build/benchmarks/$RUN_ID}"
if [[ "$OUTPUT_INPUT" == /* ]]; then
	OUTPUT_DIR="$OUTPUT_INPUT"
else
	OUTPUT_DIR="$REPO_ROOT/$OUTPUT_INPUT"
fi
mkdir -p "$OUTPUT_DIR"

run_variant()
{
	local variant="$1"
	local vm_name="bench-${RUN_ID}-${variant}"
	local vm_state="$WORK_DIR/vms/$vm_name"

	if [[ -e "$vm_state" ]]; then
		echo "benchmark VM state already exists: $vm_state" >&2
		exit 1
	fi
	echo "[benchmark] running $variant in fresh VM $vm_name"
	TEST_VM_SUITE=bench TEST_VM_BENCH_VARIANT="$variant" VM_MODE=test \
		VM_NAME="$vm_name" TEST_VM_WORK_DIR="$WORK_DIR" \
		"$REPO_ROOT/contrib/test-vm.sh"
	[[ -s "$vm_state/result/benchmark.csv" ]] || {
		echo "benchmark VM did not produce results: $vm_state" >&2
		exit 1
	}
	cp "$vm_state/result/benchmark.csv" "$OUTPUT_DIR/$variant.csv"
	if [[ -d "$vm_state/result/benchmark-raw" ]]; then
		cp -a "$vm_state/result/benchmark-raw" "$OUTPUT_DIR/${variant}-raw"
	fi
	echo "[benchmark] retained VM state: $vm_state"
}

run_variant baseline
run_variant empty
run_variant firewall

python3 "$REPO_ROOT/t/linux_obs_benchmark.py" summarize \
	--directory "$OUTPUT_DIR"
echo "[benchmark] artifacts: $OUTPUT_DIR"
