#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Single entry point each CI provider calls. Builds shirudo, runs the
# TAP test suite under t/, propagates failure exit codes.

. "$(dirname "$0")/lib.sh"

# Build with -j matching the runner's CPU count.
jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"

log "configuring + building"
run make -j"$jobs"

log "running test suite"
# The t/ suite uses TAP. `prove` is preferred for parallelism; fall
# back to running scripts in series if prove is unavailable.
if command -v prove >/dev/null 2>&1; then
	run prove -j "$jobs" --timer ./t/t[0-9]*.sh
else
	run make -C t test
fi
