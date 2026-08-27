#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Build the host-side payload imported by contrib/test-vm.sh. The bundle is
# shared by all VMs, while TPM state and the test workspace remain per-VM.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE_DIR="${TEST_VM_HOST_BUNDLE:-${REPO_ROOT}/build/test-vm/host-bundle}"
BPF_DEPS_DIR="${REPO_ROOT}/artifacts/bpf-next-kernel-debs/shirudo-bpf-deps"
LOCK_FILE="${BUNDLE_DIR}.lock"
STAMP_FILE="${TEST_VM_BUNDLE_STAMP:-${BUNDLE_DIR}/.stamp}"
STAMP_INPUTS="${TEST_VM_BUNDLE_INPUTS:-}"

log()
{
	printf '[test-vm-bundle] %s\n' "$*" >&2
}

die()
{
	log "error: $*"
	exit 1
}

bundle_is_current()
{
	local input

	[[ -f "$STAMP_FILE" && -n "$STAMP_INPUTS" ]] || return 1
	[[ -x "$BUNDLE_DIR/root/usr/local/bin/shirudo" ]] || return 1
	[[ -x "$BUNDLE_DIR/root/usr/local/libexec/shirudo/shirudo-build" ]] || return 1
	[[ -s "$BUNDLE_DIR/root/usr/local/share/shirudo/vmlinux.h" ]] || return 1
	for input in $STAMP_INPUTS; do
		[[ -e "$input" ]] || return 1
		[[ "$input" -nt "$STAMP_FILE" ]] && return 1
	done
	return 0
}

command -v flock >/dev/null 2>&1 ||
	die "flock is required; install it with: sudo apt-get install -y util-linux"

mkdir -p "$(dirname "$BUNDLE_DIR")"
exec 9>"$LOCK_FILE"
flock 9

if bundle_is_current; then
	log "reusing current host bundle: $BUNDLE_DIR"
	exit 0
fi

BPF_MAKE_ARGS=()
if [[ -f "$BPF_DEPS_DIR/bpftool" &&
	  -f "$BPF_DEPS_DIR/bpf/libbpf.a" &&
	  -f "$BPF_DEPS_DIR/vmlinux.h" ]]; then
	log "using bpf-next kernel dependency artifacts"
	BPF_MAKE_ARGS=(USE_BPF_NEXT_DEPS=1)
else
	log "bpf-next kernel dependency artifacts unavailable; using vendored tools"
fi

log "building host Shirudo payload and test helpers"
make -C "$REPO_ROOT" "${BPF_MAKE_ARGS[@]}" all shirudo-build test-helpers

TMP_DIR="$(mktemp -d "${BUNDLE_DIR}.tmp.XXXXXX")"
cleanup()
{
	rm -rf -- "$TMP_DIR"
}
trap cleanup EXIT

make -C "$REPO_ROOT" "${BPF_MAKE_ARGS[@]}" \
	DESTDIR="$TMP_DIR/root" install-operator

install -d "$TMP_DIR/test-helpers/t/helper"
while IFS= read -r helper; do
	install -m 0755 "$REPO_ROOT/$helper" "$TMP_DIR/test-helpers/$helper"
done <<'EOF'
t/helper/test-json-parser
t/helper/test-chain
t/helper/test-config
t/helper/test-selector
t/helper/test-bpf-load
t/helper/test-kernel-abi
t/helper/test-otel-map
t/helper/test-upatch-map-types
t/helper/test-upatch-prog-metadata
t/helper/test-upatch-decode
t/helper/test-upatch-serializer-pages
t/helper/test-signed-load
EOF

printf 'shirudo-test-vm-bundle-v1\n' >"$TMP_DIR/format"
if [[ ${#BPF_MAKE_ARGS[@]} -eq 1 ]]; then
	printf 'bpf-next-deps\n' >"$TMP_DIR/dependency-mode"
else
	printf 'vendored-tools\n' >"$TMP_DIR/dependency-mode"
fi
printf 'shirudo-test-vm-bundle-stamp-v1\n' >"$TMP_DIR/.stamp"

rm -rf -- "$BUNDLE_DIR"
mv -- "$TMP_DIR" "$BUNDLE_DIR"
touch "$STAMP_FILE"
trap - EXIT
log "ready: $BUNDLE_DIR"
