#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Guest-side half of contrib/test-vm.sh. The host checkout is mounted
# read-only at /mnt/shirudo-src; all build writes stay in this VM.

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
export HOME=/root
export LOGNAME=root
export USER=root
LOWER=/mnt/shirudo-src
UPPER=/var/tmp/shirudo-upper
OVERLAY_WORK=/var/tmp/shirudo-overlay-work
WORKSPACE=/workspace/shirudo
JOBS="${TEST_VM_CPUS:-$(nproc)}"
VM_MODE="${VM_MODE:-test}"

log()
{
	printf '[test-vm guest] %s\n' "$*"
}

configure_map_export()
{
	local endpoint="${TEST_VM_MAP_EXPORT_ENDPOINT:-}"
	local tenant_id="${TEST_VM_MAP_EXPORT_TENANT_ID:-}"
	local insecure="${TEST_VM_MAP_EXPORT_INSECURE:-}"

	if [[ -z "$endpoint" && -z "$tenant_id" && -z "$insecure" ]]; then
		return 0
	fi
	[[ -n "$endpoint" && -n "$tenant_id" && "$insecure" == "true" ]] || {
		log "invalid map-export bridge settings"
		return 1
	}

	log "configuring OTEL map-export bridge"
	# QEMU user networking exposes the host as 10.0.2.2. Remove any
	# stale entry first so repeated boots always use the bridge address.
	sed -E -i '/^[^#]*[[:space:]]otel\.test([[:space:]]|$)/d' /etc/hosts
	printf '%s\n' '10.0.2.2 otel.test' >>/etc/hosts
	install -d -m 0755 /etc/shirudo
	printf '%s\n' \
		"map_export.otel_endpoint = $endpoint" \
		'map_export.otel_insecure = true' \
		"map_export.tenant_id = $tenant_id" \
		>/etc/shirudo/shirudo.conf
}

configure_map_export

log "installing Ubuntu build and integration-test dependencies"
apt-get update
apt-get install -y --no-install-recommends \
	build-essential \
	ca-certificates \
	clang \
	git \
	keyutils \
	libcurl4-openssl-dev \
	libelf-dev \
	libjson-c-dev \
	libluajit-5.1-dev \
	libssh-dev \
	libssl-dev \
	libtss2-dev \
	llvm \
	openssh-server \
	pkg-config \
	python3 \
	rsync \
	tpm2-tools \
	uuid-dev \
	zlib1g-dev

log "configuring loopback root SSH for the libssh integration test"
install -d -m 0700 /root/.ssh
ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519
cat /root/.ssh/id_ed25519.pub >>/root/.ssh/authorized_keys
chmod 0600 /root/.ssh/authorized_keys
install -d -m 0755 /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/99-shirudo-test-vm.conf <<'EOF'
PermitRootLogin prohibit-password
PasswordAuthentication no
EOF
passwd -d root >/dev/null
systemctl enable --now ssh

mkdir -p "$UPPER" "$OVERLAY_WORK" "$WORKSPACE"
if mount -t overlay overlay \
	-o "lowerdir=${LOWER},upperdir=${UPPER},workdir=${OVERLAY_WORK}" \
	"$WORKSPACE"; then
	log "building in a guest overlay over the read-only checkout"
else
	log "overlay-on-9p unavailable; copying the checkout into the guest"
	rm -rf -- "$WORKSPACE"
	mkdir -p "$WORKSPACE"
	rsync -a --exclude=/.git/ --exclude=/artifacts/ --exclude=/build/ \
		"$LOWER"/ "$WORKSPACE"/
	if [[ -d "$LOWER/artifacts/bpf-next-kernel-debs/shirudo-bpf-deps" ]]; then
		mkdir -p "$WORKSPACE/artifacts/bpf-next-kernel-debs"
		rsync -a \
			"$LOWER/artifacts/bpf-next-kernel-debs/shirudo-bpf-deps/" \
			"$WORKSPACE/artifacts/bpf-next-kernel-debs/shirudo-bpf-deps/"
	fi
fi

cd "$WORKSPACE"
git config --global --add safe.directory "$WORKSPACE"
git config --global --add safe.directory "$WORKSPACE/third_party/bpf-next"

log "building Shirudo and its operator-side builder"
BPF_MAKE_ARGS=()
if [[ -f artifacts/bpf-next-kernel-debs/shirudo-bpf-deps/bpftool &&
      -f artifacts/bpf-next-kernel-debs/shirudo-bpf-deps/bpf/libbpf.a &&
      -f artifacts/bpf-next-kernel-debs/shirudo-bpf-deps/vmlinux.h ]]; then
	log "using bpf-next kernel dependency artifacts"
	BPF_MAKE_ARGS=(USE_BPF_NEXT_DEPS=1)
else
	log "bpf-next kernel dependency artifacts unavailable; building vendored tools"
fi
make distclean
make -j "$JOBS" "${BPF_MAKE_ARGS[@]}" all
make -j "$JOBS" "${BPF_MAKE_ARGS[@]}" shirudo-build
make "${BPF_MAKE_ARGS[@]}" install-target install-operator

log "checking custom-kernel and vTPM prerequisites"
mountpoint -q /sys/kernel/security || mount -t securityfs securityfs /sys/kernel/security
grep -qw bpf /sys/kernel/security/lsm
grep -aq signature_size /sys/kernel/btf/vmlinux
test -c /dev/tpm0
test -c /dev/tpmrm0
tpm2_getrandom 8 >/dev/null

log "generating an ephemeral key and attaching the measured Shirudo LSM"
/usr/local/bin/shirudo genkey
/usr/local/bin/shirudo init
test -e /var/lib/shirudo/bpffs/lsm_link
/usr/local/bin/shirudo status --json --include-tpm >/tmp/shirudo-status.json
python3 - /tmp/shirudo-status.json <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as status_file:
    status = json.load(status_file)
tpm = status.get("tpm") or {}
if not tpm.get("chain"):
    raise SystemExit("shirudo status reported no TPM chain")
if tpm.get("chain_matches_eventlog") is not True:
    raise SystemExit("TPM chain does not match the Shirudo event log")
PY

if [[ "$VM_MODE" == interactive ]]; then
	log "guest prepared; interactive mode skipping integration tests"
	exit 0
fi

log "running SHIRUDO_INTEGRATION=1 make check"
SHIRUDO_INTEGRATION=1 \
	SHIRUDO_BIN=/usr/local/bin/shirudo \
	SHIRUDO_BUILD_BIN="$WORKSPACE/tools/shirudo-build/shirudo-build" \
	make check
log "integration suite passed"
