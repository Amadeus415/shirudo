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
BUNDLE=/mnt/shirudo-bundle
UPPER=/var/tmp/shirudo-upper
OVERLAY_WORK=/var/tmp/shirudo-overlay-work
WORKSPACE=/workspace/shirudo
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

log "installing Ubuntu runtime and integration-test dependencies"
apt-get update
apt-get install -y --no-install-recommends \
	ca-certificates \
	keyutils \
	libcurl4t64 \
	libelf1t64 \
	libjson-c5 \
	libluajit-5.1-2 \
	libssh-4 \
	libssl3t64 \
	libtss2-esys-3.0.2-0t64 \
	libtss2-tctildr0t64 \
	openssh-server \
	python3 \
	rsync \
	tpm2-tools

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
	log "preparing a guest overlay over the read-only checkout"
else
	log "overlay-on-9p unavailable; copying the test checkout into the guest"
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

log "importing host-built Shirudo payload"
log "host bundle dependency mode: $(<"$BUNDLE/dependency-mode")"
install -d /usr/local/bin
install -m 0755 "$BUNDLE/root/usr/local/bin/shirudo" /usr/local/bin/shirudo
TARGET_UNITS=(
	shirudo.service
	shirudo-map-export.service
	shirudo-map-export.timer
	shirudo-keepalive.service
	shirudo-keepalive.timer
)
install -d /usr/lib/systemd/system
for unit in "${TARGET_UNITS[@]}"; do
	install -m 0644 \
		"$BUNDLE/root/usr/lib/systemd/system/$unit" \
		"/usr/lib/systemd/system/$unit"
done
systemctl daemon-reload
cp -a "$BUNDLE/test-helpers/." "$WORKSPACE/"

log "checking custom-kernel and vTPM prerequisites"
mountpoint -q /sys/kernel/security || mount -t securityfs securityfs /sys/kernel/security
grep -qw bpf /sys/kernel/security/lsm
grep -aq signature_size /sys/kernel/btf/vmlinux
test -c /dev/tpm0
test -c /dev/tpmrm0
tpm2_getrandom 8 >/dev/null

log "importing operator certificate and attaching the measured Shirudo LSM"
install -d -m 0700 /var/lib/shirudo/keys
install -m 0644 "$BUNDLE/fixtures/cert.der" \
	/var/lib/shirudo/keys/cert.der
rm -f /var/lib/shirudo/keys/signing_key.pem
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
	# init above was deliberately run directly so the current boot gets one
	# TPM measurement; enable the service only for future boots and start the
	# periodic timers after initialization has completed.
	systemctl enable shirudo.service
	systemctl enable --now shirudo-map-export.timer
	systemctl enable --now shirudo-keepalive.timer

	log "guest prepared; interactive mode skipping integration tests"
	exit 0
fi

log "running SHIRUDO_INTEGRATION=1 test suite"
: >/mnt/shirudo-out/failed-tests
: >/mnt/shirudo-out/failed-suites
(
	cd t
	SHIRUDO_INTEGRATION=1 \
		SHIRUDO_BIN=/usr/local/bin/shirudo \
		SHIRUDO_BUILD_BIN= \
		SHIRUDO_TEST_FIXTURES_DIR="$BUNDLE/fixtures" \
		SHIRUDO_TEST_FAILURES_FILE=/mnt/shirudo-out/failed-tests \
		SHIRUDO_TEST_SUITE_FAILURES_FILE=/mnt/shirudo-out/failed-suites \
		./run-target-tests.sh
)
log "integration suite passed"
