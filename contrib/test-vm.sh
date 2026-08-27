#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Boot a disposable Ubuntu guest with the bpf-next kernel and an swtpm
# vTPM, then run the live Shirudo integration suite inside it.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VM_ROOT="${TEST_VM_WORK_DIR:-${REPO_ROOT}/build/test-vm}"
CACHE_DIR="${VM_ROOT}/cache"
RUNS_DIR="${VM_ROOT}/runs"
LOGS_DIR="${VM_ROOT}/logs"
DEFAULT_KERNEL="${REPO_ROOT}/artifacts/bpf-next-kernel-debs/bzImage"
DEFAULT_ROOTFS_URL="https://cloud-images.ubuntu.com/releases/server/26.04/release/ubuntu-26.04-server-cloudimg-amd64.img"
DEFAULT_ROOTFS_SUMS_URL="https://cloud-images.ubuntu.com/releases/server/26.04/release/SHA256SUMS"
ROOTFS_NAME="ubuntu-26.04-server-cloudimg-amd64.img"
CPUS="${TEST_VM_CPUS:-4}"
MEMORY="${TEST_VM_MEMORY:-4G}"
DISK_SIZE="${TEST_VM_DISK_SIZE:-30G}"
VM_TIMEOUT="${TEST_VM_TIMEOUT:-3600}"
KEEP="${TEST_VM_KEEP:-0}"
KERNEL_URL="${TEST_VM_KERNEL_URL:-}"
KERNEL_SHA256="${TEST_VM_KERNEL_SHA256:-}"
KERNEL_OVERRIDE="${TEST_VM_KERNEL:-}"
ROOTFS_URL="${TEST_VM_ROOTFS_URL:-$DEFAULT_ROOTFS_URL}"
ROOTFS_SHA256="${TEST_VM_ROOTFS_SHA256:-}"
MAP_EXPORT_ENDPOINT="${TEST_VM_MAP_EXPORT_ENDPOINT:-}"
MAP_EXPORT_TENANT_ID="${TEST_VM_MAP_EXPORT_TENANT_ID:-}"
MAP_EXPORT_INSECURE="${TEST_VM_MAP_EXPORT_INSECURE:-}"
MAP_EXPORT_ENABLED=0
RUN_DIR=""
SWTPM_PIDFILE=""
QEMU_PID=""
FINAL_STATUS=1
HOST_DEPENDENCIES=(
	"curl:curl"
	"sha256sum:coreutils"
	"awk:mawk"
	"qemu-system-x86_64:qemu-system-x86"
	"qemu-img:qemu-utils"
	"swtpm:swtpm"
	"cloud-localds:cloud-image-utils"
	"timeout:coreutils"
	"tee:coreutils"
)

log()
{
	printf '[test-vm] %s\n' "$*" >&2
}

die()
{
	log "error: $*"
	exit 1
}

validate_map_export()
{
	local configured=0

	[[ -n "$MAP_EXPORT_ENDPOINT" ]] && configured=$((configured + 1))
	[[ -n "$MAP_EXPORT_TENANT_ID" ]] && configured=$((configured + 1))
	[[ -n "$MAP_EXPORT_INSECURE" ]] && configured=$((configured + 1))
	if (( configured == 0 )); then
		return
	fi
	(( configured == 3 )) ||
		die "TEST_VM_MAP_EXPORT_ENDPOINT, TEST_VM_MAP_EXPORT_TENANT_ID, and TEST_VM_MAP_EXPORT_INSECURE must be set together"
	[[ "$MAP_EXPORT_INSECURE" == "true" ]] ||
		die "TEST_VM_MAP_EXPORT_INSECURE must be exactly true"
	[[ ${#MAP_EXPORT_ENDPOINT} -lt 2048 ]] ||
		die "TEST_VM_MAP_EXPORT_ENDPOINT is too long"
	[[ "$MAP_EXPORT_ENDPOINT" != *[[:space:]]* ]] ||
		die "TEST_VM_MAP_EXPORT_ENDPOINT must not contain whitespace"
	[[ "$MAP_EXPORT_TENANT_ID" =~ ^[A-Za-z0-9._-]{1,128}$ ]] ||
		die "TEST_VM_MAP_EXPORT_TENANT_ID must contain 1..128 characters from A-Z, a-z, 0-9, '.', '_', '-'"
	MAP_EXPORT_ENABLED=1
}

print_dependency_install_command()
{
	printf '  sudo apt-get install -y --no-install-recommends'
	printf ' %q' "$@"
	printf '\n'
}

check_host_dependencies()
{
	local command_name
	local package
	local requirement
	local -a missing_commands=()
	local -a missing_packages=()
	local -A package_seen=()

	for requirement in "${HOST_DEPENDENCIES[@]}"; do
		command_name="${requirement%%:*}"
		package="${requirement#*:}"
		if ! command -v "$command_name" >/dev/null 2>&1; then
			missing_commands+=("$command_name")
			if [[ -z "${package_seen[$package]+present}" ]]; then
				missing_packages+=("$package")
				package_seen[$package]=1
			fi
		fi
	done

	if (( ${#missing_commands[@]} != 0 )); then
		log "error: missing host commands: ${missing_commands[*]}"
		log "Install them with:"
		print_dependency_install_command "${missing_packages[@]}" >&2
		exit 1
	fi
}

valid_sha256()
{
	[[ "$1" =~ ^[[:xdigit:]]{64}$ ]]
}

validate_kernel_selection()
{
	if [[ -n "$KERNEL_OVERRIDE" && -n "$KERNEL_URL" ]]; then
		die "TEST_VM_KERNEL and TEST_VM_KERNEL_URL are mutually exclusive"
	fi
	if [[ -n "$KERNEL_URL" ]]; then
		valid_sha256 "$KERNEL_SHA256" ||
			die "TEST_VM_KERNEL_URL requires a 64-character TEST_VM_KERNEL_SHA256"
	elif [[ -n "$KERNEL_OVERRIDE" ]]; then
		[[ -s "$KERNEL_OVERRIDE" ]] ||
			die "kernel image not found: $KERNEL_OVERRIDE"
	else
		[[ -s "$DEFAULT_KERNEL" ]] ||
			die "kernel image not found: $DEFAULT_KERNEL; run 'make bpf-next' first"
	fi
}

stop_swtpm()
{
	local pid

	[[ -n "$SWTPM_PIDFILE" && -s "$SWTPM_PIDFILE" ]] || return 0
	pid="$(<"$SWTPM_PIDFILE")"
	[[ "$pid" =~ ^[0-9]+$ ]] || return 0
	if kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null || true
		for _ in {1..20}; do
			kill -0 "$pid" 2>/dev/null || return 0
			sleep 0.1
		done
		kill -KILL "$pid" 2>/dev/null || true
	fi
}

stop_qemu()
{
	[[ -n "$QEMU_PID" ]] || return 0
	if kill -0 "$QEMU_PID" 2>/dev/null; then
		kill "$QEMU_PID" 2>/dev/null || true
		for _ in {1..50}; do
			kill -0 "$QEMU_PID" 2>/dev/null || return 0
			sleep 0.1
		done
		kill -KILL "$QEMU_PID" 2>/dev/null || true
	fi
}

save_failure_logs()
{
	local copied=0
	local path
	local saved

	[[ -n "$RUN_DIR" && -d "$RUN_DIR" ]] || return 0
	saved="${LOGS_DIR}/$(basename "$RUN_DIR")"
	for log_file in console.log guest.log swtpm.log; do
		if [[ -f "$RUN_DIR/$log_file" ]]; then
			path="$RUN_DIR/$log_file"
		elif [[ -f "$RUN_DIR/result/$log_file" ]]; then
			path="$RUN_DIR/result/$log_file"
		else
			continue
		fi
		mkdir -p "$saved"
		cp "$path" "$saved/"
		copied=1
	done
	if [[ "$copied" -eq 1 ]]; then
		log "failure logs: $saved"
	fi
}

cleanup()
{
	stop_qemu
	stop_swtpm
	if [[ "$FINAL_STATUS" -ne 0 ]]; then
		save_failure_logs
	fi
	if [[ -n "$RUN_DIR" && -d "$RUN_DIR" ]]; then
		if [[ "$KEEP" == "1" ]]; then
			log "preserved VM state: $RUN_DIR"
			log "warning: the guest overlay contains an ephemeral signing key"
		else
			rm -rf -- "$RUN_DIR"
		fi
	fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

resolve_kernel()
{
	local cache_kernel expected actual tmp

	if [[ -n "$KERNEL_OVERRIDE" && -n "$KERNEL_URL" ]]; then
		die "TEST_VM_KERNEL and TEST_VM_KERNEL_URL are mutually exclusive"
	fi

	if [[ -n "$KERNEL_URL" ]]; then
		valid_sha256 "$KERNEL_SHA256" ||
			die "TEST_VM_KERNEL_URL requires a 64-character TEST_VM_KERNEL_SHA256"
		expected="${KERNEL_SHA256,,}"
		cache_kernel="${CACHE_DIR}/kernels/${expected}/bzImage"
		mkdir -p "$(dirname "$cache_kernel")"
		if [[ -s "$cache_kernel" ]]; then
			actual="$(sha256sum "$cache_kernel" | awk '{print $1}')"
			if [[ "$actual" != "$expected" ]]; then
				rm -f -- "$cache_kernel"
			fi
		fi
		if [[ ! -s "$cache_kernel" ]]; then
			tmp="${cache_kernel}.tmp.$$"
			log "downloading kernel: $KERNEL_URL"
			curl -fL --retry 3 --output "$tmp" "$KERNEL_URL"
			actual="$(sha256sum "$tmp" | awk '{print $1}')"
			[[ "$actual" == "$expected" ]] || {
				rm -f -- "$tmp"
				die "downloaded kernel SHA-256 mismatch"
			}
			mv "$tmp" "$cache_kernel"
		fi
		printf '%s\n' "$cache_kernel"
		return
	fi

	if [[ -n "$KERNEL_OVERRIDE" ]]; then
		[[ -s "$KERNEL_OVERRIDE" ]] || die "kernel image not found: $KERNEL_OVERRIDE"
		printf '%s\n' "$(cd "$(dirname "$KERNEL_OVERRIDE")" && pwd)/$(basename "$KERNEL_OVERRIDE")"
		return
	fi

	[[ -s "$DEFAULT_KERNEL" ]] ||
		die "kernel image not found: $DEFAULT_KERNEL; run 'make bpf-next' first"
	if [[ -s "${DEFAULT_KERNEL}.sha256sum" ]]; then
		(cd "$(dirname "$DEFAULT_KERNEL")" &&
			sha256sum -c bzImage.sha256sum >/dev/null)
	else
		die "kernel checksum not found: ${DEFAULT_KERNEL}.sha256sum; run 'make bpf-next'"
	fi
	printf '%s\n' "$DEFAULT_KERNEL"
}

fetch_rootfs()
{
	local rootfs sums tmp expected actual

	rootfs="${CACHE_DIR}/rootfs/${ROOTFS_NAME}"
	mkdir -p "$(dirname "$rootfs")"

	if [[ -n "$ROOTFS_SHA256" ]]; then
		valid_sha256 "$ROOTFS_SHA256" ||
			die "TEST_VM_ROOTFS_SHA256 must contain 64 hexadecimal characters"
		expected="${ROOTFS_SHA256,,}"
	elif [[ "$ROOTFS_URL" == "$DEFAULT_ROOTFS_URL" ]]; then
		sums="${RUN_DIR}/SHA256SUMS"
		curl -fsSL --retry 3 --output "$sums" "$DEFAULT_ROOTFS_SUMS_URL"
		expected="$(awk -v name="*$ROOTFS_NAME" '$2 == name {print $1; exit}' "$sums")"
		valid_sha256 "$expected" || die "could not find $ROOTFS_NAME in Ubuntu SHA256SUMS"
	else
		die "a custom TEST_VM_ROOTFS_URL requires TEST_VM_ROOTFS_SHA256"
	fi

	if [[ -s "$rootfs" ]]; then
		actual="$(sha256sum "$rootfs" | awk '{print $1}')"
		if [[ "$actual" != "$expected" ]]; then
			log "cached rootfs checksum changed; downloading the current release"
			rm -f -- "$rootfs"
		fi
	fi
	if [[ ! -s "$rootfs" ]]; then
		tmp="${rootfs}.tmp.$$"
		log "downloading Ubuntu 26.04 rootfs"
		curl -fL --retry 3 --output "$tmp" "$ROOTFS_URL"
		actual="$(sha256sum "$tmp" | awk '{print $1}')"
		[[ "$actual" == "$expected" ]] || {
			rm -f -- "$tmp"
			die "downloaded rootfs SHA-256 mismatch"
		}
		mv "$tmp" "$rootfs"
	fi
	printf '%s\n' "$rootfs"
}

validate_kernel_selection
validate_map_export
check_host_dependencies
[[ "$CPUS" =~ ^[1-9][0-9]*$ ]] || die "TEST_VM_CPUS must be a positive integer"
[[ "$VM_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "TEST_VM_TIMEOUT must be a positive integer"
[[ "$KEEP" == "0" || "$KEEP" == "1" ]] || die "TEST_VM_KEEP must be 0 or 1"

mkdir -p "$CACHE_DIR" "$RUNS_DIR" "$LOGS_DIR"
RUN_DIR="$(mktemp -d "${RUNS_DIR}/run.XXXXXX")"
mkdir -p "$RUN_DIR/result" "$RUN_DIR/tpm"
KERNEL="$(resolve_kernel)"

[[ "$(uname -m)" == "x86_64" ]] || die "test-vm currently supports x86_64 hosts only"
[[ -r /dev/kvm && -w /dev/kvm ]] || die "/dev/kvm is required and must be accessible"

ROOTFS="$(fetch_rootfs)"
OVERLAY="${RUN_DIR}/rootfs.qcow2"
SEED="${RUN_DIR}/seed.img"
USER_DATA="${RUN_DIR}/user-data"
META_DATA="${RUN_DIR}/meta-data"
NETWORK_CONFIG="${RUN_DIR}/network-config"
SWTPM_SOCKET="${RUN_DIR}/tpm/swtpm-sock"
SWTPM_PIDFILE="${RUN_DIR}/tpm/swtpm.pid"

qemu-img create -q -f qcow2 -F qcow2 -b "$ROOTFS" "$OVERLAY"
qemu-img resize -q "$OVERLAY" "$DISK_SIZE"

cat >"$META_DATA" <<EOF
instance-id: shirudo-$(basename "$RUN_DIR")
local-hostname: shirudo-test-vm
EOF

cat >"$NETWORK_CONFIG" <<'EOF'
version: 2
ethernets:
  eth0:
    dhcp4: true
    optional: false
EOF

cat >"$USER_DATA" <<'EOF'
#cloud-config
growpart:
  mode: auto
  devices: ['/']
resize_rootfs: true
write_files:
  - path: /usr/local/sbin/shirudo-test-vm-bootstrap
    owner: root:root
    permissions: '0755'
    content: |
      #!/usr/bin/env bash
      set -uo pipefail
      mkdir -p /mnt/shirudo-src /mnt/shirudo-out
      if ! mount -t 9p -o trans=virtio,version=9p2000.L,msize=104857600 shirudo-out /mnt/shirudo-out; then
        echo "test-vm: could not mount result share" >/dev/ttyS0
        poweroff -f
        exit 1
      fi
      exec > >(tee -a /dev/ttyS0 /mnt/shirudo-out/guest.log) 2>&1
      rc=0
EOF
if [[ "$MAP_EXPORT_ENABLED" -eq 1 ]]; then
	{
		printf '      export TEST_VM_MAP_EXPORT_ENDPOINT=%q\n' \
			"$MAP_EXPORT_ENDPOINT"
		printf '      export TEST_VM_MAP_EXPORT_TENANT_ID=%q\n' \
			"$MAP_EXPORT_TENANT_ID"
		printf '      export TEST_VM_MAP_EXPORT_INSECURE=%q\n' \
			"$MAP_EXPORT_INSECURE"
	} >>"$USER_DATA"
fi
cat >>"$USER_DATA" <<'EOF'
      mount -t 9p -o trans=virtio,version=9p2000.L,msize=104857600,ro shirudo-src /mnt/shirudo-src || rc=$?
      if [ "$rc" -eq 0 ]; then
        bash /mnt/shirudo-src/contrib/test-vm-guest.sh || rc=$?
      fi
      printf '%s\n' "$rc" >/mnt/shirudo-out/status
      sync
      poweroff
      sleep 10
      poweroff -f
runcmd:
  - [ /usr/local/sbin/shirudo-test-vm-bootstrap ]
EOF

cloud-localds --network-config="$NETWORK_CONFIG" "$SEED" "$USER_DATA" "$META_DATA"

chmod 0700 "$RUN_DIR/tpm"
swtpm socket --tpmstate "dir=${RUN_DIR}/tpm,mode=0700" \
	--ctrl "type=unixio,path=${SWTPM_SOCKET}" \
	--tpm2 --log "file=${RUN_DIR}/swtpm.log,level=20" \
	--pid "file=${SWTPM_PIDFILE}" --daemon
for _ in {1..50}; do
	[[ -S "$SWTPM_SOCKET" ]] && break
	sleep 0.1
done
[[ -S "$SWTPM_SOCKET" ]] || die "swtpm control socket did not appear"

log "booting $(basename "$KERNEL") with ${CPUS} CPUs and ${MEMORY} memory"
set +e
timeout --signal=TERM --kill-after=30 "$VM_TIMEOUT" \
	qemu-system-x86_64 \
	-enable-kvm \
	-cpu host \
	-machine q35 \
	-smp "$CPUS" \
	-m "$MEMORY" \
	-drive "file=${OVERLAY},if=virtio,format=qcow2" \
	-drive "file=${SEED},if=virtio,format=raw,readonly=on" \
	-kernel "$KERNEL" \
	-append "root=/dev/vda1 rootwait rw console=ttyS0,115200n8 loglevel=7 net.ifnames=0 lsm=landlock,lockdown,yama,integrity,apparmor,bpf" \
	-netdev user,id=net0 \
	-device virtio-net-pci,netdev=net0 \
	-virtfs "local,id=shirudo-src,path=${REPO_ROOT},mount_tag=shirudo-src,security_model=none,readonly=on" \
	-virtfs "local,id=shirudo-out,path=${RUN_DIR}/result,mount_tag=shirudo-out,security_model=none" \
	-chardev "socket,id=chrtpm,path=${SWTPM_SOCKET}" \
	-tpmdev emulator,id=tpm0,chardev=chrtpm \
	-device tpm-tis,tpmdev=tpm0 \
	-display none \
	-serial stdio \
	-monitor none \
	-no-reboot > >(tee "$RUN_DIR/console.log") 2>&1 &
QEMU_PID=$!
wait "$QEMU_PID"
QEMU_STATUS=$?
QEMU_PID=""
set -e

if [[ "$QEMU_STATUS" -eq 124 ]]; then
	die "VM timed out after ${VM_TIMEOUT}s"
fi
[[ "$QEMU_STATUS" -eq 0 ]] || die "QEMU exited with status $QEMU_STATUS"
[[ -s "$RUN_DIR/result/status" ]] || die "guest did not publish a test result"
GUEST_STATUS="$(<"$RUN_DIR/result/status")"
[[ "$GUEST_STATUS" =~ ^[0-9]+$ ]] || die "invalid guest result: $GUEST_STATUS"
[[ "$GUEST_STATUS" -eq 0 ]] || die "guest test suite failed with status $GUEST_STATUS"

FINAL_STATUS=0
log "SHIRUDO_INTEGRATION=1 make check passed"
