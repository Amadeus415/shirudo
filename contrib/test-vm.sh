#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Boot an Ubuntu guest with the bpf-next kernel and an swtpm vTPM.
# In test mode it runs the live Shirudo integration suite; in interactive
# mode it prepares the guest and leaves QEMU and swtpm running.
#
# VM_MODE=test|interactive selects the mode. VM_NAME optionally selects a
# stable state directory; if omitted, a unique name is allocated atomically.
# VM_TENANT is used as the map-export tenant when OTEL export is enabled.
# VM_VERBOSE=1 streams test-mode QEMU output to the terminal as well as the
# console log.

set -euo pipefail

SECONDS=0

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
	COLOR_BOLD=$'\033[1m'
	COLOR_GREEN=$'\033[32m'
	COLOR_RED=$'\033[31m'
	COLOR_YELLOW=$'\033[33m'
	COLOR_CYAN=$'\033[36m'
	COLOR_RESET=$'\033[0m'
else
	COLOR_BOLD=""
	COLOR_GREEN=""
	COLOR_RED=""
	COLOR_YELLOW=""
	COLOR_CYAN=""
	COLOR_RESET=""
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VM_ROOT_INPUT="${TEST_VM_WORK_DIR:-${REPO_ROOT}/build/test-vm}"
if [[ "$VM_ROOT_INPUT" == /* ]]; then
	VM_ROOT="$VM_ROOT_INPUT"
else
	VM_ROOT="$REPO_ROOT/$VM_ROOT_INPUT"
fi
TEST_VM_HOST_BUNDLE="${TEST_VM_HOST_BUNDLE:-${VM_ROOT}/host-bundle}"
CACHE_DIR="${VM_ROOT}/cache"
RUNTIME_CACHE_INPUT="${TEST_VM_RUNTIME_CACHE_DIR:-${CACHE_DIR}/runtime}"
if [[ "$RUNTIME_CACHE_INPUT" == /* ]]; then
	RUNTIME_CACHE_DIR="$RUNTIME_CACHE_INPUT"
else
	RUNTIME_CACHE_DIR="$REPO_ROOT/$RUNTIME_CACHE_INPUT"
fi
VMS_DIR="${VM_ROOT}/vms"
LOGS_DIR="${VM_ROOT}/logs"
DEFAULT_KERNEL="${REPO_ROOT}/artifacts/bpf-next-kernel-debs/bzImage"
DEFAULT_ROOTFS_URL="https://cloud-images.ubuntu.com/releases/server/26.04/release/ubuntu-26.04-server-cloudimg-amd64.img"
DEFAULT_ROOTFS_SUMS_URL="https://cloud-images.ubuntu.com/releases/server/26.04/release/SHA256SUMS"
ROOTFS_NAME="ubuntu-26.04-server-cloudimg-amd64.img"
CPUS="${TEST_VM_CPUS:-4}"
MEMORY="${TEST_VM_MEMORY:-4G}"
DISK_SIZE="${TEST_VM_DISK_SIZE:-30G}"
VM_TIMEOUT="${TEST_VM_TIMEOUT:-3600}"
VM_MODE="${VM_MODE:-test}"
VM_SUITE="${TEST_VM_SUITE:-all}"
VM_VERBOSE="${VM_VERBOSE:-0}"
DNS_FUZZ="${TEST_VM_DNS_FUZZ:-0}"
DNS_FUZZ_SEED="${TEST_VM_DNS_FUZZ_SEED:-0x53484952}"
DNS_FUZZ_CASES="${TEST_VM_DNS_FUZZ_CASES:-5000}"
VM_NAME_REQUEST="${VM_NAME:-}"
VM_TENANT="${VM_TENANT:-}"
VM_SSH_COMMAND="${VM_SSH_COMMAND:-}"
SSH_PORT_REQUEST="${TEST_VM_SSH_PORT:-}"
KERNEL_URL="${TEST_VM_KERNEL_URL:-}"
KERNEL_SHA256="${TEST_VM_KERNEL_SHA256:-}"
KERNEL_OVERRIDE="${TEST_VM_KERNEL:-}"
ROOTFS_URL="${TEST_VM_ROOTFS_URL:-$DEFAULT_ROOTFS_URL}"
ROOTFS_SHA256="${TEST_VM_ROOTFS_SHA256:-}"
MAP_EXPORT_ENDPOINT="${TEST_VM_MAP_EXPORT_ENDPOINT:-}"
LEGACY_MAP_EXPORT_TENANT_ID="${TEST_VM_MAP_EXPORT_TENANT_ID:-}"
MAP_EXPORT_INSECURE="${TEST_VM_MAP_EXPORT_INSECURE:-}"
MAP_EXPORT_CA="${TEST_VM_MAP_EXPORT_CA:-}"
MAP_EXPORT_TENANT_ID=""
MAP_EXPORT_ENABLED=0
RUN_DIR=""
SSH_DIR=""
SSH_PORT=""
SSH_PUBLIC_KEY=""
SSH_PORT_LOCK_FD=""
SWTPM_PIDFILE=""
QEMU_PID=""
QEMU_STATUS=1
PROGRESS_LINES=0
GUEST_STATUS=""
FAILURE_LOG_DIR=""
FINAL_STATUS=1
LEAVE_RUNNING=0
HOST_DEPENDENCIES=(
	"curl:curl"
	"sha256sum:coreutils"
	"awk:mawk"
	"qemu-system-x86_64:qemu-system-x86"
	"qemu-img:qemu-utils"
	"swtpm:swtpm"
	"cloud-localds:cloud-image-utils"
	"timeout:coreutils"
	"flock:util-linux"
	"ssh-keygen:openssh-client"
	"ss:iproute2"
)

SSH_PORT_MIN=22000
SSH_PORT_MAX=22999

log()
{
	printf '[test-vm] %s\n' "$*" >&2
}

summary_log()
{
	printf '[test-vm] %s\n' "$*"
}

die()
{
	log "error: $*"
	exit 1
}

valid_vm_name()
{
	[[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$ ]]
}

validate_mode()
{
	case "$VM_MODE" in
	interactive|test) ;;
	*) die "VM_MODE must be 'interactive' or 'test'" ;;
	esac
	case "$VM_SUITE" in
	all|obs) ;;
	*) die "TEST_VM_SUITE must be 'all' or 'obs'" ;;
	esac
	case "$DNS_FUZZ" in
	0|1) ;;
	*) die "TEST_VM_DNS_FUZZ must be '0' or '1'" ;;
	esac
	[[ "$DNS_FUZZ_SEED" =~ ^(0[xX][0-9a-fA-F]+|[0-9]+)$ ]] ||
		die "TEST_VM_DNS_FUZZ_SEED must be a decimal or hexadecimal integer"
	[[ "$DNS_FUZZ_CASES" =~ ^[1-9][0-9]*$ ]] ||
		die "TEST_VM_DNS_FUZZ_CASES must be a positive integer"
	(( DNS_FUZZ_CASES <= 100000 )) ||
		die "TEST_VM_DNS_FUZZ_CASES must be between 1 and 100000"
}

validate_map_export()
{
	local configured=0

	if [[ -n "$VM_TENANT" && -n "$LEGACY_MAP_EXPORT_TENANT_ID" &&
	      "$VM_TENANT" != "$LEGACY_MAP_EXPORT_TENANT_ID" ]]; then
		die "VM_TENANT and TEST_VM_MAP_EXPORT_TENANT_ID conflict"
	fi
	if [[ -z "$VM_TENANT" ]]; then
		VM_TENANT="$LEGACY_MAP_EXPORT_TENANT_ID"
	fi
	MAP_EXPORT_TENANT_ID="$VM_TENANT"

	[[ -n "$MAP_EXPORT_ENDPOINT" ]] && configured=$((configured + 1))
	[[ -n "$MAP_EXPORT_INSECURE" ]] && configured=$((configured + 1))
	[[ -n "$MAP_EXPORT_CA" ]] && configured=$((configured + 1))
	if (( configured == 0 )); then
		return
	fi
	[[ -n "$MAP_EXPORT_TENANT_ID" ]] ||
		die "TEST_VM_MAP_EXPORT_ENDPOINT and VM_TENANT must be set together"
	[[ -n "$MAP_EXPORT_ENDPOINT" ]] ||
		die "TEST_VM_MAP_EXPORT_CA and TEST_VM_MAP_EXPORT_INSECURE require TEST_VM_MAP_EXPORT_ENDPOINT"
	if [[ -z "$MAP_EXPORT_INSECURE" ]]; then
		MAP_EXPORT_INSECURE=false
	fi
	[[ "$MAP_EXPORT_INSECURE" == "true" ||
	   "$MAP_EXPORT_INSECURE" == "false" ]] ||
		die "TEST_VM_MAP_EXPORT_INSECURE must be true or false"
	case "$MAP_EXPORT_ENDPOINT" in
	https://*)
		[[ "$MAP_EXPORT_INSECURE" == "false" ]] ||
			die "HTTPS map-export endpoints require TEST_VM_MAP_EXPORT_INSECURE=false"
		;;
	http://*)
		[[ "$MAP_EXPORT_INSECURE" == "true" ]] ||
			die "HTTP map-export endpoints require TEST_VM_MAP_EXPORT_INSECURE=true"
		;;
	*)
		die "TEST_VM_MAP_EXPORT_ENDPOINT must use http:// or https://"
		;;
	esac
	if [[ -n "$MAP_EXPORT_CA" ]]; then
		[[ -f "$MAP_EXPORT_CA" && -r "$MAP_EXPORT_CA" ]] ||
			die "TEST_VM_MAP_EXPORT_CA is not a readable regular file: $MAP_EXPORT_CA"
	fi
	[[ ${#MAP_EXPORT_ENDPOINT} -lt 2048 ]] ||
		die "TEST_VM_MAP_EXPORT_ENDPOINT is too long"
	[[ "$MAP_EXPORT_ENDPOINT" != *[[:space:]]* ]] ||
		die "TEST_VM_MAP_EXPORT_ENDPOINT must not contain whitespace"
	[[ "$MAP_EXPORT_TENANT_ID" =~ ^[A-Za-z0-9._-]{1,128}$ ]] ||
		die "VM_TENANT must contain 1..128 characters from A-Z, a-z, 0-9, '.', '_', '-'"
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

validate_host_bundle()
{
	local runtime_key runtime_image
	[[ -x "$TEST_VM_HOST_BUNDLE/root/usr/local/bin/shirudo" ]] ||
		die "host VM bundle is missing; run 'make test-vm-bundle' first: $TEST_VM_HOST_BUNDLE"
	[[ -s "$TEST_VM_HOST_BUNDLE/fixtures/cert.der" ]] ||
		die "host VM bundle has no target-test certificate: $TEST_VM_HOST_BUNDLE"
	[[ -s "$TEST_VM_HOST_BUNDLE/fixtures/shirudo-test-basic.upatch" ]] ||
		die "host VM bundle has no target-test fixtures: $TEST_VM_HOST_BUNDLE"
	if [[ "$VM_SUITE" == obs ]]; then
		[[ -s "$TEST_VM_HOST_BUNDLE/fixtures/linux-observability.upatch" ]] ||
			die "host VM bundle has no Linux observability fixture: $TEST_VM_HOST_BUNDLE"
	fi
	[[ -s "$TEST_VM_HOST_BUNDLE/runtime-image-key" ]] ||
		die "host VM bundle has no prepared runtime image; run 'make bundle'"
	runtime_key="$(<"$TEST_VM_HOST_BUNDLE/runtime-image-key")"
	[[ "$runtime_key" =~ ^rootfs-[0-9a-f]{64}-packages-[0-9a-f]{64}-v[0-9]+$ ]] ||
		die "host VM bundle has an invalid prepared runtime image key"
	runtime_image="$RUNTIME_CACHE_DIR/$runtime_key.qcow2"
	[[ -s "$runtime_image" ]] ||
		die "prepared runtime image is missing: $runtime_image; run 'make bundle'"
}

stop_swtpm()
{
	local pid

	[[ -n "$SWTPM_PIDFILE" && -s "$SWTPM_PIDFILE" ]] || return 0
	pid="$(<"$SWTPM_PIDFILE")"
	[[ "$pid" =~ ^[0-9]+$ ]] || { rm -f -- "$SWTPM_PIDFILE"; return 0; }
	if kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null || true
		for _ in {1..20}; do
			kill -0 "$pid" 2>/dev/null || break
			sleep 0.1
		done
		kill -KILL "$pid" 2>/dev/null || true
	fi
	rm -f -- "$SWTPM_PIDFILE"
}

stop_qemu()
{
	[[ -n "$QEMU_PID" ]] || return 0
	if kill -0 "$QEMU_PID" 2>/dev/null; then
		kill "$QEMU_PID" 2>/dev/null || true
		for _ in {1..50}; do
			kill -0 "$QEMU_PID" 2>/dev/null || break
			sleep 0.1
		done
		kill -KILL "$QEMU_PID" 2>/dev/null || true
	fi
	if [[ -n "$RUN_DIR" ]]; then
		rm -f -- "$RUN_DIR/qemu.pid"
	fi
	QEMU_PID=""
}

stop_pid_file()
{
	local pidfile="$1" pid cmdline state_dir expected

	[[ -s "$pidfile" ]] || return 0
	pid="$(<"$pidfile")"
	[[ "$pid" =~ ^[0-9]+$ ]] || { rm -f -- "$pidfile"; return 0; }
	state_dir="$(dirname "$pidfile")"
	expected=swtpm
	if [[ "$(basename "$pidfile")" == qemu.pid ]]; then
		state_dir="$(dirname "$state_dir")"
		expected=qemu-system-x86_64
	fi
	if kill -0 "$pid" 2>/dev/null; then
		cmdline="$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)"
		if [[ "$cmdline" == *"$expected"* && "$cmdline" == *"$state_dir"* ]]; then
			kill "$pid" 2>/dev/null || true
			for _ in {1..50}; do
				kill -0 "$pid" 2>/dev/null || break
				sleep 0.1
			done
			kill -KILL "$pid" 2>/dev/null || true
		fi
	fi
	rm -f -- "$pidfile"
}

check_access_dependency()
{
	local command_name="$1"

	command -v "$command_name" >/dev/null 2>&1 ||
		die "missing host command: $command_name"
}

select_named_run_dir()
{
	[[ -n "$VM_NAME_REQUEST" ]] ||
		die "VM_NAME is required for VM console/SSH access"
	valid_vm_name "$VM_NAME_REQUEST" ||
		die "VM_NAME must start with an alphanumeric and contain only A-Z, a-z, 0-9, '.', '_', or '-' (max 63 characters)"
	RUN_DIR="${VMS_DIR}/${VM_NAME_REQUEST}"
	[[ -d "$RUN_DIR" ]] ||
		die "VM_NAME '$VM_NAME_REQUEST' has no state directory under $VMS_DIR"
	VM_NAME="$VM_NAME_REQUEST"
}

require_running_vm()
{
	local pid cmdline

	select_named_run_dir
	[[ -s "$RUN_DIR/qemu.pid" ]] ||
		die "VM '$VM_NAME' is not running; start it with 'make vm VM_NAME=$VM_NAME'"
	pid="$(<"$RUN_DIR/qemu.pid")"
	[[ "$pid" =~ ^[0-9]+$ ]] ||
		die "VM '$VM_NAME' has an invalid QEMU PID file"
	if ! kill -0 "$pid" 2>/dev/null; then
		die "VM '$VM_NAME' is not running; start it with 'make vm VM_NAME=$VM_NAME'"
	fi
	cmdline="$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)"
	[[ "$cmdline" == *qemu-system-x86_64* &&
	   "$cmdline" == *"$RUN_DIR"* ]] ||
		die "VM '$VM_NAME' has a stale or unrelated QEMU PID file"
}

run_console()
{
	check_access_dependency socat
	require_running_vm
	[[ -S "$RUN_DIR/console.sock" ]] ||
		die "VM '$VM_NAME' has no serial console socket"
	log "attaching to VM console: $VM_NAME (Ctrl-] detaches)"
	exec socat 'STDIO,raw,echo=0,escape=0x1d' \
		"UNIX-CONNECT:${RUN_DIR}/console.sock"
}

ssh_options()
{
	SSH_ARGS=(
		-F /dev/null
		-o ConnectTimeout=2
		-o ConnectionAttempts=1
		-o IdentitiesOnly=yes
		-o StrictHostKeyChecking=accept-new
		-o GlobalKnownHostsFile=/dev/null
		-o UserKnownHostsFile="${SSH_DIR}/known_hosts"
		-o IdentityFile="${SSH_DIR}/id_ed25519"
		-p "$SSH_PORT"
	)
}

run_ssh()
{
	local ready=0

	check_access_dependency ssh
	require_running_vm
	SSH_DIR="${RUN_DIR}/ssh"
	[[ -s "$RUN_DIR/ssh.port" && -r "$SSH_DIR/id_ed25519" ]] ||
		die "VM '$VM_NAME' has no SSH access metadata"
	SSH_PORT="$(<"$RUN_DIR/ssh.port")"
	[[ "$SSH_PORT" =~ ^[0-9]+$ ]] ||
		die "VM '$VM_NAME' has an invalid SSH port"
	ssh_options
	for _ in {1..60}; do
		if ssh "${SSH_ARGS[@]}" -o BatchMode=yes \
			root@127.0.0.1 true >/dev/null 2>&1; then
			ready=1
			break
		fi
		sleep 1
	done
	[[ "$ready" -eq 1 ]] ||
		die "SSH did not become ready for VM '$VM_NAME'"
	if [[ -n "$VM_SSH_COMMAND" ]]; then
		exec ssh "${SSH_ARGS[@]}" root@127.0.0.1 "$VM_SSH_COMMAND"
	fi
	exec ssh "${SSH_ARGS[@]}" root@127.0.0.1
}

stop_named_state()
{
	local pidfile vm_dir

	[[ -n "$VM_NAME_REQUEST" ]] ||
		die "VM_NAME is required for named VM stop/cleanup"
	valid_vm_name "$VM_NAME_REQUEST" ||
		die "VM_NAME must start with an alphanumeric and contain only A-Z, a-z, 0-9, '.', '_', or '-' (max 63 characters)"
	vm_dir="${VMS_DIR}/${VM_NAME_REQUEST}"
	[[ -d "$vm_dir" ]] ||
		die "VM_NAME '$VM_NAME_REQUEST' has no state directory under $VMS_DIR"
	while IFS= read -r -d '' pidfile; do
		stop_pid_file "$pidfile"
	done < <(find "$vm_dir" -type f \( -name qemu.pid -o -name swtpm.pid \) -print0)
}

stop_all_state()
{
	local pidfile

	if [[ -d "$VMS_DIR" ]]; then
		while IFS= read -r -d '' pidfile; do
			stop_pid_file "$pidfile"
		done < <(find "$VMS_DIR" -type f \( -name qemu.pid -o -name swtpm.pid \) -print0)
	fi
}

stop_state()
{
	[[ -n "$VM_ROOT" && "$VM_ROOT" != "/" ]] ||
		die "refusing to stop unsafe VM root '$VM_ROOT'"
	if [[ -n "$VM_NAME_REQUEST" ]]; then
		stop_named_state
		log "stopped VM: $VM_NAME_REQUEST (state preserved)"
	else
		stop_all_state
		log "stopped all tracked VMs (state preserved)"
	fi
}

clean_state()
{
	local pidfile vm_dir

	[[ -n "$VM_ROOT" && "$VM_ROOT" != "/" ]] ||
		die "refusing to clean unsafe VM root '$VM_ROOT'"
	if [[ -n "$VM_NAME_REQUEST" ]]; then
		stop_named_state
		vm_dir="${VMS_DIR}/${VM_NAME_REQUEST}"
		rm -rf -- "$vm_dir" "${LOGS_DIR}/${VM_NAME_REQUEST}"
		log "removed VM state and logs: $VM_NAME_REQUEST"
		return 0
	fi
	stop_all_state
	rm -rf -- "$VM_ROOT"
	log "removed VM state and logs: $VM_ROOT"
}

save_failure_logs()
{
	local copied=0
	local path
	local saved

	[[ -n "$RUN_DIR" && -d "$RUN_DIR" ]] || return 0
	saved="${LOGS_DIR}/$(basename "$RUN_DIR")"
	for log_file in console.log qemu.log guest.log swtpm.log failed-tests failed-suites; do
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
		FAILURE_LOG_DIR="$saved"
	fi
}

format_elapsed()
{
	local elapsed="$1"
	local hours minutes seconds

	hours=$((elapsed / 3600))
	minutes=$(((elapsed % 3600) / 60))
	seconds=$((elapsed % 60))
	printf '%02d:%02d:%02d' "$hours" "$minutes" "$seconds"
}

print_test_summary()
{
	local result result_color elapsed guest_log console_log qemu_log failed_tests failed_suites
	local build_mode="unknown"
	local kind script title suite
	local individual_failures=0
	local suite_failures=0
	local bpffs_warning=0
	local result_share_warning=0
	declare -A recorded_suites=()

	[[ "$VM_MODE" == test ]] || return 0
	[[ -n "$RUN_DIR" && -d "$RUN_DIR" ]] || return 0

	guest_log="$RUN_DIR/result/guest.log"
	console_log="$RUN_DIR/console.log"
	qemu_log="$RUN_DIR/qemu.log"
	failed_tests="$RUN_DIR/result/failed-tests"
	failed_suites="$RUN_DIR/result/failed-suites"
	if [[ -f "$guest_log" ]]; then
		if grep -qF 'host bundle dependency mode: bpf-next-deps' "$guest_log"; then
			build_mode="host bundle (bpf-next deps)"
		elif grep -qF 'host bundle dependency mode: vendored-tools' "$guest_log"; then
			build_mode="host bundle (vendored tools)"
		fi
	fi

	if [[ "$FINAL_STATUS" -eq 0 ]]; then
		result=PASS
		result_color="$COLOR_GREEN"
	else
		result=FAIL
		result_color="$COLOR_RED"
	fi

	summary_log "${COLOR_BOLD}summary${COLOR_RESET}"
	if [[ -n "$GUEST_STATUS" && "$FINAL_STATUS" -ne 0 ]]; then
		summary_log "result: ${result_color}${result}${COLOR_RESET} (guest status $GUEST_STATUS)"
	else
		summary_log "result: ${result_color}${result}${COLOR_RESET}"
	fi
	summary_log "vm: $VM_NAME"
	summary_log "elapsed: $(format_elapsed "$SECONDS")"
	summary_log "bpf-next dependencies: ${COLOR_CYAN}${build_mode}${COLOR_RESET}"

	if [[ "$FINAL_STATUS" -ne 0 ]]; then
		if [[ -s "$failed_tests" ]]; then
			summary_log "${COLOR_RED}failed tests:${COLOR_RESET}"
			while IFS=$'\t' read -r kind script title; do
				[[ "$kind" == test ]] || continue
				script="${script#./}"
				recorded_suites["$script"]=1
				summary_log "  ${COLOR_RED}$script: $title${COLOR_RESET}"
				individual_failures=1
			done <"$failed_tests"
		fi
		if [[ -s "$failed_suites" ]]; then
			while IFS= read -r suite; do
				suite="${suite#./}"
				if [[ -z "${recorded_suites[$suite]+present}" ]]; then
					if [[ "$suite_failures" -eq 0 ]]; then
						summary_log "${COLOR_RED}failed suites:${COLOR_RESET}"
					fi
					summary_log "  ${COLOR_RED}$suite (no individual TAP failure recorded)${COLOR_RESET}"
					suite_failures=1
				fi
			done <"$failed_suites"
		fi
		if [[ "$individual_failures" -eq 0 && ! -s "$failed_suites" ]]; then
			summary_log "${COLOR_RED}failed tests: none recorded (failure occurred before the test suite)${COLOR_RESET}"
		fi
	fi

	summary_log "state: $RUN_DIR"
	summary_log "guest log: $guest_log"
	summary_log "console log: $console_log"
	summary_log "qemu log: $qemu_log"
	if [[ -n "$FAILURE_LOG_DIR" ]]; then
		summary_log "failure logs: $FAILURE_LOG_DIR"
	fi

	if [[ -f "$console_log" ]]; then
		if grep -Eq 'Failed unmounting .*var-lib-shirudo.*bpffs|Failed to unmount /oldroot/var/lib/shirudo/bpffs: Operation not permitted' "$console_log"; then
			bpffs_warning=1
		fi
		if grep -Eq 'Failed unmounting .*mnt-shirudo.*out|Failed to unmount /oldroot: Device or resource busy' "$console_log"; then
			result_share_warning=1
		fi
	fi
	if [[ "$bpffs_warning" -eq 1 ]]; then
		summary_log "cleanup: ${COLOR_YELLOW}bpffs unmount denied by Shirudo lockdown (expected)${COLOR_RESET}"
	fi
	if [[ "$result_share_warning" -eq 1 ]]; then
		summary_log "cleanup: ${COLOR_YELLOW}9p result share was busy during shutdown (non-fatal)${COLOR_RESET}"
	fi
}

print_quiet_progress()
{
	local guest_log="$RUN_DIR/result/guest.log"
	local line_count

	[[ "$VM_MODE" == test && "$VM_VERBOSE" != 1 ]] || return 0
	[[ -f "$guest_log" ]] || return 0
	line_count="$(wc -l <"$guest_log")"
	[[ "$line_count" =~ ^[0-9]+$ ]] || return 0
	(( line_count > PROGRESS_LINES )) || return 0
	awk -v start=$((PROGRESS_LINES + 1)) '
		NR >= start && /^(not )?ok [0-9]+ - / {
			printf "[test-vm] test: %s\n", $0
			fflush()
		}
	' "$guest_log"
	PROGRESS_LINES="$line_count"
}

CONSOLE_BYTES=0

stream_verbose_console()
{
	local console_log="$RUN_DIR/console.log"
	local byte_count

	[[ "$VM_MODE" == test && "$VM_VERBOSE" == 1 ]] || return 0
	[[ -f "$console_log" ]] || return 0
	byte_count="$(wc -c <"$console_log")"
	[[ "$byte_count" =~ ^[0-9]+$ ]] || return 0
	(( byte_count > CONSOLE_BYTES )) || return 0
	tail -c "+$((CONSOLE_BYTES + 1))" "$console_log"
	CONSOLE_BYTES="$byte_count"
}

cleanup()
{
	if [[ -n "$SSH_PORT_LOCK_FD" ]]; then
		flock -u "$SSH_PORT_LOCK_FD" 2>/dev/null || true
		eval "exec ${SSH_PORT_LOCK_FD}>&-"
		SSH_PORT_LOCK_FD=""
	fi
	if [[ "$LEAVE_RUNNING" -eq 0 ]]; then
		stop_qemu
		stop_swtpm
	fi
	if [[ "$FINAL_STATUS" -ne 0 ]]; then
		save_failure_logs
	fi
	if [[ "$VM_MODE" == test && -n "$RUN_DIR" && -d "$RUN_DIR" ]]; then
		print_test_summary
		log "warning: the guest overlay contains an ephemeral signing key"
	elif [[ -n "$RUN_DIR" && -d "$RUN_DIR" ]]; then
		log "preserved VM state: $RUN_DIR"
		log "warning: the guest overlay contains an ephemeral signing key"
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

allocate_ssh_access()
{
	local port

	SSH_DIR="${RUN_DIR}/ssh"
	mkdir -p "$SSH_DIR"
	(
		umask 077
		ssh-keygen -q -t ed25519 -N '' -f "$SSH_DIR/id_ed25519"
	)
	SSH_PUBLIC_KEY="$(<"$SSH_DIR/id_ed25519.pub")"

	exec {SSH_PORT_LOCK_FD}>"${VM_ROOT}/ssh-port.lock"
	flock "$SSH_PORT_LOCK_FD"
	if [[ -n "$SSH_PORT_REQUEST" ]]; then
		[[ "$SSH_PORT_REQUEST" =~ ^[0-9]+$ &&
		   "$SSH_PORT_REQUEST" -ge 1024 &&
		   "$SSH_PORT_REQUEST" -le 65535 ]] ||
			die "TEST_VM_SSH_PORT must be an unused port from 1024 through 65535"
		if ss -Hln "sport = :$SSH_PORT_REQUEST" 2>/dev/null | grep -q .; then
			die "TEST_VM_SSH_PORT is already in use: $SSH_PORT_REQUEST"
		fi
		SSH_PORT="$SSH_PORT_REQUEST"
	else
		port="$SSH_PORT_MIN"
		while (( port <= SSH_PORT_MAX )); do
			if ! ss -Hln "sport = :$port" 2>/dev/null | grep -q .; then
				SSH_PORT="$port"
				break
			fi
			port=$((port + 1))
		done
		[[ -n "$SSH_PORT" ]] ||
			die "no free localhost SSH port in ${SSH_PORT_MIN}-${SSH_PORT_MAX}"
	fi
	printf '%s\n' "$SSH_PORT" >"$RUN_DIR/ssh.port"
}

wait_for_ssh_listener()
{
	local _

	for _ in {1..50}; do
		if ss -Hln "sport = :$SSH_PORT" 2>/dev/null | grep -q .; then
			if [[ -n "$SSH_PORT_LOCK_FD" ]]; then
				flock -u "$SSH_PORT_LOCK_FD"
				eval "exec ${SSH_PORT_LOCK_FD}>&-"
				SSH_PORT_LOCK_FD=""
			fi
			return 0
		fi
		sleep 0.1
	done
	die "QEMU did not open localhost SSH port $SSH_PORT"
}

allocate_run_dir()
{
	mkdir -p "$VMS_DIR" "$LOGS_DIR"
	if [[ -n "$VM_NAME_REQUEST" ]]; then
		valid_vm_name "$VM_NAME_REQUEST" ||
			die "VM_NAME must start with an alphanumeric and contain only A-Z, a-z, 0-9, '.', '_', or '-' (max 63 characters)"
		RUN_DIR="${VMS_DIR}/${VM_NAME_REQUEST}"
		[[ ! -e "$RUN_DIR" ]] ||
			die "VM_NAME '$VM_NAME_REQUEST' already has state at $RUN_DIR"
		mkdir "$RUN_DIR" || die "could not create VM state directory $RUN_DIR"
		VM_NAME="$VM_NAME_REQUEST"
	else
		RUN_DIR="$(mktemp -d "${VMS_DIR}/${VM_MODE}-XXXXXX")" ||
			die "could not allocate a unique VM state directory"
		VM_NAME="$(basename "$RUN_DIR")"
	fi
	mkdir -p "$RUN_DIR/result" "$RUN_DIR/tpm"
}

while [[ "$#" -gt 0 ]]; do
	case "$1" in
	--stop)
		[[ "$#" -eq 1 ]] || die "--stop does not accept additional arguments"
		stop_state
		exit 0
		;;
	--clean)
		[[ "$#" -eq 1 ]] || die "--clean does not accept additional arguments"
		clean_state
		exit 0
		;;
	--console)
		[[ "$#" -eq 1 ]] || die "--console does not accept additional arguments"
		run_console
		exit 0
		;;
	--ssh)
		[[ "$#" -eq 1 ]] || die "--ssh does not accept additional arguments"
		run_ssh
		exit 0
		;;
	--verbose)
		VM_VERBOSE=1
		shift
		;;
	*)
		die "unknown argument '$1'"
		;;
	esac
done

validate_mode
validate_kernel_selection
validate_map_export
check_host_dependencies
validate_host_bundle
[[ "$CPUS" =~ ^[1-9][0-9]*$ ]] || die "TEST_VM_CPUS must be a positive integer"
[[ "$VM_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "TEST_VM_TIMEOUT must be a positive integer"

mkdir -p "$CACHE_DIR"
allocate_run_dir
allocate_ssh_access
KERNEL="$(resolve_kernel)"

[[ "$(uname -m)" == "x86_64" ]] || die "test-vm currently supports x86_64 hosts only"
[[ -r /dev/kvm && -w /dev/kvm ]] || die "/dev/kvm is required and must be accessible"

RUNTIME_KEY="$(<"$TEST_VM_HOST_BUNDLE/runtime-image-key")"
ROOTFS="$RUNTIME_CACHE_DIR/$RUNTIME_KEY.qcow2"
OVERLAY="${RUN_DIR}/rootfs.qcow2"
SEED="${RUN_DIR}/seed.img"
USER_DATA="${RUN_DIR}/user-data"
META_DATA="${RUN_DIR}/meta-data"
NETWORK_CONFIG="${RUN_DIR}/network-config"
SWTPM_SOCKET="${RUN_DIR}/tpm/swtpm-sock"
SWTPM_PIDFILE="${RUN_DIR}/tpm/swtpm.pid"
OTEL_CA_DIR=""

if [[ "$MAP_EXPORT_ENABLED" -eq 1 && -n "$MAP_EXPORT_CA" ]]; then
	OTEL_CA_DIR="${RUN_DIR}/otel-ca"
	mkdir -p "$OTEL_CA_DIR"
	install -m 0644 "$MAP_EXPORT_CA" "$OTEL_CA_DIR/ca.pem"
fi

qemu-img create -q -f qcow2 -F qcow2 -b "$ROOTFS" "$OVERLAY"
qemu-img resize -q "$OVERLAY" "$DISK_SIZE"

cat >"$META_DATA" <<EOF
instance-id: shirudo-${VM_NAME}
local-hostname: ${VM_NAME}
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
      mkdir -p /mnt/shirudo-src /mnt/shirudo-bundle /mnt/shirudo-out
      if ! mount -t 9p -o trans=virtio,version=9p2000.L,msize=104857600 shirudo-out /mnt/shirudo-out; then
        echo "test-vm: could not mount result share" >/dev/ttyS0
        poweroff -f
        exit 1
      fi
      if ! mount -t 9p -o trans=virtio,version=9p2000.L,msize=104857600,ro shirudo-bundle /mnt/shirudo-bundle; then
        echo "test-vm: could not mount host bundle share" >/dev/ttyS0
        poweroff -f
        exit 1
      fi
      exec > >(tee -a /dev/ttyS0 /mnt/shirudo-out/guest.log) 2>&1
      rc=0
EOF
printf '      export VM_MODE=%q\n' "$VM_MODE" >>"$USER_DATA"
printf '      export TEST_VM_SUITE=%q\n' "$VM_SUITE" >>"$USER_DATA"
printf '      export TEST_VM_DNS_FUZZ=%q\n' "$DNS_FUZZ" >>"$USER_DATA"
printf '      export TEST_VM_DNS_FUZZ_SEED=%q\n' "$DNS_FUZZ_SEED" >>"$USER_DATA"
printf '      export TEST_VM_DNS_FUZZ_CASES=%q\n' "$DNS_FUZZ_CASES" >>"$USER_DATA"
printf '      export TEST_VM_SSH_PUBLIC_KEY=%q\n' "$SSH_PUBLIC_KEY" >>"$USER_DATA"
if [[ "$MAP_EXPORT_ENABLED" -eq 1 ]]; then
	{
		printf '      export TEST_VM_MAP_EXPORT_ENDPOINT=%q\n' \
			"$MAP_EXPORT_ENDPOINT"
		printf '      export TEST_VM_MAP_EXPORT_TENANT_ID=%q\n' \
			"$MAP_EXPORT_TENANT_ID"
		printf '      export TEST_VM_MAP_EXPORT_INSECURE=%q\n' \
			"$MAP_EXPORT_INSECURE"
		if [[ -n "$OTEL_CA_DIR" ]]; then
			printf '      export TEST_VM_MAP_EXPORT_CA=/mnt/shirudo-otel/ca.pem\n'
		fi
	} >>"$USER_DATA"
fi
cat >>"$USER_DATA" <<'EOF'
      if [ -n "${TEST_VM_MAP_EXPORT_CA:-}" ]; then
        mkdir -p /mnt/shirudo-otel
        mount -t 9p -o trans=virtio,version=9p2000.L,msize=104857600,ro shirudo-otel /mnt/shirudo-otel || rc=$?
      fi
EOF
cat >>"$USER_DATA" <<'EOF'
      mount -t 9p -o trans=virtio,version=9p2000.L,msize=104857600,ro shirudo-src /mnt/shirudo-src || rc=$?
      if [ "$rc" -eq 0 ]; then
        bash /mnt/shirudo-src/contrib/test-vm-guest.sh || rc=$?
      fi
      printf '%s\n' "$rc" >/mnt/shirudo-out/status
      sync
      if [ "${VM_MODE:-test}" = interactive ] && [ "$rc" -eq 0 ]; then
        while :; do sleep 3600; done
      fi
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

QEMU_ARGS=(
	-enable-kvm \
	-cpu host \
	-machine q35 \
	-smp "$CPUS" \
	-m "$MEMORY" \
	-drive "file=${OVERLAY},if=virtio,format=qcow2" \
	-drive "file=${SEED},if=virtio,format=raw,readonly=on" \
	-kernel "$KERNEL" \
	-append "root=/dev/vda1 rootwait rw console=ttyS0,115200n8 loglevel=7 net.ifnames=0 lsm=landlock,lockdown,yama,integrity,apparmor,bpf" \
	-netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22" \
	-device virtio-net-pci,netdev=net0 \
	-virtfs "local,id=shirudo-src,path=${REPO_ROOT},mount_tag=shirudo-src,security_model=none,readonly=on" \
	-virtfs "local,id=shirudo-bundle,path=${TEST_VM_HOST_BUNDLE},mount_tag=shirudo-bundle,security_model=none,readonly=on" \
	-virtfs "local,id=shirudo-out,path=${RUN_DIR}/result,mount_tag=shirudo-out,security_model=none" \
	-chardev "socket,id=chrtpm,path=${SWTPM_SOCKET}" \
	-tpmdev emulator,id=tpm0,chardev=chrtpm \
	-device tpm-tis,tpmdev=tpm0 \
	-chardev "socket,id=console,path=${RUN_DIR}/console.sock,server=on,wait=off,logfile=${RUN_DIR}/console.log,logappend=on" \
	-serial chardev:console \
	-display none \
	-monitor none \
	-no-reboot
)

if [[ -n "$OTEL_CA_DIR" ]]; then
	QEMU_ARGS+=(
		-virtfs "local,id=shirudo-otel,path=${OTEL_CA_DIR},mount_tag=shirudo-otel,security_model=none,readonly=on"
	)
fi

wait_for_guest_status()
{
	local elapsed=0

	while [[ ! -s "$RUN_DIR/result/status" ]]; do
		kill -0 "$QEMU_PID" 2>/dev/null ||
			die "QEMU exited before guest preparation completed"
		(( elapsed < VM_TIMEOUT )) ||
			die "VM timed out after ${VM_TIMEOUT}s"
		sleep 1
		elapsed=$((elapsed + 1))
	done
	read_guest_status
}

read_guest_status()
{
	[[ -s "$RUN_DIR/result/status" ]] ||
		die "guest did not publish a test result"
	GUEST_STATUS="$(<"$RUN_DIR/result/status")"
	[[ "$GUEST_STATUS" =~ ^[0-9]+$ ]] ||
		die "invalid guest result: $GUEST_STATUS"
	[[ "$GUEST_STATUS" -eq 0 ]] ||
		die "guest preparation/test failed with status $GUEST_STATUS"
}

if [[ "$VM_MODE" == interactive ]]; then
	nohup qemu-system-x86_64 "${QEMU_ARGS[@]}" \
		>"$RUN_DIR/qemu.log" 2>&1 < /dev/null &
	QEMU_PID=$!
	printf '%s\n' "$QEMU_PID" >"$RUN_DIR/qemu.pid"
	wait_for_ssh_listener
	wait_for_guest_status
	LEAVE_RUNNING=1
	FINAL_STATUS=0
	log "VM ready: name=$VM_NAME state=$RUN_DIR qemu_pid=$QEMU_PID swtpm_pid=$(<"$SWTPM_PIDFILE")"
	log "console log: $RUN_DIR/console.log"
	log "console: make vm-console VM_NAME=$VM_NAME"
	log "ssh: make vm-ssh VM_NAME=$VM_NAME"
else
	set +e
	timeout --signal=TERM --kill-after=30 "$VM_TIMEOUT" \
		qemu-system-x86_64 "${QEMU_ARGS[@]}" \
		>"$RUN_DIR/qemu.log" 2>&1 &
	QEMU_PID=$!
	wait_for_ssh_listener
	while :; do
		if [[ "$VM_VERBOSE" == 1 ]]; then
			stream_verbose_console
		else
			print_quiet_progress
		fi
		[[ -s "$RUN_DIR/result/status" ]] && break
		kill -0 "$QEMU_PID" 2>/dev/null || break
		sleep 0.2
	done
	wait "$QEMU_PID"
	QEMU_STATUS=$?
	for _ in {1..5}; do
		if [[ "$VM_VERBOSE" == 1 ]]; then
			stream_verbose_console
		else
			print_quiet_progress
		fi
		sleep 0.1
	done
	set -e

	if [[ "$QEMU_STATUS" -eq 124 ]]; then
		die "VM timed out after ${VM_TIMEOUT}s"
	fi
	[[ "$QEMU_STATUS" -eq 0 ]] ||
		die "QEMU exited with status $QEMU_STATUS"
	QEMU_PID=""
	read_guest_status

	FINAL_STATUS=0
fi

exit "$FINAL_STATUS"
