#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ./test-lib.sh

RUNNER=../contrib/test-vm.sh
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

test_expect_success 'test-vm rejects a missing local kernel before boot' '
	! TEST_VM_WORK_DIR="$WORK/missing" \
		TEST_VM_KERNEL="$WORK/no-bzImage" "$RUNNER" \
		>"$WORK/missing.out" 2>&1 &&
	grep -q "kernel image not found" "$WORK/missing.out"
'

test_expect_success 'test-vm requires a SHA-256 for a remote kernel' '
	! TEST_VM_WORK_DIR="$WORK/no-sha" \
		TEST_VM_KERNEL_URL=https://example.invalid/bzImage "$RUNNER" \
		>"$WORK/no-sha.out" 2>&1 &&
	grep -q "requires a 64-character TEST_VM_KERNEL_SHA256" \
		"$WORK/no-sha.out"
'

test_expect_success 'test-vm rejects conflicting kernel selectors' '
	! TEST_VM_WORK_DIR="$WORK/conflict" \
		TEST_VM_KERNEL="$WORK/bzImage" \
		TEST_VM_KERNEL_URL=https://example.invalid/bzImage \
		TEST_VM_KERNEL_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
		"$RUNNER" >"$WORK/conflict.out" 2>&1 &&
	grep -q "TEST_VM_KERNEL and TEST_VM_KERNEL_URL are mutually exclusive" \
		"$WORK/conflict.out"
'

test_expect_success 'test-vm prints an install command for missing dependencies' '
	mkdir "$WORK/fake-bin" &&
	ln -s /bin/bash "$WORK/fake-bin/bash" &&
	ln -s /usr/bin/dirname "$WORK/fake-bin/dirname" &&
	for command_name in curl sha256sum awk qemu-system-x86_64 qemu-img \
		swtpm timeout tee
	do
		ln -s /bin/true "$WORK/fake-bin/$command_name" || return 1
	done &&
	printf kernel >"$WORK/bzImage" &&
	! PATH="$WORK/fake-bin" \
		TEST_VM_WORK_DIR="$WORK/missing-dependency" \
		TEST_VM_KERNEL="$WORK/bzImage" "$RUNNER" \
		>"$WORK/missing-dependency.out" 2>&1 &&
	grep -q "missing host commands: cloud-localds" \
		"$WORK/missing-dependency.out" &&
	grep -q "sudo apt-get install -y --no-install-recommends cloud-image-utils" \
		"$WORK/missing-dependency.out"
'

test_expect_success 'test-vm selects the root partition without an initramfs' '
	grep -q "root=/dev/vda1 rootwait rw" "$RUNNER" &&
	! grep -q "root=LABEL=cloudimg-rootfs" "$RUNNER"
'

test_expect_success 'test-vm guest uses prebuilt target fixtures' '
	grep -q "SHIRUDO_TEST_FIXTURES_DIR" ../contrib/test-vm-guest.sh &&
	grep -q "SHIRUDO_BUILD_BIN=" ../contrib/test-vm-guest.sh &&
	grep -q "run-target-tests.sh" ../contrib/test-vm-guest.sh &&
	test -x run-target-tests.sh &&
	test -x t1200-target-fixtures.sh &&
	! grep -q "libluajit-5.1-dev" ../contrib/test-vm-guest.sh
'

test_expect_success 'test-vm imports the host-built payload' '
	grep -q "TEST_VM_BUNDLE_DIR" ../Makefile &&
	grep -q "test-vm-bundle" ../Makefile &&
	grep -q "build-test-vm-bundle.sh" ../Makefile &&
	grep -q "mount_tag=shirudo-bundle" ../contrib/test-vm.sh &&
	grep -q "importing host-built Shirudo payload" \
		../contrib/test-vm-guest.sh &&
	grep -q "install -m 0644 \"\$BUNDLE/fixtures/cert.der\"" \
		../contrib/test-vm-guest.sh &&
	! grep -q "vmlinux.h" ../contrib/test-vm-guest.sh &&
	! grep -q "shirudo-build" ../contrib/test-vm-guest.sh &&
	! grep -Fq "make \"\${BPF_MAKE_ARGS[@]}\" check" \
		../contrib/test-vm-guest.sh &&
	grep -Fq "BPFTOOL ?= \$(BPFTOOL_SOURCE_DIR)/bpftool" \
		../Makefile.shirudo &&
	grep -Fq "\$(LIBBPF_A)" ../Makefile.shirudo &&
	grep -q "shirudo-bpf-deps" ../Makefile.shirudo &&
	grep -q "Building Shirudo BPF dependency artifacts" \
		../contrib/build-kernel-deb.sh
'
	test_expect_success 'test-vm bundle stamp controls incremental rebuilds' '
	grep -q "TEST_VM_BUNDLE_STAMP" ../Makefile &&
	grep -q "TEST_VM_BUNDLE_INPUTS" ../Makefile &&
	grep -q "bundle_is_current" ../contrib/build-test-vm-bundle.sh &&
	grep -q "flock 9" ../Makefile &&
	grep -q "bundle_dir.lock" ../Makefile &&
	! grep -Fq "rm -rf \"\$\$bundle_dir.lock\"" ../Makefile &&
	grep -Fq "\$\$bundle_dir" ../Makefile
'

	test_expect_success 'test-vm summary records failed test names' '
	grep -q "print_test_summary" ../contrib/test-vm.sh &&
	grep -q "exit \"\$FINAL_STATUS\"" ../contrib/test-vm.sh &&
	grep -q "failed tests:" ../contrib/test-vm.sh &&
	grep -q "VM_VERBOSE" ../Makefile &&
	grep -q "summary_log" ../contrib/test-vm.sh &&
	grep -q "print_quiet_progress" ../contrib/test-vm.sh &&
	grep -q "stream_verbose_console" ../contrib/test-vm.sh &&
	grep -q "qemu.log\\\" 2>&1 &" ../contrib/test-vm.sh &&
	grep -q "SHIRUDO_TEST_FAILURES_FILE" ../contrib/test-vm-guest.sh &&
	grep -q "SHIRUDO_TEST_SUITE_FAILURES_FILE" ../contrib/test-vm-guest.sh &&
	grep -q "SHIRUDO_TEST_FAILURES_FILE" ../t/test-lib.sh &&
	grep -q "SHIRUDO_TEST_SUITE_FAILURES_FILE" ../t/run-tests.sh
'

test_expect_success 'test harness records a failed test title' '
	printf "%s\n" \
		"#!/bin/sh" \
		". \"\$PWD/test-lib.sh\"" \
		"test_expect_success \"synthetic failure\" \"false\"" \
		"test_done" >"$WORK/failing-suite.sh" &&
	! SHIRUDO_TEST_FAILURES_FILE="$WORK/failed-tests" \
		sh "$WORK/failing-suite.sh" >"$WORK/failing-suite.out" 2>&1 &&
	grep -Fq "test	$WORK/failing-suite.sh	synthetic failure" \
		"$WORK/failed-tests"
'

test_expect_success 'make vm and test-vm share named mode support' '
	grep -q "^[[:space:]]*vm:" ../Makefile &&
	grep -q "VM_MODE=interactive" ../Makefile &&
	grep -q "VM_MODE=test" ../Makefile &&
	grep -Fq "VMS_DIR=\"\${VM_ROOT}/vms\"" ../contrib/test-vm.sh &&
	grep -Fq "mktemp -d \"\${VMS_DIR}/\${VM_MODE}-XXXXXX\"" \
		../contrib/test-vm.sh &&
	grep -q "VM_TENANT" ../contrib/test-vm.sh &&
	grep -q "while :; do sleep 3600; done" ../contrib/test-vm.sh
'

test_expect_success 'named VM console and SSH access helpers are wired up' '
	grep -q "^vm-console:" ../Makefile &&
	grep -q "^vm-ssh:" ../Makefile &&
	grep -q "contrib/test-vm.sh --console" ../Makefile &&
	grep -q "contrib/test-vm.sh --ssh" ../Makefile &&
	grep -q "VM_SSH_COMMAND" ../Makefile &&
	grep -q "TEST_VM_SSH_PORT" ../Makefile &&
	grep -q "hostfwd=tcp:127.0.0.1" ../contrib/test-vm.sh &&
	grep -q "socket,id=console" ../contrib/test-vm.sh &&
	grep -q "logfile=.*console.log" ../contrib/test-vm.sh &&
	grep -q "TEST_VM_SSH_PUBLIC_KEY" ../contrib/test-vm.sh &&
	grep -q "serial-getty@ttyS0.service" ../contrib/test-vm-guest.sh &&
	grep -q "TEST_VM_SSH_PUBLIC_KEY" ../contrib/test-vm-guest.sh
'

test_expect_success 'VM console and SSH access require a named VM' '
	! TEST_VM_WORK_DIR="$WORK/access-console" "$RUNNER" --console \
		>"$WORK/access-console.out" 2>&1 &&
	grep -q "VM_NAME is required for VM console/SSH access" \
		"$WORK/access-console.out" &&
	! TEST_VM_WORK_DIR="$WORK/access-ssh" "$RUNNER" --ssh \
		>"$WORK/access-ssh.out" 2>&1 &&
	grep -q "VM_NAME is required for VM console/SSH access" \
		"$WORK/access-ssh.out"
'

test_expect_success 'VM bundle installs target units and interactive mode activates timers' '
	grep -q "DESTDIR=\"\$TMP_DIR/root\" install-target" \
		../contrib/build-test-vm-bundle.sh &&
	grep -q "systemd/\\*.timer" ../Makefile &&
	grep -q "shirudo-map-export.timer" ../contrib/test-vm-guest.sh &&
	grep -q "shirudo-keepalive.timer" ../contrib/test-vm-guest.sh &&
	grep -q "systemctl enable shirudo.service" ../contrib/test-vm-guest.sh &&
	grep -q "systemctl enable --now shirudo-map-export.timer" \
		../contrib/test-vm-guest.sh &&
	grep -q "systemctl enable --now shirudo-keepalive.timer" \
		../contrib/test-vm-guest.sh &&
	grep -Fq "if [[ \"\$VM_MODE\" == interactive ]]" \
		../contrib/test-vm-guest.sh
'

test_expect_success 'VM stop and cleanup use the VM runner paths' '
	grep -q "^vm-stop:" ../Makefile &&
	grep -q "contrib/test-vm.sh --stop" ../Makefile &&
	grep -q "^vm-clean:" ../Makefile &&
	grep -q "contrib/test-vm.sh --clean" ../Makefile &&
	grep -q "^test-vm-clean: vm-clean" ../Makefile &&
	grep -q "VM_NAME=\"\$(VM_NAME)\"" ../Makefile &&
	grep -q "stop_pid_file" ../contrib/test-vm.sh &&
	grep -q "removed VM state and logs" ../contrib/test-vm.sh
'

test_expect_success 'named vm-stop preserves the selected VM state' '
	root="$WORK/named-stop" &&
	mkdir -p "$root/vms/one" "$root/logs/one" &&
	printf state >"$root/vms/one/sentinel" &&
	printf log >"$root/logs/one/sentinel" &&
	VM_NAME=one TEST_VM_WORK_DIR="$root" "$RUNNER" --stop &&
	test -e "$root/vms/one/sentinel" &&
	test -e "$root/logs/one/sentinel"
'

test_expect_success 'unnamed vm-stop stops all VMs and preserves state' '
	root="$WORK/all-stop" &&
	mkdir -p "$root/vms/one" "$root/vms/two" "$root/logs/one" \
		"$root/logs/two" &&
	printf state >"$root/vms/one/sentinel" &&
	printf state >"$root/vms/two/sentinel" &&
	printf log >"$root/logs/one/sentinel" &&
	printf log >"$root/logs/two/sentinel" &&
	TEST_VM_WORK_DIR="$root" "$RUNNER" --stop &&
	test -e "$root/vms/one/sentinel" &&
	test -e "$root/vms/two/sentinel" &&
	test -e "$root/logs/one/sentinel" &&
	test -e "$root/logs/two/sentinel"
'

test_expect_success 'named test-vm-clean removes only the selected VM' '
	root="$WORK/named-clean" &&
	mkdir -p "$root/vms/one" "$root/vms/two" "$root/logs/one" \
		"$root/logs/two" "$root/cache" &&
	printf state >"$root/vms/one/sentinel" &&
	printf state >"$root/vms/two/sentinel" &&
	printf log >"$root/logs/one/sentinel" &&
	printf log >"$root/logs/two/sentinel" &&
	VM_NAME=one TEST_VM_WORK_DIR="$root" "$RUNNER" --clean &&
	! test -e "$root/vms/one" &&
	! test -e "$root/logs/one" &&
	test -e "$root/vms/two/sentinel" &&
	test -e "$root/logs/two/sentinel" &&
	test -d "$root/cache"
'

test_expect_success 'test-vm supports secure and explicit insecure map-export modes' '
	grep -q "MAP_EXPORT_CA=\"\${TEST_VM_MAP_EXPORT_CA:-}\"" "$RUNNER" &&
	grep -q "MAP_EXPORT_INSECURE=false" "$RUNNER" &&
	grep -q "HTTPS map-export endpoints require TEST_VM_MAP_EXPORT_INSECURE=false" "$RUNNER" &&
	grep -q "HTTP map-export endpoints require TEST_VM_MAP_EXPORT_INSECURE=true" "$RUNNER" &&
	grep -q "TEST_VM_MAP_EXPORT_CA=\"\$(TEST_VM_MAP_EXPORT_CA)\"" ../Makefile &&
	grep -q "export TEST_VM_MAP_EXPORT_ENDPOINT" "$RUNNER" &&
	grep -q "export TEST_VM_MAP_EXPORT_CA=/mnt/shirudo-otel/ca.pem" "$RUNNER" &&
	grep -q "mount_tag=shirudo-otel" "$RUNNER" &&
	grep -q "10.0.2.2 otel.test" ../contrib/test-vm-guest.sh &&
	grep -q "map_export.otel_endpoint = \$endpoint" ../contrib/test-vm-guest.sh &&
	grep -q "map_export.otel_insecure = \$insecure" ../contrib/test-vm-guest.sh &&
	grep -q "OTEL_EXPORTER_OTLP_CERTIFICATE=/etc/shirudo/otel/ca.pem" \
		../contrib/test-vm-guest.sh &&
	grep -q "map_export.tenant_id = \$tenant_id" ../contrib/test-vm-guest.sh
'

test_expect_success 'test-vm rejects incomplete map-export bridge settings' '
	printf kernel >"$WORK/map-export-kernel" &&
	! TEST_VM_WORK_DIR="$WORK/incomplete-map-export" \
		TEST_VM_KERNEL="$WORK/map-export-kernel" \
		TEST_VM_MAP_EXPORT_ENDPOINT=http://otel.test:4318 \
		TEST_VM_MAP_EXPORT_INSECURE=true "$RUNNER" \
		>"$WORK/incomplete-map-export.out" 2>&1 &&
	grep -q "must be set together" "$WORK/incomplete-map-export.out"
'

test_expect_success 'test-vm accepts secure HTTPS export without insecure setting' '
	! TEST_VM_WORK_DIR="$WORK/secure-map-export" \
		TEST_VM_KERNEL="$WORK/map-export-kernel" \
		TEST_VM_MAP_EXPORT_ENDPOINT=https://otel.test:4318 \
		TEST_VM_MAP_EXPORT_TENANT_ID=tenant-test "$RUNNER" \
		>"$WORK/secure-map-export.out" 2>&1 &&
	! grep -q "must be exactly true" "$WORK/secure-map-export.out" &&
	! grep -q "must be true or false" "$WORK/secure-map-export.out"
'

test_expect_success 'test-vm rejects cleartext export without explicit insecure setting' '
	! TEST_VM_WORK_DIR="$WORK/cleartext-map-export" \
		TEST_VM_KERNEL="$WORK/map-export-kernel" \
		TEST_VM_MAP_EXPORT_ENDPOINT=http://otel.test:4318 \
		TEST_VM_MAP_EXPORT_TENANT_ID=tenant-test "$RUNNER" \
		>"$WORK/cleartext-map-export.out" 2>&1 &&
	grep -q "HTTP map-export endpoints require TEST_VM_MAP_EXPORT_INSECURE=true" \
		"$WORK/cleartext-map-export.out"
'

test_expect_success 'test-vm validates a custom OTEL CA file before boot' '
	! TEST_VM_WORK_DIR="$WORK/missing-map-export-ca" \
		TEST_VM_KERNEL="$WORK/map-export-kernel" \
		TEST_VM_MAP_EXPORT_ENDPOINT=https://otel.test:4318 \
		TEST_VM_MAP_EXPORT_TENANT_ID=tenant-test \
		TEST_VM_MAP_EXPORT_CA="$WORK/no-ca.pem" "$RUNNER" \
		>"$WORK/missing-map-export-ca.out" 2>&1 &&
	grep -q "TEST_VM_MAP_EXPORT_CA is not a readable regular file" \
		"$WORK/missing-map-export-ca.out"
'

test_expect_success 'make test runs the complete pipeline in order' '
	grep -q "^test-op: all" ../Makefile &&
	! grep -Eq "^(check:|.*\bcheck\b.*\.PHONY)" ../Makefile &&
	grep -q "^bundle: test-vm-bundle" ../Makefile &&
	grep -A5 "^test:$" ../Makefile | grep -q "\$(MAKE) bundle" &&
	grep -A5 "^test:$" ../Makefile | grep -q "\$(MAKE) test-op" &&
	grep -A5 "^test:$" ../Makefile | grep -q "\$(MAKE) test-tgt" &&
	! grep -A5 "^test:$" ../Makefile | grep -q "\$(MAKE) bpf-next"
'

test_done
