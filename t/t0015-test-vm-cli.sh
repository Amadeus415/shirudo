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

test_expect_success 'test-vm guest installs optional decoder dependencies' '
	grep -q "^[[:space:]]*libluajit-5.1-dev" \
		../contrib/test-vm-guest.sh
'

test_expect_success 'test-vm imports the host-built payload' '
	grep -q "TEST_VM_BUNDLE_DIR" ../Makefile &&
	grep -q "test-vm-bundle" ../Makefile &&
	grep -q "build-test-vm-bundle.sh" ../Makefile &&
	grep -q "mount_tag=shirudo-bundle" ../contrib/test-vm.sh &&
	grep -q "importing host-built Shirudo payload" \
		../contrib/test-vm-guest.sh &&
	grep -q "SHIRUDO_BUILD_BIN=/usr/local/libexec/shirudo/shirudo-build" \
		../contrib/test-vm-guest.sh &&
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

test_expect_success 'test-vm-clean uses the VM runner cleanup path' '
	grep -q "contrib/test-vm.sh --clean" ../Makefile &&
	grep -q "stop_pid_file" ../contrib/test-vm.sh &&
	grep -q "removed VM state and logs" ../contrib/test-vm.sh
'

test_expect_success 'test-vm has an opt-in map-export bridge contract' '
	grep -q "TEST_VM_MAP_EXPORT_ENDPOINT, TEST_VM_MAP_EXPORT_TENANT_ID, and TEST_VM_MAP_EXPORT_INSECURE must be set together" \
		"$RUNNER" &&
	grep -q "TEST_VM_MAP_EXPORT_INSECURE must be exactly true" "$RUNNER" &&
	grep -q "export TEST_VM_MAP_EXPORT_ENDPOINT" "$RUNNER" &&
	grep -q "10.0.2.2 otel.test" ../contrib/test-vm-guest.sh &&
	grep -q "map_export.otel_endpoint = \$endpoint" ../contrib/test-vm-guest.sh &&
	grep -q "map_export.otel_insecure = true" ../contrib/test-vm-guest.sh &&
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

test_expect_success 'test-vm requires an insecure map-export bridge' '
	! TEST_VM_WORK_DIR="$WORK/non-insecure-map-export" \
		TEST_VM_KERNEL="$WORK/map-export-kernel" \
		TEST_VM_MAP_EXPORT_ENDPOINT=http://otel.test:4318 \
		TEST_VM_MAP_EXPORT_TENANT_ID=tenant-test \
		TEST_VM_MAP_EXPORT_INSECURE=false "$RUNNER" \
		>"$WORK/non-insecure-map-export.out" 2>&1 &&
	grep -q "must be exactly true" "$WORK/non-insecure-map-export.out"
'

test_done
