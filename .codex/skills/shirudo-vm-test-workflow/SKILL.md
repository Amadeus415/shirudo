---
name: shirudo-vm-test-workflow
description: Build and operate Shirudo's QEMU/swtpm test VMs, stop or clean named or all VM state safely, and run host/operator and target integration tests. Use for VM-based Shirudo development and test workflows in the repository; do not use for Multipass or JB localstack workflows.
---

# Shirudo VM/Test Workflow

Use the repository Makefile targets as the public interface. Run commands from
the Shirudo repository root and preserve the caller's working-tree changes.

## Prerequisites and build

The target VM workflow needs an x86_64 host with accessible `/dev/kvm`,
`qemu-system-x86_64`, `qemu-img`, `swtpm`, and `cloud-localds`. The runner also
uses `curl`, `sha256sum`, `awk`, `timeout`, and `flock`. It reports a package
install suggestion when a dependency is missing; do not install host packages
without the user's authorization.

Build the userspace project and the pinned bpf-next kernel artifact when it is
not already available:

```sh
make -j
make bpf-next
```

The VM commands build or reuse the host bundle automatically. To build it
explicitly, use:

```sh
make test-vm-bundle
```

`make bundle` is an alias for that target. The bundle contains the target
payload and prebuilt target-test fixtures and is cached under
`build/test-vm/host-bundle`.

## Run VMs

Create a prepared interactive VM without running the target test suite:

```sh
make vm
```

This allocates a unique persistent VM name when `VM_NAME` is omitted, leaves
QEMU and swtpm running, and returns when the guest is ready. Use a stable name
for a VM that will be inspected or reused:

```sh
make vm VM_NAME=policy-session VM_TENANT=tenant-test
```

Run the target-side integration suite in a test-mode VM:

```sh
make test-tgt
```

Use `VM_NAME=name` for a predictable retained state directory and
`TEST_VM_VERBOSE=1` to stream the guest console while the suite runs. The
compatibility alias `make test-vm` has the same behavior as `make test-tgt`.
Test-mode VMs are stopped after the suite and retained for inspection.

The default kernel is
`artifacts/bpf-next-kernel-debs/bzImage`, produced by `make bpf-next`. A local
raw kernel can be selected with `TEST_VM_KERNEL=/path/to/bzImage`; a remote
kernel requires both `TEST_VM_KERNEL_URL` and its 64-hex-digit
`TEST_VM_KERNEL_SHA256`. Resource and location overrides include
`TEST_VM_CPUS`, `TEST_VM_MEMORY`, `TEST_VM_DISK_SIZE`, `TEST_VM_TIMEOUT`, and
`TEST_VM_WORK_DIR`.

Map export is opt-in. For a secure HTTPS collector, omit
`TEST_VM_MAP_EXPORT_INSECURE` (it defaults to `false`) and optionally provide
a PEM CA file when the collector is not trusted by the guest's normal CA
store:

```sh
make vm \
  TEST_VM_MAP_EXPORT_ENDPOINT=https://otel.test:4318 \
  TEST_VM_MAP_EXPORT_CA=/path/to/otel-ca.pem \
  VM_TENANT=tenant-test
```

The CA file is copied into the guest and supplied to both systemd exporters
through `/etc/shirudo/map-export.env`. The collector certificate must contain
`otel.test` in its subject alternative names when using the QEMU host bridge.
`make vm` configures the exporter but does not start a collector. For an
explicitly insecure cleartext HTTP collector, set
`TEST_VM_MAP_EXPORT_INSECURE=true`; HTTPS with insecure mode enabled is
rejected. Leaving all map-export variables unset keeps the normal VM workflow
unchanged, with no implicit localhost collector fallback.

## Stop and clean VMs

Stop one named VM while preserving its overlay, TPM state, and logs:

```sh
make vm-stop VM_NAME=policy-session
```

With no `VM_NAME`, `make vm-stop` stops all tracked VMs that have active QEMU
or swtpm processes and preserves every VM's state and logs:

```sh
make vm-stop
```

Remove one named VM's state and logs:

```sh
make vm-clean VM_NAME=policy-session
```

With no name, `make vm-clean` stops tracked VMs and removes the entire
`build/test-vm` work directory, including all VM state, logs, cache, and the
host bundle:

```sh
make vm-clean
```

Treat unnamed cleanup as destructive. If the user did not explicitly request
cleanup of all VMs, inspect `build/test-vm/vms` and ask for a name instead.
Use the Makefile targets rather than manually killing QEMU or recursively
deleting the work directory. `make test-vm-clean` remains a compatibility
alias for `make vm-clean`.

Retained per-VM logs are under `build/test-vm/logs/<VM_NAME>` by default,
including `console.log` and `qemu.log`. A custom `TEST_VM_WORK_DIR` relocates
the `vms`, `logs`, cache, and bundle directories together.

## Run tests

Host/operator-side tests:

```sh
make test-op
```

This builds Shirudo and runs the host TAP suite; unit tests always run, while
the live `t11xx` integration tests remain skipped unless explicitly enabled:

```sh
SHIRUDO_INTEGRATION=1 make test-op
```

Target-side integration tests:

```sh
make test-tgt
```

This prepares the host bundle, boots the vTPM VM, imports the signed fixtures,
and runs the target suite. Use `VM_NAME` and `TEST_VM_VERBOSE=1` as needed.

Run the complete pipeline in order—bundle, host tests, then target VM tests—with:

```sh
make test
```

Report the command's exit status and the retained VM/log paths. Do not claim a
target test passed merely because the VM booted; require the target suite's
successful exit and final summary.

## Operational boundaries

- Prefer `VM_NAME` when the VM must be inspected, stopped, or cleaned later.
- Preserve unrelated build artifacts and working-tree files.
- Check `make help` and the current Makefile if a command's behavior appears
  inconsistent with this guide.
- This skill covers Shirudo's local QEMU/swtpm runner only; it does not manage
  Multipass VMs, JB localstack services, or external deployment systems.
