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
uses `curl`, `sha256sum`, `awk`, `timeout`, `flock`, `ss`, and `ssh-keygen`.
The access helpers use `socat` and the OpenSSH client. It reports a package
install suggestion when a dependency is missing; do not install host packages
without the user's authorization.

Build the userspace project and the pinned bpf-next kernel artifact when it is
not already available:

```sh
make -j
make bpf-next
```

### Build stable kernel variants

The default VM kernel is bpf-next. The supported stable-kernel selectors are
`7.2`, `6.18`, `6.12`, `6.6`, and `6.1`. Build a tagged third-party Linux
kernel with:

```sh
make kernel KERNEL_TAG=v6.18
```

Select an exact stable-kernel commit by pairing the release tag with a
7-to-40-character hexadecimal commit selector:

```sh
make kernel KERNEL_TAG=v6.18 KERNEL_COMMIT=<commit-sha>
```

Commit-specific artifacts are isolated under a path such as
`artifacts/linux-v6.18-<commit-sha>-kernel-debs/`. The builder records the
resolved full commit in the `linux-*-kernel-build` metadata. A supplied
`KERNEL_SOURCE_DIR` must contain the requested commit; the input checkout is
never modified.

`TAG=v6.18` is accepted as an alias. `make` does not accept
`make kernel --tag=v6.18`; use the Make variable form. The builder clones the
tag from the upstream Linux repository, applies any requested
`KERNEL_PATCHES`, enables the VM-required configuration, and writes a
versioned artifact directory such as
`artifacts/linux-v6.18-kernel-debs/`. Override the source or configuration
when needed:

```sh
make kernel KERNEL_TAG=v6.18 \
  KERNEL_REPOSITORY=https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git \
  KERNEL_SOURCE_DIR=/path/to/clean/linux \
  KERNEL_CONFIG=/path/to/kernel.config
```

Kernel builds require the host packages checked by
`contrib/build-kernel-package.sh`; if any are missing, the command prints an
install command. Do not install host packages without authorization.

To build or reuse the image and boot an interactive VM on a selected stable
kernel, use:

```sh
make vm KERNEL=6.18 VM_NAME=kernel-6.18
```

Use the same commit selector for an interactive or target-test VM:

```sh
make vm KERNEL=6.18 KERNEL_COMMIT=<commit-sha> VM_NAME=kernel-6.18
make test-tgt KERNEL=6.18 KERNEL_COMMIT=<commit-sha>
```

Stable-kernel VM preparation automatically initializes Shirudo with
``--trusted-root`` because those third-party kernels do not carry the native
Shirudo signing ABI. The mode is committed in the guest and the status and
keepalive payload report ``trusted-root``. Override the test harness only when
the selected kernel was separately patched with native signing support:

```sh
make vm KERNEL=6.18 TEST_VM_TRUSTED_ROOT=0 VM_NAME=kernel-6.18
```

The bpf-next default uses ``untrusted-root`` and native kernel signatures.
Production systemd provisioning follows the same rule explicitly: put
``SHIRUDO_INIT_ARGS=--trusted-root`` in ``/etc/shirudo/init.env`` before the
first boot on a legacy kernel. Do not copy ``signing_key.pem`` to the guest;
trusted-root userspace verification needs only the public ``cert.der``.

`KERNEL=v6.18` is also accepted. `KERNEL_COMMIT` is supported for stable/LTS
selectors and is not valid with `bpf-next`. The selected kernel artifact is built first
when absent, then the normal host bundle and prepared runtime QCOW2 are built
or reused. The same selector is supported by `make test-tgt`,
`make test-tgt-obs`, `make test-tgt-obs-fuzz`, and `make bench`.

For a quick kernel verification, leave the named VM running and query it over
SSH:

```sh
make vm KERNEL=6.18 VM_NAME=kernel-6.18
make vm-ssh VM_NAME=kernel-6.18 \
  VM_SSH_COMMAND='uname -a; test -r /sys/kernel/btf/vmlinux && echo BTF=present'
make vm-stop VM_NAME=kernel-6.18
```

The VM image uses the selected kernel's `bzImage`; the host userspace bundle
continues to use the repository's bpf-next build dependencies. Shirudo's
documented feature floor is 7.2, so 6.18/6.12/6.6/6.1 are compatibility
probes: they may boot while Shirudo preparation or target tests fail because
required signed-loading or bpffs features are absent. Treat a kernel as
verified only when the requested command or test exits successfully, and
retain the VM logs for failures.

The VM commands build or reuse the host bundle automatically. To build it
explicitly, use:

```sh
make test-vm-bundle
```

`make bundle` is an alias for that target. The bundle contains the target
payload and prebuilt target-test fixtures and is cached under
`build/test-vm/host-bundle`.

The bundle build also prepares or reuses a content-keyed runtime QCOW2 under
`build/test-vm/cache/runtime`. The image contains the guest runtime packages,
so normal VM boots do not run `apt update` or install packages. Runtime image
preparation requires `virt-customize` from `libguestfs-tools` and uses the
selected rootfs digest and package manifest as its cache key.

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

The command prints the retained state directory and the access commands when
the guest is ready. Attach to the interactive serial console with:

```sh
make vm-console VM_NAME=policy-session
```

Detach from the console with `Ctrl-]`; the VM continues running. Open a root
shell over the loopback-only SSH forward with:

```sh
make vm-ssh VM_NAME=policy-session
```

Run one exploratory command instead of opening a shell with:

```sh
make vm-ssh VM_NAME=policy-session \
  VM_SSH_COMMAND='shirudo status --json --include-tpm'
```

Console and SSH access require a named VM. SSH uses a per-VM ephemeral key
and a dynamically allocated localhost port; set `TEST_VM_SSH_PORT` when a
fixed port is needed.

Run the target-side integration suite in a test-mode VM:

```sh
make test-tgt
```

Use `VM_NAME=name` for a predictable retained state directory and
`TEST_VM_VERBOSE=1` to stream the guest console while the suite runs. The
compatibility alias `make test-vm` has the same behavior as `make test-tgt`.
Test-mode VMs are stopped after the suite and retained for inspection.

The default kernel is
`artifacts/bpf-next-kernel-debs/bzImage`, produced by `make bpf-next`. A
stable `KERNEL=6.18` selection uses
`artifacts/linux-v6.18-kernel-debs/bzImage`, or a commit-keyed path when
`KERNEL_COMMIT` is set. A local raw kernel can be selected
with `TEST_VM_KERNEL=/path/to/bzImage`; a remote kernel requires both
`TEST_VM_KERNEL_URL` and its 64-hex-digit `TEST_VM_KERNEL_SHA256`. Resource and
location overrides include
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

This builds the operator tools and runs only the `t0xxx` operator/build suite.
It is safe without root, a BPF LSM, or a target kernel.

Target-side integration tests:

```sh
make test-tgt
```

This prepares the host bundle, boots the vTPM VM, imports the signed fixtures,
and runs all target tests (`t1101` through `t1117`, plus
`t1200-target-fixtures.sh`). These tests require root and the attached Shirudo
BPF LSM, which the VM setup provides. All BPF/upatch test fixtures are built
by the host bundle builder; the guest needs only runtime dependencies. Use
`VM_NAME` and `TEST_VM_VERBOSE=1` as needed.

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
