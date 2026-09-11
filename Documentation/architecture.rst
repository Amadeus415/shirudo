.. SPDX-License-Identifier: BSD-2-Clause
.. Copyright (c) 2026 Authors of shirudo

=====================
shirudo architecture
=====================

This document describes the implemented architecture. ``PLAN.md``
contains the historical implementation plan and deferred work; this
document is the source of truth for the current command and package
boundaries.

What shirudo is
===============

shirudo is a BPF LSM-based security platform. Once initialized on a
target, the kernel accepts BPF programs from userspace only when the
program carries a valid PKCS#7 signature for the certificate in the
``shirudo`` kernel keyring. Signed loader programs install the
requested upatch, and shirudo pins the resulting links and maps under
``/var/lib/shirudo/bpffs/``.

Root modes and legacy kernels
=============================

Initialization commits one immutable root mode in
``/var/lib/shirudo/mode``. The default ``untrusted-root`` mode uses the
native kernel signature ABI: the kernel verifies the CMS signature and
the BPF LSM admission hook checks the resulting ``bpf_prog_aux.sig``
verdict. ``shirudo init --trusted-root`` commits the alternate
``trusted-root`` mode for userspace-authorized loading. A later
``init`` cannot change the committed mode or certificate digest.

Trusted-root always reads the public certificate from
``/var/lib/shirudo/keys/cert.der``, verifies the detached CMS signature
over ``loader_insns || data`` in userspace, and sends an unsigned outer
``BPF_PROG_TYPE_SYSCALL`` loader to the kernel. There is no literal
userspace access to ``bpf_prog_aux.sig``; that is kernel-private state.
The native kernel signature path remains available only in
``untrusted-root`` mode.
The legacy embedded BPF-LSM object has no signature-field references and
does not attach ``lsm/bpf_prog_load``. Its ``lsm/bpf`` hook permits an
unsigned outer loader only when its caller's executable ``(device,inode)``
matches the identity frozen by the first initialization. Other userspace
BPF loads remain denied.

The target never needs the private signing key. Only the public
certificate, its committed SHA-256 digest, and transient parsed public-key
and signature buffers are held by target userspace during verification.
Status JSON and the periodic ``shirudo.keepalive`` event include
``mode``, ``mode_committed``, ``kernel_signature_supported``, and
``load_authorization`` so monitoring can distinguish the two policies.

shirudo is agentless on the target. There is no long-lived shirudo
daemon and no shirudo-owned listening socket. The systemd unit used
for reboot persistence is ``Type=oneshot``; ordinary target
operations are one-shot CLI invocations run locally or through the
system's existing ``sshd``.

The operator/target split
=========================

The operator holds the private signing key and runs the build/sign
pipeline. The target holds only the public certificate, the target
binary, and its sealed kernel state.

The operator package includes ``shirudo-build``, clang, and the
crypto needed to create signed artifacts. The target package contains
the target-profile ``shirudo`` binary and its target runtime
dependencies. The target does not need the operator build helper or
the operator's private key.

Artifact movement is deliberately outside shirudo:

::

    # operator
    shirudo genkey
    shirudo build fix.bpf.c -o fix.upatch
    scp fix.upatch user@target:/tmp/

    # target
    ssh user@target sudo shirudo upatch load /tmp/fix.upatch
    ssh user@target sudo shirudo status --include-tpm

The same path applies to signed unload directives:

::

    shirudo build --unload fix -o fix.unload.upatch
    scp fix.unload.upatch user@target:/tmp/
    ssh user@target sudo shirudo upatch unload fix

The standard OpenSSH client, bastion configuration, credentials, and
host-key policy remain the operator's responsibility. shirudo does not
implement transport, remote registries, fleet selection, or fleet
aggregation.

End-to-end flow charts
======================

The following charts show the package-manager and observability paths in
their implementation order.  A ``.bee`` is the OCI-published package
envelope; it contains one or more ``.upatch`` artifacts.

Build and publish
-----------------

::

    C source/object (.bpf.c/.bpf.o) --+
                                       +--> bpm build
    Java agent (.jar) -----------------+        |
                                                +-------------------------+
                                                |                         |
                                                v                         v
                                  C: compile/gen_loader/sign  Java: package JAR
                                                |                         |
                                                +------------+------------+
                                                             v
                                                      .upatch artifact(s)
                                                             |
                                                             v
                                             .bee package (contains .upatch)
                                                             |
                                      bpm push <package.bee> oci://...
                                                             |
                                                             v
                                                       OCI repository

``gen_loader`` and BPF CMS signing are performed by the operator-side
builder.  Java upatches carry the JAR payload and intentionally do not use
the kernel loader signing path in v1.

Pull and load
-------------

::

    OCI repository
          |
          | pull
          v
    systemd BPM update/install
    (repo update + upgrade, or bpm install)
          |
          v
    signed index and package digest checks
          |
          v
    pull .bee package
          |
          v
    unpack .bee
          |
          v
    .upatch payload
       /       \
      v         v
    Java      BPF
      |         |
      v         v
    install   kernel signature check
    JAR          |
      |         v
      v    execute embedded loader
    Java         |
    runtime     v
             BPF LSM load gate
             + filesystem seal
                   |
                   v
             pinned and active
                 upatch

The target does not run ``gen_loader``.  It verifies and executes the loader
already embedded in the signed ``.upatch`` produced during the build.

Map export
----------

::

    shirudo upatch map --otel --all
                    |
                    v
             pinned map(s)
               /       \
              v         v
       serializer     direct map reader
    (when pinned)    (other map types)
              \       /
               v     v
             LuaJIT Lua decoder
                    |
                    v
              OTLP/HTTP push
                    |
                    v
              OTEL Collector
                    |
                    v
                 ClickHouse

Serializer-backed maps use the pinned serializer program to produce the
decoder input pages; other supported map types are read directly.  Shirudo
pushes OTLP data to the Collector, while ClickHouse is a downstream
Collector destination.

There are no other channels. There is no shirudo-specific listener on
the target, no agent daemon, no out-of-band heartbeat. ``sshd`` is the
only always-on infrastructure shirudo needs.
Runtime design
==============

The core binary does not fork or exec external runtime tools. It uses
system libraries and direct kernel interfaces for BPF, keyrings, TPM
measurement, ELF, compression, and cryptography. The only subprocess
exception is the operator-only ``shirudo build`` dispatch to
``shirudo-build``; that helper invokes clang to compile BPF
source.

The target profile is independent of the operator profile. It uses
the target's static mbedTLS/libcurl arrangement and shared libbpf,
libelf, zlib, and TPM2-TSS dependencies. Neither profile includes an
SSH transport library.

The signed-loader path
======================

``shirudo build`` packages a signed loader rather than signing
the user's BPF program as a directly loadable userspace object:

1. ``shirudo-build`` compiles ``.bpf.c`` when needed.
2. libbpf generates a loader that embeds the requested BPF operations.
3. The operator signs the loader and writes the ``.upatch``
   container.
4. Target-local ``shirudo upatch load`` asks the kernel to load
   the signed loader.
5. The loader creates and attaches the requested program; shirudo pins
   links and maps and records the transition.

Unload artifacts are signed directives. The target verifies the
directive and payload binding before detaching and removing the
requested upatch.

Target-local status and safety checks
=====================================

``shirudo status`` reports the local target state. It can include
TPM chain data, system information, eventlog entries, kernel log
lines, loaded modules, and pinned map contents. It never takes a
destination argument and never opens an SSH session.

State-changing ``upatch load`` and ``upatch unload``
operations perform target-local preflight checks before loading or
extending the TPM chain. A caller can supply expected chain and
version values explicitly when an external workflow needs optimistic
concurrency or version-skew protection.

Failure reporting
=================

``shirudo upatch load --report=<path>`` and the corresponding
unload command emit structured JSON containing the phase, result,
errno, category, verifier log when available, and TPM state. The
primary categories include ``verifier_rejected``,
``btf_mismatch``, ``signature_rejected``,
``lsm_denied``, and ``tampered``.

Project layout
==============

::

    shirudo/
    ├── shirudo.c              # command dispatch
    ├── builtin-*.c            # supported top-level commands
    ├── util/                  # shared userspace library
    ├── bpf/                   # signed loader and enforcement programs
    ├── include/shirudo/       # public artifact definitions
    ├── t/                     # TAP tests
    └── Documentation/         # contributor and operator documentation

The supported top-level command set is shown by
``shirudo help --list-cmds``. Target access is intentionally
provided by ordinary SSH tooling rather than by a shirudo transport
layer.
