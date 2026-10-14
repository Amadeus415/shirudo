.. SPDX-License-Identifier: BSD-2-Clause
.. Copyright (c) 2026 Authors of shirudo

=====================
shirudo architecture
=====================

This document describes the implemented architecture and is the source
of truth for the current command and package boundaries; deferred work
is listed at the end of :doc:`threat-model`.

What shirudo is
===============

shirudo is a BPF LSM-based security platform. Once initialized on a
target, the kernel accepts BPF programs from userspace only when the
program carries a valid PKCS#7 signature for the certificate in the
``shirudo`` kernel keyring. Signed loader programs install the
requested upatch, and shirudo pins the resulting links and maps under
``/var/lib/shirudo/bpffs/``.

Signature verification is kernel-only: the kernel verifies the CMS
signature at ``BPF_PROG_LOAD`` and the BPF LSM admission hook checks the
resulting ``bpf_prog_aux.sig`` verdict against the sealed ``shirudo``
keyring. A target kernel without that ABI fails the ``shirudo init``
pre-flight; there is no userspace verification fallback. The target
never needs the private signing key.

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

    C source/object (.bpf.c/.bpf.o)
                   |
                   v
           shirudo bpm build
                   |
                   v
        compile / gen_loader / sign
             (shirudo-build)
                   |
                   v
            .upatch artifact(s)
                   |
                   v
      .bee package (contains .upatch)
                   |
    shirudo bpm push <package.bee> oci://...
                   |
                   v
      OCI repository + signed index
    (shirudo/bpm-index:stable, CMS by
            shirudo-build --sign)

``shirudo bpm build``, ``push`` and ``tree append`` are implemented in the
operator-side ``shirudo-build`` helper, not in the ``shirudo`` binary
shipped to targets: the core binary only execs the helper with the
argument vector. ``gen_loader``, BPF CMS signing and the detached CMS
over the repository index and tree publications therefore happen in one
process that links the signer, while the target binary carries neither
the signer nor the publishing code. ``bpm push`` updates the index only
when given the signing material (``--keys-dir`` or
``--index-cert``/``--index-key``); published versions are immutable, so
an index that already lists the version with different digests is
refused.

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
          |
          v
    kernel signature check
          |
          v
    execute embedded loader
          |
          v
    BPF LSM load gate
    + filesystem seal
          |
          v
    pinned and active
        upatch

The target does not run ``gen_loader``.  It verifies and executes the loader
already embedded in the signed ``.upatch`` produced during the build.

Optional append-only upatch tree
--------------------------------

Targets may additionally consume a CMS-signed, globally ordered upatch tree
from an OCI repository.  ``shirudo bpm tree sync`` evaluates each operation's
kernel-release, architecture, Kconfig, and node-label selectors locally, then
downloads and applies only matching immutable ``.upatch`` artifacts in
sequence order.  Each node's selector-specific projection is reported from a
dedicated TPM NV chain when available.
Publications are authenticated by their CMS signature, OCI digests, operation
digests, and sequence continuity; this version has no global tree-root value.
The feature is enabled by
``/etc/shirudo/bpm/upatch-tree.conf`` and its 60-second timer, while omitting
that file preserves manual ``shirudo upatch`` loading.

Publishing a tree
~~~~~~~~~~~~~~~~~

Trees are published from a built ``.bee`` by ``shirudo bpm tree append``.
A ``[[upatches]]`` entry opts in with an ``[upatches.tree]`` table::

    [[upatches]]
    source = "fix.bpf.c"

    [upatches.tree]
    id = "fix"                                # must equal the upatch name
    load_artifact = "upatches/fix.upatch"     # default: load_target
    unload_artifact = "upatches/fix.unload.upatch"

    [upatches.tree.selector]                  # every list is optional
    architecture = ["x86_64"]
    kernel_release_prefix = ["7."]
    [upatches.tree.selector.kconfig]
    CONFIG_BPF_LSM = ["y"]
    [upatches.tree.selector.labels]
    env = ["prod"]

``shirudo bpm tree append <package.bee> oci://registry/repo [--op add|delete]
[--reference stable] [--tree-id <id>] [--keys-dir <dir>]`` fetches and
verifies the current publication (``-ENOENT`` starts generation 1 with the
package name as tree id), pushes each artifact as an immutable OCI manifest
tagged ``upatch-<id>-<payload16>``, appends one operation per entry with
``seq = head + 1``, and republishes the reference with ``generation + 1`` and
``parent_manifest_digest`` set to the manifest it replaced. The publication
is ``{"schema":2,"tree_id","generation","parent_manifest_digest"?,"base":
{"seq"},"operations":[...],"head":{"seq"}}``; each operation is
``{"seq","op","id","selector","artifact":{"repository","manifest_digest",
"layer_digest","payload_sha256"},"operation_digest"}`` where
``operation_digest`` is the SHA-256 of the compact JSON of the same object
without that field, selector keys and list values sorted. The payload and
its detached CMS signature are the two layers of the ``stable`` manifest.
A ``delete`` operation publishes the entry's unload directive and is
accepted by the target only for an id it loaded from the same tree.

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

The target profile is independent of the operator profile. Both
profiles run on OpenSSL 3.5 or newer: libcrypto for certificates, CMS
and digests, libssl behind libcurl for TLS, so ML-DSA signatures and
the hybrid ML-KEM key exchange come from one implementation. The
operator links the system shared libraries; the target links a static
OpenSSL, an OpenSSL-backed static libcurl and static TPM2-TSS that
``make target-deps`` builds from source, plus libbpf, libelf and zlib.
Neither profile includes an SSH transport library. The default signing
algorithm is ML-DSA-87; see :doc:`requirements` for the kernel and
toolchain prerequisites that implies.

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
``btf_mismatch``, ``signature_rejected``, ``signature_unsupported``
(the kernel lacks the signature's algorithm, typically
``CONFIG_CRYPTO_MLDSA``), ``lsm_denied``, and ``tampered``.

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
