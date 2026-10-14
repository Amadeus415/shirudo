.. SPDX-License-Identifier: BSD-2-Clause
.. Copyright (c) 2026 Authors of shirudo

==================
Getting started
==================

This guide covers the current two-part workflow:

* an operator builds and signs a ``.upatch`` artifact;
* an operator uses existing ``scp``/``ssh`` access to copy the
  artifact and invoke the target-local shirudo command.

There is no shirudo-managed node registry, rollout service, or remote
status collector.

Prerequisites
=============

The operator needs a supported C/BPF toolchain, libbpf development
files, OpenSSL 3.5+ crypto development files, and the TPM2-TSS
development files required by the selected build profile. The target
needs a supported Linux kernel built with ``CONFIG_CRYPTO_MLDSA`` and
``CONFIG_CRYPTO_SHA512`` for the default ML-DSA-87 signatures, the
target runtime libraries, and root access for initialization and BPF
operations. Neither package includes an SSH transport library. The
complete list is in :doc:`requirements`.

Build the binaries
==================

From the repository root:

::

    make

The normal build produces the operator binary and target binary. Use
the repository's packaging targets when producing installable
packages. The operator-only ``shirudo-build`` helper and clang
are not needed on a target.

Inspect a BPM package
=====================

Print a package's README before installing it:

::

    shirudo bpm info ./package.bee
    shirudo bpm info oci://quay.io/namespace/package:tag

The command is available in both packages. It prints ``README.md`` from
the package directory containing ``Beefile`` and fails if either file is
missing. OCI downloads are checked against the manifest's digest and size
and removed after inspection. The command does not install or load upatches.

Build and publish a BPM package
===============================

On the operator, a ``Beefile`` next to the BPF sources describes the
package; ``shirudo bpm build`` compiles and signs every listed upatch
through ``shirudo-build`` and writes ``<name>-<version>.bee``:

::

    shirudo bpm build ./pkg --version 1.0.0 --keys-dir /var/lib/shirudo/keys
    shirudo bpm push ./pkg-1.0.0.bee oci://quay.io/namespace/pkg \
        --keys-dir /var/lib/shirudo/keys

``push`` uploads the package and its certificate and, with the signing
material, adds the version to the registry's signed index at
``shirudo/bpm-index:stable`` that targets consume with ``shirudo bpm
repo update``. Packages whose Beefile carries ``[upatches.tree]``
tables can also be appended to a signed upatch tree:

::

    shirudo bpm tree append ./pkg-1.0.0.bee oci://quay.io/namespace/tree \
        --keys-dir /var/lib/shirudo/keys
    shirudo bpm tree append ./pkg-1.0.0.bee oci://quay.io/namespace/tree \
        --keys-dir /var/lib/shirudo/keys --op delete

Both commands sign through ``shirudo-build``, so they exist only where
the operator package is installed. See ``Documentation/architecture.rst``
for the tree format.

Initialize a target
===================

Install the target package and its systemd unit, then initialize the
target as root:

::

    sudo shirudo init
    sudo shirudo status --include-tpm

A TPM 2.0 is mandatory: init refuses to complete without a measurement
chain, and there is no unmeasured mode. On a machine without a TPM,
run a software TPM with ``contrib/swtpm.sh`` and export the
``SHIRUDO_TPM_TCTI`` line it prints before initializing.

The BPF LSM and target kernel configuration must support the features
described in ``Documentation/architecture.rst``, including native kernel
BPF-signature support; the init pre-flight refuses a kernel without it.
The init command installs the public certificate into the target
keyring, attaches the enforcement links, and prepares the private bpffs
state. It also removes state an older version may have left for
features that no longer exist, such as the mode record under
``/var/lib/shirudo`` or an installed Java agent and its
``/etc/environment.d/shirudo.conf`` selector. The target stores only
the public ``cert.der``; the private ``signing_key.pem`` remains on
the operator/build host.

Create a signing key
====================

On the operator machine:

::

    sudo shirudo genkey

This writes an ML-DSA-87 (FIPS 204, post-quantum) private key and a
self-signed certificate. There is no other key type: the builder
refuses classical signing keys, and the target's pre-flight refuses a
classical certificate. ``shirudo keys`` prints the algorithm and
fingerprints of the material on disk.

Transfer the generated public certificate to the target through the
organization's normal provisioning path. Do not copy the private
signing key to a target. The exact key directory can be selected with
the command's existing options; keep it readable only by the signing
operator.

Build a signed upatch
=====================

Build from BPF source:

::

    shirudo build my-fix.bpf.c -o my-fix.upatch

Or build from an already compiled BPF object:

::

    shirudo build my-fix.bpf.o -o my-fix.upatch

The build command compiles source when necessary, generates the signed
loader, and writes the artifact. Review it before transfer:

::

    shirudo upatch info --json cve-2026-31431.upatch

Copy and load
=============

Use the existing SSH setup for the target:

::

    scp cve-2026-31431.upatch user@target:/tmp/
    ssh user@target sudo shirudo upatch load \
        /tmp/cve-2026-31431.upatch

The load and its signature verification happen on the target. A
preflight can be made stricter by supplying the expected chain or
version values:

::

    ssh user@target sudo shirudo upatch load \
        --expect-chain=<hex> --expect-version-id=<hex> \
        /tmp/cve-2026-31431.upatch

Inspect target state
====================

All status and inspection commands are local to the machine on which
they run:

::

    ssh user@target sudo shirudo status --include-tpm
    ssh user@target sudo shirudo upatch list
    ssh user@target sudo shirudo bpm list
    ssh user@target sudo shirudo upatch info --json \
        /tmp/cve-2026-31431.upatch

``shirudo bpm uninstall <package>`` detaches a package's upatches through
the signed unload directives it shipped and removes it.

For an artifact already loaded on the target:

::

    ssh user@target sudo shirudo upatch get cve-2026-31431
    ssh user@target sudo shirudo upatch map cve-2026-31431 <map-name>

Structured load/unload reports can be written on the target with
``--report=<path>``. If a report is needed elsewhere, copy it
back with ``scp``.

Unload a signed upatch
======================

Create an unload directive on the operator, then transfer it:

::

    shirudo build --unload cve-2026-31431 \
        -o cve-2026-31431.unload.upatch
    scp cve-2026-31431.unload.upatch user@target:/tmp/
    ssh user@target sudo shirudo upatch unload cve-2026-31431

The target validates the directive and its payload binding before
detaching the upatch.

Troubleshooting
===============

* ``signature_rejected`` or ``keyring_missing``: verify that
  the target was initialized with the matching public certificate.
* ``signature_unsupported``, or a ``cert_kernel_support`` pre-flight
  failure from ``shirudo init``: the target kernel cannot verify
  ML-DSA. Enable ``CONFIG_CRYPTO_MLDSA`` and ``CONFIG_CRYPTO_SHA512``
  (see :doc:`requirements`).
* A ``cert_algorithm`` pre-flight failure: the provisioned ``cert.der``
  is not ML-DSA-87. Re-key with ``shirudo genkey`` on the operator.
* ``tpm_error`` or a ``tpm2_reachable`` pre-flight failure: shirudo
  requires a TPM 2.0 and a definable NV index. Check ``/dev/tpmrm0``,
  the ``tpm.tcti`` setting for a software TPM, and ``tpm.owner_auth``
  on a TPM whose owner hierarchy is password-protected.
* ``verifier_rejected``: inspect the verifier log in the
  structured report and rebuild against the target's BTF.
* ``btf_mismatch``: regenerate ``vmlinux.h`` from the target
  kernel and rebuild.
* ``tampered``: inspect local bpffs, LSM, keyring, and TPM state
  with ``shirudo status``; retry only after the local state is
  understood.
* SSH transport failures are handled by the existing SSH setup. Check
  the destination, credentials, host keys, and sudo policy independently
  of shirudo.
