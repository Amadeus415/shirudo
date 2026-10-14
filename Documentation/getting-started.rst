.. SPDX-License-Identifier: BSD-2-Clause
.. Copyright (c) 2026 Authors of shirudo

==================
Getting started
==================

This guide covers the current workflow:

* an operator builds and signs ``.upatch`` artifacts and publishes
  them as packages to an OCI registry;
* a target registers that repository and installs or upgrades from it,
  on systemd timers or by hand.

A single artifact can also be loaded from a local file. There is no
shirudo-managed node registry, rollout service, or remote status
collector; delivery is pull-based.

Prerequisites
=============

The operator needs a supported C/BPF toolchain, libbpf development
files, OpenSSL 3.5+ crypto development files, and the TPM2-TSS
development files required by the selected build profile. The target
needs a supported Linux kernel built with ``CONFIG_CRYPTO_MLDSA`` and
``CONFIG_CRYPTO_SHA512`` for the default ML-DSA-87 signatures, the
target runtime libraries, and root access for initialization and BPF
operations. The complete list is in :doc:`requirements`.

Build the binaries
==================

From the repository root:

::

    make

The normal build produces the operator binary and target binary. Use
the repository's packaging targets when producing installable
packages: ``make bindeb-pkg`` writes a ``shirudo-target`` and a
``shirudo-operator`` .deb, ``make binrpm-pkg`` the same two packages as
RPMs. The operator-only ``shirudo-build`` helper and clang are not
needed on a target.

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

Install from the registry
=========================

On the target, register the repository once with the operator's
certificate, then let the timers refresh the signed index and upgrade,
or do it by hand:

::

    sudo shirudo bpm config register add ns oci://quay.io \
        --key-file cert.der
    sudo shirudo bpm repo update
    sudo shirudo bpm install ns/pkg
    sudo shirudo bpm list

``shirudo bpm install oci://quay.io/namespace/pkg:1.0.0`` installs a
package directly by reference. Targets that follow a signed upatch tree
configure it in ``/etc/shirudo/bpm/upatch-tree.conf`` and run
``shirudo bpm tree sync`` on its timer.

Load a local artifact
=====================

A single ``.upatch`` copied to the target loads the same way a package
member does:

::

    sudo shirudo upatch load /tmp/cve-2026-31431.upatch

The load and its signature verification happen on the target. A
preflight can be made stricter by supplying the expected chain or
version values:

::

    sudo shirudo upatch load \
        --expect-chain=<hex> --expect-version-id=<hex> \
        /tmp/cve-2026-31431.upatch

Inspect target state
====================

All status and inspection commands are local to the machine on which
they run:

::

    sudo shirudo status --include-tpm
    sudo shirudo upatch list
    sudo shirudo bpm list
    sudo shirudo upatch info --json /tmp/cve-2026-31431.upatch

``shirudo bpm uninstall <package>`` detaches a package's upatches through
the signed unload directives it shipped and removes it.

For an artifact already loaded on the target:

::

    sudo shirudo upatch get cve-2026-31431
    sudo shirudo upatch map cve-2026-31431 <map-name>

Structured load/unload reports can be written on the target with
``--report=<path>``; ``shirudo status --otel`` and the map exporter
push state to an OTLP collector.

Unload a signed upatch
======================

Packages carry their unload directives, so ``sudo shirudo bpm
uninstall <package>`` detaches everything a package loaded. For a
locally loaded artifact, create the directive on the operator and copy
it to the target:

::

    shirudo build --unload cve-2026-31431 \
        -o cve-2026-31431.unload.upatch
    sudo shirudo upatch unload /tmp/cve-2026-31431.unload.upatch

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
* Registry fetch failures: check the ``oci://`` endpoint, the
  ``BPM_OCI_*`` environment, the registered certificate under
  ``/etc/shirudo/bpm``, and that the registry offers TLS 1.3 with a
  hybrid ML-KEM group; shirudo never falls back to classical TLS.
