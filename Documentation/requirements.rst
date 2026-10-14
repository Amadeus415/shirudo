.. SPDX-License-Identifier: BSD-2-Clause
.. Copyright (c) 2026 Authors of shirudo

====================
System requirements
====================

This page is the single list of what a host needs before shirudo is
built, installed, or initialized on it. The operator and target roles
have different needs; a development host that plays both roles needs
the union. shirudo assumes the current upstream kernel and toolchain
and has no fallback paths for older ones (see
:doc:`architecture`), so a missing item here fails loudly at build
or pre-flight time rather than degrading silently.

Target kernel
=============

The target runs a current upstream Linux kernel with signed-BPF
support (``union bpf_attr.signature_size`` present in the kernel's
BTF; ``shirudo init`` pre-flight checks this). The following options
must be enabled. ``contrib/kernel-small.config`` and
``contrib/build-kernel-package.sh`` carry the same list for the test
VM kernels.

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Option
     - Why shirudo needs it
   * - ``CONFIG_BPF``, ``CONFIG_BPF_SYSCALL``, ``CONFIG_BPF_JIT``
     - The ``bpf()`` syscall and JIT for the loader and LSM programs.
   * - ``CONFIG_BPF_LSM``, ``CONFIG_SECURITY``, ``bpf`` in ``CONFIG_LSM``
       (or ``lsm=`` on the kernel command line)
     - The ``lsm/bpf`` and ``lsm/bpf_prog_load`` enforcement hooks and
       the filesystem/mount guards.
   * - ``CONFIG_DEBUG_INFO_BTF``
     - CO-RE relocation of every shipped and user-built BPF program;
       ``vmlinux.h`` generation.
   * - ``CONFIG_BPF_FS``
     - The private bpffs mount under ``/var/lib/shirudo/bpffs``.
   * - ``CONFIG_KEYS``, ``CONFIG_ASYMMETRIC_KEY_TYPE``,
       ``CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE``
     - The sealed ``shirudo`` keyring that holds the operator
       certificate.
   * - ``CONFIG_X509_CERTIFICATE_PARSER``,
       ``CONFIG_PKCS7_MESSAGE_PARSER``,
       ``CONFIG_SYSTEM_DATA_VERIFICATION``
     - Parsing ``cert.der`` and the detached CMS signature at
       ``BPF_PROG_LOAD``.
   * - ``CONFIG_CRYPTO_MLDSA``
     - **Verification of shirudo's default ML-DSA-87 (FIPS 204)
       signatures and certificates.** Without it the kernel rejects the
       cert at ``add_key(2)``; ``shirudo init`` reports this as the
       ``cert_kernel_support`` pre-flight failure.
   * - ``CONFIG_CRYPTO_SHA512``
     - The signed-attributes digest that OpenSSL 3.x emits next to an
       ML-DSA signature; ``CONFIG_CRYPTO_MLDSA`` does not select it.
   * - ``CONFIG_CRYPTO_SHA256``
     - ``excl_prog_hash``, ``payload_sha256`` and the TPM chain
       digests.
   * - ``CONFIG_TCG_TPM`` plus a TPM driver (``CONFIG_TCG_TIS``,
       ``CONFIG_TCG_CRB``, or the virtual TPM of the platform)
     - The NV-extend measurement chain. A TPM 2.0 is mandatory;
       ``shirudo init`` has no unmeasured mode (``contrib/swtpm.sh``
       provides a software TPM for machines without one).
   * - ``CONFIG_UPROBES``, ``CONFIG_FUNCTION_TRACER``,
       ``CONFIG_CGROUP_BPF``
     - Attach points used by upatches (uprobe-multi, fentry/fexit,
       cgroup programs).
   * - ``CONFIG_SECURITYFS``
     - ``/sys/kernel/security/lsm``, which the pre-flight reads to
       confirm the BPF LSM is active.

``CONFIG_PKCS7_WAIVE_AUTHATTRS_REJECTION_FOR_MLDSA`` is **not**
required: it only relaxes module-signature checks, and BPF signature
verification already accepts the signed-attributes form.

Cryptographic algorithms
========================

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Use
     - Algorithm
   * - Signing key and certificate
     - ML-DSA-87 (FIPS 204, NIST category 5), and nothing else:
       ``shirudo genkey`` has no algorithm option, the builder refuses
       a classical signing key, and the target pre-flight refuses a
       classical certificate. The smaller ML-DSA sets are not offered:
       a fleet-wide trust anchor gets the largest margin for about
       2 KiB per signature. The certificate is self-signed with the
       same key.
   * - ``.upatch`` loader signature
     - Detached CMS over ``loader_insns || data``. With an ML-DSA key
       and OpenSSL 3.x the SignerInfo carries signed attributes and a
       SHA-512 message digest; OpenSSL 4 signs the content directly
       (no attributes). The kernel verifies both forms; see
       :doc:`upatch-spec`.
   * - BPM repository index and upatch tree signatures
     - Detached CMS in the same form as a loader signature, produced
       by ``shirudo-build --sign`` on behalf of ``shirudo bpm push``
       and ``shirudo bpm tree append``; verified by the target with
       libcrypto against the registered certificate.
   * - Payload, program and chain digests
     - SHA-256 (``payload_sha256``, ``excl_prog_hash``, the TPM
       NV-extend chain and event log). Hash functions keep their
       security margin against quantum adversaries.
   * - TPM NV index authorization
     - SHA-256 derived auth value; no asymmetric TPM keys are used in
       the current scope.

   * - TLS (BPM registry fetches, OTLP and S3 export)
     - TLS 1.3 only and hybrid ML-KEM key exchange only
       (X25519MLKEM768, with SecP256r1MLKEM768 as the libcurl
       fallback), on every libcurl client in both profiles. A registry
       or collector that does not offer a hybrid group cannot be
       reached; there is no classical fallback.
       Server certificates are whatever the registry or collector
       presents.

Artifact transfer rides on the organization's SSH and is outside
shirudo; see :doc:`threat-model` for the residual classical pieces.

Operator host
=============

Build and sign tooling:

* A C toolchain (``cc``, ``make``, ``pkg-config``).
* Current upstream ``clang``/``llvm`` with the BPF target, for
  ``shirudo build`` and the embedded LSM programs.
* **OpenSSL 3.5 or newer** (``libcrypto``, ``libssl`` development
  files and the ``openssl`` command). 3.5 is the first release with
  ML-DSA; the build probe refuses older versions.
* ``libelf``, ``zlib``, ``libcurl`` (>= 7.75), ``libluajit-5.1`` and
  TPM2-TSS (``tss2-esys`` >= 4.0, ``tss2-tctildr``) development
  files.
* No kernel tree: ``libbpf``, its BPF-side headers and the BPF UAPI
  headers are vendored under ``vendor/libbpf`` and ``vmlinux.h`` is
  generated by the in-tree ``tools/gen-vmlinux-h`` into
  ``vendor/linux/`` (never committed), so neither a submodule nor
  bpftool is needed. ``make update-bpf-deps`` refreshes
  the vendored copy from a kernel tree on demand (``KERNEL_SRC=/path``,
  or a fresh bpf-next clone by default).
* Nothing else: BPM packages, repository indexes and upatch trees are
  built and published by ``shirudo bpm`` through the same
  ``shirudo-build`` helper, so there is no second toolchain.

The operator never needs a TPM, the kernel keyring, or ``CAP_BPF``;
only the private key under ``/var/lib/shirudo/keys/``.

Target host
===========

* The kernel configuration above, booted with the BPF LSM enabled.
* Root (``CAP_SYS_ADMIN``, ``CAP_BPF``) for ``shirudo init`` and
  every state-changing command.
* Runtime libraries for the dynamic build: ``libcrypto`` and
  ``libssl`` >= 3.5, TPM2-TSS, ``libelf``, ``zlib``, ``libcurl``,
  ``libluajit-5.1``. The static target image (``make target``) carries
  its own OpenSSL 3.5+, OpenSSL-backed libcurl and TPM2-TSS, built from
  source by ``make target-deps``; the build host then only needs static
  ``libjitterentropy``, ``libelf``, ``zlib``, ``libzstd`` and
  ``libluajit-5.1`` archives.
* A TPM 2.0 exposed as ``/dev/tpmrm0`` (discrete, firmware, cloud
  vTPM) or a software TPM reachable through ``tpm.tcti`` for the
  measurement chain. There is no opt-out.
* ``systemd`` for the reboot-persistence unit.
* A supported architecture: x86_64 or arm64.

Operator and target may be on different architectures; the artifact
format is little-endian and the signature is architecture-neutral.
