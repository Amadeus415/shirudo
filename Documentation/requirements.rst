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
   * - ``CONFIG_CRYPTO_RSA``
     - Only for fleets that opted out with ``shirudo genkey
       --algorithm rsa-2048``.
   * - ``CONFIG_TCG_TPM`` plus a TPM driver (``CONFIG_TCG_TIS``,
       ``CONFIG_TCG_CRB``, or the virtual TPM of the platform)
     - The NV-extend measurement chain. Hosts without TPM 2.0 run
       ``shirudo init --no-tpm`` (unmeasured mode).
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
     - ML-DSA-87 (FIPS 204, NIST category 5) by default; ``shirudo
       genkey --algorithm rsa-2048`` is the only other choice, the
       classical opt-out. The smaller ML-DSA sets are not offered: a
       fleet-wide trust anchor gets the largest margin for about 2 KiB
       per signature. The certificate is self-signed with the same key.
   * - ``.upatch`` loader signature
     - Detached CMS over ``loader_insns || data``. With an ML-DSA key
       and OpenSSL 3.x the SignerInfo carries signed attributes and a
       SHA-512 message digest; OpenSSL 4 signs the content directly
       (no attributes). The kernel verifies both forms; see
       :doc:`upatch-spec`.
   * - BPM repository index and upatch tree signatures
     - Detached CMS produced by ``openssl cms -sign -md sha512``
       (signed attributes, any supported key); verified by the target
       with libcrypto against the registered certificate.
   * - Payload, program and chain digests
     - SHA-256 (``payload_sha256``, ``excl_prog_hash``, the TPM
       NV-extend chain and event log). Hash functions keep their
       security margin against quantum adversaries.
   * - TPM NV index authorization
     - SHA-256 derived auth value; no asymmetric TPM keys are used in
       the current scope.

Transport security is outside shirudo: artifact transfer rides on the
organization's SSH, and the target's BPM OCI fetches use libcurl with
the platform's TLS stack. Neither is made post-quantum by shirudo;
see :doc:`threat-model`.

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
  files. ``libbpf`` and ``bpftool`` build from the
  ``third_party/bpf-next`` submodule.
* Kernel UAPI headers new enough to carry
  ``union bpf_attr.keyring_id`` (the submodule provides them).
* Go 1.25 or newer for the BPM publisher under ``bpm/``, which calls
  the ``openssl`` command for CMS signing and therefore shares the
  OpenSSL 3.5 requirement.

The operator never needs a TPM, the kernel keyring, or ``CAP_BPF``;
only the private key under ``/var/lib/shirudo/keys/``.

Target host
===========

* The kernel configuration above, booted with the BPF LSM enabled.
* Root (``CAP_SYS_ADMIN``, ``CAP_BPF``) for ``shirudo init`` and
  every state-changing command.
* Runtime libraries for the dynamic build: ``libcrypto`` >= 3.5,
  TPM2-TSS, ``libelf``, ``zlib``, ``libcurl``, ``libluajit-5.1``. The
  static target image (``make target``) bundles them; its
  ``libcrypto.a`` must also be 3.5 or newer, and mbedTLS 3.6+ provides
  only libcurl's TLS backend there.
* A TPM 2.0 exposed as ``/dev/tpmrm0`` (discrete, firmware, cloud
  vTPM or ``swtpm``) for the measurement chain, or ``--no-tpm``.
* ``systemd`` for the reboot-persistence unit.
* A supported architecture: x86_64 or arm64.

Operator and target may be on different architectures; the artifact
format is little-endian and the signature is architecture-neutral.
