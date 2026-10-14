..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

System requirements
===================

This is the single list of what a host needs before shirudo is built,
installed or initialised on it.  The operator and target roles have
different needs; a development host that plays both needs the union.
shirudo assumes the current upstream kernel and toolchain and has no
fallback paths for older ones, so a missing item here fails loudly at
build or pre-flight time rather than degrading silently.


1) Target kernel
----------------

The target runs a current upstream Linux kernel with the signed-loader
ABI: ``struct bpf_map`` carries ``sha`` and ``excl_prog_sha``, ``struct
bpf_prog_aux`` carries ``sig``, and ``union bpf_attr`` carries
``signature_size``.  The ``shirudo init`` pre-flight checks the
kernel's BTF for these (``signed_loader_kernel_abi``) and refuses
without them; a load on such a kernel reports
``kernel_abi_unsupported``.  The following options must be enabled.
``contrib/kernel-small.config`` carries the same list for the test VM
kernel.

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Option
     - Why shirudo needs it
   * - ``CONFIG_BPF``, ``CONFIG_BPF_SYSCALL``, ``CONFIG_BPF_JIT``
     - The ``bpf()`` syscall, the JIT and bpffs, for the loaders, the
       enforcement programs and the private pin mount.
   * - ``CONFIG_BPF_LSM``, ``CONFIG_SECURITY``, ``bpf`` in
       ``CONFIG_LSM`` (or ``lsm=`` on the kernel command line)
     - The ``lsm/bpf`` and ``lsm/bpf_prog_load`` gates, the bpffs and
       mount guards, and the filesystem seal.
   * - ``CONFIG_SECURITYFS``
     - ``/sys/kernel/security/lsm``, which the pre-flight reads to
       confirm the BPF LSM is active (``bpf_lsm_active``).
   * - ``CONFIG_DEBUG_INFO_BTF``
     - CO-RE relocation of every shipped and user-built BPF program,
       ``vmlinux.h`` generation, and the ABI check above.
   * - ``CONFIG_KEYS``, ``CONFIG_ASYMMETRIC_KEY_TYPE``,
       ``CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE``
     - The sealed ``shirudo`` keyring that holds the operator
       certificate.
   * - ``CONFIG_X509_CERTIFICATE_PARSER``,
       ``CONFIG_PKCS7_MESSAGE_PARSER``,
       ``CONFIG_SYSTEM_DATA_VERIFICATION``
     - Parsing ``cert.der`` at ``add_key(2)`` and verifying the
       detached CMS signature at ``BPF_PROG_LOAD``.  The last one is
       usually pulled in by module signing or IMA; set it explicitly
       on a kernel that has neither.
   * - ``CONFIG_CRYPTO_MLDSA``
     - Verification of ML-DSA-87 (FIPS 204) signatures and
       certificates, the only kind shirudo produces.  Without it the
       kernel rejects the certificate at ``add_key(2)``; ``shirudo
       init`` reports the ``cert_kernel_support`` pre-flight failure
       and a load reports ``signature_unsupported``.
   * - ``CONFIG_CRYPTO_SHA512``
     - The signed-attributes digest OpenSSL 3.x emits next to an
       ML-DSA signature; ``CONFIG_CRYPTO_MLDSA`` does not select it.
   * - ``CONFIG_CRYPTO_SHA256``
     - ``excl_prog_hash``, ``payload_sha256``, the TPM chain and the
       eventlog digests.
   * - ``CONFIG_TCG_TPM`` plus a TPM driver (``CONFIG_TCG_TIS``,
       ``CONFIG_TCG_CRB``, or the platform's virtual TPM)
     - The NV-extend measurement chain.  A TPM 2.0 is mandatory; there
       is no unmeasured mode.  ``contrib/swtpm.sh`` provides a software
       TPM for machines without one.
   * - ``CONFIG_BPF_EVENTS``, ``CONFIG_FUNCTION_TRACER``,
       ``CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS``
     - ``fentry``, ``fexit``, ``fmod_ret`` and kprobe attach points for
       upatches.
   * - ``CONFIG_UPROBES``, ``CONFIG_UPROBE_EVENTS``
     - ``uprobe.multi`` upatches against userspace binaries.
   * - ``CONFIG_CGROUP_BPF``
     - ``cgroup_skb`` upatches on the cgroup v2 root.
   * - ``CONFIG_NETFILTER_BPF_LINK``
     - ``netfilter`` upatches at IPv6 pre-routing.

``CONFIG_PKCS7_WAIVE_AUTHATTRS_REJECTION_FOR_MLDSA`` is not required: it
only relaxes module-signature checks, and BPF signature verification
accepts the signed-attributes form.


2) Cryptography
---------------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Use
     - Algorithm
   * - Signing key and certificate
     - ML-DSA-87 (FIPS 204, NIST category 5) and nothing else:
       ``shirudo genkey`` has no algorithm option, the builder refuses
       a classical key, the target pre-flight refuses a classical
       certificate.  The smaller ML-DSA parameter sets are not offered:
       a fleet-wide trust anchor gets the largest margin for about
       2 KiB more per signature.  The certificate is self-signed with
       the same key.
   * - ``.upatch`` loader signature
     - Detached CMS over ``loader_insns || data``.  With OpenSSL 3.x the
       SignerInfo carries signed attributes and a SHA-512 message
       digest; OpenSSL 4 signs the content directly.  The kernel
       verifies both forms; see `upatch-spec <upatch-spec.rst>`__.
   * - BPM index and upatch-tree signatures
     - Detached CMS in the same form, produced by ``shirudo-build`` on
       behalf of ``shirudo bpm push`` and ``shirudo bpm tree append``,
       verified on the target with libcrypto against the registered
       certificate.
   * - Payload, program and chain digests
     - SHA-256: ``payload_sha256``, ``excl_prog_hash``, the TPM
       NV-extend chain and the eventlog.
   * - TPM NV index authorisation
     - A SHA-256-derived auth value.  No asymmetric TPM keys are used.
   * - TLS (registries, OTLP and S3 export)
     - TLS 1.3 only with hybrid ML-KEM key exchange only
       (X25519MLKEM768, SecP256r1MLKEM768), on every libcurl client in
       both profiles.  A server that offers only classical groups is
       refused; there is no fallback.  Server certificates are whatever
       the registry or collector presents.


3) Operator host
----------------

* A C toolchain (``cc``, ``make``, ``pkg-config``).
* Current upstream ``clang`` and ``llvm`` with the BPF target, for
  ``shirudo build`` and the embedded enforcement programs.
* OpenSSL 3.5 or newer: ``libcrypto`` and ``libssl`` development files
  and the ``openssl`` command.  3.5 is the first release with ML-DSA;
  the build probe refuses older versions.
* ``libelf``, ``zlib``, ``libcurl`` 7.75 or newer, ``libluajit-5.1``
  and tpm2-tss (``tss2-esys`` 4.0 or newer, ``tss2-tctildr``)
  development files.
* No kernel tree: libbpf, its BPF-side headers and the BPF UAPI headers
  are vendored under ``vendor/libbpf``, and ``vmlinux.h`` is generated
  by the in-tree ``tools/gen-vmlinux-h`` into ``vendor/linux/`` (never
  committed), so neither a submodule nor bpftool is needed.  ``make
  update-bpf-deps`` refreshes the vendored copy from a kernel tree on
  demand.
* Nothing else: packages, indexes and trees are built and published
  through the same ``shirudo-build`` helper.

The operator never needs a TPM, the kernel keyring or ``CAP_BPF``; only
the private key under ``/var/lib/shirudo/keys/``.


4) Target host
--------------

* The kernel configuration above, booted with the BPF LSM enabled.
* Root (``CAP_SYS_ADMIN``, ``CAP_BPF``) for ``shirudo init`` and every
  state-changing command.
* The target binary from ``make target`` links OpenSSL, libcurl,
  tpm2-tss, libbpf, libelf, zlib, zstd, jitterentropy and LuaJIT
  statically and needs only the C library at runtime, so it runs on a
  distribution whose own OpenSSL predates ML-DSA.
* A TPM 2.0 exposed as ``/dev/tpmrm0`` (discrete, firmware or cloud
  vTPM), or a software TPM reachable through ``tpm.tcti``.  TPM 1.2 is
  refused; there is no opt-out.
* ``systemd`` for the boot unit and the timers.
* x86_64 or arm64.

Operator and target may be on different architectures; the artifact
format is little-endian and the signature is architecture-neutral.


5) Build host for the target binary
-----------------------------------

``make target`` runs ``make target-deps`` first, which builds OpenSSL,
an OpenSSL-backed libcurl and tpm2-tss from source and stages them as
static archives.  The build host then needs static ``libelf``,
``zlib``, ``zstd``, ``jitterentropy`` and ``libluajit-5.1`` archives;
``SHIRUDO_TARGET_STATIC_LIBDIR`` names their directory when it is not
the system one.  The operator package, by contrast, links the host's
shared libraries and must be built on the distribution it is installed
on.
