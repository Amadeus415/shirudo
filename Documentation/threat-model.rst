.. SPDX-License-Identifier: BSD-2-Clause
.. Copyright (c) 2026 Authors of shirudo

==========================
shirudo threat model
==========================

Scope
=====

shirudo protects a Linux target after ``shirudo init`` has attached
its BPF LSM enforcement programs. The target's kernel verifies signed
loader programs, and the target-local CLI manages the resulting links,
maps, and audit state.

The operator builds and signs artifacts. Artifact transfer and command
invocation use the organization's existing SSH tooling; they are
outside shirudo's trust boundary. shirudo does not provide an SSH
client, remote registry, fleet selector, rollout coordinator, or
remote status aggregator.

Assets
======

* The private signing key on the operator.
* The public certificate and sealed ``shirudo`` keyring on the
  target.
* Signed loader artifacts and their payload bindings.
* Target BPF links, maps, filesystem pins, and TPM measurement chain.
* Target status and failure reports.

Trust boundaries
================

The target kernel is trusted to enforce BPF LSM hooks, signature
verification, keyrings, and the configured TPM interfaces. The target
binary, its signed enforcement programs, and the certificate in the
keyring are part of the target TCB.

The operator host, build toolchain, package manager, private key, and
existing SSH infrastructure are trusted according to the operator's
deployment policy. shirudo does not make SSH credentials, bastions,
host-key files, or the SSH server part of its own TCB.

Threats addressed
=================

Unsigned BPF injection
----------------------

After initialization, the BPF LSM denies userspace BPF loads that do
not satisfy the signature/keyring policy. This includes root and
processes with the ordinary administrative capabilities. Signed
loader programs remain the controlled way to install an upatch.

Unmeasured state
----------------

The TPM measurement chain is mandatory. ``shirudo init`` refuses to
complete without a reachable TPM 2.0 and a definable NV index, and an
operator-driven load or unload whose chain extension fails reports
``tpm_error`` instead of succeeding unmeasured. A target without a
live chain is therefore either not initialized or an incident, never
an accepted configuration.

Tampering with shirudo state
----------------------------

Enforcement links, upatch links, maps, and protected metadata are
pinned under the private bpffs and protected by the installed BPF
filesystem and mount-lifecycle hooks. Target-local preflight checks
validate the expected local state before a state-changing operation.

Unauthorized artifact changes
-----------------------------

The target verifies the artifact signature before the loader runs.
Unload directives are bound to the payload they remove, so a signed
directive cannot silently remove a different loaded payload.

State ambiguity
---------------

Target-local status and structured reports expose the local result,
TPM chain, verifier log, and failure category. External automation can
collect those reports over its own SSH or monitoring path. shirudo
does not claim to provide a complete or synchronized fleet view.

Cryptographic algorithms
========================

shirudo's own trust anchors are post-quantum by default. ``shirudo
genkey`` produces an ML-DSA-87 (FIPS 204) key and self-signed
certificate, every ``.upatch`` loader is CMS-signed with that key, and
the BPM index and upatch-tree signatures use the same key. The kernel
verifies ML-DSA natively (``CONFIG_CRYPTO_MLDSA``), so no userspace
verifier is on the load path. Long-lived fleets and embedded devices
that cannot be re-keyed quickly are the reason: a signature scheme a
quantum adversary can forge would let such an adversary install BPF on
every target that still trusts the old certificate. ML-DSA-87 keeps the
anchor ahead of the 2029 migration horizon published by the major
browser and cloud programs. There is no classical option: ``genkey``
produces nothing else, the builder refuses a classical signing key, and
the target pre-flight refuses a classical certificate, so a fleet cannot
drift back by misconfiguration.

Digests stay SHA-256 (payload, program and TPM chain) and SHA-512 (the
CMS signed-attributes digest). Hash functions retain roughly half their
bit strength against Grover-style search, which leaves both well above
the 128-bit margin.

Residual classical cryptography is outside shirudo's trust boundary:

* The organization's SSH transport (OpenSSH already negotiates a
  hybrid ML-KEM key exchange by default; host-key signatures remain
  the operator's policy).
* TLS to OCI registries and telemetry collectors. shirudo's clients
  on both profiles and the Go publisher require TLS 1.3 and a hybrid
  ML-KEM key exchange; a server that offers only classical groups is
  refused rather than downgraded. Server certificates remain classical
  WebPKI, which is an authentication rather than a confidentiality
  exposure. Artifacts fetched this way are still authenticated by their
  ML-DSA CMS signature.
* Future TPM attestation keys (``TPM2_NV_Certify``) would be RSA or
  ECC until TPM vendors ship post-quantum attestation.

Threats outside scope
=====================

* Compromise of the operator or signing key.
* A malicious or compromised Linux kernel, BPF verifier, TPM, or
  hardware.
* Compromise of the existing SSH client, SSH server, credentials,
  bastion, host-key policy, or network.
* Denial of service, including removal of the target binary or making
  the target unreachable.
* Correctness of the BPF payload written by an authorized signer.
* Fleet inventory, rollout ordering, retries, scheduling, and
  cross-target consistency.

Operational mitigations
=======================

Protect the signing key with filesystem and operator-host controls.
Use the organization's normal SSH host-key, credential, bastion, and
sudo policies. Generate artifacts against the target kernel's BTF,
review structured verifier failures, and inspect target-local status
after every load or unload.

The target's systemd oneshot unit re-runs initialization on reboot
according to the unit's ordering. Operators should still verify
target-local status after boot and treat unavailable or tampered state
as an incident rather than assuming that a previous load persisted.
