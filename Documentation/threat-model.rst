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
