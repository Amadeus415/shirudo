..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

shirudo threat model
====================

This is the security design document.  It says what shirudo protects,
against whom, by which mechanism, and where each mechanism stops.  Read
it before changing anything on a security-relevant path: the
`architecture <architecture.rst>`__ says how the pieces fit, this
document says why they must.  A change that keeps the code's shape but
breaks one of the properties below is worse than no change, because it
ships a false sense of safety to fleets and devices that are hard to
patch.


1) Scope and assets
-------------------

shirudo protects a Linux target after ``shirudo init`` has attached its
enforcement programs.  The property it provides: from that point on,
the BPF programs running in the target kernel are exactly the set the
holder of the signing key authorised, every change to that set is
recorded in a TPM measurement an operator can check from one value, and
the target-local state shirudo depends on cannot be altered by anyone
but shirudo itself.

The assets, in the order an attacker would want them:

- the private signing key on the operator;
- the certificate on the target and the sealed ``shirudo`` keyring it
  is loaded into;
- the enforcement links and the identity map pinned in the private
  bpffs: losing them means losing enforcement;
- the loaded upatches, their pins and the payload xattrs that bind a
  pin to its artifact;
- the TPM NV chain and the eventlog that explains it;
- the installed artifacts and the configuration under
  ``/var/lib/shirudo`` and ``/etc/shirudo``;
- the status, reports and exported telemetry an operator acts on.


2) Trust boundaries
-------------------

The target trusted computing base is the kernel, with the BPF LSM
active and the signed-BPF verification path compiled in, plus shirudo:
the binary, its two embedded enforcement programs, and the certificate
in the keyring.  Every other process on the target, including root with
every capability, is outside the TCB and constrained by it.

The operator TCB is the operator host, clang/LLVM, libbpf and the
signing key.  An upatch does what its author wrote; shirudo guarantees
provenance, not correctness.

Outside both: the OCI registry, the network, the TLS certificates of
registries and collectors, and whatever remote access an administrator
uses.  A registry can withhold or replay signed content; it cannot
forge any, because every package index, tree publication and loader is
authenticated on the target by its ML-DSA signature.

The kernel is trusted.  shirudo does not defend against a compromised
kernel, verifier, TPM or hardware, and it does not harden the kernel.


3) Adversaries
--------------

A.  Unprivileged local code.  Constrained by the kernel already;
    shirudo adds nothing it needs.

B.  Root on the target without the signing key.  The main adversary: a
    compromised administrator account, a container escape, a
    persistence implant.  It can issue any syscall, write any file,
    ptrace whatever the kernel lets it, and load modules where that is
    allowed.  shirudo must keep this adversary from loading BPF, from
    detaching or replacing shirudo's BPF, from altering shirudo's state
    unnoticed, and from making a tampered target look healthy.

C.  A network adversary between registry and target, or a hostile
    registry.  Can observe, drop, delay and replay.

D.  An adversary holding the operator's signing key.  Out of scope:
    that adversary is the operator.


4) Threats addressed
--------------------

T1  Loading unsigned BPF.  ``lsm/bpf`` admits a userspace
    ``BPF_PROG_LOAD`` only for a ``BPF_PROG_TYPE_SYSCALL`` program that
    carries a signature.  The kernel verifies that signature against
    the sealed ``shirudo`` keyring, whose serial is passed as
    ``attr.keyring_id``, before the verifier runs, and
    ``lsm/bpf_prog_load`` then requires the verdict ``BPF_SIG_VERIFIED``
    from exactly that keyring serial.  The payload is hash-locked to the
    loader by ``excl_prog_hash``.  Root without the key gets
    ``-EACCES`` or ``-ENOKEY``; a certificate planted in any other
    keyring is ignored, and a foreign-signed artifact fails with
    ``ENOKEY``.

T2  Detaching or replacing enforcement.  ``lsm/bpf`` denies
    ``LINK_DETACH``, ``LINK_UPDATE``, ``PROG_ATTACH``, ``PROG_DETACH``
    and ``BTF_LOAD`` from userspace.  The links are kept alive by pins
    in a private bpffs; ``inode_unlink`` on that filesystem allows only
    shirudo's own executable, and ``sb_umount``, ``move_mount``,
    ``sb_mount`` and ``sb_remount`` deny everyone, so neither ``rm`` nor
    ``umount`` nor mounting over the directory removes a pin.
    Infrastructure maps are frozen at creation, so even with the LSM
    gone userspace could not rewrite the identity map.

T3  Tampering with shirudo's files and process.  Every inode under
    ``/var/lib/shirudo`` carries the ``security.bpf.shirudo`` label;
    the seal program allows write open, unlink, rename and xattr
    changes only to a process whose executable carries the same label,
    compared by xattr value and never by path.  Marked shirudo tasks
    cannot be ptraced or perf-sampled, and the process drops
    dumpability, forbids new privileges and locks sensitive buffers.
    The keyring is sealed with ``KEYCTL_SETPERM`` so no key can be
    added or removed for the rest of the boot, and its serial is pinned
    on disk; a swapped same-name keyring makes every load refuse
    ``tampered``.

T4  Substituting artifacts.  The signature covers the loader
    instructions and data, so the kernel refuses a modified loader.  An
    unload directive is itself a signed loader and goes through the same
    ``BPF_PROG_LOAD``.  Before detaching, shirudo compares the live
    pin's payload xattr, which only shirudo can write, against the
    directive's expected payload, and refuses ``payload_mismatch`` on
    disagreement or when the xattr is unreadable.

T5  Silent state change.  Every init, load and unload extends the
    non-resettable NV index with a domain-separated digest and appends
    the event to the eventlog.  A load whose extension fails reports
    ``tpm_error`` rather than succeeding unmeasured; an eventlog that
    would overflow refuses ``eventlog_full`` before anything happens.
    Every state-changing command compares the chain to
    ``--expect-chain`` first and refuses ``tampered`` on drift, which
    also serialises concurrent operators.  ``shirudo status`` replays
    the eventlog and flags a chain it cannot explain.  There is no
    unmeasured mode: a target without a TPM 2.0 does not initialise.

T6  The boot window.  Enforcement is BPF and does not survive a reboot
    by itself.  ``shirudo.service`` runs ``init`` before
    ``sysinit.target``, re-applies the installed set all or nothing, and
    extends the chain by exactly one predictable event.  Until it has
    run the target is unprotected; see residual risk 7.

T7  The delivery path.  The registry index is a detached CMS signature
    by the operator's key, checked against the certificate registered
    with the repository; a package installed from a repository is
    checked against the digests in that signed index; a tree
    publication is signed, carries per-operation digests and sequence
    continuity, and a ``delete`` is accepted only for an id loaded from
    the same tree.  TLS is 1.3 with hybrid ML-KEM only, so the
    transport is not the weak link even though it is not the trust
    anchor.

T8  Quantum-capable adversaries against the trust anchor.  Signing is
    ML-DSA-87 (FIPS 204) only: ``genkey`` makes nothing else, the
    builder refuses a classical key, and the pre-flight refuses a
    classical certificate, so a fleet cannot drift back by
    misconfiguration.  Digests are SHA-256 and SHA-512, which stay well
    above a 128-bit margin against Grover-style search.  Long-lived
    embedded fleets are the reason: a forgeable signature would let a
    future adversary install BPF on every device that still trusts the
    old certificate.


5) Residual risks
-----------------

Each of these is known, documented and bounded; none is silent.

1.  The unload directive's target name and expected payload live in
    unsigned metadata.  The kernel's ``bpf_sys_bpf()`` cannot detach or
    unlink, so the detach runs in userspace, and root can repoint a
    signed directive at another upatch loaded under the same key, or
    edit the expected payload to match it.  ``payload_mismatch`` catches
    honest substitution; closing this fully needs an in-kernel detach so
    the compare runs against signed ``.rodata``.

2.  ``CAP_SYS_RESOURCE`` can rewrite ``mm->exe_file`` with
    ``prctl(PR_SET_MM_EXE_FILE)``.  A root process with that capability
    that can open shirudo's binary impersonates it to the seal and the
    bpffs guards.  Bound ``CAP_SYS_RESOURCE`` out of untrusted contexts
    with ``CapabilityBoundingSet=`` and container capability profiles.
    This is a property of the kernel's process model, not a shirudo
    bug to fix.

3.  A lazy (``MNT_DETACH``) unmount of an ancestor of
    ``/var/lib/shirudo/bpffs`` tears the subtree down without firing
    ``sb_umount`` on the child.  The ancestor is normally the root or
    ``/var`` filesystem, a far higher bar than the direct unmount the
    guards close.

4.  Chain denial of service.  A process that can open ``/dev/tpmrm0``
    and knows the NV auth value, which is derived from ``cert.der``,
    can extend the index with garbage.  The result is detected
    (``tampered`` on every operation, ``ChainIntact`` at ``ALERT``), not
    hidden, and the attacker still cannot load BPF; it costs the
    operator a re-provisioning.

5.  The binary on disk.  shirudo cannot defend its own executable
    against substitution or patching before it runs; that belongs to
    the distribution layer (signed packages, IMA appraisal, fs-verity,
    measured boot).  ``SHIRUDO_VERSION_ID`` is a skew guard, not an
    integrity check: a malicious binary can lie about it.

6.  Keyring swap degrades to denial of service.  Root can unlink the
    sealed keyring and create a fake one with the same name; the serial
    pin turns that into a fail-closed refusal instead of a bypass.  A
    complete fix needs a kernel kfunc that lets ``lsm/key_permission``
    identify the keyring.

7.  The boot window before ``shirudo.service`` has run.  An initramfs
    stage would close it; the unit runs as early as a root-filesystem
    service can.

8.  Registry withholding and replay.  A hostile registry can serve an
    old signed index, or none; it cannot serve a forged one.  Operators
    who need freshness compare the versions ``shirudo bpm list``
    reports and the chain ``status`` exports against what they
    published.

9.  Classical pieces outside the boundary: WebPKI server certificates
    on registries and collectors (they authenticate the transport, not
    the artifacts), and any future TPM attestation key, which TPM
    vendors ship as RSA or ECC today.


6) Out of scope
---------------

- Compromise of the operator host or the signing key.
- A malicious or buggy kernel, verifier, TPM or hardware.
- Denial of service: removing the binary, cutting the network, filling
  the disk.  shirudo fails closed and loud; it does not fail over.
- Correctness or safety of an upatch an authorised signer built.
- Fleet inventory, rollout ordering, retries, scheduling and
  cross-target consistency.  shirudo reports one machine; aggregation
  is the collector's job.
- SSH, remote access and audit retention.  Those belong to the
  infrastructure the operator already runs.


7) Operational guidance
-----------------------

Keep the signing key on a host with the controls of a certificate
authority and never on a target.  Treat ``tampered`` as an incident to
understand, not a condition to retry.  Verify ``shirudo status`` after
every boot and every load; a target whose chain the eventlog cannot
explain is not healthy just because it is still running.  Build
upatches against the target kernel's BTF and read verifier logs from
the structured report.  Restrict who can register repositories and who
can run state-changing commands, and drop ``CAP_SYS_RESOURCE`` from
anything that does not need it.
