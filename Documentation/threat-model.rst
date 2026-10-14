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
- the TPM measurement register and the eventlog that explains it;
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

T1  Loading unsigned BPF
    ``lsm/bpf`` admits a userspace ``BPF_PROG_LOAD`` only for a
    ``BPF_PROG_TYPE_SYSCALL`` program that carries a signature.  The
    kernel verifies that signature against the sealed ``shirudo``
    keyring, whose serial is passed as ``attr.keyring_id``, before the
    verifier runs, and ``lsm/bpf_prog_load`` then requires the verdict
    ``BPF_SIG_VERIFIED`` from exactly that keyring serial.  The payload
    is hash-locked to the loader by ``excl_prog_hash``.  Root without
    the key gets ``-EACCES`` or ``-ENOKEY``; a certificate planted in
    any other keyring is ignored, and a foreign-signed artifact fails
    with ``ENOKEY``.

T2  Detaching or replacing enforcement
    ``lsm/bpf`` denies ``LINK_DETACH``, ``LINK_UPDATE``,
    ``PROG_ATTACH``, ``PROG_DETACH`` and ``BTF_LOAD`` from userspace.
    The links are kept alive by pins in a private bpffs;
    ``inode_unlink`` on that filesystem allows only shirudo's own
    executable, and ``sb_umount``, ``move_mount``, ``sb_mount`` and
    ``sb_remount`` deny everyone, so neither ``rm`` nor ``umount`` nor
    mounting over the directory removes a pin. Infrastructure maps are
    frozen at creation, so even with the LSM gone userspace could not
    rewrite the identity map.

T3  Tampering with shirudo's files and process
    Every inode under ``/var/lib/shirudo`` carries the
    ``security.bpf.shirudo`` label; the seal program allows write open,
    unlink, rename and xattr changes only to a process whose executable
    carries the same label, compared by xattr value and never by path.
    Marked shirudo tasks cannot be ptraced or perf-sampled, and the
    process drops dumpability, forbids new privileges and locks
    sensitive buffers. The keyring is sealed with ``KEYCTL_SETPERM`` so
    no key can be added or removed for the rest of the boot, and its
    serial is pinned on disk; a swapped same-name keyring makes every
    load refuse ``tampered``.

T4  Substituting artifacts
    The signature covers the loader instructions and data, so the kernel
    refuses a modified loader.  An unload directive is itself a signed
    loader and goes through the same ``BPF_PROG_LOAD``.  Before
    detaching, shirudo compares the live pin's payload xattr, which only
    shirudo can write, against the directive's expected payload, and
    refuses ``payload_mismatch`` on disagreement or when the xattr is
    unreadable.

T5  Silent state change
    Every init, load, unload and tree operation extends this boot's
    measurement register with a domain-separated digest and appends
    the event to the eventlog.  The register is an NV extend index
    that clears at TPM reset and is written only under its policy: the
    first write of a boot needs PCR 15 to hold the value the policy was
    computed from, and ``init`` extends PCR 15 with the index name right
    after that write, so an index undefined and recreated at runtime
    cannot be written again, and one recreated under another policy has
    a name the eventlog does not know.  A load whose extension fails
    reports ``tpm_error`` rather than succeeding unmeasured; an eventlog
    that would overflow refuses ``eventlog_full`` before anything
    happens.  Every state-changing command reads the register first and
    refuses ``tampered`` when ``--expect-chain`` disagrees or the index
    is not the one ``init`` recorded, which also serialises concurrent
    operators.  ``shirudo status`` replays this boot's records and flags
    a register it cannot explain.  There is no unmeasured mode: a target
    without a TPM 2.0 does not initialise.

T6  The boot window
    Enforcement is BPF and does not survive a reboot by itself.
    ``shirudo.service`` runs ``init`` before ``sysinit.target``,
    re-applies the installed set all or nothing, binds the register and
    extends it by exactly one event an operator predicts from the
    certificate and the set.  Until it has run the target is
    unprotected; see residual risk 7.

T7  The delivery path
    The registry index is a detached CMS signature by the operator's
    key, checked against the certificate registered with the repository;
    a package installed from a repository is checked against the digests
    in that signed index; a tree publication is signed, carries
    per-operation digests and sequence continuity, and a ``delete`` is
    accepted only for an id loaded from the same tree.  TLS is 1.3 with
    hybrid ML-KEM only, so the transport is not the weak link even
    though it is not the trust anchor.

T8  Quantum-capable adversaries against the trust anchor
    Signing is ML-DSA-87 (FIPS 204) only: ``genkey`` makes nothing else,
    the builder refuses a classical key, and the pre-flight refuses a
    classical certificate, so a fleet cannot drift back by
    misconfiguration.  Digests are SHA-256 and SHA-512, which stay well
    above a 128-bit margin against Grover-style search.  Long-lived
    embedded fleets are the reason: a forgeable signature would let a
    future adversary install BPF on every device that still trusts the
    old certificate.

T9  A target lying about its state
    ``shirudo status`` is the target's own account and proves nothing
    by itself.  ``shirudo attest`` makes the TPM speak: a quote over
    the firmware, boot loader, kernel, initrd and systemd PCRs and a
    certification of the register, both signed by an attestation key
    the operator pinned by name and carrying the operator's nonce.
    ``shirudo attest verify`` ties the certified index to the recorded
    PCR binding, replays the eventlog to the certified value and
    compares it with the value predicted from the certificate and the
    installed artifacts, so a substituted binary, a recreated index or
    an unexpected set is a failed check, not a healthy report.  Which
    firmware, kernel and initrd values are acceptable is the platform
    owner's policy; ``--expect-pcr`` pins them and the logs in the
    evidence explain them.


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

4.  Register denial of service.  A process that can open
    ``/dev/tpmrm0`` can extend PCR 15 or the written register with
    garbage, and with the owner auth (empty on most TPMs) undefine the
    index.  None of it is hidden: a garbage event fails the replay, a
    recreated index cannot be written and fails the name check, and
    ``status``, every state-changing command and ``attest verify``
    report ``tampered``; the attacker still cannot load BPF.  It costs
    the operator a reboot and an investigation.

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
    reports and the register ``attest`` certifies against what they
    published.

9.  Classical pieces outside the boundary: WebPKI server certificates
    on registries and collectors (they authenticate the transport, not
    the artifacts), and the attestation key, which is ECDSA P-256
    because TPMs sign with nothing post-quantum today.  The evidence is
    therefore classical even though the artifacts it describes are not.

10. Attestation key trust.  The operator pins the key by its name when
    enrolling a target, over whatever channel they trust at that
    moment, and nothing in the evidence proves by itself that the key
    lives in the TPM whose endorsement certificate it carries.  A
    credential activation against that certificate is deferred (see
    below); until then the pin is a first-use trust.

11. The anchor shares PCR 15 with systemd's own system-identity
    measurements, so ``attest verify`` proves the anchor exactly only
    when PCR 15 holds nothing else; otherwise it says so and leaves the
    replay of the systemd measurement log, which the evidence carries,
    to the verifier's tooling.  ``--strict-anchor`` turns the note into
    a failure for systems where PCR 15 is known to hold nothing else.

12. A root attacker who runs before ``shirudo.service`` can bind and
    write the register first.  ``init`` then rebinds it under the
    current PCR 15 value and anchors again, and the evidence shows two
    anchors and a register the eventlog does not explain; the window is
    the same one residual risk 7 describes.

Deferred mitigations
~~~~~~~~~~~~~~~~~~~~

In scope and not yet built: credential activation
(``TPM2_MakeCredential`` on the operator, ``TPM2_ActivateCredential`` on
the target) that proves the attestation key sits beside the endorsement
key whose certificate the evidence carries; registering the register as
a systemd NvPCR through ``io.systemd.PCRExtend`` once systemd-aware
verifiers consume third-party NvPCRs, so that systemd anchors it from
the initrd; signed PCR policies for the kernel and initrd PCRs so a
verifier needs no golden values; an in-kernel detach so the unload
compare runs against signed ``.rodata`` (residual risk 1); and the
keyring kfunc of residual risk 6.


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
every boot and every load; a target whose register the eventlog cannot
explain is not healthy just because it is still running.  Record the
attestation key name when a target is enrolled (``shirudo attest``
once, keep ``ak.name``), and let the fleet's health be ``shirudo attest
verify`` against a fresh nonce and the values ``shirudo attest
predict`` computes from what you installed, not a status the target
wrote about itself.  Build
upatches against the target kernel's BTF and read verifier logs from
the structured report.  Restrict who can register repositories and who
can run state-changing commands, and drop ``CAP_SYS_RESOURCE`` from
anything that does not need it.
