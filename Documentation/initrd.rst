..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

Bringing shirudo up from the initrd
===================================

The production configuration of a target brings enforcement up before
the root file system runs anything: ``shirudo init`` runs inside the
initrd.  This document describes what that run does, what the root
file system's run finishes afterwards, what an initrd needs to contain
and how the pieces survive the switch from one to the other.  The
``threat-model`` document says why it matters; ``tpm`` describes the
register the initrd binds.


1) Two runs of init
-------------------

``shirudo init`` is one command that runs twice per boot in production:

The initrd run
    Starts from ``shirudo-initrd.service`` after the root file system is
    mounted at ``/sysroot`` and after ``systemd-pcrphase-initrd.service``
    has measured ``enter-initrd`` into PCR 11, and finishes before the
    switch to the root file system.  It enrols the initrd's own copy of
    the certificate, ``/etc/shirudo/cert.der``, in the kernel's bpf
    keyring and seals it, which needs the kernel booted with
    ``bpf.keyring_unsealed=1``; mounts the private bpffs at
    ``/run/shirudo/bpffs`` and attaches the enforcement programs with
    their pins in it; re-applies the upatches archived under
    ``/sysroot/var/lib/shirudo/upatches``; binds the measurement
    register under PCRs 9 and 11 and extends it by the init event; and
    writes the ``init`` record to ``/run/shirudo/eventlog.pending``.

The root file system's run
    Starts from ``shirudo.service`` inside the sysinit phase.  It finds
    the keyring sealed around the certificate, the LSM attached, the
    upatches loaded and the register bound, and does what the initrd
    could not do on a root file system that was still read-only: it
    labels the state tree and the binary with the sealing xattr and
    appends the pending record to ``/var/lib/shirudo/eventlog``, exactly
    once.  Then it stops.  ``status`` reports ``mode: production`` and
    ``bound_in: initrd``.

Without an initrd that runs the first half, the root file system's run
does everything itself.  The kernel sealed the bpf keyring empty at
boot, so the certificate is staged in a ``shirudo`` keyring under the
user keyring until the next reboot, and the register binds after
``leave-initrd`` moved PCR 11.  That is the staging configuration:
``status`` says ``mode: staging`` and ``bound_in: root``, the keepalive
condition warns, and a verifier can refuse the evidence with
``--require-initrd`` or by pinning PCR 11.


2) What survives the switch to the root file system
---------------------------------------------------

systemd's switch-root carries ``/dev``, ``/sys``, ``/proc`` and ``/run``
from the initrd into the root file system and lazily detaches every
other mount of the initrd.  A BPF link stays attached only while
something holds it, and in an agentless design the only holders are
the pins in the bpffs; a bpffs mounted anywhere the switch detaches
dies with the old root and takes enforcement with it.  That is why the
private bpffs lives at ``/run/shirudo/bpffs``: a mount under ``/run``
is carried across, is never shadowed by a later mount of ``/var``, and
needs nothing from the root file system.

The kernel keyring is kernel state and survives by itself; so do the
TPM's NV index and PCRs.  The init record cannot be written to the
root's eventlog while the root is read-only, so it waits under ``/run``
in the same tmpfs, labelled with the sealing xattr, and the eventlog
readers treat it as part of this boot's log until the root file
system's run appends it and removes the file.

The bpffs guards admit the executable recorded at init.  From the
initrd the running binary is the initrd's copy, which is gone after
the switch; the identity that lasts is the root's binary at the same
path, ``/sysroot`` plus the path the initrd ran shirudo from, and the
initrd's copy is recorded beside it for the rest of that one run.  The
root file system therefore needs shirudo installed at the path the
initrd runs it from, which the dracut module guarantees by copying the
installed binary.


3) What the initrd needs
------------------------

* The target binary at its installed path.  It is static apart from
  the C library.
* ``/etc/shirudo/cert.der``, a copy of ``/var/lib/shirudo/keys/cert.der``.
  This copy is measured with the initrd, so a verifier that pins PCR 11
  knows which certificate was enrolled.  ``init`` warns when the root's
  copy differs, which means an initrd that was not regenerated after
  the certificate changed; the initrd's copy is the anchor either way.
* ``/etc/shirudo/shirudo.conf`` when the TPM has an owner password
  (``tpm.owner_auth``).
* ``shirudo-initrd.service``, enabled in ``initrd.target``.
* A TPM 2.0 reachable as ``/dev/tpmrm0``: the TPM driver and the
  device node.  dracut's ``tpm2-tss`` module provides both.
* ``systemd-pcrphase-initrd.service``, so that PCR 11 holds the
  ``enter-initrd`` value when the register binds and moves at
  ``leave-initrd``.  dracut's ``systemd-pcrextend`` module (called
  ``systemd-pcrphase`` before dracut 103) provides it.  systemd runs
  the unit only for a measured UKI boot (``ConditionSecurity=
  measured-uki``); a kernel and initrd loaded by grub or passed to QEMU
  directly leave PCR 11 at its boot value, ``init`` warns that no phase
  was measured, and the binding then has the PCR 9 anchor but not the
  PCR 11 distinction between an initrd and a later binding.  The
  production configuration is therefore a UKI boot; the rest of the
  design holds without it.
* The root file system mounted at ``/sysroot`` with
  ``/var/lib/shirudo`` on it.  When ``/var`` is a separate file system
  it must be mounted in the initrd (``x-initrd.mount`` in fstab), or
  the initrd run refuses with a message that says so and the root's
  run falls back to the staging configuration.
* The kernel booted with ``bpf.keyring_unsealed=1``.  The parameter is
  read-only after boot, so the only way to open the keyring is the
  measured command line.

The ``tools/gen-initrd`` directory holds the dracut module that
installs all of this, a generator that drives dracut and verifies the
result, and the installer; the ``getting-started`` document shows how
they are used.  Non-systemd initrds (initramfs-tools, busybox) are
not supported: without the phase measurements an initrd binding is no
stronger than a late one.


4) Checking a target
--------------------

On the target::

    shirudo status --json | python3 -c \
        'import json,sys; d=json.load(sys.stdin); print(d["mode"], d["bound_in"])'

prints ``production initrd`` when both runs did their part.  The
eventlog's ``init`` record carries ``bound_in: initrd`` and the PCR 11
value the register was bound under; ``shirudo attest verify
--require-initrd --expect-bind-pcr=11=<enter-initrd value>`` checks
both against the evidence, with the value computed from the UKI or
initrd by ``systemd-measure`` or ``systemd-pcrlock``.  No pending
record remains under ``/run/shirudo`` once the root's run has adopted
it; a target where it lingers is one whose ``shirudo.service`` has not
run.
