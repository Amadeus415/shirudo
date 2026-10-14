..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

Key lifecycle
=============

shirudo's trust rests on one key pair: the operator's ML-DSA-87 signing
key and its self-signed certificate.  This guide covers that pair from
creation to retirement: what it signs, where the certificate goes, how
targets come to trust it, how to rotate it, and what to do when it is
compromised.  The `threat-model <threat-model.rst>`__ says why the
mechanisms are shaped the way they are; this document says what to do.


1) The keys in the system
-------------------------

The operator signing key
    ML-DSA-87 (FIPS 204), the only algorithm shirudo signs with.
    ``shirudo genkey`` writes ``signing_key.pem`` (mode 0600) and
    ``cert.der`` into ``/var/lib/shirudo/keys`` or ``--keys-dir``, and
    refuses to overwrite an existing pair without ``--force``.  The key
    signs every upatch, every unload directive, every package index
    and every tree publication.  It lives on the operator and never on
    a target.

The certificate
    A self-signed X.509 v3 certificate over the signing key, valid for
    ten years from creation.  It is the only thing a target holds, and
    everything a target trusts chains to it: the kernel verifies every
    signed loader against it once ``init`` has enrolled it in the bpf
    keyring, and ``shirudo bpm`` verifies package indexes and tree
    publications against it in userspace.  Its SHA-256 enters every
    boot's ``init`` event, so an operator who predicts a register value
    with ``shirudo attest predict`` predicts it for this certificate.

The attestation and endorsement keys
    These belong to the target's TPM, not to the operator: the
    attestation key is a fixed-template P-256 primary the operator pins
    by name at enrolment, and the endorsement key is the TPM's own,
    vouched for by the manufacturer's certificate.  Their lifecycle is
    the TPM's; the `tpm <tpm.rst>`__ document covers both.

Transport certificates
    The WebPKI certificates of registries and collectors authenticate
    the transport and nothing else; the artifacts carry their own
    signatures.  They are the infrastructure's to manage.

``shirudo keys`` shows what a host holds: the certificate and, on an
operator, the key on disk, and the kernel keyring's contents on a
target that ran ``init``.  Two roles may share a host for development;
production operators and targets do not.


2) Where the certificate goes on a target
-----------------------------------------

A target needs the certificate in two places, for two purposes.

``/var/lib/shirudo/keys/cert.der``
    The copy the root file system reads: ``init`` enrols it when it
    runs from the root (the staging configuration), ``status`` and
    ``attest`` read its hash, and ``init`` compares it with the
    initrd's copy.  The installer's ``--cert`` puts it there; so does
    ``shirudo bpm key add <cert.der>``, which stores certificates
    under ``keys/<fingerprint>.der`` and points ``cert.der`` at the
    first one it installs.  ``bpm key add`` refuses to point ``cert.der``
    at a different certificate while one is active, and ``bpm key
    list`` and ``bpm key fingerprint`` show what is installed; the
    fingerprint is the SHA-256 of the certificate's public key.

``/etc/shirudo/keys/cert.der`` in the initrd
    The copy the production configuration enrols.  dracut's shirudo
    module copies the active certificate into the initrd when the
    initrd is built, so the enrolment is done by measured code with a
    measured certificate: a verifier that pins PCR 11 to the UKI knows
    exactly which certificate the keyring holds.  The copy is taken at
    build time, so **a changed certificate needs the initrd rebuilt**
    (``shirudo-gen-initrd``); until then ``init`` enrols the old one
    and warns that the root's copy differs.  The `initrd
    <initrd.rst>`__ document describes that run.

Repositories registered with ``shirudo bpm config register add <name>
<endpoint> --key-file <cert.der>`` keep their own reference to the
certificate that must sign the repository's index, under
``/etc/shirudo/bpm``; a tree publication is verified the same way.
Registering a repository with a certificate other than the one the
keyring holds is possible and pointless: its packages would verify in
userspace and fail at the kernel.

The kernel does not check the certificate's validity period when it
verifies a signature, and shirudo adds no date check of its own.  The
ten years are a statement of intent and the trigger for rotation, not
a cut-off a target enforces.


3) What the design fixes
------------------------

Rotation is constrained by three facts worth knowing before planning
one:

* **One certificate per boot.**  ``init`` enrols exactly one
  certificate and seals the keyring; nothing can be added for the
  rest of the boot.  A boot therefore verifies against either the old
  key or the new one, never both.
* **Boot-restore is all or nothing.**  On every boot ``init`` reloads
  the archived upatches under ``/var/lib/shirudo/upatches``.  An
  archive signed with a key the new certificate does not cover fails
  verification, the restore stops, and the target comes up with the
  LSM active but nothing loaded and no register bound
  (``init-pending``) until the archive is cleaned up.
* **The archive is sealed.**  Only shirudo can remove an archived
  upatch, and it does so only through a signed unload directive that
  the current keyring accepts.  An archive signed by a retired key can
  no longer be unloaded; it can only be left behind by a reinstall of
  the state directory.

Together these make rotation a maintenance operation with an order to
respect, not a certificate swap.  Section 7 describes the extension
that would lift the first two constraints; it does not exist today.


4) Rotating the key
-------------------

On the operator
~~~~~~~~~~~~~~~

1. Generate the new pair into a new directory so both exist side by
   side::

       shirudo genkey --keys-dir /var/lib/shirudo/keys.next

2. Rebuild every package the fleet carries with the new key, as new
   versions (published versions are immutable), and publish them::

       shirudo bpm build ./example-shields --version 1.1.0 \
           --keys-dir /var/lib/shirudo/keys.next
       shirudo bpm push ./example-shields-1.1.0.bee oci://.../example-shields \
           --keys-dir /var/lib/shirudo/keys.next

   The registry's index is signed by whichever key ``push`` is given;
   from now on the index at ``shirudo/bpm-index:stable`` carries the
   new signature, and targets still registered with the old
   certificate stop accepting it.  Plan the target steps below to
   follow promptly, or publish the new versions into a second
   repository first.

3. For a fleet that follows a tree, append the new versions as
   operations of a tree published with the new key.  Because a target
   accepts a ``delete`` only for an id it loaded from the same tree
   and verifies the publication against its registered certificate,
   a tree cannot change keys mid-sequence: start a new tree
   (``--tree-id``) or a new reference for the new key and point the
   targets at it in step 5 of the target side.

On each target
~~~~~~~~~~~~~~

The old anchor must unload everything it signed before the new one
takes over, or the archive outlives the key that can remove it.

1. While the old certificate is still enrolled, remove every installed
   package and withdraw every tree operation the node applied::

       sudo shirudo bpm list
       sudo shirudo bpm uninstall <package>          # for each
       sudo shirudo bpm tree sync                   # after the operator's deletes

   ``shirudo upatch list`` must show nothing archived and nothing
   loaded.  The register records every unload.

2. Install the new certificate and re-register the repositories with
   it::

       sudo install -m 0644 cert.der /var/lib/shirudo/keys/cert.der
       sudo shirudo bpm config register remove example
       sudo shirudo bpm config register add example oci://registry.example.com \
           --key-file cert.der

   Replace the tree configuration in ``/etc/shirudo/bpm/upatch-tree.conf``
   when the fleet follows a tree, and remove the old tree state under
   ``/var/lib/shirudo/bpm/upatch-tree`` on the next boot before the
   first sync, or the sequence check refuses the new tree's first
   generation.

3. Rebuild the initrd so that the measured copy is the new certificate::

       sudo shirudo-gen-initrd

4. Reboot.  ``init`` in the initrd enrols the new certificate; the
   root's ``init`` finds the two copies equal.  ``shirudo status``
   shows the new keyring serial, ``mode: production`` and an empty
   set.

5. Install the re-signed packages, or let ``bpm tree sync`` pull the
   new tree.  Record the new ``cert_sha256`` from ``status --json`` and
   update the expected values an operator verifies with (``shirudo
   attest predict`` takes the certificate as input).

Do the target side in waves so that the fleet is never without
mitigations as a whole; a node is unprotected by its upatches between
step 1 and step 5, but never unenforced: the LSM stays up throughout
and nothing unsigned loads.

When the old pair is no longer needed anywhere, shred the private key
and keep the certificate: old evidence and old eventlogs name its hash,
and verifying them later needs it.


5) Revocation
-------------

shirudo has no revocation list; the mechanisms are the ones above used
with intent.

A upatch
    Withdrawing a shield is a signed unload: ``bpm tree append --op
    delete`` for a fleet following a tree, ``bpm uninstall`` for a
    package installed by name, or ``upatch unload`` with the
    directive.  Every unload is measured, so an operator can tell from
    the evidence which nodes have acted.

A key
    A key is retired by rotating it (section 4).  There is no way to
    tell a target that a certificate it holds is no longer trusted
    other than giving it a new one; until the reboot of step 4 the old
    key signs loads the kernel accepts.

A compromised key
    The adversary holding the key is the operator, as far as a target
    can tell: whatever they sign loads and measures as authorised.
    Detection is by content, not by signature: ``shirudo attest
    verify`` against ``shirudo attest predict`` fails for any node
    whose register certifies a set the operator did not publish, and
    the eventlog names each load.  Response is the rotation above,
    run as fast as the waves allow, plus a review of every artifact
    the key signed and of the registry's index and tree publications
    for entries the operator did not make.  A target whose binary or
    state is in doubt is reinstalled, not repaired; the
    `operations <operations.rst>`__ guide covers both.


6) Custody
----------

* The signing key belongs on a host with the controls of a certificate
  authority: offline or isolated, with access limited to the people
  who publish.  The operator role needs no network beyond the registry
  it pushes to.
* The key is a PEM file protected by file permissions; shirudo does
  not use PKCS#11 or an HSM.  Keep the directory on an encrypted
  volume and back it up encrypted, with the certificate beside it.
* Keep separate pairs for development, staging and production fleets
  with ``--keys-dir``, and never enrol a development certificate on a
  production target.  The test suites generate throwaway pairs of
  their own.
* Record the certificate's fingerprint (``shirudo bpm key
  fingerprint cert.der``) and the SHA-256 the ``init`` event carries
  (``status --json``), and check them wherever a certificate is copied:
  into the initrd, into a registry registration, into an inventory.
* Treat a key that left the operator host, even once, as compromised.


7) Several operator keys
------------------------

The kernel's bpf keyring is not limited to one key: a signed loader
verifies against any key the keyring holds, and sealing the keyring
with ``KEYCTL_RESTRICT_KEYRING`` stops keys from being linked into it,
not from being unlinked.  That is the room for a lifecycle without the
constraints of section 3, and the direction the design is meant to
take:

* ``init`` enrols every certificate the target holds, the whole of
  ``keys/*.der`` rather than ``cert.der`` alone, and the ``init`` event
  covers the set, so ``shirudo attest predict`` predicts the register
  for a set of certificates.
* Rotation becomes incremental: the new certificate is distributed and
  enrolled beside the old one, the initrd rebuilt once, packages are
  rebuilt and republished with the new key at leisure, and the old key
  is withdrawn when nothing depends on it.
* A compromised key is revoked on the node, during the boot and
  without one: ``shirudo keys revoke <fingerprint>`` unlinks that key
  from the bpf keyring, so the kernel accepts nothing signed by it from
  that moment, unloads and purges every archived artifact it signed
  (identified by the signer of their signatures) and measures the
  revocation into the register, while loads signed by the other keys
  keep working.

What it needs before it can be built: the set digest in the ``init``
event and in ``predict``, a purge of the archive by signer that does
not depend on the revoked key's unload directives, the initrd copy as
a set, and a guard on the keyring itself.  The last one is the catch
today: the kernel grants root write permission on the bpf keyring, so
root can already unlink keys from the sealed keyring; with one key that
is denial of service, every load failing ``ENOKEY`` until a reboot,
and the threat model lists it as such.  A ``key_permission`` hook in
the enforcement programs that denies writes to the bpf keyring except
from shirudo's own executable would turn unlinking into the revocation
primitive and nothing else.
