..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: upatch authors

Package, index and tree formats
===============================

shirudo publishes three kinds of objects to an OCI registry: packages
(``.bee`` files), the signed repository index that lists them, and upatch
trees. The operator writes them with ``bpm build``, ``bpm push`` and
``bpm tree append`` (see :doc:`/reference/cli/bpm`). The target reads them
with ``bpm repo update``, ``bpm install``, ``bpm upgrade`` and
``bpm tree sync``. The ``.upatch`` files inside are specified in
:doc:`upatch-format`.

CBMC proves the target's readers of these formats within the bounds
:doc:`/contribute/testing/proof-coverage` lists: the tar headers and
member names, the registry's challenges, tokens, headers and
descriptors, the package names and versions, the tree publication's
selectors and operations, and the checks that keep a publication from
taking a node back. Lean 4 proves the version order total for versions
of every length, that every member name the archive check takes, of any
length, extracts strictly below the package's directory, and that across
any history of syncs, stops and reboots a node's generation, cursor and
tree eventlog never go back and each operation is applied at most once;
CBMC shows that ``bpm tree sync`` makes exactly the model's writes.

What is signed
--------------

.. list-table::
   :header-rows: 1
   :widths: 24 40 36

   * - Object
     - Protection
     - Checked by
   * - ``.upatch`` file
     - CMS signature, ML-DSA-87, over ``loader_insns || data``.
     - The kernel, at every load and unload.
   * - Repository index document
     - Detached CMS signature over the exact document bytes.
     - ``bpm repo update``, against the repository's key file from the
       configuration. ``bpm push`` also checks the published index against
       ``--index-cert`` before it adds an entry.
   * - Package manifest and ``.bee`` archive
     - Not signed. The signed index pins them by ``manifest_digest``,
       ``package_digest`` and ``package_size``.
     - ``bpm install`` and ``bpm upgrade`` from a repository.
   * - Package installed by ``oci://`` reference
     - Not signed and not pinned. The reference names a tag.
     - Only the per-``.upatch`` signatures and the ``cert.der`` check below.
   * - ``cert.der`` in a package
     - Its public key must equal the public key of the target's
       ``/var/lib/shirudo/keys/cert.der``.
     - ``bpm install`` and ``bpm upgrade``, before any upatch loads.
   * - ``Beefile``, ``README.md``, ``build-environment.json``, files
     - Not signed. Covered by the archive digest when the index pins it.
     - None beyond the archive digest.
   * - Tree publication document
     - Detached CMS signature over the exact document bytes.
     - ``bpm tree sync``, against the active config's non-revoked BPF signer set.
   * - Tree artifact manifest and ``.upatch`` layer
     - Not signed. Each signed operation pins them by
       ``manifest_digest``, ``layer_digest`` and ``payload_sha256``.
     - ``bpm tree sync``.
   * - Certificate referrer manifest
     - Not signed.
     - Not read by shirudo.

The detached signatures use the same CMS profile as the ``.upatch``
signature: DER ``SignedData``, no encapsulated content, no certificates,
ML-DSA-87, signer named by subject key identifier. The verifier checks it
without a validity-time check: against the repository certificate for
an index, or any active, enrolled BPF signer for a tree publication.

Names
-----

.. list-table::
   :header-rows: 1
   :widths: 24 30 46

   * - Name
     - Source
     - Rule
   * - Package name
     - Beefile ``[package] name``
     - Starts with a letter or digit, then ``[A-Za-z0-9._-]``, fewer than
       128 characters.
   * - Package version
     - ``bpm build --version``
     - A SemVer 2.0.0 version such as ``1.2.0``, ``1.2.0-rc.1`` or
       ``1.2.0+build.5``, fewer than 128 characters. The newest version is
       chosen by SemVer 2.0.0 precedence, build metadata ignored. The
       target also accepts other versions of ``[A-Za-z0-9._+-]`` that do
       not start with ``.``, from packages built before this rule: such
       a version is older than every SemVer one, and they order by
       their bytes.
   * - upatch name
     - The source file's basename without ``.bpf.c``, ``.bpf.o`` or ``.o``
     - The Beefile cannot override it. 1 to 255 characters of
       ``[A-Za-z0-9._-]``, each ``.`` counting as two, not starting with
       ``.``.
   * - Tree operation ``id``
     - Beefile ``[upatches.tree] id``
     - Must equal the upatch name of the artifact it publishes, so the
       source file's basename. ``bpm tree append`` and ``bpm tree sync``
       both refuse a mismatch.
   * - Tree ``tree_id``
     - ``--tree-id``, else the package name of the first append
     - Fixed for the life of the tree. Distinct from the operation ``id``.

Package archive
---------------

``bpm build`` writes ``<name>-<version>.bee``, a gzip-compressed ustar
archive with one top-level directory ``<name>-<version>/``. Members carry
uid and gid 0 and mtime 0.

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Member
     - Content
   * - ``<name>-<version>/``
     - The top-level directory, mode 0755.
   * - ``Beefile``
     - The Beefile the package was built from.
   * - ``<target>``
     - Each ``[[files]]`` entry at its ``target`` path.
   * - ``upatches/<base>.upatch``
     - Each ``[[upatches]]`` load artifact, at its ``load_target``. The
       default name is the source basename without its extension.
   * - ``upatches/<base>.unload.upatch``
     - The matching unload directive, at its ``unload_target``.
   * - ``README.md``
     - Present when the package directory has one.
   * - ``cert.der``
     - The signing certificate, DER.
   * - ``build-environment.json``
     - Build record, see below.

``Beefile``, ``README.md``, ``cert.der`` and ``build-environment.json`` are
reserved and cannot be ``[[files]]`` or upatch targets.
:doc:`/upatches/publish/beefile` describes the Beefile.

On install the target loads every regular file in :src:`upatches/` whose name
ends in ``.upatch`` but not in ``.unload.upatch``, in name order. Uninstall
and upgrade apply the package's ``<base>.unload.upatch`` files in reverse
name order, and a rolled back install or upgrade reloads each one's
``<base>.upatch``. A name that starts with ``.`` is neither.

Archive reader rules
~~~~~~~~~~~~~~~~~~~~

The target refuses an archive that breaks any of these:

- Each header is a 512-byte ustar header with a valid checksum, a name
  that is NUL-terminated within its 100 bytes, an empty prefix field and a
  size field of octal digits.
- Every member lies under the one top-level directory. No path is
  absolute or has an empty, ``.`` or ``..`` component, so an archive
  rooted at ``./`` is refused, as the member readers would find nothing
  in it.
- Every member is a regular file or a directory.
- At most 4096 members and 256 MiB of content.
- No regular file appears twice.

build-environment.json
~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Key
     - Value
   * - ``format_version``
     - ``1``.
   * - ``builder``
     - ``"bpm build"``.
   * - ``created_at``
     - UTC time, ``YYYY-MM-DDTHH:MM:SSZ``.
   * - ``package.name``, ``package.version``
     - Package name and version. ``bpm push``, ``bpm tree append`` and
       ``bpm config update`` require both.
   * - ``os``, ``arch``
     - ``uname`` system name and machine of the build host.
   * - ``bpm_version``
     - shirudo version of the builder.
   * - ``shirudo.path``, ``shirudo.version``
     - Path and version of the building binary.
   * - ``shirudo.spki_sha256_fingerprint``
     - SHA-256 of the DER ``SubjectPublicKeyInfo`` of ``cert.der``, hex.
       When present, ``bpm push``, ``bpm tree append`` and
       ``bpm config update`` refuse the package if it differs from
       ``cert.der``.
   * - ``upatches[]``
     - Per upatch: ``source``, ``type``, ``load_target``, ``load_output``,
       ``unload_target``, ``unload_output``, ``upatch_name``,
       ``payload_sha256``.

Package in the registry
~~~~~~~~~~~~~~~~~~~~~~~

``bpm push <package> oci://<registry>/<repository>`` uploads:

.. list-table::
   :header-rows: 1
   :widths: 26 74

   * - Object
     - Content
   * - Package manifest
     - OCI image manifest, ``schemaVersion`` 2. Config blob
       ``{"mediaType":"application/vnd.shirudo.bpm.config.v1+json"}`` of
       that media type. One layer, the ``.bee`` file, media type
       ``application/vnd.shirudo.bpm.package.v1+gzip``, with an
       ``org.opencontainers.image.title`` annotation of the file name.
       Manifest annotations ``dev.shirudo.bpm.package.name``,
       ``dev.shirudo.bpm.package.version``,
       ``org.opencontainers.image.title`` and
       ``org.opencontainers.image.version``. Tagged with the package
       version after the index update.
   * - Certificate referrer
     - OCI image manifest with ``artifactType``
       ``application/vnd.shirudo.bpm.public-key.v1+der``, the empty config
       ``application/vnd.oci.empty.v1+json``, one ``application/pkix-cert``
       layer holding ``cert.der``, and ``subject`` set to the package
       manifest.
   * - Index entry
     - Added when signing material is given (``--keys-dir``, or
       ``--index-cert`` with ``--index-key``), see below.

The last path component of ``<repository>`` follows the package name rule.

A manifest shirudo reads, for a package, an index, a tree publication or
an artifact, is refused unless each of its layers is an object with a
``mediaType``, a ``sha256:`` digest and a ``size``.

Repository index
----------------

One index per registry namespace, at
``<registry>/<namespace>/bpm-index:stable``.

.. list-table::
   :header-rows: 1
   :widths: 26 74

   * - Object
     - Content
   * - Index manifest
     - OCI image manifest, ``schemaVersion`` 2, ``artifactType``
       ``application/vnd.shirudo.bpm.index.v1``, the empty config, and
       exactly one document layer and one signature layer.
   * - Document layer
     - The index document, media type
       ``application/vnd.shirudo.bpm.index.v1+json``.
   * - Signature layer
     - Detached CMS signature over the document layer's bytes, media type
       ``application/vnd.shirudo.bpm.index.signature.v1``.

The index document:

.. code-block:: text

   {"schema": 1,
    "generated_at": "<utc-time>",
    "packages": [
      {"name": "<package>", "version": "<version>",
       "repository": "<repository>",
       "manifest_digest": "sha256:<hex>",
       "package_digest": "sha256:<hex>",
       "package_size": <bytes>,
       "signer_fingerprint": "<hex>"}]}

.. list-table::
   :header-rows: 1
   :widths: 26 74

   * - Key
     - Value
   * - ``schema``
     - ``1``. Required.
   * - ``generated_at``
     - UTC time of the push. Not read by the target.
   * - ``packages``
     - Required. At most 512 entries. ``bpm push`` sorts them by name,
       then version.
   * - ``name``, ``version``
     - Package name and version.
   * - ``repository``
     - Repository path on the index's registry, without the host.
   * - ``manifest_digest``
     - Digest of the package manifest. The target fetches the manifest by
       this digest and refuses other bytes.
   * - ``package_digest``
     - Digest of the ``.bee`` layer. The target refuses a manifest whose
       package layer has another digest, and a download that hashes to
       another value.
   * - ``package_size``
     - Size of the ``.bee`` layer in bytes, required and positive. The
       target refuses a layer of another size.
   * - ``signer_fingerprint``
     - ``shirudo.spki_sha256_fingerprint`` of the package. Not checked by
       the target.

A published version is immutable: ``bpm push`` refuses to list a name and
version again with a different ``manifest_digest`` or ``package_digest``.
The target keeps the verified document as
``/var/lib/shirudo/bpm/repos/<source>/index.json``.

upatch tree
-----------

A tree is an append-only sequence of ``add`` and ``delete`` operations in
one repository, ``oci://<registry>/<repository>``. ``bpm tree append``
publishes one operation per ``[upatches.tree]`` entry of a package.

Tree objects in the registry
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 26 74

   * - Object
     - Content
   * - Publication manifest
     - At ``<repository>:<reference>``, ``stable`` unless
       ``--reference`` names another tag. OCI image manifest,
       ``schemaVersion`` 2, ``artifactType``
       ``application/vnd.shirudo.upatch.tree.v1``, the empty config, and
       exactly one document layer and one signature layer, in that order.
       Its bytes are exactly those ``bpm tree append`` writes: compact
       JSON with the keys ``schemaVersion``, ``mediaType``,
       ``artifactType``, ``config`` and ``layers`` in this order, and each
       descriptor's ``mediaType``, ``digest`` and ``size``. A target and
       ``bpm tree append`` refuse a manifest in any other form, so that the
       manifest digest a target records and a successor names as its
       parent or segment follows from the two signed layers.
   * - Sealed segment
     - A publication manifest that a later segment names in
       ``base.segment_manifest_digest``, unchanged since it was the
       current one. Tagged ``segment-<k>``, ``k`` counting the sealed
       segments from 1, only so that registry garbage collection keeps
       it; targets fetch it by digest and never read the tag.
   * - Document layer
     - The publication document, media type
       ``application/vnd.shirudo.upatch.tree.v1+json``.
   * - Signature layer
     - Detached CMS signature over the document layer's bytes, media type
       ``application/vnd.shirudo.upatch.tree.signature.v1``.
   * - Artifact manifest
     - One per operation, tagged ``upatch-<id>-<payload16>``, where
       ``<payload16>`` is the first 16 hex digits of the artifact's
       ``payload_sha256``. ``artifactType`` and layer media type
       ``application/vnd.shirudo.upatch.v1``, the empty config, one layer
       holding the ``.upatch`` file, annotation
       ``org.opencontainers.image.title`` ``<id>.upatch``. An ``add``
       publishes the load artifact, a ``delete`` the unload directive.

Publication document
~~~~~~~~~~~~~~~~~~~~

.. code-block:: text

   {"schema": 1,
    "tree_id": "<tree-id>",
    "generation": <n>,
    "parent_manifest_digest": "sha256:<hex>",
    "base": {"seq": <b>,
             "segment_manifest_digest": "sha256:<hex>",
             "history_root": "<hex>"},
    "operations": [<operation>, ...],
    "head": {"seq": <n>}}

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Key
     - Value
   * - ``schema``
     - ``1``. Required.
   * - ``tree_id``
     - A package name. Required.
   * - ``generation``
     - Required. 1 for the first publication, one more for each append.
       From 0 to 2\ :sup:`63` - 2.
   * - ``parent_manifest_digest``
     - Digest of the publication manifest this one replaces. Absent in
       the first publication.
   * - ``base.seq``
     - Required. 0 for the first segment of the tree, otherwise the
       ``head.seq`` of the sealed segment before it.
   * - ``base.segment_manifest_digest``
     - Required when ``base.seq`` is above 0 and refused at 0. Digest of
       the sealed publication manifest of the segment before this one.
   * - ``base.history_root``
     - Required when ``base.seq`` is above 0 and refused at 0. 64 hex
       digits: the ``history_root`` every node's ``outcomes`` record
       holds at ``base.seq``, see `Node records`_.
   * - ``operations``
     - Required. At most 512. Each ``seq`` is one more than the previous
       one, and the first is ``base.seq + 1``. At least one when
       ``base.seq`` is above 0.
   * - ``head.seq``
     - Required. The ``seq`` of the last operation, or ``base.seq`` when
       there is none. Below 2\ :sup:`63` - 1.

Unknown keys are ignored.

Operation
~~~~~~~~~

.. code-block:: text

   {"seq": <n>, "op": "add", "id": "<upatch-name>",
    "selector": {...},
    "artifact": {"repository": "oci://<registry>/<repository>",
                 "manifest_digest": "sha256:<hex>",
                 "layer_digest": "sha256:<hex>",
                 "payload_sha256": "sha256:<hex>"},
    "fixes": ["<advisory-id>", ...],
    "operation_digest": "sha256:<hex>"}

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Key
     - Value
   * - ``seq``
     - Positive sequence number.
   * - ``op``
     - ``add`` or ``delete``.
   * - ``id``
     - The upatch name of the artifact. Must be a valid upatch name.
   * - ``selector``
     - Which nodes apply the operation, see `Selector`_. ``bpm tree
       append`` always writes it. Absent or ``{}``, it matches every node.
   * - ``artifact.repository``
     - ``oci://<registry>/<repository>`` the artifact manifest lives in.
   * - ``artifact.manifest_digest``
     - Digest of the artifact manifest.
   * - ``artifact.layer_digest``
     - Digest of the ``.upatch`` layer.
   * - ``artifact.payload_sha256``
     - ``sha256:`` and the artifact's header ``payload_sha256``.
   * - ``fixes``
     - Optional, on an ``add`` only: the IDs of the advisories the upatch
       fixes, 1 to 16 strings of 1 to 255 bytes of letters, digits,
       ``.``, ``_``, ``:`` and ``-``, each once, in byte order. A
       convention of the keepalive backend, not of shirudo: the CMS
       signature covers it, the operation digest does not, and the target
       never reads, checks or measures it, so a malformed one never makes
       a node refuse the publication. ``bpm tree append`` writes it after
       ``artifact`` from the Beefile's ``fixes``
       (:doc:`/upatches/publish/beefile`), leaves it out when the list is
       empty, carries every earlier operation's list into the next
       generation unchanged, and refuses to append to a publication whose
       list breaks these rules.
   * - ``operation_digest``
     - ``sha256:`` and the SHA-256 of the canonical operation, see
       `Operation digest`_.

Selector
~~~~~~~~

Every key present must match. A list matches when one value matches.
Lists hold at least one value, and an option or label appears once in
``kconfig`` and ``kernel_config`` together or in ``labels``: the node
refuses a publication otherwise.

.. list-table::
   :header-rows: 1
   :widths: 26 30 44

   * - Key
     - Type
     - Matches when
   * - ``architecture``
     - list of strings
     - One value equals ``uname`` machine, for example ``x86_64``.
   * - ``kernel_release_prefix``
     - list of strings
     - The kernel release starts with the value, followed by the end, a
       ``.`` or a ``-``.
   * - ``kernel_build_id``
     - list of strings
     - One value equals the kernel's GNU build ID from
       ``/sys/kernel/notes``, lowercase hex. A kernel without one never
       matches.
   * - ``kconfig``
     - object of lists
     - For each option, its value in ``/proc/config.gz``, else
       ``/boot/config-<release>``, is in the list. ``# CONFIG_<x> is not
       set`` reads as ``n``. ``kernel_config`` is accepted as an alias when
       parsing.
   * - ``labels``
     - object of lists
     - For each key, the node label's value is in the list. Node labels
       come from ``etc/shirudo/node.labels`` in the config image. A node
       without labels never matches.

Lists hold 1 to 16 strings of fewer than 256 bytes. ``kconfig`` and
``labels`` hold at most 64 keys each.

Operation digest
~~~~~~~~~~~~~~~~

``operation_digest`` is the SHA-256 of the compact JSON of the operation
without ``operation_digest`` and ``fixes``, in this form:

- Keys in the order ``seq``, ``op``, ``id``, ``selector``, ``artifact``.
- ``selector`` keys in byte order: ``architecture``, ``kconfig``,
  ``kernel_build_id``, ``kernel_release_prefix``, ``labels``. Empty lists
  are left out. ``kconfig`` and ``labels`` keys in byte order.
- List values in the published order. ``bpm tree append`` sorts them in
  byte order before it publishes.
- ``artifact`` keys in the order ``repository``, ``manifest_digest``,
  ``layer_digest``, ``payload_sha256``.

The target recomputes the digest from the parsed operation and refuses the
publication when one differs. The digest of each applied operation enters
the measurement register as a ``tree_op`` event, see
:doc:`eventlog`.

Target acceptance
~~~~~~~~~~~~~~~~~

``bpm tree sync`` applies a publication only when all of these hold:

#. The manifest has one document layer and one signature layer, each
   matching its descriptor's digest and size.
#. The signature verifies against the runtime image's initial
   certificate.
#. The document parses with the rules above, ``tree_id`` is a package
   name, and every operation has a valid ``id``, ``op`` and digests and a
   correct ``operation_digest``.
#. ``tree_id`` equals the one the node recorded.
#. A publication other than the recorded one has a higher
   ``generation``. A direct successor that names a
   ``parent_manifest_digest`` names the recorded manifest.
#. ``head.seq`` is not below the node's last applied ``seq``.
#. When ``base.seq`` lies past the node's last applied ``seq``, 0 for a
   node without a state, the node walks back to it through the sealed
   segments, see `Walk`_.
#. Base check: the ``history_root`` of the node's ``outcomes`` at
   ``base.seq``, 32 zero bytes at 0, equals ``base.history_root``.
#. Prefix check: the publication's operation digests, folded from
   ``base.history_root`` up to the node's last applied ``seq``, give the
   node's ``history_root`` there. This applies to every publication, so
   a registry that serves operations other than the ones a node already
   processed, inside a segment or at its base, is refused with
   ``EKEYREJECTED``.

The node then records the publication, see `Node records`_, and processes
the operations after its last applied ``seq``.

For each new operation whose selector matches, the target then fetches the
artifact manifest by ``manifest_digest``, takes the layer with
``layer_digest`` and media type ``application/vnd.shirudo.upatch.v1``,
checks its digest and size, and refuses the ``.upatch`` unless its header
``payload_sha256`` equals ``artifact.payload_sha256``, its ``name`` equals
``id`` and it is an unload directive exactly when ``op`` is ``delete``.

Walk
~~~~

A node behind the segment that ``<reference>`` names fetches back to the
segment its last applied ``seq`` lies in, then applies the segments
forwards. It keeps the manifest digest, ``base.seq``, ``head.seq`` and
``generation`` of each segment, not the documents.

#. While the oldest segment so far starts past the node's last applied
   ``seq``, the node refuses the sync when the distance between the two
   exceeds the walk limit (``E2BIG``), see `Limits`_, then fetches
   ``manifests/<base.segment_manifest_digest>``. The sealed segment must
   pass checks 1 to 3 above, hash to that digest, have the same
   ``tree_id``, end at its successor's ``base.seq`` and have a lower
   ``generation`` (``ERANGE``). A segment the registry does not serve
   refuses the sync; the node never skips ahead.
#. Oldest first, the node fetches each sealed segment again by its
   digest and checks it as before, then runs checks 4 to 9 and applies
   it as above. The segment ``<reference>`` names, which the walk holds,
   comes last.

An operation left in progress is completed against the oldest segment of
the walk alone: the node records a segment before it processes it, so the
operation lies in the segment its state names. ``state.json`` moves at
each applied operation and at each segment recorded, so a walk that stops
resumes with a shorter one. A reboot never walks: ``init`` reads
``state.json`` alone.

Node records
~~~~~~~~~~~~

The target keeps these under ``/var/lib/shirudo/bpm/upatch-tree/``. They are
not published.

.. list-table::
   :header-rows: 1
   :widths: 22 78

   * - File
     - Content
   * - ``state.json``
     - JSON object with ``schema`` (1), ``tree_id``, ``generation``,
       ``manifest_digest``, ``head_seq`` and ``segment_base_seq`` of the
       publication the node last accepted, ``last_seq``,
       ``projection_root`` and ``projection_root_tpm``. ``head_seq`` and
       ``segment_base_seq`` are the publication's ``head.seq`` and
       ``base.seq``. A sync records a publication, each segment of a walk
       in turn, once it passes the checks above and an interrupted
       operation is completed, before it processes the first new
       operation of it, so a sync that stops among them leaves
       ``last_seq`` from ``segment_base_seq`` to ``head_seq`` and the
       node refuses
       an older generation from then on. ``last_seq`` also moves past
       operations whose selector does not match. A state without one of
       ``tree_id``, ``last_seq``, the two roots, ``head_seq`` and
       ``segment_base_seq`` is refused.
   * - ``tree-eventlog``
     - One JSON object per line and applied operation, with ``schema``
       (1), ``seq``, ``digest`` (the ``operation_digest``) and
       ``projection_root``. ``projection_root`` is the SHA-256 of the
       previous root followed by the raw operation digest, starting from
       32 zero bytes. A last line without its newline is an append that
       did not finish: the replay skips it and the next append drops it.
   * - ``outcomes``
     - One JSON object per line and processed operation, in order from
       ``seq`` 1, with ``schema`` (1), ``seq``, ``outcome``,
       ``projection_root`` and ``history_root``. ``outcome`` is 1 for an
       operation that was applied, 2 for one whose selector did not
       match and 3 for an ``add`` that was measured but not loaded
       because of ``attach_target_missing``. ``projection_root`` is the
       node's projection root after the operation, which an unmatched
       one leaves where it was. ``history_root`` is the SHA-256 of
       ``shirudo-tree-history``, a NUL byte, the previous history root
       and the raw operation digest, starting from 32 zero bytes: it
       counts every operation, whatever its outcome, so it is the same
       on every node at the same ``seq``. A line is written and synced
       to disk before the ``state.json`` that covers it, and a line at
       or below ``last_seq`` is never rewritten. Lines past ``last_seq``
       and a last line without its newline are what a sync that stopped
       left: the next sync drops them before it appends. It then refuses
       a state with ``last_seq`` above 0 whose ``outcomes`` is missing
       (``ENOENT``), or has a gap or a malformed line or ends before
       ``last_seq`` (``EBADMSG``). Nothing rebuilds or prunes the file:
       the keepalive reads its last 512 operations from it whatever
       segments held them (:doc:`/reference/cli/status`).
   * - ``pending.json``
     - JSON object with ``schema`` (1), ``seq``, ``id`` and
       ``operation_digest`` while an operation is in progress. The next
       sync completes the operation without applying it again when the
       tree eventlog or this boot's eventlog already records it, and
       applies it again otherwise. Completing it writes the ``outcomes``
       lines the stopped sync did not commit: outcome 2 for each
       operation between ``last_seq`` and the pending one, which that
       sync passed over, then the pending operation's, 3 when it is an
       ``add`` whose upatch is not loaded, with its ``status/<id>``, and
       1 otherwise. An ``add`` applied again whose upatch
       a stopped sync already loaded with its payload counts as
       installed.
   * - ``artifacts/<hex>.upatch``
     - Fetched artifacts, named by their layer digest.
   * - ``status/<id>``
     - ``skipped: module not loaded`` for an ``add`` whose attach target
       was missing.

:doc:`/reference/files` lists every file shirudo keeps.

Limits
------

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - Item
     - Limit
   * - Package file read by ``bpm push``
     - 256 MiB
   * - Archive members
     - 4096 members, 256 MiB of content
   * - Member name
     - fewer than 100 bytes, no ustar prefix
   * - ``build-environment.json`` and ``Beefile`` read by ``bpm push``
       and ``bpm tree append``
     - 4 MiB
   * - Index entries
     - 512
   * - Tree operations per publication
     - 512
   * - Tree walk of a node that has processed an operation,
       ``TREE_MAX_WALK_OPS``
     - 65,536 operations from its last applied ``seq``
   * - Tree walk of a node that has processed none, ``TREE_MAX_JOIN_OPS``
     - 1,048,576 operations from ``seq`` 0
   * - JSON document
     - 8 MiB
   * - Detached signature
     - 64 KiB (writer)

A walk past its limit refuses the sync with ``E2BIG`` before it fetches a
sealed segment, see `Walk`_. The bound is on the distance from the node's
last applied ``seq``, not on the size of the tree. A node that has
applied nothing holds no upatch of the tree yet and is joining, so it
gets the higher limit; a running node walks holding the bpm lock, which
stops its keepalive, and gets the lower one. A higher limit only allows
more verified fetches and never makes a node accept what it would
otherwise refuse. Join time grows linearly with the tree: each segment
of a walk costs two fetches of its manifest, document and signature and
two signature checks, so a node that joins at the limit with the default
64 operations per segment walks 16,384 segments, about 100,000 registry
requests, besides fetching, loading and measuring each operation its
selectors match. Both limits are compile-time defines, settled for now
and to be revisited by experiment on live clusters; a node further
behind than its limit is refused every sync of the tree.

Related
-------

- :doc:`/upatches/publish/publishing`
- :doc:`/operate/run/deliver-packages`
- :doc:`/reference/cli/bpm`
- :doc:`configuration` for repository and tree settings
