..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: shirudo contributors

Proof coverage
==============

This page lists the CBMC proofs under :src:`testing/proofs/cbmc/` and the
Lean 4 proofs under :src:`testing/proofs/lean4/`, what each one proves and
for which inputs, and the parsers no proof covers yet. :doc:`proofs`
explains how to run and write them.

CBMC proofs
-----------

Every CBMC proof shows that the code reads and writes nothing outside its
objects and has no undefined arithmetic for the inputs it covers, besides
the properties the table lists. "Every input" means every input of any
length. A bound such as "up to 22 bytes" means every input of that length
or shorter, and "lengths 0 to 6" every input of each of those lengths.

.. list-table::
   :header-rows: 1
   :widths: 22 26 18 34

   * - Proof
     - Code
     - Inputs
     - Properties
   * - ``string-number``
     - ``parse_u64()``, ``parse_x64()``, ``parse_s64()``, ``digits()``
     - Up to 22 bytes, past the 20 digits of the largest value
     - Refuses exactly what is empty or holds a non-digit; a number
       within its bounds and of the sign the string spells; nothing
       written on refusal; ``digits()`` finds the whole run
   * - ``string-number-model``
     - ``parse_u64()``, ``parse_x64()``
     - Up to 4 bytes
     - The value of the Lean model ``Shirudo.Number``, or ``-ERANGE``
       exactly where the model refuses
   * - ``string-utf8``
     - ``utf8_width()``
     - Every input
     - Equals Table 3-7 of the Unicode Standard, the well-formed byte
       sequences, row by row
   * - ``string-sanitize``
     - ``text_sanitize()``
     - Lengths 0 to 6, with and without line breaks
     - Leaves well-formed UTF-8 without a C0, DEL or C1 control but a
       kept line break; changes a byte only to ``?``; keeps every
       printable character
   * - ``string-copy``
     - ``strscpy()``
     - Strings and buffers up to 8 bytes
     - Terminates what it writes; the whole string and its length, or
       what fits and ``-E2BIG``
   * - ``string-suffix``
     - ``name_has_suffix()``
     - Names up to 6 bytes, suffixes up to 3
     - True exactly when the name's last bytes are the suffix and at
       least one byte comes before them
   * - ``hex``
     - ``hex_encode()``, ``hex_decode()``, ``hex_decode_max()``
     - Up to 4 bytes, strings up to 9 characters
     - Lowercase hex that decodes back to the input; a decode takes
       exactly ``2 * n`` hex digits of either case and yields their
       value, and ``hex_decode_max()`` any even count up to ``2 * cap``,
       reading no further than the digit after them
   * - ``hex-model``
     - ``hex_encode()``, ``hex_decode()``, ``hex_decode_max()``
     - Up to 8 bytes, strings up to 17 characters, counts and capacities
       up to 8 and past ``SIZE_MAX / 2``
     - The result and the bytes of the Lean model ``Shirudo.Hex``
   * - ``paths-bpffs-name``
     - ``upatch_bpffs_name()``, ``upatch_name_from_bpffs()``
     - Names up to 4 bytes, pin names up to 8
     - A name without ``~`` maps to a pin name without a dot and back to
       itself; a pin name without a dot that decodes is the encoding of
       what it decodes to
   * - ``paths-bpffs-name-model``
     - ``upatch_bpffs_name()``, ``upatch_name_from_bpffs()``
     - Up to 8 bytes, buffers up to 18
     - The result and the string of the Lean model ``Shirudo.PinName``
   * - ``bpm-tree-selector``
     - ``tree_selector_kv_add()``, ``tree_selector_copy()``,
       ``tree_selector_free()``, ``tree_text()``
     - 0 or 1 pairs, every limit, allocations allowed to fail
     - ``-E2BIG`` exactly at the limit with nothing changed; a copy owns
       its arrays, a failed one holds nothing; text without controls
   * - ``bpm-tree-reader``
     - ``tree_map_pair()``, ``tree_take_operation()``
     - Every pair and operation, into an empty or a full publication
     - A key taken once, with a value, below its limit; an operation
       taken exactly when whole and with room
   * - ``bpm-tree-follows``
     - ``tree_publication_follows()``
     - Every sequence number and generation; strings up to 2 bytes
     - Accepts exactly a publication of the same tree, of a later
       generation unless the same manifest, naming the recorded parent
       when the next generation, with the node's cursor between its base
       and head; without a state, one that starts at 0
   * - ``bpm-tree-sync-model``
     - ``cmd_bpm_tree_sync()``, ``tree_recover_pending()``,
       ``tree_publication_check()``, ``tree_publication_follows()``
     - Every state, pending record, tree eventlog replay and record of the
       pending operation, publications of 0 to 2 operations that
       ``tree_parse()`` lets through, every selector answer and every
       failure below sync; strings of one byte
     - The writes of the Lean model ``Shirudo.TreeSync``, in its order,
       none after a failure, all of them when nothing fails
   * - ``otel-header-fields``
     - The OTLP header checks and ``percent_decode()``
     - Strings up to 32 bytes
     - Names exactly RFC 9110 tokens, values without controls but tab;
       each ``%XX`` decoded, a stray ``%`` and ``%00`` refused
   * - ``otel-retry-after``
     - ``otel_retry_after()``, ``response_header()``
     - Headers up to 32 bytes, dates modelled
     - A delay is at most 30 seconds, the value itself when shorter; a
       header line read only within itself
   * - ``log-escape``
     - ``escape()`` of :src:`util/log.c`
     - Messages of 0 to 5 bytes, every buffer size
     - Terminated printable ASCII, every backslash a ``\\`` or three octal
       digits, decoding to the message or to a prefix cut between
       characters

Lean 4 proofs
-------------

Each proof holds for every input of the model; the last column says how
the model follows the C.

.. list-table::
   :header-rows: 1
   :widths: 22 30 26 22

   * - Model
     - Theorems
     - Assumptions
     - Follows the C
   * - ``Shirudo.Number``, ``parse_base()`` of :src:`util/string.c`
     - ``parse_exact``: for digit strings of every length, the value they
       spell, or ``-ERANGE`` exactly when it passes ``max``
     - ``max`` fits a ``__u64``
     - CBMC, ``string-number-model``, up to 4 bytes
   * - ``Shirudo.Chain``, the register of :src:`rust/src/util/chain.rs`
     - ``register_injective``, ``register_tagged_injective``: equal
       registers come from the same events, tagged the same, in the same
       order; ``register_injective_on``: the same with the hash injective
       only on the pairs the two sequences fold; ``register_eq_foldl``: the
       register folds the events in the order they came
     - The hash is injective on the (register, event) pairs (for
       ``register_injective_on`` only those folded) and never yields the
       initial value; ``register_tagged_injective`` also takes the tagged
       encoding as injective, which ``Shirudo.Events`` proves
     - Review
   * - ``Shirudo.Events``, the event encodings of
       :src:`rust/src/util/chain.rs`
     - ``bytes_injective``: two admitted events hash the same bytes only
       when they are the same event; ``listing_injective``: the init
       event's listing spells one set while no name holds a newline;
       ``sorts_unique``: ``qsort()`` leaves a set of distinct names in one
       order; ``replay_injective_on``, ``replay_collision``,
       ``verify_sound``: equal registers come from the same typed events in
       the same order, or the strings hashed hold a SHA-256 collision or a
       string that hashes to zero; ``upatch_cut``, ``listing_newline``,
       ``sorts_tie``: where the domain ends
     - SHA-256 maps no two different strings the two histories hash to one
       digest and none to 32 zero bytes; names ``upatch_name_valid()``
       accepts of at most 256 bytes; sequence numbers of a ``__s64``
     - Review of the listing of a non-empty set and the NV extend; the
       CBMC harness of the rest, ``chain-events``, went with
       ``util/chain.c`` in the port to Rust
   * - ``Shirudo.Measured``, ``measured_event()`` of
       :src:`rust/src/util/measured.rs`
     - ``holds_iff``: ``measured_holds()`` finds a name and payload exactly
       when the last init, load or unload bearing on the name is its load
       with that payload; ``measuredSet_nodup``: each name once;
       ``measuredSet_init``: an init record starts the set over;
       ``holds_last_load``, ``not_holds_after_unload``
     - None
     - Review
   * - ``Shirudo.SemVer``, ``semver::compare()`` of
       :src:`rust/src/util/bpm_package/`
     - ``compareStrings_refl``, ``compareStrings_swap``,
       ``compareStrings_trans``: a total order on strings of every
       length; ``compareStrings_eq_iff``, ``compareStrings_invalid``,
       ``compareStrings_valid``: equal exactly for the same version up to
       build metadata, and for strings that are not SemVer for the same
       bytes; ``numCmp_value`` and the other rules of SemVer 2.0.0
       precedence
     - None; numeric identifiers compare by value only without a leading
       zero, which ``semverParse_wellFormed`` shows the parser ensures
     - None since the port to Rust; the CBMC model went with
       ``util/bpm_package.c``
   * - ``Shirudo.PinName``, ``upatch_bpffs_name()`` and
       ``upatch_name_from_bpffs()`` of :src:`util/paths.h`
     - ``decode_encode``: a name without ``~`` decodes back from its
       encoding; ``dot_not_mem_encode``: an encoding holds no dot;
       ``encode_injective``: no two names without ``~`` share a pin;
       ``encode_decode``, ``tilde_not_mem_decode``: a pin name without a
       dot that decodes is the encoding of a name without ``~``;
       ``bpffsName_ok``, ``nameFromBpffs_ok``, ``pin_round_trip``: the
       same through the buffers, ``-ENAMETOOLONG`` exactly where the C
       refuses
     - A C string is shorter than 2^63 bytes
     - CBMC, ``paths-bpffs-name-model``, up to 8 bytes
   * - ``Shirudo.ArchivePath``, ``archive_rel_ok()``,
       ``package_member_name_ok()`` and the member checks of
       ``extract()`` of :src:`rust/src/util/bpm_package/`
     - ``relOk_iff``, ``relOk_plain``: the check takes exactly the relative
       paths of plain components, with or without a final ``/``;
       ``relOk_contained``: every name it takes, resolved below any
       directory, leads strictly below it, as does each directory on the
       way; ``memberNameOk_iff``: a member matches only as one plain
       component, ``/`` and the member; ``extract_contained``: every
       member extracted is a regular file or a directory strictly below
       ``dest``, or ``dest`` itself
     - Resolution as the kernel walks a path, ``.`` staying, ``..`` going
       up and an empty component refused; the extraction's limits on
       count, size and path length are left out
     - Review; the CBMC model of the two checks went with
       ``util/bpm_package.c`` in the port to Rust
   * - ``Shirudo.Hex``, :src:`util/hex.c`
     - ``decode_encode``, ``length_encode``, ``encode_lower``: an encoding
       is lowercase hex twice its length that decodes back;
       ``decode_spec``: ``hex_decode()`` takes exactly ``2 * n`` hex
       digits of either case, and its bytes encode back to them in
       lowercase; ``decodeMax_spec``: ``hex_decode_max()`` takes exactly
       the even runs of at most ``2 * cap``; ``encode_injective``
     - A string is shorter than ``SIZE_MAX``
     - CBMC, ``hex-model``, up to 8 bytes and 17 digits
   * - ``Shirudo.JsonString``, the strict ``put_string()`` that
       ``json_str()`` calls and ``Cursor::string()`` of
       :src:`rust/src/util/json/`
     - ``read_write``: the reader returns exactly every string the writer
       takes and stops at its closing quote; ``write_isSome``: the writer
       takes exactly well-formed UTF-8 without NUL; ``write_string``: it
       writes one ECMA-404 string in well-formed UTF-8, with no control
       byte and no ``"`` or ``\`` outside an escape; ``readString_wf``:
       whatever the reader returns, from any input, is well-formed UTF-8
       without NUL
     - The emitter has room; for ``read_write``, the string fits
       ``JSON_MAX_STRING_BYTES`` and the buffer; well-formed UTF-8 is
       Table 3-7, which the Rust core checks
     - None since the port to Rust; the CBMC models went with
       ``util/json.c``
   * - ``Shirudo.ConfigActivation``, the config activation of
       :src:`rust/src/util/config_update.rs` as ``image update``,
       ``status`` and ``init`` drive it
     - ``consistent_or_refusing``, ``refusal_persists``: the PCR replays
       from the record with its config mounted, or every command but
       ``status`` and ``image status`` refuses, a pending or drifted state
       until the TPM boot changes; ``extends_once``,
       ``extension_follows_pending``, ``interrupted_never_extends``: one
       extension per activation and TPM boot, after the pending record,
       none after an interruption; ``reboot_stale``, ``reboot_recovers``,
       ``boot_completion``: after a reboot commands refuse until ``init``
       records a boot event, which an uninterrupted ``init`` does, and from
       any journal ``init`` completes only with the PCR holding exactly the
       selected config's boot event; ``configInUse_vouched``,
       ``mounted_selected``, ``consistent_mounted``, ``journal_wellformed``,
       ``pcr_replay``, ``completion_by_complete``
     - Commands one at a time; an atomic ``state`` rename; a crash leaves a
       prefix of a line; only shirudo writes the journal and the config
       mount during a boot; PCRs reset only at a reboot or TPM Restart;
       equal values from equal extensions (``pcr_value_eq_iff`` with
       ``Shirudo.Chain``'s assumptions); TPM boot identities never repeat;
       a TPM Restart or Resume only between commands
     - Review; the CBMC harness ``config-update-follows`` of
       ``event_follows()`` and ``same_event()`` went with
       ``util/config_update.c`` in the port to Rust
   * - ``Shirudo.UpatchLoad``, the load, unload and purge of
       :src:`builtin-upatch.c`, the gate of :src:`util/image_runtime.c` and
       the boot restore of :src:`builtin-init.c`
     - ``undo_pass_sound``: once a command's undo pass is done, every pin
       directory holds one link, of the payload its xattr names and this
       boot's records hold, and every archive file shirudo wrote is on
       record; ``loaded_once``: no name holds two links;
       ``recorded_runs``: every name the records hold is pinned with one
       link of that payload; ``commands_need_init``: every command runs
       in a boot whose init record is on the log;
       ``init_restores_exactly``: ``init`` loads exactly the labeled
       archive files whose last record is a load of that payload, and the
       new boot's records hold exactly those; ``log_sublist_register``,
       ``register_length``, ``register_eq_log_iff``, ``replay_differs``:
       this boot's records are a sublist of the register's events, equal
       once the lock is free unless an append was lost, and a difference
       shows in the replay; dropping the lock, the undo pass, its refusal,
       the gate, the undo of a failed payload xattr, the lock across the
       purge or the restore's filter breaks the matching theorem
     - The lock excludes and a kill releases it; a kill keeps pins and
       files; pin directory removals, archive renames and appends are
       whole; a reboot clears pins and register and ``init`` runs as one
       step; root changes only unlabeled archive files and brings files
       back; the hash of ``Shirudo.Chain`` for ``replay_differs``
     - Review; the CBMC harness ``measured-fold-model`` of
       ``measured_event()`` and ``measured_holds()`` went with
       ``util/measured.c`` in the port to Rust
   * - ``Shirudo.TreeSync``, ``cmd_bpm_tree_sync()`` and
       ``tree_recover_pending()`` of :src:`builtin-bpm.c`
     - ``generation_mono``, ``lastSeq_mono``, ``log_grows``: between any two
       points of any history of syncs of signed publications, stops after
       any write and reboots, the generation, the cursor and the tree
       eventlog never go back; ``manifest_fixed``: at an equal generation
       only the recorded manifest; ``older_refused``,
       ``accepted_older_refused``: a publication older than one accepted
       writes nothing; ``log_increasing``, ``measured_increasing``: each
       operation applied at most once, in increasing order, in the tree
       eventlog and in this boot's records; ``recover_pending``,
       ``measured_kept``, ``recover_settles``: after a stop between
       ``pending.json`` and the commit, recovery appends the operation once,
       exactly when it was measured or appended, and otherwise leaves the
       cursor below it; nothing measured is lost; ``state_is_fold``,
       ``replay_not_bad``: the state is the fold of the tree eventlog but
       between an append and its commit; ``applied_signed``,
       ``applied_consistent``: an applied operation is one of a signed
       publication of the tree, and that of every one when the signer never
       gives a number two operations
     - A manifest digest names one publication; the hash is injective on
       (root, digest) and never 64 zeros; only sync writes the tree files,
       each write whole, one sync at a time; the unlink of ``pending.json``
       succeeds; an extend and its eventlog record are one write
     - CBMC: ``bpm-tree-follows`` for ``tree_publication_follows()``,
       ``bpm-tree-sync-model`` for the writes of a sync of up to two
       operations; ``tree_parse()`` by review

Not covered yet
---------------

The fuzz targets in :doc:`test-coverage` cover these parsers; no proof
does: the JSON reader and writer of :src:`rust/src/util/json/`, the OCI
client of :src:`rust/src/util/bpm_oci/`, the package reader of
:src:`rust/src/util/bpm_package/`, its tar headers, member paths,
version order and upatch member names included, the TPM structures,
policy digests and key derivations of :src:`rust/src/util/tpm_wire/`,
the eventlog of :src:`rust/src/util/eventlog/`, the site configuration
of :src:`rust/src/util/config.rs`, the kernel's build ID and release
match of :src:`rust/src/util/kernel_build_id.rs` and
:src:`rust/src/util/kernel_release.rs`, the registry source and tree
lines of :src:`rust/src/util/bpm_source_config.rs`, the bootstrap file
and config root event of :src:`rust/src/util/image_bootstrap.rs` and
:src:`rust/src/util/config_measure.rs`, the config image's superblock
of :src:`rust/src/util/config_image.rs`, the ``.upatch`` container
reader of :src:`rust/src/util/upatch.rs` and its ``.rodata`` reader of
:src:`rust/src/util/upatch_rodata.rs`, whose CBMC proofs went with the C
they proved when the modules moved to Rust; and how
``json_parse()`` dispatches objects, arrays and maps to their schemas,
the OTLP headers a configuration adds, the registry references and URLs,
the kernel configuration the tree selectors read, the tree log, the
evidence document beyond its PCRs, the config update record, the site
configuration file and the config image's settings and tree. The tree
reader is covered part by part, as the table shows; what joins those
parts has no proof.
