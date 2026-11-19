..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: shirudo contributors

Check the Aeneas pilot
=====================

The pilot under :src:`testing/proofs/aeneas/` extracts small slices
of production Rust with Charon and Aeneas. The config event equality and
successor predicates, pin-name codec and archive-path predicates have
checked refinements against the existing Lean models. The existing model proofs retain their
coverage and limits in
:doc:`proof-coverage`.

The candidates are ``same_event()`` and ``event_follows()`` in
:src:`rust/src/util/config_update.rs`, and ``archive_rel_ok()`` and
``package_member_name_ok()`` in :src:`rust/src/util/bpm_package/tar.rs`.
The pin-name codec in :src:`rust/src/util/upatch.rs` is another candidate.
The pilot does not cover the activation journal protocol, the TPM, tar
checksums or archive extraction.

Before you begin
----------------

Use Python 3 to prepare the source slices. Extraction additionally needs
the tools in :src:`testing/proofs/aeneas/toolchain.json`, already built
in the recorded checkouts:

* Aeneas ``bfb92090dff8ca0f24a62d3051e5afcbe16b3975`` from the private
  `shirudo-dev/aeneas
  <https://github.com/shirudo-dev/aeneas/tree/borrow-iterator-fixes>`_
  branch ``borrow-iterator-fixes``.
* Its Charon pin, ``4e83769c4c77571784b6ede7a9aa4237de76d1c4``, in the
  Aeneas checkout's ``charon/`` directory.
* Charon's Rust ``nightly-2026-09-17``, its compiler components and the
  ``x86_64-unknown-linux-gnu`` target.
* Aeneas's Lean ``leanprover/lean4:v4.36.0-rc2`` for checking generated
  Lean later. The existing proof suite keeps its own toolchain.

The fork's `Aeneas instructions
<https://github.com/shirudo-dev/aeneas/blob/bfb92090dff8ca0f24a62d3051e5afcbe16b3975/README.md>`_
describe building the tools. The extraction runner never installs tools, fetches a
dependency or runs Lean. Obtain approval before installing missing
packages or toolchains. Extraction runs Cargo offline; missing cached
dependencies or compiler components are errors.

The current run uses the combined ``borrow-iterator-fixes``
checkout under ``~/src/shirudo-dev/verification/aeneas-borrow-iterators/``.
It integrates iterator support and local extraction fixes.
``toolchain.json`` records the committed revision; the runner requires
tracked tool sources to be clean. The compiler is
``upstream/src/_build/default/main.exe`` and Charon is
``toolchain/charon-target/release/charon`` beside ``upstream/``.
Rust and Lean remain under ``~/src/shirudo-dev/verification/aeneas/``.
Use the installed Rust toolchain's ``bin/`` on ``PATH`` and set
``RUSTUP_HOME`` and ``CARGO_HOME`` to that installation's directories.

For a new checkout, obtain the branch from the private repository and
select the recorded commit::

   git clone --branch borrow-iterator-fixes \
     git@github.com:shirudo-dev/aeneas.git /path/to/aeneas
   git -C /path/to/aeneas checkout --detach \
     bfb92090dff8ca0f24a62d3051e5afcbe16b3975

The repository and branch are recorded in ``toolchain.json`` and extraction
reports. Advancing the branch does not change the compiler used by the
pilot until its commit pin is explicitly updated.

The runner explicitly selects the distributed Rust sysroot and disables
Charon's automatic toolchain installation and Miri sysroot setup. The
distributed sysroot lacks some standard library MIR. Use ``--sysroot``
to select an already built full-MIR sysroot when extraction needs those
bodies; building that sysroot is a separate setup step.

Prepare and extract
-------------------

1. Prepare the source slices from the working tree::

      python3 testing/proofs/aeneas/prepare.py

   This writes ``build/aeneas/config_predicates/`` and
   ``build/aeneas/archive_path/``. Each crate contains the exact selected
   Rust items, including their attributes, types and constants. No
   production code is rewritten. The only additional Rust is a module
   containing ``include!`` and the import of ``c_int``. The config slice also includes the current
   ``BootIdentity`` type and the unchanged ``boot()`` method, wrapped in
   its ``impl ConfigUpdateRecord`` block. Selection relies
   on rustfmt's top-level item boundaries and refuses an unexpected
   boundary or a missing or repeated item.

   Inspect ``build/aeneas/sources.json``: each selected item records its
   source path, line range, item hash and whole source file hash. This
   makes the source transformation reviewable; it is not a proof of that
   transformation or of the compiler. The generated crate has no external
   dependencies. Charon's target fixes ``usize`` at 64 bits and ``c_int``
   at 32 bits; overflow checks stay enabled.

2. With the pinned tools already built, extract either candidate::

      python3 testing/proofs/aeneas/extract.py \
        --aeneas /path/to/aeneas --candidate config_predicates
      python3 testing/proofs/aeneas/extract.py \
        --aeneas /path/to/aeneas --candidate archive_path

   Omitting ``--candidate`` attempts all candidates, stopping on failure.
   ``pin_codec`` selects both pin-name functions; ``pin_encode`` selects
   the encoder alone. Checking ``pin_codec`` also needs a ``pin_encode``
   extraction in the same output directory, because the decoder proof
   imports the encoder's shared declarations. Extract both candidates
   or use ``--candidate all``. The runner regenerates the
   slices, selects the private production functions with Charon's
   ``--start-from``, runs ``charon cargo --preset=aeneas``, then runs
   ``aeneas -backend lean -split-files``. It records commands, pins,
   binary, source and generated Lean hashes and completion status in each
   crate's ``extraction.json``. A failed command records the failure.
   The prepared Lake manifest uses the backend's existing dependency
   checkouts by local path; missing dependencies are errors, and the
   runner does not fetch or install them.

   Generated Lean goes under ``build/aeneas/lean/generated/``. Use a new
   ``--output`` directory for another extraction of the same candidate;
   the runner refuses to overwrite a nonempty generated directory.
   Both scripts accept ``--output``. Keep build artifacts under
   ``build/``; use ``/opt/Data/scratch/shirudo/`` for temporary experiments.

3. Inspect any external templates that Aeneas emits. Array and slice
   equality, iterators, ``position``, ``is_none_or``, slice indexing and
   ``wrapping_add`` may need library support. The config extraction needs
   no external templates; its array equality model is proved equal to
   exact ordered-byte equality in ``ConfigRefinement.lean``. Supply
   justified models for missing
   operations before using a translation; do not replace the predicates
   with handwritten copies or discharge missing operations with axioms.
   The current archive candidate supplies its three missing operations
   from ``ArchiveModels.lean`` as ``ArchivePath/FunsExternal.lean``.

Connect the models
------------------

The prepared Lean package copies the existing ``ArchivePath``,
``ConfigActivation``, ``Chain`` and ``PinName`` sources unchanged. Its
:src:`testing/proofs/aeneas/Contracts.lean` defines propositions to prove,
not theorems. ``ConfigRefinement.lean`` supplies the concrete config
projections, runners and proofs. For another candidate, add projections from the generated types
and instantiate each runner with the generated function. A runner maps
successful evaluation to ``some`` and failure or divergence to ``none``;
an equality to ``some`` must therefore establish successful termination
as well as the result. Do not leave a runner as a free hypothesis in the
final refinement theorem.

For config activation:

* Project only reset and restart counts, sequence, PCR, kind,
  ``initial_pcr`` and ``target.root_hash`` into ``Fields``. Keep the
  32 bytes of each digest, in order. ``SameEventRefines`` requires exact
  equality for all records, including invalid kind values. Prefix,
  pending and padding are deliberately absent.
* Prove ``EventProjectionFaithful`` for decoded fields, mapping kinds
  1 and 2 to ``boot`` and ``update``. The concrete boot identity is the
  pair of unsigned counters. ``event`` specializes ``ConfigActivation``
  with a raw initial digest as one atom in a singleton list; it does not
  interpret those bytes as a history of PCR extensions. Connecting real
  histories still needs ``Chain``'s hash assumptions.
* Prove ``EventFollowsRefines`` against ``ConfigActivation.Follows``.
  Sequence zero maps to ``none``, as the zeroed scan sentinel does.
  Other predecessors and current records have sequences from 1 through
  ``INT64_MAX``, the decoder's domain. Adding one cannot wrap a ``u64``
  there; a maximum predecessor cannot have a decoded successor.
  The Rust function returns ``Ok(())`` or ``Err(-EUCLEAN)``;
  the runner maps these to 0 and -117 for the existing proposition.
  Arbitrary wrapping sequences are outside this contract.

For archive paths, project an explicit slice to its ordered bytes and
then their natural-number values. Prove ``ArchiveRelRefines`` against
``ArchivePath.relOk`` and ``PackageMemberRefines`` against
``ArchivePath.memberNameOk``, including ``None`` returning false. The
contracts bound slice lengths by the target's ``isize::MAX``. The archive
refinement theorems explicitly require ``System.Platform.numBits = 64``,
matching the pinned Charon target and shirudo's supported architectures;
no architecture axiom is added. Establish
the loop's decreasing remaining length and the safety of every slice
and increment. A single trailing slash is accepted, an empty component
between slashes is refused, and member equality compares the complete
suffix after the first slash.

NUL is an ordinary byte to these Rust predicates. The abstract boolean
checks can be compared on such slices, but the existing filesystem
interpretation describes bytes before a terminator. Apply
``relOk_contained`` and ``memberNameOk_iff`` to NUL-free caller inputs,
after proving the boolean refinement; do not infer filesystem containment
for slices containing embedded NUL.

Verify the connection
---------------------

When proof runs are authorized, first check the generated package's
``Contracts`` target, then the ``ConfigPredicates`` and ``ArchivePath``
targets after supplying any required external models. The default
``lake build`` checks only the contract definitions and imported models;
it does not prove a connection to Rust. Explicitly check the
concrete refinement modules, with warnings as
errors and without ``sorry`` or new axioms. Inspect their dependencies
with ``#print axioms``.

Before claiming coverage, regenerate from current sources, check the
concrete refinement theorems, and demonstrate that a changed predicate
breaks its proof. Record that evidence in :doc:`proof-coverage`. Neither
source preparation, successful extraction nor type-checking the contract
definitions constitutes a completed refinement proof.

The checked config run used a fresh ``build/aeneas-current/`` output
directory. The clean committed compiler reproduces those checked Lean
inputs exactly in ``build/aeneas-committed/``. After extraction, run the
checker inside the pinned Aeneas backend's environment, passing an absolute
output path::

   cd /path/to/aeneas/backends/lean
   lake env python3 /path/to/shirudo/testing/proofs/aeneas/check.py \
     --output /path/to/shirudo/build/aeneas-committed \
     --candidate config_predicates

The checker compiles the copied models, contracts, generated types and
functions, then the concrete refinement with warnings as errors. It
records source hashes, commands, Lean version and the refinement's axiom
report in ``check.json``. It refuses stale production sources, altered
generated Lean or prepared models and refinements that differ from the
repository, and rejects extra axiom dependencies. It also validates
both tool binaries and the recorded local compiler source hashes.
The checker accepts ``config_predicates``, ``pin_encode``, ``pin_codec``
and ``archive_path``; the latter two check their concrete refinement
modules.
``--refinement-only`` is for proof iteration
after the imports have been checked; use the full check for coverage.

``same_event_contract`` holds for every generated record, including
invalid sequence or kind values. ``event_follows_contract`` holds for a
zero-sequence predecessor or a decoded predecessor, and a decoded current
record. It proves successful termination and the exact Rust result,
``Ok(())`` or ``Err(-117)``, against ``ConfigActivation.Follows``. ``event_projection_faithful``
proves that the decoded field projection preserves and reflects event
equality. Their axiom reports contain only ``propext``,
``Classical.choice`` and ``Quot.sound``; the projection theorem needs
only ``propext``.

In an earlier negative control, a separate copied Rust crate omitted
``same_event``'s sequence comparison. Charon and Aeneas re-extracted that
crate successfully. The original refinement then failed with the
unprovable obligation that equal root hashes imply equal sequence
numbers. Production Rust was unchanged.

The ``pin_encode`` extraction and full check completed in
``build/aeneas-current/``. Its ``PinCodec.lean`` proves exact equality
with ``PinName.encode`` and successful termination when the encoded
length is at most 255. It also proves that the result contains no dot,
that the existing pure decoder reverses it for names without a tilde,
and that two tilde-free names with equal encodings are equal. These
claims use Aeneas's vector allocation model, which excludes allocation
exhaustion. They do not prove the Rust decoder. All four theorem audits
contain only the standard Lean axioms listed above. Changing the dot
test to an underscore in a separate copied Rust crate, re-extracting it
and checking the original proof fails at the changed byte equality.
Use ``--candidate pin_encode`` with the checker for this refinement.

The ``pin_codec`` candidate's ``PinDecode.lean`` proves the unchanged Rust
decoder terminates and agrees exactly with ``PinName.decode`` for input
slices of at most 255 bytes. It covers every byte value, including NUL,
and both accepted and malformed escapes. Rust ``None`` is a successful
result, distinct from Aeneas failure or divergence. Its axiom audit lists
only ``propext``, ``Classical.choice`` and ``Quot.sound``. A native negative
control changes only the ephemeral generated decoder's dot push to an
exclamation mark; the unchanged proof then fails on the output byte.
The production and recorded generated files remain unchanged.

The ``archive_path`` candidate's ``ArchiveRefinement.lean`` proves
``archive_rel_contract`` and ``package_member_contract`` against the exact
``ArchiveRelRefines`` and ``PackageMemberRefines`` propositions. Both
require the explicit 64-bit target premise. They prove successful
termination and exact booleans on every slice within the stated bound,
including ``None`` returning false for package members. ``ArchiveList``
connects first-slash positions to the existing path model; ``ArchiveSlice``
proves exact component, slice equality and prefix checks. Both contract
axiom audits contain only the standard Lean axioms listed above. An
ephemeral generated-code mutation changes the loop's slash predicate to
dot; the unchanged proof fails at its position specification. The
production and recorded generated files remain unchanged.

The combined compiler extracts the unchanged archive predicates and full
pin decoder with ``-checks`` and ``-strict-joins``. Local fixes cover shared
slice metadata and shared nested borrowers and context joins. The archive
translation uses concrete models of ``Option.is_none_or``, ``Slice.first``
and ``Slice.starts_with`` from ``ArchiveModels.lean``; external templates
are not imported. Successful extraction alone adds no functional coverage.

The compiler fixes remain trusted. Finite comparisons against Rust did
not demonstrate a mistranslation, but do not prove compiler soundness.
The unresolved generic ``Flatten.fold`` override dispatch issue is outside
these pilots, which do not call it. No upstream regression suites were run.

The Rust compiler, Charon, Aeneas, their library models and the source
selection are trusted parts of this connection. Lean checks the generated
definitions and their refinements; this is not a verified compiler or a
proof of the whole activation journal, TPM or archive reader. The pilot
is not part of the existing CI proof targets.
