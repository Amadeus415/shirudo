..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: shirudo contributors

Prove code with CBMC and Lean 4
===============================

A test checks the inputs someone thought of, and a fuzz target the ones it
happens to find. shirudo's proofs check all of them, in two ways that
complement each other:

- `CBMC <https://www.cprover.org/cbmc/>`_ proves properties of the C
  itself. The proofs under :src:`testing/proofs/cbmc/` turn shirudo's C
  and a harness into a formula and ask a SAT solver for an input that
  breaks a property; when none exists, the property holds for every input
  within the harness's bounds.
- `Lean 4 <https://lean-lang.org/>`_ proves properties of a model of an
  algorithm. The proofs under :src:`testing/proofs/lean4/` state the
  algorithm in Lean and prove it meets its specification for every input,
  of any length, without a bound. Lean does not read shirudo's C: a CBMC
  proof checks the C against the model within its bounds, where one does.

A CBMC proof states two kinds of property. CBMC adds the first to every
proof: no read or write outside an object, no null or dangling pointer,
no signed overflow, no shift past the width of a type, no division by
zero, no conversion that changes a value, and no loop that runs longer
than the harness allows. The harness states the second: what the code
must do, such as that a parser accepts exactly the well-formed inputs and
that every offset it returns lies inside the input. A CBMC proof covers
every input up to the bound its harness names. Where the format itself
bounds what the code reads, as a fixed-size header does, the proof covers
every input of any size; elsewhere it covers every input up to the stated
length, and :doc:`proof-coverage` says which is which.

Before you begin
----------------

- CBMC 5.95 or newer, packaged as ``cbmc`` by Debian and Ubuntu.
- For the Lean 4 proofs, elan, packaged as ``elan``, and the toolchain
  :src:`testing/proofs/lean4/lean-toolchain` names:

  .. code-block:: console

     $ elan toolchain install "$(cat testing/proofs/lean4/lean-toolchain)"

- Memory: most CBMC proofs need little, but a large one can take several
  gigabytes.

Run the proofs
--------------

1. Run all of them from the checkout:

   .. code-block:: console

      $ make proofs

   Each CBMC line names a proof, the number of checks CBMC made and the
   time it took, and ``proofs: <n> hold`` ends a run in which all of them
   held. ``Build completed successfully`` ends the Lean 4 run. CI does
   not run the proofs: all of them take about an hour, a few of them
   minutes and gigabytes each. Run the ones that cover the code you
   change by name, as the next step shows, and all of them after a
   change to ``proof.h`` or ``run.sh``.

2. Run one kind, or some CBMC proofs by name:

   .. code-block:: console

      $ make proofs-lean4
      $ make proofs-cbmc PROOFS="string-number log-escape"

3. Read why a CBMC proof failed:

   .. code-block:: console

      $ testing/proofs/cbmc/run.sh -v string-number

   ``-v`` prints CBMC's whole output, with the trace of each failed
   check: the input that breaks it and the steps that lead there. Lean
   prints the theorem and the goal it could not close.

Write a CBMC proof
------------------

1. Write ``testing/proofs/cbmc/<name>.c``. It includes ``proof.h`` and
   the source file it proves, so that it reaches static functions too, and
   defines ``harness()``, which CBMC runs with every input at once.
   ``any_bytes(n)`` gives ``n`` bytes of any contents, ``any_input(len,
   max)`` an input of any length for code that reads at most ``max``
   bytes of it, and a variable left uninitialized takes any value;
   ``__CPROVER_assume()`` narrows the inputs to the bound, and
   ``__CPROVER_assert()`` states each property with a message that says
   what holds.

2. State what the code must do from its contract, not from its code: an
   accepted string is a number of the right digits, an accepted file has
   every section inside it. A check that restates the implementation
   proves nothing about it.

3. Add the proof to :src:`testing/proofs/cbmc/proofs.list` with its CBMC
   options:

   - ``--unwind <n>`` for loops, ``--unwindset <loop>:<n>`` for one loop,
     with ``goto-instrument --show-loops`` naming them. The unwinding
     assertions ``run.sh`` adds fail when an input needs more iterations,
     so a bound too low fails the proof rather than weakening it.
   - ``LEN=<a>-<b>``, or a list of lengths and ranges such as
     ``LEN=0-24,28,32``, runs the proof once for each length, with
     ``LEN`` defined: CBMC takes far longer over an input whose length it
     has to keep symbolic.
   - ``--object-bits <n>`` when CBMC reports too many addressed objects.

4. Check that the proof can fail: break the code it proves, for instance
   a loop that reads one byte too many, run it and see it fail, then
   restore the code.

5. Add a row to :doc:`proof-coverage`.

A function without a body in the proof, a libc one CBMC does not model or
a system call, returns any value, and ``run.sh`` fails a proof that calls
one. Give the function a model in ``proof.h``, or keep the proof away from
the code that calls it. CBMC 5.95's own ``memcpy()`` reads wrong bytes from
a string literal that symbolic data picks among several, and fails a proof
the code meets; a harness that copies from such a pointer defines
``PROOF_MEMCPY_BYTEWISE`` before it includes ``proof.h``. A harness whose
code searches thousands of bytes with ``memchr()`` only to learn whether
a byte is there defines ``PROOF_MEMCHR_QUANTIFIED`` for a model that
answers without a loop. ``PROOF_FILE`` models a file of that many bytes
that ``getline()`` and ``pread()`` read, and an ``errno`` that keeps what
was stored, where CBMC's own takes any value and lets a loop that
retries on ``EINTR`` run for ever; ``PROOF_DEVICE_NUMBERS`` gives
``makedev()``, ``major()`` and ``minor()`` bodies.

Write a Lean 4 proof
--------------------

1. Write the model in ``testing/proofs/lean4/Shirudo/<Name>.lean`` as
   close to the C as Lean allows: the same steps, the same checks, the
   values the C can hold. State each theorem as the specification the
   algorithm must meet for every input, and assume what the C cannot
   prove, such as a hash being collision resistant, as an explicit
   hypothesis of the theorem.

2. Import the module in :src:`testing/proofs/lean4/Shirudo.lean`. A
   ``sorry`` or any other warning fails the build, so every theorem is
   proved in full.

3. Where CBMC can, add a CBMC proof that the C computes what the model
   computes, for every input up to a bound, as
   :src:`testing/proofs/cbmc/string-number-model.c` does for the number
   parser; elsewhere the model follows the C by review, and the coverage
   page says so.

4. Add a row to :doc:`proof-coverage`.

Limits
------

A CBMC proof is about the code CBMC sees: the C of the files the harness
includes, with ``-funsigned-char`` as the build sets it, against a model
of the libc functions it calls. It says nothing about the kernel, the
compiler's code generation, time, or other threads, and it holds only
within its bounds. A Lean 4 proof holds for every input, but of the model:
it carries over to the C as far as the model matches the C, and its
assumptions hold.

Related
-------

- :doc:`proof-coverage`
- :doc:`testing`
- :doc:`test-coverage`
