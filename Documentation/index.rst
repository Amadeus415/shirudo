..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

================
shirudo manual
================

shirudo is a BPF LSM-based security platform that locks down the
``bpf()`` syscall so only signed in-kernel BPF loader programs can
install BPF code. The userspace tool is agentless on the target side
and is operated through SSH.

This index points at the three main documents in the shirudo source
tree. ``PLAN.md`` in the repository root is the implementation plan
and source-of-truth design.

.. toctree::
   :maxdepth: 2
   :caption: Contents

   architecture
   threat-model
   getting-started

Quick orientation
=================

- **Just want to deploy shirudo on a target?** Start with
  :doc:`getting-started`.
- **Want to understand what shirudo does and how?** Read
  :doc:`architecture`.
- **Reviewing the design or considering shirudo for your fleet?**
  Read :doc:`threat-model`, which enumerates the adversary classes,
  target- and operator-node threats, and residual risks.

Companion files in the repository root
======================================

- ``PLAN.md`` — implementation plan, source-of-truth design, MVP
  scope, phase-by-phase build order, file format specs.
- ``CLAUDE.md`` — guidance for AI-driven contribution to shirudo.
- ``README.md`` — short overview of what shirudo is and where to look.
- ``LICENSE`` — BSD-2-Clause (userspace). BPF programs declare
  ``Dual BSD/GPL`` (kernel LSM-hook framework requirement). Vendored
  files retain their upstream SPDX identifiers.
- ``examples/`` — worked ``.upatch`` examples (CVE mitigations).
