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

This index points at the documents in the shirudo source tree. The
architecture and threat model are the source of truth for the current
design; the code is authoritative for behaviour.

.. toctree::
   :maxdepth: 2
   :caption: Contents

   requirements
   architecture
   threat-model
   getting-started
   upatch-spec
   coding-style

Quick orientation
=================

- **Checking whether a host can run shirudo?**
  :doc:`requirements` lists the kernel options (including
  ``CONFIG_CRYPTO_MLDSA`` for the default ML-DSA signatures), the
  operator toolchain and the target runtime.
- **Just want to deploy shirudo on a target?** Start with
  :doc:`getting-started`.
- **Want to understand what shirudo does and how?** Read
  :doc:`architecture`.
- **Reviewing the design or considering shirudo for your fleet?**
  Read :doc:`threat-model`, which enumerates the adversary classes,
  target- and operator-node threats, and residual risks.
- **Contributing C or BPF code?** :doc:`coding-style` is the kernel
  coding-style document, copied verbatim from the Linux kernel's
  ``Documentation/process/coding-style.rst``; shirudo applies it to
  userspace too.

Companion files in the repository root
======================================

- ``CLAUDE.md`` — guidance for AI-driven contribution to shirudo.
- ``TODO.kernel`` — kernel/libbpf limitations shirudo's design bumps
  into, with the userspace workaround for each (the docs reference
  these by item number).
- ``README.md`` — short overview of what shirudo is and where to look.
- ``LICENSE`` — BSD-2-Clause (userspace). BPF programs declare
  ``Dual BSD/GPL`` (kernel LSM-hook framework requirement). Vendored
  files retain their upstream SPDX identifiers.
- ``upatches/`` — the BPF upatch packages shirudo ships (Linux
  observability, kernel CVE mitigations), each with its ``Beefile``.
- ``vendor/libbpf/`` — vendored libbpf and BPF UAPI headers with
  shirudo's BSD shims for the kernel's ``tools/include`` internals;
  refreshed by ``make update-bpf-deps``, see its ``README.md``.
