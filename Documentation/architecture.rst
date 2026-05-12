.. SPDX-License-Identifier: BSD-2-Clause
.. Copyright (c) 2026 Authors of shirudo

=====================
shirudo architecture
=====================

This document is the **contributor-facing** description of shirudo.
Read it once to build a mental model; then read ``PLAN.md`` for
implementation specifics and ``Documentation/threat-model.rst`` for
security rationale. The three documents complement each other:

- ``architecture.rst`` (this file) — *what shirudo is*; the
  conceptual description.
- ``PLAN.md`` — *what shirudo does and how it is built*; the
  implementation plan, scope, deferred work.
- ``Documentation/threat-model.rst`` — *what shirudo defends
  against and why*; the security spec.

What shirudo is
===============

shirudo is a BPF LSM-based security platform written in plain C. Its
one-sentence promise:

  **On a target machine where shirudo is active, no BPF program can
  be loaded, attached, or otherwise made to mutate kernel BPF state
  from userspace unless it carries a valid PKCS#7 signature against a
  cert held in the target's** ``shirudo`` **kernel keyring.**

Everything else in shirudo — the artifact format, the rollout/rollback
flow, the TPM measurement chain, the LSM hook policy, the operator
tooling — serves that promise.

shirudo is **agentless on the target**: nothing runs as a long-lived
process. Every target-side operation is a one-shot CLI invocation
fronted by the system's ``sshd``. The deferred reboot-persistence
systemd unit is ``Type=oneshot``: it runs ``shirudo init`` and
exits.

shirudo is **library-only at runtime**: no subprocess execution, no
``fork+exec`` of ``ssh``, ``scp``, ``openssl``, ``bpftool``,
``journalctl``, or ``tpm2_pcrread``. Every external operation goes
through a linked library — OpenSSL for crypto, libssh for SSH/SFTP,
libtss2 for TPM, libbpf for kernel BPF I/O, raw ``syscall()`` for
``keyctl``.

The operator/target split
=========================

shirudo deploys to two kinds of machine, with very different roles:

The **operator machine** holds the private signing key. It is where a
human operator (or an AI agent acting on their behalf) generates
signing material, signs BPF artifacts, and pushes them to one or many
targets. It needs:

- ``libcrypto`` and ``libssh`` linked into the shirudo binary.
- The signing key and cert under ``/var/lib/shirudo/keys/``.
- The operator's SSH material under ``~/.ssh/`` (agent socket,
  default keys, ``known_hosts``).

The **target machine** holds only the public X.509 cert. It is where
the kernel cryptographically verifies every BPF program before loading
and where the BPF LSM hook enforces "only signed loader progs from
userspace". It needs:

- The same shirudo binary, with the same library set linked in (plus
  libtss2 for TPM measurement). Distributions ship one binary, not
  two.
- A **current upstream Linux kernel** with the relevant config
  options (``BPF_SYSCALL``, ``BPF_LSM``, ``KEYS``,
  ``X509_CERTIFICATE_PARSER``, ``PKCS7_MESSAGE_PARSER``,
  ``SYSTEM_DATA_VERIFICATION``, ``TCG_TPM``, and the
  ``keyring_id`` field in ``union bpf_attr``). shirudo has no
  legacy-kernel support and does not attempt graceful
  feature-probe fallback at runtime; older kernels are simply not
  supported. See PLAN.md §"Bleeding-edge kernel and toolchain
  assumed".
- Root privileges to invoke ``bpf()``, ``keyctl()``, mount bpffs, and
  talk to ``/dev/tpmrm0``.

The **private signing key is never present on a target**. This is a
hard invariant — code paths that would put it there are bugs.

The flow of artifacts mirrors ``git push``:

::

    operator                                    target
    --------                                    ------
    shirudo genkey      ── produces ─→ keys on disk
                                                cert.der copied
                                                  out-of-band
                                                shirudo init
                                                  → cert added to
                                                    'shirudo' keyring
                                                  → LSM attached
                                                  → TPM chain extended
    shirudo build       ── produces ─→ foo.upatch
    shirudo rollout foo.upatch user@target ─→ libssh ─→ shirudo upatch load
                                                  → kernel verifies sig
                                                  → loader runs
                                                  → upatch link pinned
                                                  → TPM chain extended

There are no other channels. There is no shirudo-specific listener on
the target, no agent daemon, no out-of-band heartbeat. ``sshd`` is the
only always-on infrastructure shirudo needs.

The signed-loader path
======================

When ``shirudo build foo.bpf.c -o foo.upatch`` (or the equivalent
``shirudo build foo.bpf.o -o foo.upatch`` if the operator has already
compiled the source) produces a ``.upatch``, it does **not** sign
the user's BPF program directly. It signs a **loader program** that
itself will load the user's BPF.

The chain of events:

1. ``shirudo build`` dispatches via ``execv`` to the operator-only
   ``shirudo-build`` binary at
   ``$(libexecdir)/shirudo/shirudo-build``. This is the **single
   subprocess exception** in shirudo (see "Cross-cutting
   invariants" below).
2. If the input is a ``.bpf.c`` source file, ``shirudo-build``
   ``execv``s ``clang -target bpf -O2 -g -Wall -Wextra …`` to
   compile it to a ``.bpf.o``. If the input is already a
   ``.bpf.o``, this step is skipped. (clang is operator-only —
   it does not ship to targets.)
3. ``shirudo-build`` opens the ``.bpf.o`` via libbpf.
4. ``bpf_object__gen_loader(obj, &opts)`` with ``opts.gen_hash = true``
   generates a small ``BPF_PROG_TYPE_SYSCALL`` *loader* program whose
   job is to ``BPF_PROG_LOAD`` the payload BPF inside the kernel. The
   loader carries ``excl_prog_hash`` — the SHA-256 of the payload —
   embedded in its instruction stream.
5. ``shirudo-build`` calls the signing routine vendored from
   ``tools/bpf/bpftool/sign.c`` to produce a detached CMS/PKCS#7
   signature over the loader's instructions.
6. Loader instructions, loader data, signature, payload SHA-256, and
   metadata are bundled into a portable ``.upatch`` container.

When ``shirudo upatch load foo.upatch`` runs on the target:

1. The kernel's ``bpf_prog_verify_signature()`` (in
   ``kernel/bpf/syscall.c``) runs **before** any LSM hook, against
   keys in the keyring whose serial is passed via ``attr.keyring_id``.
   A bad signature returns ``-EKEYREJECTED`` without touching the LSM.
2. shirudo's LSM hook then sees a userspace ``bpf()`` call with
   ``cmd == BPF_PROG_LOAD``, ``prog_type == BPF_PROG_TYPE_SYSCALL``,
   ``signature_size > 0``. It allows the load.
3. shirudo issues ``BPF_PROG_TEST_RUN`` against the signed loader.
   The loader runs **in kernel context**: the LSM hook sees
   ``kernel == true`` for any nested ``bpf()`` calls and allows them
   all.
4. The loader installs the payload BPF program via its own
   ``BPF_PROG_LOAD``. The payload's instructions are constrained by
   the loader's embedded ``excl_prog_hash`` — only the exact bytes
   that were signed can succeed.
5. shirudo creates a link to the payload, pins the link into bpffs,
   and extends the TPM measurement chain.

The same path serves the LSM bootstrap itself — shirudo's own LSM
program is loaded via this signed-loader mechanism. There is no
second loading path anywhere in shirudo.

The LSM enforcement policy
==========================

shirudo's primary LSM lives in ``bpf/bpf2.c`` — a multi-attach BPF
object that hooks **two** LSM hooks: ``lsm/bpf`` (gates ``bpf()``
syscalls — the central enforcement point) and ``lsm/inode_unlink``
(gates VFS unlink on shirudo's bpffs superblock — closes the race
window between bpf2 attach and seal attach during which ``rm`` on
the pin file would otherwise detach the LSM). The name "bpf2"
reflects "BPF guarding the ``bpf()`` syscall"; the second hook is
narrowly scoped to protecting bpf2's own attach surface. Future
LSM attach points get their own sibling files (``bpf/seal.c`` is
the next one, covering broader filesystem sealing).

A single frozen ``BPF_MAP_TYPE_ARRAY`` records shirudo's bpffs
superblock identity, populated by userspace at init time
**before** bpf2's ``BPF_LINK_CREATE`` and then ``BPF_MAP_FREEZE``d
so it cannot be rewritten. The inode_unlink hook reads it via
``bpf_map_lookup_elem`` and denies unlinks on inodes whose
``i_sb`` matches the recorded sb, unless the calling task's
``mm->exe_file`` carries the ``security.bpf.shirudo`` xattr.
Identity rule shared with ``bpf/seal.c``, scoped narrowly to the
bpffs mount.

The hook receives a ``bool kernel`` flag (from
``include/linux/lsm_hook_defs.h``) that distinguishes calls coming
from a signed-loader running in kernel context from calls coming
straight from userspace. This single bit is the **load-bearing
discriminator**:

- ``kernel == true`` → always allow. The call originated inside a
  signed loader the kernel already verified.
- ``kernel == false`` → policy applies:

  - **Read-only commands** are allowed (``BPF_OBJ_GET``,
    ``BPF_*_GET_FD_BY_ID``, ``BPF_MAP_LOOKUP_*``, ``BPF_PROG_QUERY``,
    ``BPF_OBJ_GET_INFO_BY_FD``). Observability survives:
    ``bpftool prog show`` keeps working, ``shirudo status`` keeps
    working.
  - **``BPF_PROG_LOAD``** is allowed iff ``prog_type ==
    BPF_PROG_TYPE_SYSCALL`` and ``signature_size > 0``. The kernel
    then verifies the signature against the keyring.
  - **Every other mutating command** (``BPF_MAP_CREATE``,
    ``BPF_MAP_UPDATE_ELEM``, ``BPF_LINK_CREATE``, ``BPF_OBJ_PIN``,
    ``BPF_OBJ_UNPIN``, ``BPF_PROG_ATTACH``, ``BPF_BTF_LOAD``,
    ``BPF_RAW_TRACEPOINT_OPEN``, …) returns ``-EACCES`` regardless of
    caller privilege.

The policy is intentionally **denying with carve-outs for visibility**,
not allowing with carve-outs for safety. Operators can ``bpftool prog
show`` a fleet of locked-down targets without weakening enforcement.

Coexistence with SELinux / AppArmor / SMACK / Yama
--------------------------------------------------

The Linux LSM framework stacks: every active major LSM gets a turn
at every hook, and the most-restrictive verdict wins. shirudo's LSM
program returns either ``0`` (allow) or a negative errno (deny); it
never tries to override another LSM's deny, and structurally cannot.

If a stacked LSM denies a ``bpf()`` call before shirudo's hook
fires, the caller sees that denial and shirudo never observes the
attempt. shirudo's "only signed BPF runs" property is unaffected —
the stacked LSM is more restrictive, not less. Conversely, if a
stacked LSM denies shirudo's own bootstrap operations
(e.g. SELinux blocking writes under ``/var/lib/shirudo/``),
``shirudo init`` fails with the underlying errno surfaced via the
JSON report; operators on policy-strict hosts must add the necessary
policy fragments for the shirudo binary. shirudo ships no per-distro
policy in MVP. Yama (``ptrace_scope``) augments shirudo's own
``PR_SET_DUMPABLE`` / ``PR_SET_PTRACER`` defences additively.

See ``Documentation/threat-model.rst`` §"LSM coexistence" for the
threat-model framing.

The keyring model
=================

shirudo creates a named kernel keyring called ``shirudo`` under the
user keyring (``@u``) on first ``shirudo init``. The cert is added as
an asymmetric key with description ``shirudo:<sha256-of-cert>`` so
multiple keys can coexist and ``shirudo keys`` can show fingerprints.

Important specifics:

- ``attr.keyring_id`` in ``BPF_PROG_LOAD`` is a key **serial number**
  (``s32``), not a string. shirudo gets it from the return value of
  ``add_key(2)``.
- The kernel only consults the keyring at ``BPF_PROG_LOAD`` time. Once
  the LSM link is pinned, the keyring is no longer required for the
  LSM to remain enforcing — but it is required for future signed
  loaders.
- **No kernel keyring persists across reboots.** Persistence is a
  systemd-unit problem (deferred). For MVP, the cert lives on disk
  and gets re-installed on each ``shirudo init``.

The ``.upatch`` artifact format
===============================

``.upatch`` is the portable, signed unit produced on the operator
machine and consumed on the target. Layout summary (full spec in
PLAN.md):

- Fixed-size header with magic ``"SHIRUDO\0"``, version, flags,
  ``payload_sha256``, plus offset/size pairs for each section.
- ``flags`` bit 0 is ``DIRECTIVE_UNLOAD`` — distinguishes LOAD
  artifacts (most upatches) from UNLOAD directives (rollback).
- Sections: ``loader_insns`` (signed), ``loader_data``,
  ``signature``, ``metadata`` (TLV with name, version, build host,
  timestamp), ``log_buf`` (zero-initialised verifier-log region).
- Integrity is provided entirely by the kernel's PKCS#7 verification
  of ``loader_insns`` against the target's ``shirudo`` keyring.
  Tampering with any other section either breaks parsing or causes
  the loader's runtime ``excl_prog_hash`` check to fail.

A single ``include/shirudo/upatch.h`` header defines the on-disk
layout for both sides.

Rollback
========

Rollback is **symmetric to rollout** and uses the same signed-loader
mechanism. There is no "destroy" path that bypasses signatures.

``shirudo build --unload foo`` emits a ``.upatch`` with
``DIRECTIVE_UNLOAD`` set. Its ``loader_insns`` is not a gen_loader
output but a small hand-written SYSCALL-type BPF program (from
``bpf/unload.bpf.c``) that:

1. Opens the pin at ``/var/lib/shirudo/bpffs/upatches/<name>/link`` via
   ``bpf_obj_get()`` from kernel context.
2. Verifies the loaded upatch's ``payload_sha256`` matches the
   directive's expected value — refuses on mismatch (catches an
   attacker who substituted a different upatch under the same
   name).
3. Issues ``BPF_LINK_DETACH`` and ``BPF_OBJ_UNPIN`` from kernel
   context. The LSM allows these because ``kernel == true``.

On success the target removes ``/var/lib/shirudo/upatches/<name>.upatch``
and extends the TPM chain with a domain-separated ``"shirudo-unload\0"``
event.

**Both load and unload are forward progress** in the TPM chain.
Loading upatch X and then unloading it does not return the chain to
its pre-load value — it advances it by a third digest. The chain
records the full history of state transitions, not just current state.

TPM measurement
===============

shirudo records every state transition into a **TPM2 NV-extend
index**. Choosing an NV index rather than a PCR is deliberate:

- PCRs 0–15 are in use by firmware, grub, IMA, and systemd's PCR
  registry. None are free.
- PCR 23 (application-specific) and PCR 16 (debug) are resettable
  from locality 0, which defeats extend-only semantics — a root
  attacker can ``TPM2_PCR_Reset`` either.
- An NV index with ``TPMA_NV_EXTEND`` cannot be reset without
  ``TPM2_NV_UndefineSpace`` + ``TPM2_NV_DefineSpace``, which require
  platform-hierarchy auth that is effectively unavailable from
  userspace.

shirudo's NV index lives at ``SHIRUDO_NV_INDEX`` (default
``0x01818E00``, in the owner-defined range). The chain is **persistent
across reboots**.

Extension digests are deterministic and domain-separated. There are
three event types; **boot-time re-apply is collapsed into a single
set-valued init event, not N per-upatch events** (see the next
paragraph for why):

- ``shirudo init`` (first-ever or post-boot re-init, optionally
  restoring a set of upatches):
  ``SHA256("shirudo-init\0" || cert_sha256 || set_digest)`` where
  ``set_digest`` is the SHA-256 of the canonical sorted listing of
  upatches loaded at the moment of the init event (sha256sum-style
  format, sorted by name; empty set hashes the empty string).
- ``shirudo upatch load <foo>`` — operator-driven only:
  ``SHA256("shirudo-upatch\0" || payload_sha256 || upatch_name)``.
- ``shirudo upatch unload <foo>``:
  ``SHA256("shirudo-unload\0" || payload_sha256 || upatch_name)``.

**Boot-restore is one event, not N.** When the target reboots and
the deferred reboot-persistence systemd unit re-runs ``shirudo
init``, the chain advances by **exactly one** init event whose
``set_digest`` captures the entire restored upatch set. The
rationale is semantic: a reboot+re-apply restores state, it does
not add new state. Per-upatch granularity belongs to operator-driven
events (load, unload) — each of those is a distinct intent. The
chain length therefore grows with operator activity, not with boot
frequency, which matters for embedded targets that reboot
frequently. The operator's local prediction is one SHA-256:

::

    Y = SHA256(X || SHA256("shirudo-init\0" || cert_sha256 || set_digest_of_S))

where ``S`` is the set the operator knows is loaded on the target
(operator-side audit) and ``cert_sha256`` is the cert (constant per
fleet).

A human-readable **eventlog** at ``/var/lib/shirudo/eventlog``
(append-only JSON lines) records what extended the chain when.
The eventlog is not trusted on its own — root can rewrite it — but
its integrity is checked by replay: walking the eventlog from a known
starting point must reproduce the live NV chain value, or the chain
is the ground truth and the log is tampered.

For fleet comparison across homogeneous machines that may have
rebooted different numbers of times, operators compare the **eventlog
tail since the most recent** ``shirudo-init`` **event** rather than
raw chain values. The chain authenticates the tail; the tail
identifies the current loaded set.

Pre-flight gates
================

shirudo's state-changing commands run pre-flight checks before
touching anything. There are two distinct gates:

1. **`shirudo init`'s infrastructure pre-flight** — runs once at
   bootstrap to confirm the *infrastructure* shirudo needs is
   actually present: root privilege, BPF LSM in the kernel,
   bpffs mountable, cert on disk, embedded LSM loader present in
   the binary, kernel keyring usable, TPM reachable. Every check
   runs; failures are collected and reported as a complete list;
   no kernel state is touched if any required check fails. The
   only override is `--no-tpm`, which downgrades to
   measurement-disabled mode (LSM still enforces; chain not
   extended). Failure category: `init_prereqs_missing`. See
   PLAN.md §"Pre-flight checks (run by every `shirudo init`)".
2. **`shirudo upatch load` / `upatch unload`'s state pre-flight**
   — runs before every operator-driven state change to confirm
   the target's *current state* matches the operator's last
   observation. This is the version-id + chain + LSM-pinned +
   keyring-present gate described below.

Both gates are belt-and-suspenders: the infrastructure gate
catches "this target was never properly set up"; the state gate
catches "this target's state has drifted since I last observed
it." A target failing the infrastructure gate cannot pass the
state gate either, and vice versa — but the diagnostic is
different and operators / AI agents respond differently.

Pre-flight TPM state check
==========================

Every operation that would extend the chain — ``shirudo upatch load``,
``shirudo upatch unload`` — performs a **pre-flight check** first:

1. Read the current NV chain value via ``Esys_NV_Read``.
2. Compare against ``--expect-chain=<hex>`` supplied by the caller.
   ``shirudo rollout`` and ``shirudo rollback`` auto-derive this by
   running ``shirudo status --json --include-tpm`` against each target
   in a preceding libssh exec channel; AI agents can pass the value
   explicitly from a stashed ``chain_after``.
3. Verify the LSM link is still pinned at
   ``/var/lib/shirudo/bpffs/lsm_link``.
4. Verify the ``shirudo`` keyring still exists with the expected cert.

Any failure short-circuits the operation: no ``BPF_PROG_LOAD``, no
chain extend, no eventlog write. The report category is ``tampered``
with a sub-message naming the specific check that failed
(``chain_drift``, ``lsm_detached``, ``keyring_missing``).

The pre-flight check serves two purposes:

- **Tamper detection.** A target whose state diverged from the
  operator's last observation is refused — silent state changes
  between observations become loud.
- **Optimistic concurrency control between operators.** Two
  concurrent operators (or AI agents) implicitly serialise through
  the chain: the second to act finds the first's extension has
  changed the chain, mismatches, and re-statuses before retrying.
  No locks, no coordination service required.

Across legitimate reboots, the operator (or agent) updates its cached
expected chain value locally as
``SHA256(chain_after || init_event_digest)`` — where
``init_event_digest = SHA256("shirudo-init\0" || cert_sha256 ||
set_digest)`` and ``set_digest`` is the canonical hash of the
loaded-upatch set the operator knows is on the target. Both inputs
are operator-known (cert from the keyring, set from the operator's
audit trail), so no round-trip is needed. Reboots do not invalidate
operator state.

Fleet selection: registered remotes, labels, selectors
======================================================

shirudo refuses literal ``user@host[:port]`` arguments to
``rollout``, ``rollback``, and ``nodes``. Every destination must
be a name previously registered via ``shirudo remote add`` on the
operator. The registry lives on the operator only, in
``$XDG_CONFIG_HOME/shirudo/remotes.d/<name>.conf`` (per-user) or
``/etc/shirudo/remotes.d/<name>.conf`` (system-wide, with
``--system``). Each remote is one drop-in file with simple
``key = value`` lines for ``host``, ``user``, ``port``, optional
``identity_file``, optional ``sudo``, and zero or more
``label.<key> = <value>`` lines.

Forcing every state-changing operation through the auditable
remote set gives three properties:

- **``shirudo nodes`` is complete by construction** — it enumerates
  the same set of remotes that ``rollout`` operates over, so the
  operator's fleet view and the operator's deployment surface
  never disagree.
- **Audit trails reference stable names**, not ad-hoc hostnames
  that may resolve differently from different operator hosts.
- **Fat-finger rollouts are filtered out** — a typo in a hostname
  fails immediately with "not registered" instead of silently
  routing to whatever happens to resolve.

Labels are operator-chosen ``key=value`` pairs attached to each
registered remote, in the Kubernetes style:

::

    # ~/.config/shirudo/remotes.d/prod-fleet-a.conf
    host = target-a.prod.example.com
    user = root
    port = 22

    label.shirudo.nodes.type     = production
    label.shirudo.nodes.location = us-east-1
    label.shirudo.nodes.role     = database
    label.team                   = platform

``shirudo rollout``, ``shirudo rollback``, and ``shirudo nodes``
accept ``--selector=<expr>`` to pick a subset of remotes by label
expression. The grammar is small:

::

    expr := term ('||' term)*
    term := atom ('&&' atom)*
    atom := key '=' value         # has this exact value
          | key '!=' value        # has a different value (key must exist)
          | key                   # has this label, any value
          | '!' key               # does not have this label
          | '(' expr ')'

``&&`` (AND) binds tighter than ``||`` (OR), matching C precedence.
Examples:

::

    shirudo rollout foo.upatch --selector='shirudo.nodes.type=production'
    shirudo nodes --selector='(role=database || role=cache) && env!=staging'
    shirudo rollback foo.unload.upatch --selector='!maintenance'

Empty match set is an error — the caller should know whether their
selector is expected to match. The parser/evaluator lives in
``util/selector.{c,h}`` (~150 LOC, recursive descent, no external
library).

**Labels are operator-side metadata only.** They are not signed,
not synchronised to targets, not part of any security boundary.
Compromise of the operator's ``remotes.d/`` files could let an
attacker change which set of targets ``--selector=type=production``
expands to — but compromising those files also compromises the
operator's host, at which point the signing key is the much bigger
problem. Labels are an audit/operational-ergonomics layer, not a
trust layer.

See PLAN.md §"Remote registry" for the full file format, lookup
precedence, and the label-selector grammar in formal notation.

Failure reporting
=================

shirudo is intended to be driven both by humans and by AI agents that
iterate on BPF source. Failures must be parseable, not stderr-scrape.

``shirudo upatch load --report=<path>`` and ``shirudo upatch unload
--report=<path>`` (and the aggregated ``shirudo rollout --report=``
/ ``shirudo rollback --report=``) emit structured JSON documents
covering ``result``, ``phase``, ``errno``, a small ``category``
taxonomy, the kernel **verifier log** verbatim on rejection (up to
1 MiB), and the TPM state on success.

The ``category`` taxonomy is the agent's primary decision input:

- ``verifier_rejected`` — read ``verifier_log``, fix the BPF source,
  retry.
- ``btf_mismatch`` — regenerate ``vmlinux.h``, rebuild, retry.
- ``attach_target_missing`` — wrong hook for this kernel; pick
  another.
- ``signature_rejected`` / ``keyring_missing`` — operator-config
  problem; surface to a human.
- ``lsm_denied`` — policy or upatch is malformed; surface to a
  human.
- ``tampered`` — pre-flight failed; do not iterate the BPF, re-status
  the target and investigate.
- ``already_unloaded`` — idempotent no-op on rollback; move on.
- ``payload_mismatch`` / ``detach_failed`` — rollback-specific
  failures.

The verifier log capture is wired through the ``log_buf`` region of
the ``.upatch`` artifact: the in-kernel signed loader writes the
inner ``BPF_PROG_LOAD``'s verifier output there, and userspace reads
it back after ``BPF_PROG_TEST_RUN``.

Logging
=======

shirudo logs operational events to the systemd journal via
``syslog(3)`` with ``openlog("shirudo", LOG_PID | LOG_NDELAY,
LOG_AUTHPRIV)`` — no ``libsystemd`` dependency, no
``journalctl`` shell-out. Operators filter cleanly with:

::

    journalctl _EXE=/usr/local/bin/shirudo _UID=0

Filtering by ``_EXE`` and ``_UID`` (trusted journald fields, attached
at receive time from ``SO_PEERCRED`` and ``/proc/<pid>/``) rather than
by ``-t shirudo`` (which is the user-controllable ``SYSLOG_IDENTIFIER``
and is forgeable by any process).

In-kernel LSM denial events are not surfaced in MVP — they appear as
``-EACCES`` to the rejected caller. Future work surfaces them through
an on-demand BPF ringbuf drained by ``shirudo status --include-audit``,
preserving the agentless-on-target invariant.

Cross-cutting invariants
========================

These properties hold throughout shirudo's design and must be
preserved by every change:

0. **Kernel + shirudo is the TCB on the target.** Once
   ``shirudo init`` has run, the trusted compute base is the
   Linux kernel and shirudo (its binary, its signed BPF
   programs, and the cert in the keyring). Every other userspace
   process — root-owned or not — is outside the TCB and is
   constrained by it. If a change brings new userspace
   components into the target TCB, that's a TCB-growth red
   flag; the agentless-on-target invariant exists precisely to
   prevent this. The operator-side TCB is larger and includes
   clang/LLVM and the signing key. See PLAN.md §"Trusted compute
   base" and ``threat-model.rst`` §"Trust boundaries and the
   trusted compute base".

1. **Only signed BPF runs.** The kernel's PKCS#7 verifier, the
   ``shirudo`` keyring, and the LSM hook together enforce this. There
   is no path around them.

2. **The operator/target split is hermetic.** The operator never
   touches a kernel keyring or a TPM. The target never touches the
   private signing key. Code paths that would cross this line are
   bugs.

3. **No subprocesses at runtime, ever — with one named exception.**
   The core ``shirudo`` binary does no ``fork+exec`` of ``ssh``,
   ``scp``, ``sftp``, ``openssl``, ``bpftool``, ``journalctl``,
   ``tpm2_pcrread``, or anything else; every external operation
   goes through a linked library or a direct ``syscall()``. The
   single, named exception is the operator-side ``shirudo build``
   subcommand, which dispatches via ``execv`` to a separate
   ``shirudo-build`` binary at
   ``$(libexecdir)/shirudo/shirudo-build`` (git-style libexec
   pattern); ``shirudo-build`` itself ``execv``s ``clang`` to
   compile BPF source. ``shirudo-build`` and ``clang`` ship only
   in the operator package, so the invariant remains absolute on
   every target-side code path.

4. **Agentless on the target.** No long-lived shirudo process. No
   shirudo-owned listening socket. The only always-on infrastructure
   shirudo relies on is ``sshd``.

5. **One binary, two roles.** The same shirudo executable runs on
   both sides; role separation is by what's locally present, not by
   separate builds.

6. **Every state transition is measured.** Init, upatch load,
   upatch unload all extend the TPM NV chain with domain-separated
   tags. Silent state transitions don't exist.

7. **Shirudo infrastructure maps are frozen at creation.** Every
   BPF map shirudo creates as part of its own infrastructure
   (the upatches registry, future config/ringbuf maps) is
   ``BPF_MAP_FREEZE``d between ``BPF_MAP_CREATE`` and
   ``BPF_OBJ_PIN``. Userspace can never mutate these maps
   from the syscall side regardless of what the LSM policy
   does; only signed BPF running with ``kernel == true`` can
   update them. Defence in depth alongside the bpf2 LSM's
   userspace-mutation deny. User-loaded upatch maps are not
   auto-frozen — the upatch author chooses.

8. **Pre-flight check refuses on state drift.** Including drift
   caused by a concurrent legitimate operator. AI agents handle
   ``tampered`` as "refresh state and decide", not "retry as-is".

9. **BSD-2-Clause throughout.** Every line of code in the shirudo
   binary is either fresh BSD-2-Clause or vendored from an upstream
   with a BSD-2-Clause OR-branch. GPL-2.0 upstreams (perf,
   libsubcmd, git) provide *patterns* (uncopyrightable) but never
   code. See PLAN.md §"Vendoring and whiteroom reimplementation".

If a proposed change would weaken any of these, it should be
re-examined — usually it's the change that needs to bend, not the
invariant.

Project layout
==============

The source tree mirrors ``tools/perf/``'s shape:

::

    shirudo/
    ├── shirudo.c              # main(), cmd_struct[] dispatch
    ├── builtin-*.c            # one per top-level subcommand
    ├── util/                  # shared C library
    │   ├── parse-options.{c,h}    # whiteroom CLI parser (BSD-2-Clause)
    │   ├── loader.{c,h}           # gen_loader wrappers, .incbin of bpf/*.o
    │   ├── sign.{c,h}             # CMS signing (vendored from bpftool)
    │   ├── upatch.{c,h}           # .upatch container parser/writer
    │   ├── keyring.{c,h}          # add_key / keyctl raw syscalls
    │   ├── tpm.{c,h}              # libtss2 wrappers (NV-extend)
    │   ├── eventlog.{c,h}         # /var/lib/shirudo/eventlog
    │   ├── report.{c,h}           # JSON failure-report assembly
    │   ├── kmsg.{c,h}             # /dev/kmsg replay
    │   ├── remotes.{c,h}          # remote registry
    │   ├── ssh.{c,h}              # libssh wrappers
    │   ├── paths.{c,h}            # filesystem path constants
    │   ├── kconfig.{c,h}          # kernel config probes
    │   └── log.{c,h}              # syslog wrappers
    ├── bpf/
    │   ├── bpf2.c             # LSM prog for lsm/bpf
    │   ├── unload.bpf.c       # signed UNLOAD directive template
    │   └── lib/               # reusable BPF headers
    ├── include/shirudo/upatch.h   # on-disk format header
    ├── t/                     # test suite (TAP, numbered shell scripts)
    ├── ci/                    # shell-driven CI logic
    ├── Documentation/         # this tree
    └── third_party/bpf-next/  # git submodule

See PLAN.md "Project layout" for the full annotated tree.

License and vendoring
=====================

shirudo's project license is **BSD-2-Clause**. To keep it that way:

- All shirudo-authored code carries
  ``// SPDX-License-Identifier: BSD-2-Clause`` on line one, followed
  by ``Copyright (c) 2026 Authors of shirudo`` (collective copyright;
  individual contributions are recorded by git history).
- The BPF programs in ``bpf/`` use
  ``// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)`` to match
  the runtime ``_license`` string the BPF verifier requires for LSM
  hooks.
- ``util/sign.c`` is vendored from
  ``tools/bpf/bpftool/sign.c`` (upstream dual-licensed
  ``(GPL-2.0-only OR BSD-2-Clause)``); both the original Google
  copyright and shirudo's copyright are preserved verbatim in the
  file header.
- Code from **perf**, **libsubcmd**, and **git** is GPL-2.0 and
  **must not be copied or linked**. shirudo whiteroom-reimplements
  the subset of those libraries' functionality it needs (CLI parsing,
  command dispatch, etc.) under BSD-2-Clause.

See PLAN.md "Vendoring and whiteroom reimplementation" for the
clean-room procedure.

Version identity and cross-architecture support
================================================

shirudo's MVP supports two target architectures: **x86_64** and
**arm64**. Both are little-endian; the on-disk ``.upatch`` format is
defined little-endian throughout; JSON over SSH is text and
architecture-neutral. The operator and the target can run on
different architectures — the canonical case is "CI on x86_64
operator pushing upatches to an arm64 embedded fleet". riscv64 is
deferred: not technically blocked (it is also little-endian), but
not in the MVP test matrix until a target need arises. Big-endian
and 32-bit targets are out of scope for MVP entirely.

Cross-arch operations need a way for an operator on one architecture
to confirm that the binary running on a target of a *different*
architecture is the **same version**. A literal sha256 of the
shirudo binary file does not give this: x86_64 and arm64 builds of
the same source produce different binary bytes by construction. So
shirudo computes a different hash:

**``SHIRUDO_VERSION_ID``** is a 64-character hex sha256 generated at
build time over **architecture-independent inputs**: the git commit
hash, the digest of the build configuration (``config.mk``,
``Makefile.shirudo``), and a ``-dirty`` marker if the working tree
has uncommitted changes. The result is embedded in the binary as a
``const char shirudo_version_id[]``. Two builds from the same source
on different architectures share the same ``SHIRUDO_VERSION_ID``;
two builds from different commits or different configs have
different identities. See PLAN.md "Build system — Version identity
(``SHIRUDO_VERSION_ID``)" for the exact generation rule.

The pre-flight check on every state-changing operation compares the
operator's ``SHIRUDO_VERSION_ID`` against the target's. Mismatch
returns ``category: version_mismatch`` and the operation is refused.
``shirudo rollout`` and ``shirudo rollback`` auto-derive the
target's version-id from a pre-status read in the same libssh
session; AI agents can supply it explicitly via
``--expect-version-id=<hex>``.

This is a **version-skew guard**, not a tamper-detection mechanism.
A malicious shirudo binary on the target could simply return any
``version_id`` string it wants — the check has no cryptographic
authority over the target's reported value. The threat it addresses
is the routine fleet-management hazard of "operator upgraded its
binary, half the targets still run last week's" and the development
hazard of "I'm pointing my dev build at a prod target by accident".
Binary-on-disk integrity is a separate concern handled at the
distribution layer (RPM signatures, dpkg-sig, cosign, or — better —
measured boot with a TPM-attested binary identity). shirudo defers
to that layer; see ``threat-model.rst`` for the explicit
out-of-scope statement.

Where to look next
==================

- For implementation specifics — function signatures, exact attribute
  values, build-system rules: ``PLAN.md``.
- For security rationale and threat-by-threat analysis:
  ``Documentation/threat-model.rst``.
- For operator quickstart and end-to-end flow:
  ``Documentation/getting-started.rst``.
- For coding style: ``/root/bpf-next/Documentation/process/coding-style.rst``
  (kernel coding style applies to all C in this repo).
- For the in-kernel infrastructure shirudo depends on:
  ``/root/bpf-next`` (the kernel source tree at
  ``kernel/bpf/syscall.c``, ``tools/bpf/bpftool/sign.c``,
  ``tools/lib/bpf/skel_internal.h``, ``include/linux/lsm_hook_defs.h``).
