# shirudo — kernel live-patching roadmap (`PLAN.kspace.md`)

> Status: roadmap / forward-looking design. Layers on the existing platform in
> `PLAN.md` (signed `.upatch`, signature-gated `BPF_PROG_LOAD`, TPM measurement,
> agentless target, and direct target-local loading); read `PLAN.md` first. The userspace counterpart
> is `PLAN.uspace.md`. Primary sources under `research/`.

## Context

The same pressure that motivates userspace live patching applies to the kernel:
Mythos/Glasswing surface kernel CVEs faster than fleets can be rebooted, and
embedded/edge devices may not be rebootable on demand at all. shirudo already
delivers and measures signed BPF on the target; this roadmap describes using
that pipeline to **mitigate a kernel vulnerability in the running kernel** —
shielding the vulnerable function so it can no longer be exploited — without a
reboot and without a custom kernel build.

This is the kernel-side counterpart to `PLAN.uspace.md`, with the same patch
model: **shielding now** (sanitize arguments, reject, override the return,
block the vulnerable path at a function boundary), **redirection later** (full
body replacement, kpatch-style). The crucial difference from `PLAN.uspace.md` is
that the kernel-side attach surface — kprobe, fentry/fexit, fmod_ret, LSM — is
mature and largely already wired into shirudo, so a large class of kernel-CVE
shields is deliverable on today's pipeline with modest additions.

## Goals and non-goals

Goals:

- **No reboot.** Mitigate the running kernel in place.
- **No custom kernel build.** Attach by BTF id with CO-RE relocations; the patch
  is portable across the fleet's kernels (`CLAUDE.md` "CO-RE for portable BPF").
- **Signed and measured.** Kernel patches travel as signed `.upatch` artifacts
  through the same `BPF_PROG_LOAD` + `keyring_id` path and extend the TPM chain
  on apply, exactly as every other shirudo artifact.
- **Shielding at the function boundary** — reject a dangerous argument
  combination, clamp an attacker-controlled length, force an error return, or
  deny via an LSM hook.

Non-goals:

- **Full kpatch/livepatch-style code replacement** in the MVP. It is, however,
  the eventual **north-star goal**, not a permanent exclusion — see "Full code
  replacement via BPF (the eventual goal)". It is out of the MVP because it
  requires BPF itself to grow substantially, which is a much bigger lift than
  boundary shielding.
- **Patching kernel data structures** in place (until full replacement lands).
- **Disabling or overriding other LSMs.** shirudo composes to the most-
  restrictive verdict (`CLAUDE.md` "LSM coexistence"); a kernel patch never
  weakens another LSM's deny.
- **Kernel hardening generally.** shirudo trusts the kernel (`CLAUDE.md`
  "Explicitly out of scope"). This is targeted CVE mitigation, not a
  general-purpose kernel-defense framework — though it composes with such
  frameworks (see "Prior art": kShield).

## What already works today

shirudo's existing `.upatch` pipeline already supports the attach kinds that
deliver kernel shielding:

- **kprobe / kretprobe** are first-class attach kinds
  (`include/shirudo/upatch.h`, `enum shirudo_upatch_attach_kind`), attached via
  `perf_event_open` + `BPF_LINK_CREATE` (`builtin-upatch.c`
  `perf_event_open_kprobe` / `prog_attach_perf_event`).
- **raw_tracepoint** and the **BTF/trampoline** attach types
  (`BPF_TRACE_FENTRY`, `BPF_TRACE_FEXIT`, `BPF_MODIFY_RETURN`, `BPF_LSM_MAC`)
  already have the raw-tracepoint/BTF-link fallback wired
  (`builtin-upatch.c` `attach_type_has_raw_tp_fallback`,
  `prog_attach_default` / `prog_attach_btf_link`).

So a kprobe-based shield (observe a vulnerable path, count it, and — on the
allowlist — force an error return) can be authored, signed, rolled out, and
measured **on the current pipeline**, with the gaps below being build-side
section parsing and a config pre-flight.

## Kernel patch primitives

Honest about each lever's preconditions up front:

- **kprobe + `bpf_override_return`.** A kprobe BPF program can force a function
  to return a chosen value via `bpf_override_return`, but it is **gated**:
  `CONFIG_BPF_KPROBE_OVERRIDE` must be set, and the target function must be on
  the error-injection allowlist (`within_error_injection_list()`,
  `kernel/trace/bpf_trace.c`; the helper is exposed only under that config). This
  is the cleanest "reject / short-circuit" lever where the target qualifies.
- **fmod_ret / `BPF_MODIFY_RETURN`.** A modify-return program attached to a
  function on the fmod_ret-eligible set can change the return value (e.g. turn a
  success into `-EACCES` to block a vulnerable path). Eligibility is similarly
  constrained to functions the kernel marks.
- **fentry / fexit.** Read arguments (fentry) and return values (fexit) for
  observation, telemetry, and deciding whether a path is hot — the kernel
  analogue of the userspace "how often did the problematic code fire?" telemetry.
  Cannot by themselves change control flow.
- **`lsm/*` hooks.** Deny a security-relevant operation outright (the same
  mechanism shirudo's own `bpf/bpf2.c` and `bpf/seal.c` use). The right lever
  when the CVE is reachable through an LSM-hooked operation.

The shielding pattern is always: intercept at the function boundary, inspect the
arguments, and either let the call proceed, reject it (override return /
fmod_ret / LSM deny), or clamp an argument — never rewrite the function body.

## `.upatch` format extension

Same container, additive metadata (mirrors `PLAN.uspace.md`):

- **New attach kinds** in `include/shirudo/upatch.h`:
  `SHIRUDO_UPATCH_ATTACH_FENTRY`, `_FEXIT`, `_FMOD_RET`. kprobe/kretprobe already
  exist. Bump the metadata format version; unknown kinds refuse (fail-closed).
- **Target identity by BTF id**, recorded from the program's `SEC()` and resolved
  via CO-RE at load — architecture-stripped, so one signed patch applies across
  x86-64 and arm64 fleet members (`CLAUDE.md` "CO-RE for portable BPF"). A
  CO-RE/BTF mismatch surfaces as `btf_mismatch`, not a silent misfire.

No new LSM allow-list entry is needed: `lsm/bpf` already permits
`BPF_LINK_CREATE` / `BPF_RAW_TRACEPOINT_OPEN` / `BPF_OBJ_PIN` from userspace
(`PLAN.md` "LSM enforcement policy"); the signed `BPF_PROG_LOAD` stays the trust
boundary.

## Mitigation cookbook

Concrete shielding recipes, each with its attach kind and precondition:

- **Reject a dangerous syscall argument combination** — fentry on the syscall
  entry / relevant kernel function; inspect args; `bpf_override_return -EINVAL`
  (requires the function be error-injection-listed) or an `lsm/*` deny where one
  exists.
- **Clamp an attacker-controlled length before a vulnerable copy** — fentry reads
  the argument; where the kernel exposes a writable context for that hook, clamp;
  otherwise reject the over-range call via override/fmod_ret. (Honest: argument
  *rewrite* in the kernel is more restricted than the userspace `pt_regs` write;
  many kernel shields are reject-only.)
- **Force an error return on a vulnerable path** — fmod_ret / `BPF_MODIFY_RETURN`
  on an eligible function, or `bpf_override_return` on an error-injection-listed
  one.
- **Block via an LSM hook** — attach an `lsm/<hook>` program that denies the
  specific operation the CVE is exploited through.

Each recipe in the shipped doc carries: the attach kind, the config/allowlist
precondition, what it can and cannot do, and a worked example.

## CLI deltas

- **`shirudo build`** — section parsing for `fentry/<fn>`, `fexit/<fn>`,
  `fmod_ret/<fn>` (kprobe/kretprobe already parsed),
  `tools/shirudo-build/package.c` `attach_kind_from_section`.
- **`shirudo status`** — surface kernel patch targets (function, attach kind,
  whether the override/fmod_ret precondition is satisfied on this kernel).
- **Pre-flight** — extend `util/preflight` (`PLAN.md` "Pre-flight checks") to
  check `CONFIG_BPF_KPROBE_OVERRIDE`, `CONFIG_FUNCTION_ERROR_INJECTION`, and BTF
  availability when a patch needs them; refuse early with an actionable category
  rather than failing at attach. New category: `kernel_patch_unsupported`.

## Threat-model deltas

To fold into `Documentation/threat-model.rst`:

- A signed kernel patch is **within the existing operator-signed trust model** —
  it is signed BPF verified against the sealed keyring, the same trust class as
  shirudo's own LSM. It adds no new trust boundary.
- It is **powerful** (it can change kernel control flow on the allowlisted
  surface), but bounded by the verifier, the BPF LSM gate, and the
  override/fmod_ret allowlists — it cannot replace arbitrary function bodies or
  touch data structures.
- **LSM coexistence** is unchanged: verdicts compose to the most-restrictive;
  shirudo never overrides another LSM's deny (`CLAUDE.md` "LSM coexistence").

## Limits / open questions

- **Allowlist coverage.** `bpf_override_return` and fmod_ret only work on
  functions the kernel marks (error-injection / fmod_ret-eligible). CVEs in
  unmarked functions cannot be shielded by return override; the fallback is an
  LSM-hook deny if one covers the path, or telemetry-only until a body-
  replacement path exists.
- **No arbitrary body replacement in the MVP.** This is shielding, not kpatch.
  Full replacement is the eventual goal and has its own section and roadmap phase
  ("Full code replacement via BPF (the eventual goal)", P4); it is a much bigger
  lift because BPF itself must grow more powerful first.
- **Config dependence.** Targets without `CONFIG_BPF_KPROBE_OVERRIDE` /
  `CONFIG_FUNCTION_ERROR_INJECTION` lose the return-override lever; the pre-flight
  must say so rather than silently degrade.
- **Complementary to upstream livepatch — until full replacement lands.**
  shirudo's BPF shielding trades completeness (it cannot replace a whole
  function) for not needing a built, signed livepatch module and not needing the
  consistency-model stop-the-world / lazy-migration machinery. For a fix that
  genuinely requires rewriting a function body, upstream `livepatch` / `kpatch`
  remains the right tool *today*; shirudo shields fast while that is prepared.
  The eventual goal (P4) is to do the body replacement itself in verified BPF,
  inheriting livepatch's consistency model but with the verifier's
  can't-crash-the-kernel guarantee that a binary `.ko` livepatch module lacks.

## Full code replacement via BPF (the eventual goal)

Boundary shielding mitigates exploitation; it does not *fix the bug*. The
eventual goal is what `kpatch`/`kGraft`/`livepatch` do — **replace the whole
vulnerable function with a corrected body** — but with the corrected body
expressed as **verified BPF** rather than an unverified native `.ko` module. The
payoff is decisive: a binary livepatch module is trusted native code that can
panic the kernel if wrong, whereas a BPF replacement carries the verifier's
can't-crash-the-kernel guarantee (the same "BPF, not a binary blob" argument the
userspace talk makes, applied to the kernel). It also rides shirudo's existing
trust and delivery: signed, keyring-verified, TPM-measured, agentless,
CO-RE-portable across the fleet.

This is a **much bigger lift than shielding**, because BPF itself must grow more
powerful before a BPF program can stand in for an arbitrary kernel function. The
gap, honestly stated:

- **Stand-in calling convention.** The replacement must match the original
  function's ABI exactly — argument count and types (including struct-by-value),
  return type, and be reachable via the same call sites. Needs a "BPF program as
  a typed kernel function" mode beyond today's fixed program-type contexts.
- **Unrestricted control flow and runtime.** A real function body is not a probe:
  it loops (often unboundedly by the verifier's current standards), can sleep,
  can take locks, and runs for as long as the work takes. BPF's
  must-terminate / bounded-loop model is the core thing that must relax —
  building on the recent direction (bounded loops, open-coded iterators,
  exceptions, larger programs, arena) but going substantially further. This is
  the "BPF itself must become more powerful" crux.
- **Full kernel-memory read *and write*.** Shielding reads arguments; a
  replacement mutates the same kernel structures the original did. Needs safe,
  verifier-checked write access to arbitrary kernel objects (not just CO-RE
  reads), likely via a much-expanded kfunc surface so the body can call whatever
  the original called.
- **Atomic switch with a consistency model.** Replacement cannot race a task
  that is mid-execution in the old body. shirudo would either integrate with the
  kernel's existing `klp` consistency machinery (ftrace-based redirect + per-task
  consistency / lazy migration) or grow a BPF-native equivalent — the
  text-poke/redirect itself is already a solved kernel primitive (the same family
  shirudo's uprobe/optimized-uprobe work uses), but the *quiesce* is the hard
  part, exactly as it is for `livepatch` today.
- **Stacking, ordering, and revert.** Multiple replacements on one function, a
  defined apply order, and clean rollback — all of which map naturally onto
  shirudo's signed LOAD/UNLOAD directive model (`PLAN.md` "Removal flow"), but
  need the consistency model to revert safely.

None of this is shirudo-only work; it is BPF-core and kernel co-design, tracked
as a `TODO.kernel`-style wishlist. shirudo's role is to be the **signed,
measured, agentless delivery and trust layer** for these replacements once the
BPF substrate can express them — the same role it already plays for shielding.
Until then, P0-P3 shield, and upstream `livepatch`/`kpatch` remain the tool for
fixes that truly require a new function body.

## Phased roadmap

- **P0 — Document + examples on today's path.** Author kprobe-based shields and
  the mitigation cookbook on the existing pipeline; no code change beyond docs
  and examples.
- **P1 — Attach kinds + pre-flight.** Add fentry/fexit/fmod_ret build-side
  section parsing and attach metadata; add the config/BTF pre-flight and the
  `kernel_patch_unsupported` category.
- **P2 — Override integration + cookbook.** Wire `bpf_override_return` /
  fmod_ret into the shielding recipes; `status` reports per-target lever
  availability.
- **P3 — Partial redirection (future).** Replace narrow function bodies where the
  verifier already suffices (small, terminating, read-mostly), e.g. via
  struct_ops-style attach or an fexit/fmod_ret-driven substitute return; the
  stepping stone to P4 that needs no BPF-core changes.
- **P4 — Full code replacement via BPF (eventual goal).** kpatch/livepatch-style
  whole-function replacement expressed as verified BPF, with the consistency
  model and the BPF capability growth described above. The largest item;
  BPF-core and kernel co-design, gated on the verifier/kfunc/runtime advances
  listed in "Full code replacement via BPF (the eventual goal)".

## Prior art and research

- **Kernel live patching (full-replacement, for contrast).** Ksplice; kpatch
  (Red Hat); kGraft (SUSE); mainline `livepatch` (CONFIG_LIVEPATCH) — these
  replace whole functions and rely on a consistency model (stop-the-world or
  lazy migration). shirudo's BPF shielding is complementary: narrower (boundary
  shielding, not body replacement) but needs no signed module and no quiesce.
- **eBPF for kernel CVE mitigation.** Cloudflare, "Live-patching security
  vulnerabilities with eBPF LSM"; kShield (eBPF runtime defence against
  privilege-escalation exploits, ~91% of tested exploits mitigated); eBPF-PATROL
  (runtime threat recognition). These validate eBPF as a real kernel-exploit
  mitigation surface.
- **Primitive references.** `bpf_override_return` (kprobe, error-injection list,
  `CONFIG_BPF_KPROBE_OVERRIDE`); `BPF_MODIFY_RETURN` / fmod_ret; fentry/fexit BTF
  trampolines; BPF LSM. See `/home/darkstar/bpf-next` `kernel/trace/bpf_trace.c`
  and `include/linux/lsm_hook_defs.h`.
