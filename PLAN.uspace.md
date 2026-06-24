# shirudo — userspace live-patching roadmap (`PLAN.uspace.md`)

> Status: roadmap / forward-looking design. This document describes a
> capability shirudo does **not** yet implement. It layers on the existing
> platform described in `PLAN.md` (the signed `.upatch` pipeline, the
> signature-gated `BPF_PROG_LOAD` trust boundary, TPM measurement, the
> agentless target model, and `rollout`); read `PLAN.md` first. The
> kernel-space counterpart is `PLAN.kspace.md`. Primary sources are vendored
> under `research/` (see `research/README.md`).

## Context

Mythos/Glasswing find new vulnerabilities — kernel and userspace — faster than
fleets can be rebuilt, redeployed, and restarted. For a large class of
production services a restart is expensive (connection draining, cache warmup,
quorum churn) or operationally constrained (maintenance windows, embedded
devices that cannot easily be redeployed). shirudo already delivers signed BPF
to a fleet and measures every state transition; what it does not yet do is use
that pipeline to **change the behaviour of a running userspace application** so
that a known-vulnerable code path can no longer be exploited — without
restarting the application and without recompiling it.

This roadmap describes how to add that. The design north star is the
project author's LSF/MM/BPF 2026 talk *"BPF for user space live patching"*
(`research/borkmann-lsfmmbpf-2026-bpf-userspace-live-patching.pdf`): the kernel
installs a **trap-free trampoline** into a running process that calls a
**signed BPF program JIT-compiled to position-independent userspace code**, with
a **BPF arena** as the shared kernel<->user channel. No long-lived agent is
injected into the target process, and the target binary is never rebuilt — the
kernel owns the text rewrite, exactly as it already owns kprobe/uprobe text
rewrites today. The academic foundation for the trap-free mechanism is the
`Libpatch` work of Dion, Desnoyers et al.
(`research/dion-libpatch-dynamic-patching-userspace.pdf`).

The patch class is the same one `PLAN.kspace.md` targets for the kernel:
**shielding** — reject, short-circuit, clamp, or override at a function
boundary — graduating over time toward **redirection** (replacing a function
body with fixed logic).

## Goals and non-goals

Goals:

- **No restart.** Mitigate a running process in place.
- **No rebuild.** The target application is patched as-is; it is not
  recompiled, relinked, or shipped with instrumentation. Symbol/offset and
  build-id are the only things shirudo needs from it.
- **No injected agent / no import library.** Unlike `LD_PRELOAD`, JVMTI agents,
  or `Libpatch`'s in-process bootstrap (`research/...libpatch...pdf` §3.10), the
  kernel installs and owns the patch. This preserves shirudo's
  agentless-on-target invariant (`PLAN.md` "agentless on the target").
- **Signed and measured.** Every userspace patch travels as a signed `.upatch`,
  loads through the same signature-gated `BPF_PROG_LOAD` + `keyring_id` path as
  every other shirudo artifact, and extends the TPM NV chain on apply
  (`PLAN.md` "TPM measurement").
- **Trap-free where the architecture allows.** Use the optimized-uprobe
  jump path (no per-hit `int3` trap) on supported targets; fall back to the
  breakpoint path only when a jump slot cannot be planted.
- **Verifier-safe.** The injected code is BPF: it cannot crash the application
  any more than a kernel BPF program can crash the kernel (the talk's central
  argument for "BPF, not a binary blob").

Non-goals (state these plainly in the artifact docs):

- **`bpf_probe_write_user` is never used.** It is GPL- and
  `LOCKDOWN_BPF_WRITE_USER`-gated, absent on most hardened production kernels,
  and emits an unmaskable kernel warning on load. Userspace memory is never
  written through it. (The sanctioned lever is the uprobe `pt_regs` write; see
  "The patch primitive".)
- **Containing a hostile process.** uprobe-based instrumentation can be detected
  and subverted by the code it runs in (Quarkslab, "Defeating eBPF Uprobe
  Monitoring"). shirudo shields a *trusted* application against exploitation of
  a bug; it does not sandbox malware. If the target itself is the adversary,
  this is the wrong tool.
- **Recompiling or instrumenting the target**, injecting a shared library, or
  running a per-app daemon.
- **Full function-body replacement in the MVP.** That is the longer-term
  redirection goal (P5), gated on kernel work.

## The vision (target architecture)

The end-state mechanism from the LSF/MM/BPF 2026 talk, slide 16, reproduced here
as the design target. Two halves, kernel and userspace:

```
userspace process                         kernel
-----------------                         ------
app text:                                 BPF_PROG_LOAD:
  foo:    jmp <tramp>   <- patched          verifier (ABI-preservation pass)
  foo+5:  <displaced...>                     JIT -> PIC code for a user RX page
                                             BPF LSM as gate + signature check
trampoline page (PROT_RX, kernel-installed)
  prologue: save clobbered regs           BPF_LINK_CREATE:
  body:     read args, call user helper     locate VMA (build-id, offset)
            maybe write back / synthesize    map RX page into target pid
  epilogue: jmp foo+5   (fall through)       process_text_poke()/uprobe_write
            or ret      (short-circuit)        rewrite head to jmp <tramp>

user helpers (loader-supplied, app code)  arena: shared mmap, kernel + user BPF
  sanitize_path, clamp_iov, allowlist...  kernel-side BPF (LSM, kprobe, tcx) can
arena (rules, counters, telemetry rb)     read/write the same arena
                                            -> cross-plane policy
```

Key properties:

- **The probe handler is signed BPF, JIT'd to position-independent userspace
  code** in a kernel-owned `PROT_RX` page mapped into the target. The verifier
  gains an **ABI-preservation pass** that guarantees the JIT'd code restores
  whatever the System V AMD64 / AArch64 ABI requires (red zone, callee-saved
  registers, the xmm argument registers, `errno`) — the property `Libpatch`'s
  hand-written handler establishes by brute-force save/restore
  (`research/...libpatch...pdf` §3.7), here proven by the verifier instead.
- **The kernel installs the trampoline**, not an in-process agent. It rewrites
  the function head to a 5-byte `jmp` using the same cross-modifying-safe text
  poke it already uses for uprobes (see "Kernel infrastructure"). The epilogue
  either falls through to the displaced original instructions (`jmp foo+5`) or
  returns early (`ret`) for a short-circuit.
- **The only kernel<->user comms channel is a BPF arena**, not BPF maps. The
  same arena is reachable from kernel-side BPF (an `lsm/*`, kprobe, or tcx
  program) so a userspace patch and a kernel policy can share state — *cross-
  plane policy*. (Talk constraint: "Restricting to only allow BPF arena as a
  communication mechanism, no BPF maps".)
- **Helpers the BPF cannot express are user-provided**, identified by a call-id
  that resolves to a relative function address plus a BTF signature the verifier
  checks — "different mappings for different applications, no fixed UAPI needed"
  (talk, slide 15). This is the userspace analogue of kfuncs.
- **Trust is unchanged from the rest of shirudo:** the BPF LSM gates the load
  and the kernel verifies the CMS signature against the sealed keyring before
  the verifier runs (`PLAN.md` "LSM enforcement policy").

This is a kernel co-design effort. The rest of this document separates what is
achievable on a current upstream kernel **today** (Tier A) from what this vision
**needs the kernel to grow** (Tier B).

## Mechanism, in two tiers of maturity

### Tier A — signed uprobe with register rewrite (in-tree today)

A signed BPF program attached to a uprobe at a function entry can already
shield that function on a current upstream kernel, with no new kernel code:

- **The lever is the uprobe `pt_regs` write.** Since commit `7384893d970e`
  ("bpf: Allow uprobe program to change context registers", Jiri Olsa, Sept
  2025) the verifier permits a uprobe BPF program to write the `pt_regs` context
  (`kernel/trace/bpf_trace.c` `kprobe_prog_is_valid_access`, which sets
  `kprobe_write_ctx`), and the attach path allows that write **only for uprobes**
  (`kernel/events/core.c`, `kprobe_write_ctx && !is_uprobe` rejects). So a signed
  uprobe can rewrite the argument registers, the return-value register, and the
  instruction pointer of the probed userspace thread.
- **What that buys (shielding):**
  - *Argument sanitization* — clamp a length, mask a flag, reject an
    out-of-range value by rewriting the argument register before the function
    body runs.
  - *Short-circuit / synthetic early return* — set the return-value register and
    redirect control flow so the vulnerable body never executes (the
    register/control-flow equivalent of forcing an early `return -EINVAL;`).
  - *Telemetry* — count how often the vulnerable path is hit and surface it
    (how the talk frames "how often did the problematic code fire?").
- **Honest limit:** this writes *registers*, not *memory*. It can reject,
  clamp-by-value, override a return, or redirect; it **cannot** rewrite a buffer
  or a struct passed by pointer. Mitigations that require touching memory are out
  of scope for Tier A (and `bpf_probe_write_user` is refused). Many real CVEs are
  shieldable at the boundary anyway (reject the malicious input, clamp the
  attacker-controlled length, take the safe branch); those that are not wait for
  Tier B.
- **Trap-free where possible.** The kernel's optimized-uprobe path already
  rewrites the `int3` breakpoint into a 5-byte `jmp` to a trampoline
  (`arch/x86/kernel/uprobes.c`, `swbp_optimize` / `swbp_unoptimize`), removing
  the per-hit trap on x86-64 when a 5-byte slot is available; otherwise it falls
  back to the breakpoint. Tier A inherits this automatically.

**Phase-0 spike (gates Tier A):** validate the exact "synthetic early return"
semantics against the uprobe single-step / execute-out-of-line (XOL) path. The
sequence — set the return register, load the return address (x86-64: `[rsp]`;
AArch64: `x30`), set `regs->ip`, fix up `rsp` — must be confirmed to compose
with the displaced-original-instruction handling before we commit. If redirect
timing turns out to be unworkable, Tier A degrades to *observe + return-value
override at a uretprobe* and the early-return technique waits for Tier B's
trampoline (which controls the epilogue directly).

### Tier B — signed BPF as user PIC in a kernel-installed trampoline (needs new kernel work)

Tier B realises the vision above. It removes Tier A's register-only limit (the
trampoline body can read args, call user helpers, write back, and synthesize a
result) and makes the patch a first-class jump-based detour rather than a probe.
It requires kernel work; some of the load-bearing pieces already exist.

Already in-tree (reuse):

- **Trap-free text rewrite.** `uprobe_write()` (`kernel/events/uprobes.c`) is the
  kernel's cross-modifying-safe in-process instruction writer — the
  `process_text_poke()` analog the talk names. Optimized uprobes
  (`arch/x86/kernel/uprobes.c`) already plant the 5-byte `jmp`.
- **BPF arena.** `kernel/bpf/arena.c` / `BPF_MAP_TYPE_ARENA` is the shared
  kernel+user mmap the talk requires as the sole comms channel.
- **Register/control-flow rewrite** (Tier A's lever) generalises to the
  trampoline epilogue.

Needs new kernel work (the wishlist; track in a `TODO.kernel`-style list):

- **ABI-preservation verifier pass** — a verifier mode that proves the JIT'd
  userspace BPF preserves the target ABI (red zone, callee-saved, xmm, `errno`),
  so the trampoline prologue/epilogue can be minimal and safe.
- **JIT to position-independent userspace code + RX-page mapping** — emit PIC for
  a kernel-owned `PROT_RX` page and map it into the target pid at
  `BPF_LINK_CREATE`.
- **VMA resolution by build-id + offset** at `BPF_LINK_CREATE`, then the
  text poke to `jmp <tramp>`.
- **User-provided helper mechanism** — call-id -> relative function address + BTF
  signature, verified at load; per-application mappings, no fixed UAPI.
- **Arena cross-plane wiring** — let a kernel-side BPF program and the userspace
  patch share one arena under the LSM's eye.

And the hard problems the kernel must own to do jump-based patching safely —
all solved in userspace by `Libpatch`, to be lifted into the kernel
(`research/dion-libpatch-dynamic-patching-userspace.pdf`):

- **Jump-pattern reachability** — planting a 5-byte relative `jmp` when the
  instruction at the patch site is shorter, the trampoline must be within
  +/-2GiB, and the slot may straddle basic-block entries. `Libpatch` unifies
  fit-jump, NOP-hole (NOProbe), alias/instruction-punning (Liteinst), and
  E9Patch pad-jump/eviction, with a fast trampoline allocator (memfd pools placed
  with `MAP_FIXED_NOREPLACE`, chunked bitmaps, a page-mask Bloom-filter search).
- **OLX (out-of-line execution) buffers** — relocate or emulate the displaced
  instructions, including RIP-relative ones; landing pads carry `endbr64` for
  CET/IBT.
- **Cross-modifying-code protocol without stop-the-world** — `Libpatch` uses
  `int3` as a lock, `membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE)` for
  core serialization, and thread eviction (unwinding threads out of the patch
  window via `.eh_frame` / `.sframe`); the ARM fallback is Memory-Protection
  Bypass (`PROT_READ|PROT_WRITE` + a `SIGSEGV` handler). The kernel's
  `uprobe_write` already implements the int3-lock discipline for single-instruction
  uprobes; widening it to a multi-byte window is the new part.
- **Executable-region GC on unpatch** — a trampoline cannot be freed while a
  thread may still be inside it; `Libpatch` marks and reclaims by per-thread
  unwinding (no stop-the-world), which needs async unwind tables (`.sframe` /
  `.eh_frame`).
- **Intel CET / shadow stack** — return-redirecting probes must rebalance the
  shadow stack; the trampoline's indirect branches need IBT-valid landing pads.

## `.upatch` format extension

Userspace patches travel in the existing `.upatch` container (`PLAN.md`
".upatch artifact format"); only the attach metadata grows. This mirrors how
kprobe/kretprobe were added — additive, backward-compatible.

- **New attach kinds** in `include/shirudo/upatch.h` (`enum
  shirudo_upatch_attach_kind`): `SHIRUDO_UPATCH_ATTACH_UPROBE`,
  `_URETPROBE`, `_UPROBE_SESSION` for Tier A; `_UPROBE_TRAMPOLINE` for Tier B.
  Bump the metadata format version. Readers that predate a kind reject it
  cleanly (unknown == refuse), consistent with the fail-closed posture.
- **New metadata TLV: the userspace target descriptor** — the target ELF
  **path**, the **symbol** name, the resolved **offset**, and the binary's
  **build-id**. The target may be the main executable or a shared library
  (`/lib/.../libssl.so.3`); the patch attaches to that inode and so covers every
  current and future process that maps it.
- **Signature coverage is unchanged.** Only the gen_loader instructions are
  signature-covered (`PLAN.md` "Integrity: what is signed"). The userspace
  target descriptor is **advisory metadata, not signature-covered** — the same
  residual class as the unload directive's name binding (`TODO.kernel` #6): a
  root attacker who edits the unsigned metadata could repoint a signed patch at a
  different symbol. The defence is the build-id match at attach (refuse if the
  on-disk binary's build-id differs from the descriptor) plus the operator's
  signed intent; closing it fully needs the target identity inside the
  signature-covered loader, which is future work.

Attach plumbing is a small extension of what exists. kprobe/kretprobe already
attach via `perf_event_open` + `BPF_LINK_CREATE` (`builtin-upatch.c`
`perf_event_open_kprobe` / `prog_attach_perf_event`); a uprobe is the same path
with the uprobe PMU and a `path:offset`. Prefer the **`uprobe.multi` link**
(`BPF_LINK_TYPE_UPROBE_MULTI`, attached by `BPF_LINK_CREATE` with a path +
offsets) over the sysfs `uprobe_events` interface — it needs no tracefs writes
and rides the existing LSM allow-list. **No LSM policy change is required for
Tier A:** `lsm/bpf` already permits `BPF_LINK_CREATE`, `BPF_RAW_TRACEPOINT_OPEN`,
`BPF_OBJ_PIN`, and `BPF_PROG_TEST_RUN` from userspace (`PLAN.md` "LSM enforcement
policy"); the signature-gated `BPF_PROG_LOAD` remains the only trust boundary.

## Per-runtime support, tiered

Each runtime differs in how a probe finds code, how arguments are passed, and
whether a stable native site even exists. Support lands in tiers.

### C/C++ and Rust — native AOT (Tier 1, MVP)

The baseline and the easiest case.

- **Finding code.** uprobe by ELF symbol (`.symtab`, or `.dynsym` for exported
  symbols even when stripped); PIE/ASLR is handled by attaching at an inode +
  file offset, which the kernel translates per mapping. Stripped-but-dynamic
  binaries still expose `.dynsym`.
- **Arguments.** System V AMD64: `rdi, rsi, rdx, rcx, r8, r9`, return in `rax`.
  AArch64: `x0-x7`, return in `x0`. Read via `PT_REGS_PARM*` / CO-RE.
- **What a patch looks like.** Tier A: read args from registers, decide,
  reject/clamp/override-return/redirect. Tier B: the trampoline body can also
  call user helpers and synthesize a result.
- **Rust** is native and identical at the ABI level; differences are cosmetic:
  v0 symbol mangling (resolve/demangle at build), and care not to disturb
  panic-unwind metadata (a synthetic early return must leave the unwinder
  consistent — prefer return-value override at a clean boundary).

### Go — static binaries, movable stacks (Tier 2)

Viable at function entry, with real caveats.

- **Finding code.** Exported Go symbols are present; internal call sites use
  direct calls (no PLT). Attach at entry by symbol/offset.
- **Arguments.** Go 1.17+ ABIInternal is register-based (x86-64: `rax, rbx, rcx,
  rdi, rsi, r8-r11`, then stack); the builder must know ABIInternal to map args.
- **Entry only — no uretprobe.** Goroutine stacks are movable; a hijacked return
  address (how uretprobes work) is invalidated when the runtime relocates the
  stack, crashing the process (golang/go#22008; this is why Pixie and Grafana
  Beyla instrument entry only and avoid uretprobes). shirudo follows suit: Tier-2
  Go patches attach at entry and shield there; return-value shaping needs Tier B
  cooperation.
- **Cooperation for coroutines.** Go implements coroutines with user-space stack
  switching; `Libpatch` notes (§3.9) that return-probe bookkeeping must cooperate
  with such a runtime. Tier B carries that cooperation; Tier A sidesteps it by
  staying at entry.

### Java/JVM and Python/CPython — managed runtimes (Tier 3)

A specific Java method or Python function has **no stable native address**: the
JVM's C2 compiler inlines, recompiles, and deoptimizes; CPython executes
bytecode in an interpreter loop. A uprobe on "the compiled method" goes stale on
the next recompile. The general industry mechanisms — JVMTI `RedefineClasses` /
DCEVM for Java, `importlib`/monkeypatching/`sys.audit` for Python — all require a
**runtime agent inside the process**, which conflicts with shirudo's
agentless-on-target invariant. shirudo's posture, in order of preference, is to
**avoid the agent**:

1. **Native-boundary shielding (in-model now).** Patch the native functions the
   managed runtime calls — `libssl`/OpenSSL, `libc`, JNI native methods, the
   CPython C-API — with Tier-1 uprobes. This catches a large fraction of real
   CVEs (TLS, crypto, parsing, deserialization shims) without touching the
   managed layer.
2. **Cooperative USDT (in-model now, no rebuild, no agent).** Both runtimes ship
   **compiled-in USDT probes**: HotSpot (`hotspot` / `hotspot_jni` providers —
   method-compile, JNI entry/return, etc.) and CPython
   (`function__entry`/`function__return`, `line`, `audit` per PEP 578). These are
   static markers already present in stock builds — attachable with **no rebuild
   and no injected agent**, and they are exactly the "applications could use it
   co-operatively" mode from the talk (slide 12). They give stable, semantically
   meaningful attach points the JIT cannot move.
3. **Language-level patching of a specific managed function — deferred.** Doing
   this without an agent and without a rebuild is open research: it needs the
   Tier-B kernel co-design plus cooperative markers (e.g. the runtime exposing
   ground-truth method addresses through an arena, or USDT-style probes the
   operator can target). shirudo does **not** plan to ship a JVMTI or
   `importlib` agent; if that boundary is ever revisited it is a deliberate
   threat-model change, documented, not an accident.

## Authoring a userspace patch

A uspace patch is authored and built exactly like any other shirudo BPF artifact
(`PLAN.md` `shirudo build`), with a uprobe `SEC()`:

- `SEC("uprobe/usr/bin/nginx:ngx_http_validate_host")` (Tier A) or the
  `uprobe.multi` / `uprobe.session` forms; `shirudo build` parses the section to
  the new attach kind and records the target descriptor (path, symbol, build-id;
  offset resolved at build or attach).
- CO-RE is required for any kernel-struct access, same as every shirudo BPF
  (`CLAUDE.md` "CO-RE for portable BPF").
- A Tier-A skeleton reads arguments via `PT_REGS_PARM*`, decides, and on the
  reject path sets the return register and redirects — the synthetic early return
  validated by the Phase-0 spike.
- Arena usage (Tier B): the patch reads its rule table and writes counters into a
  `BPF_MAP_TYPE_ARENA` region shared with kernel-side policy; no BPF maps.

## CLI deltas

- **`shirudo build`** — section parsing for `uprobe`/`uretprobe`/
  `uprobe.session` (and later `uprobe.trampoline`); records the target ELF path,
  symbol, and build-id into the new metadata TLV
  (`tools/shirudo-build/package.c` `attach_kind_from_section`).
- **`shirudo upatch load` / attach** — extend the perf_event/link dispatch
  (`builtin-upatch.c` `prog_attach_for_spec`) with the uprobe kind, preferring
  the `uprobe.multi` link; resolve and verify the target binary (build-id match)
  before `BPF_LINK_CREATE`.
- **`shirudo status` / `shirudo upatch list`** — surface uprobe targets: binary,
  symbol, and the count of currently-attached processes (so an operator sees both
  "is the patch installed" and "is anything actually running it").
- **Failure categories** (extending the taxonomy in `PLAN.md` "category
  taxonomy"): `symbol_unresolved`, `binary_mismatch` (build-id differs),
  `target_not_running` (no process maps the inode yet — not necessarily an
  error), `slot_unreachable` (no 5-byte jump slot; Tier-A breakpoint fallback or
  refuse).

## Persistence and boot-restore

A uprobe attached by inode + build-id covers every current and future process
that maps that binary, so it naturally survives individual process restarts. On
reboot, `shirudo init` re-applies the persisted upatch set as it does today and
extends the TPM chain by exactly one event (`PLAN.md` "Boot-restore protocol").
A uspace patch with no running target at apply time is recorded and becomes
effective when a matching process next execs the binary; `shirudo status`
reports installed-but-inactive distinctly from active.

## Threat-model deltas

To fold into `Documentation/threat-model.rst`:

- **A signed userspace patch can alter application execution.** This is
  operator-signed code, the same trust class as every other shirudo BPF; a
  malicious or buggy signed patch can break the app, exactly as a malicious
  signed kernel BPF can today. The trust root is unchanged: signature + sealed
  keyring + BPF LSM.
- **Tier A blast radius is register-only** — no memory writes, no
  `bpf_probe_write_user`. Tier B widens the blast radius to a kernel-installed
  text rewrite, but the kernel owns and verifies it (verifier + LSM + signature),
  and it is reversible through the same GC the kernel must implement.
- **Target identity is advisory.** Build-id match degrades a metadata-repoint
  attack from silent to fail-closed; full binding awaits signature-covered target
  identity (`TODO.kernel` #6 class).
- **Trusted-app boundary.** uprobe-based shielding is not a containment boundary
  against the patched process itself (Quarkslab). shirudo shields a trusted app;
  it is not a sandbox for untrusted code. State this as an explicit non-goal so
  operators do not over-trust it.

## Limits in MVP / open questions

- **Register-only until Tier B lands.** Memory-touching mitigations are out of
  scope in Tier A; `bpf_probe_write_user` stays refused.
- **Tier B is a substantial, upstream-gated kernel effort** (verifier ABI pass,
  user-PIC JIT + RX mapping, build-id VMA resolution in `BPF_LINK_CREATE`,
  user-helper call-id mechanism, arena cross-plane, the `Libpatch` hard problems,
  CET/IBT, GC). It is co-design, not a shirudo-only change.
- **Managed-runtime language-level patching is open** — native-boundary +
  cooperative USDT now; specific-method patching without an agent or rebuild is
  research.
- **Multi-arch ABI tables.** Argument-register maps and the synthetic-early-
  return sequence differ across x86-64 / AArch64 (and Go ABIInternal); the doc
  and the builder must carry both. Big-endian / 32-bit stay out of scope
  (`CLAUDE.md` supported architectures).
- **CET/IBT interaction** must be handled before Tier B ships on hosts with
  shadow stacks enabled.

## Phased roadmap

- **P0 — Tier-A spike + plumbing.** Validate the synthetic-early-return semantics
  against the XOL path; add the uprobe attach kinds and the target-descriptor TLV
  to `include/shirudo/upatch.h` and `shirudo build`.
- **P1 — C/C++/Rust Tier-A end to end.** Author -> build -> sign -> `rollout` ->
  attach -> pin -> measure, for native binaries; `status`/`list` surfacing;
  failure taxonomy.
- **P2 — Go Tier-2.** Entry-only shielding with ABIInternal argument mapping; no
  uretprobes.
- **P3 — Tier-B kernel co-design.** User-PIC BPF + arena + ABI-preservation
  verifier pass + the optimized-trampoline link; the `TODO.kernel` wishlist
  above.
- **P4 — Managed runtimes.** Native-boundary shielding productized; cooperative
  USDT attach for HotSpot/CPython.
- **P5 — Redirection (future).** Function-body reimplementation via the
  trampoline, with executable-region GC for clean unpatch.

## Prior art and research

Vendored locally under `research/` (see `research/README.md`); upstream links
follow.

- **North star.** D. Borkmann, *"BPF for user space live patching"*, LSF/MM/BPF
  2026 — `research/borkmann-lsfmmbpf-2026-bpf-userspace-live-patching.pdf`.
- **Trap-free jump-based foundation.** O. Dion, M. Desnoyers, M. Nassiri, M.
  Dagenais, *"Dynamic patching of binaries in user space"* (Libpatch) —
  `research/dion-libpatch-dynamic-patching-userspace.pdf`.
- **Detour / instrumentation prior art.** Dyninst; GDB fast tracepoints; Uftrace;
  Liteinst (instruction punning); E9Patch (static rewriting, pad-jump &
  eviction); NOProbe (NOP-hole hijacking); Dyntrace; kprobe jump-optimization;
  `bpftime` (userspace eBPF runtime, binary rewriting).
- **uprobe register write.** Linux commit `7384893d970e`, "bpf: Allow uprobe
  program to change context registers" (Jiri Olsa, 2025).
- **Go tracing.** Pixie (`px.dev`) and Grafana Beyla — both entry-only, avoid
  uretprobes on Go; "Challenges of BPF tracing Go".
- **Managed-runtime USDT.** HotSpot DTrace/USDT probes (Oracle); CPython
  DTrace/SystemTap instrumentation and PEP 578 audit hooks.
- **Threat bound.** Quarkslab, "Defeating eBPF Uprobe Monitoring" (2024) —
  uprobe instrumentation is not a containment boundary against the monitored
  code.
