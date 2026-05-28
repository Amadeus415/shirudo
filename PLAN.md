# shirudo — BPF LSM Security Platform: MVP Implementation Plan

> Status: **design only — not yet implemented**. This document is the
> approved plan. Refine in place; revisit before implementation begins.

## Context

**shirudo** ("shields" in Japanese) is a new, agentless security platform built on
BPF LSM. It locks down the `bpf()` syscall so that, once shirudo is active, only
**signed in-kernel BPF loader programs** can install BPF code, create maps, attach
links, or otherwise mutate BPF state — even for callers holding `CAP_SYS_ADMIN`.

shirudo follows a **git-like split between operator machine and target machine**:

- The *operator machine* holds the private key. Operators compile BPF programs
  there and produce signed, portable artifacts called **BPF upatches**
  (`.upatch` files). This is the side a human (or CI) interacts with to
  produce and ship updates; the term "operator" rather than "build" is
  deliberate, since the role is signing + distribution, not just compilation.
- The *target machine* holds only the public X.509 cert in its kernel keyring.
  `shirudo init` installs the cert and the BPF LSM; from then on the kernel
  cryptographically verifies every BPF program before loading. Targets are
  the production fleet — they consume upatches, they never produce them.
- `shirudo rollout` pushes upatches from the operator machine to one or more
  target machines over SSH (SFTP for transfer, SSH exec channel to run
  `shirudo upatch load` remotely) — all via libssh linked into the binary,
  never by shelling out to `ssh`/`scp`. On the target, upatches are loaded
  into the kernel through the same LSM-enforced signature-validation path
  as any other BPF.

This mirrors `git push`: artifacts move outward from the place that owns the
private credential to the places that consume them.

The repo at `/root/shirudo` is empty. The Linux kernel source at `/root/bpf-next`
already ships the complete cryptographic primitives shirudo needs:

- `bpf_prog_verify_signature()` in `kernel/bpf/syscall.c:2801` validates PKCS#7
  signatures on `BPF_PROG_LOAD` against keys in a keyring whose serial is passed
  via `attr.keyring_id`.
- `bpftool gen skeleton -L -S` already implements the signing model end-to-end:
  the signed program is a `BPF_PROG_TYPE_SYSCALL` *loader* prog (produced by
  `bpf_object__gen_loader()` in libbpf) that carries `excl_prog_hash` (the
  SHA-256 of the payload program), so only the exact pre-signed BPF can run.
- `tools/bpf/bpftool/sign.c` (~250 LOC, OpenSSL CMS) is a clean reference for the
  signing primitive — copyable with attribution.
- LSM hooks `lsm/bpf`, `lsm/bpf_prog_load`, `lsm/bpf_map_create`, `lsm/bpf_token_*`
  are defined at `include/linux/lsm_hook_defs.h:440-455`; the `lsm/bpf` hook
  receives the crucial `bool kernel` discriminator so we can distinguish
  "userspace `bpf()` call" from "nested `bpf()` from inside a signed loader".

The MVP delivers a working end-to-end story: generate keys, sign BPF, install
the key into a named kernel keyring, load the LSM, and inspect status — all
from a single `shirudo` binary written in plain C following the Linux kernel
coding style (`Documentation/process/coding-style.rst`).

## Goals & non-goals

**In scope (MVP):**
- Single static binary, plain C, BSD-2-Clause, kernel coding style.
- Subcommands: `init`, `genkey`, `sign`, `status`, `keys`, `upatch list`,
  `upatch load`, `rollout`.
- BPF LSM that enforces "only signed loader progs from userspace".
- bpffs pinning so the LSM survives `shirudo init` exiting.
- Named kernel keyring `shirudo` under the user keyring (`@u`), visible via
  `keyctl list @u`.
- `.upatch` artifact format: portable, signed bundle that targets can load
  without needing the private key.
- Structured logging to the systemd journal via `syslog(3)` with
  `ident="shirudo"`, filterable via `journalctl -t shirudo`.
- **No subprocesses at runtime, ever — with one named exception.** Every
  external operation in the core `shirudo` binary goes through a linked
  library: OpenSSL for crypto/CMS, libbpf for `bpf()` / BTF / maps /
  links, **libssh** for SSH + SFTP, **libtss2** for TPM, raw `syscall()`
  for `keyctl`/`add_key`/`bpf`. The core binary never `fork`s and never
  `execve`s any program on either side — no `ssh`, no `scp`, no `sftp`,
  no `openssl`, no `keyctl`, no `bpftool`, no `journalctl`, no `dmesg`,
  no `tpm2_pcrread`. **The single, narrow, named exception** is the
  operator-side `shirudo build` subcommand, which dispatches to a
  separate `shirudo-build` binary (git-style, modeled on
  `libexec/git-core/git-<foo>`); `shirudo-build` itself `execv`s `clang`
  to compile BPF source. **`shirudo-build` and `clang` do not ship to
  the target** — they are operator-only by packaging, so the no-
  subprocess invariant remains absolute for every target-side code path
  and for every shirudo invocation on the operator other than `build`.
  This eliminates `$PATH` surprises, shell-injection vectors, and
  subprocess-plumbing code from every security-critical path while still
  giving operators a one-stop BPF build experience. If a future feature
  appears to require shelling out from anywhere other than the explicit
  build dispatch, that's a signal the library binding is missing, not a
  license to call `system(3)`.
- **Agentless on the target, ever.** shirudo runs nothing as a long-lived
  process on the target. Every target-side operation is a one-shot CLI
  invocation, fronted by the system's **sshd**: `shirudo init` exits after
  pinning the LSM link; `shirudo upatch load` exits after pinning the new
  link and extending the PCR; `shirudo status` exits after printing. There
  is no `shirudo-daemon`, no shirudo-owned listening socket, no long-lived
  `systemd` service (the deferred reboot-persistence unit is
  `Type=oneshot`, runs `shirudo init`, exits). The only always-on
  infrastructure shirudo relies on is sshd, which already exists on every
  administrable Linux box, already has a key/agent/audit story operators
  understand, and already gives the operator a single trust boundary to
  think about. An ssh-agent on the operator machine is sufficient for the
  entire rollout loop — operators authenticate to sshd as themselves;
  sshd execs `shirudo upatch load` (or `sudo -n shirudo upatch load`) on
  the target as the SSH user; the target authenticates the BPF
  cryptographically against its keyring; the kernel enforces. Nothing in
  this chain requires a shirudo-specific credential or process. If a
  future feature appears to require a long-lived target-side process,
  that's a design re-think (see the ringbuf-drainer note under "Open
  questions"), not a license to add a daemon.
- **Pre-flight TPM state check on every state-changing operation.**
  Before extending the chain, the target verifies that its current chain
  value matches the operator's last-observed value (`--expect-chain=<hex>`,
  auto-derived by `rollout` from a pre-status read against
  the same target on the same libssh session, or supplied explicitly
  by an AI agent that maintains its own per-host expected_pcr from the
  previous report). On mismatch the operation is refused with
  `category: tampered`: no extend, no eventlog entry, no link install
  or detach. The operator (or AI agent) must re-run `shirudo status`,
  reconcile, and decide whether to re-issue. This closes the window
  between observation and action — concurrent operators serialize
  against each other through the chain, and tampering between status
  reads is loud rather than silent. `init` is exempt (target-local
  bootstrap, fresh-boot PCR == 0 is its own pre-flight); a
  `--no-precheck` override exists for emergencies and is logged at
  `LOG_WARNING`.

- **Version-identity check** between operator and target on every
  state-changing operation. Each shirudo binary embeds a
  `SHIRUDO_VERSION_ID` (sha256 of `git commit || build config ||
  source-tree manifest`, **architecture-stripped**) computed at build
  time. The operator's pre-flight exchange surfaces the target's
  `version_id` alongside the chain value; on mismatch the operation
  is refused with `category: version_mismatch`. This catches the
  routine fleet-management hazard of "operator binary upgraded,
  some targets didn't" and the development hazard of "I'm pointing a
  dev build at a prod target by accident". It is **not** a defense
  against an attacker who has rewritten the target's shirudo binary
  on disk — a malicious shirudo would simply lie about its
  `version_id`. Binary-on-disk integrity is the package-manager
  layer's job (distribution signing of the binary, RPM signatures,
  dpkg-sig, cosign, etc.); shirudo defers to that layer and notes
  it as out-of-scope in `Documentation/threat-model.rst`.
- **Single shirudo instance per host.** shirudo is designed to run
  as the **only** shirudo installation on a given target (and a
  given operator) machine. The named keyring (`shirudo`), the
  private bpffs mount (`/var/lib/shirudo/bpffs/`), the runtime tree
  (`/var/lib/shirudo/`), the inode xattr label namespace
  (`security.bpf.shirudo`), and the TPM NV index (`0x01818E00` by
  default) are all single-tenant by design — running two shirudo
  installations side by side on one host would have them stepping
  on each other's keyring, eventlog, and chain state with no useful
  semantics. The `init` pre-flight does not actively detect a
  second installation (no global lockfile, no cross-process
  coordination — adding one would invite TOCTOU); the design simply
  does not support the topology. Operators who want multiple
  independent policy authorities on a single host are out of scope
  for the MVP. If a future need for multi-instance arises, the
  resource names above become the namespacing axis (suffix every
  one with an instance id) — listed in Open questions.
- **Cross-architecture support: x86_64 and arm64.** Both
  little-endian; the on-disk `.upatch` format is little-endian by
  spec; wire formats over SSH are text JSON. The operator and the
  target can be on different architectures (operator x86_64 →
  target arm64 is the canonical "ship from CI to embedded fleet"
  case). `SHIRUDO_VERSION_ID` is architecture-stripped precisely so
  same-source-different-arch binaries share an identity. **riscv64
  is deferred** — not technically blocked (it's also little-endian),
  but not in the MVP test matrix until a target need arises.

- **Minimal, vetted library dependencies — no random library
  crap.** shirudo links against the **smallest possible set of
  well-vetted core system libraries** and refuses convenience
  dependencies. Every library that ends up in the shirudo binary
  expands the supply-chain attack surface; every transitive
  dependency carries with it the integrity of whoever maintains
  it. The selection criteria, applied uniformly:

  1. **Absolutely necessary**, not merely convenient. A library
     is acceptable only if shirudo cannot reasonably do its
     job without it. "Convenient" is not a reason — if a
     functionality can be implemented in a few hundred lines
     of shirudo C, that's the path (with the whiteroom
     procedure from §"Vendoring and whiteroom reimplementation"
     if a reference implementation exists under an incompatible
     license).
  2. **Universally available** across every mainstream Linux
     distribution (Debian/Ubuntu, Fedora/RHEL, Arch, Alpine,
     OpenSUSE) — i.e. in the base repos of all of them, not
     "available if you pull in this additional repo".
  3. **Actively maintained** with a large user base — the kind
     of library distribution security teams already track and
     update on CVE alerts.
  4. **BSD-2-Clause compatible** license, per
     §"Vendoring and whiteroom reimplementation". This rules
     in LGPL-2.1+-OR-BSD and similar dual-licensed projects;
     rules out GPL-only.
  5. **Single load-bearing role** in shirudo — the library does
     one thing shirudo needs, not "and also a hundred unrelated
     features we link in".

  **The complete MVP library list and its justification**:

  | Library | Why absolutely needed | Alternatives ruled out |
  |---|---|---|
  | `libc` | Obvious. | n/a |
  | `libcrypto` (OpenSSL) | X.509, EVP, CMS/PKCS#7, SHA-256. The kernel's signature-verification path matches OpenSSL CMS by design; using anything else would require shirudo to re-implement CMS — large, security-critical surface. | `libgcrypt`, mbed TLS — more niche, smaller user base; no compelling reason to prefer. |
  | `libssh ≥ 0.10` | SSH session, SFTP, exec channel for `rollout`/`status`. Required by the no-subprocess invariant (we can't exec the OpenSSH client). | `libssh2` — also acceptable in principle, smaller user base and historically more CVEs. libssh is the canonical choice. Hand-rolling SSH is out of the question. |
  | `libtss2-esys` + `libtss2-tcti-device` (tpm2-tss) | TPM2 NV-extend chain (target only). The reference TCG implementation; no realistic alternative. | None viable. |
  | `libbpf` | `bpf()` syscall wrapper, BTF handling, gen_loader, the entire BPF userspace API. shirudo cannot reasonably re-implement this. | None — kernel-tools-canonical. |
  | `libelf` | Parses BPF ELF objects for libbpf. | None viable. |
  | `zlib` | Pulled in by libelf for compressed sections; not directly called by shirudo. | n/a (transitive). |

  **The complete list of libraries shirudo refuses to link**:

  - **`libsystemd`** — would add a large transitive surface for
    one thing (structured journald logging) that `syslog(3)` in
    libc handles fine. Already explicitly rejected.
  - **`libsubcmd`** (from kernel tools) — GPL-2.0; whiteroom
    instead.
  - **`libkeyutils`** — convenience wrapper around `keyctl(2)`;
    shirudo uses `syscall(__NR_keyctl, …)` directly.
  - **JSON / YAML / TOML libraries** (`cJSON`, `json-c`,
    `libyaml`, `tomlc99`, …) — shirudo ships an in-tree
    BSD-2-Clause **emitter and bounded-schema parser** for
    JSON under `util/json.{c,h}` (~400 LOC, recursive
    descent, no general-purpose deserialisation — see
    "Build system §"In-tree JSON parser""). The parser is
    only ever applied to JSON shirudo itself emitted on the
    other side of an SSH channel; never to arbitrary
    operator input. Config parsing uses a separate ~50-line
    `key = value` parser. Pulling a full general-purpose
    JSON parser in for the schema-bounded use case would
    expand the supply-chain attack surface for no benefit
    over the in-tree parser whose schema is fixed at compile
    time and whose entire input space is exercised by
    `t/helper/test-json-parser.c`'s fuzzer harness.
  - **`libcurl`** — no HTTP in shirudo, ever.
  - **`libargp`**, GNU readline, `liblua`, embeddable
    interpreters, plugin frameworks — none of them have a
    role here.
  - **`libcap`** — capability-dropping is useful; if shirudo
    ever needs it, `capset(2)` is one syscall and a small struct.
    No library needed.

  This list grows by adding a row to this table after a
  pull-request-level discussion of whether a new dependency
  passes all five criteria. The default answer for "should we
  pull in library X to save Y lines of code" is **no**. The
  supply-chain cost is paid at every install of shirudo on
  every target; the in-tree code cost is paid once.

- **Bleeding-edge kernel and toolchain assumed.** shirudo targets
  the **current upstream Linux kernel** and the **current
  upstream clang/LLVM** as hard prerequisites. There is no
  legacy-kernel detection path, no graceful-degradation feature
  probe at runtime, no `-E2BIG`-style "old kernel?" fallback in
  the bootstrap sequence. If the kernel UAPI headers used at
  build time don't expose `keyring_id` in `union bpf_attr`,
  `BPF_PROG_TYPE_SYSCALL`, `BPF_LINK_CREATE` with
  `BPF_LSM_MAC`, BPF LSM hooks, BPF token (when shirudo eventually
  uses it), and signed-loader CMS verification in
  `kernel/bpf/syscall.c`, the build fails closed with an
  actionable error. The build-time toolchain (clang for BPF,
  libbpf, bpftool, tpm2-tss, libssh) is assumed to be current
  enough to expose every API shirudo calls; minimum versions of
  the userspace libraries listed in "Build system §"Linkage and
  runtime dependencies"" are precise ABI markers, not graceful
  upper bounds. The deployment story is **"shirudo runs on
  modern kernels; vendors who can't ship recent kernels can't
  use shirudo"**. This simplifies the code (no version-gated
  branches), shrinks the test matrix (one supported kernel
  generation), and lets shirudo lean on the latest verifier
  capabilities for the signed-loader path without
  reservations. The embedded-target value proposition (see
  Documentation/threat-model.rst §"Embedded Linux at the edge")
  is not "shirudo helps you keep an ancient kernel running" —
  it is "shirudo lets you ship BPF mitigations to a modern
  embedded kernel without rebooting the device."

- **Target hardening, in two layers.** shirudo on the target
  treats every local attacker (including root) as potentially
  hostile to its own integrity, even though shirudo itself runs
  as root. Two complementary mechanisms:

  1. **Process hardening (`util/harden.{c,h}`)** — called from
     `shirudo.c` `main()` before any subcommand runs. Sets
     `PR_SET_DUMPABLE = 0` (denies ptrace from anyone without
     `CAP_SYS_PTRACE`; makes `/proc/<pid>/{mem,environ,maps}`
     root-only), `PR_SET_NO_NEW_PRIVS = 1` (blocks privilege
     escalation via execve), `PR_SET_PTRACER = 0` (Yama ptrace
     scope), `setrlimit(RLIMIT_CORE, 0)` (no core dumps that
     could leak in-memory key material). For specific buffers
     holding cert bytes, signature buffers, or signed-loader
     working memory, `madvise(MADV_DONTDUMP)` excludes them from
     any residual dump path, and `explicit_bzero` clears them
     after use. Raises the bar from "any root can ptrace" to
     "root with explicit `CAP_SYS_PTRACE`"; not absolute, but
     valuable defense-in-depth.

  2. **Filesystem sealing via inode xattr labels**
     (`bpf/seal.c`, sibling of `bpf/bpf2.c`). The LSM **never
     uses file paths** — path-based identity is tamperable via
     bind-mounts, symlinks, mount-namespace shenanigans, and
     TOCTOU races between lookup and the actual operation.
     Instead the LSM uses **inode-bound extended attributes**:
     every file/directory under `/var/lib/shirudo/` (cert,
     upatch archive, eventlog, the private bpffs mount, and
     every LSM/upatch pin file inside it) is labelled with the
     xattr `security.bpf.shirudo` whose value is the installed
     shirudo's `SHIRUDO_VERSION_ID`. The installed shirudo
     binary itself carries the same xattr with the same value.
     **Pre-signed at build time, loaded by `shirudo init` as a
     second signed-loader pair** alongside `bpf2.bpf.o`.
     Attaches to: `lsm/file_open` (write mode),
     `lsm/inode_unlink`, `lsm/inode_rename`,
     `lsm/inode_setxattr`, `lsm/inode_removexattr`. The
     authorisation logic is **purely inode-based**:

     ```
     target_label = bpf_get_inode_xattr(target_inode,
                                        "security.bpf.shirudo")
     if target_label is absent:                  return 0  /* not protected */
     if kernel == true:                          return 0  /* signed-loader path */
     caller_label = bpf_get_inode_xattr(current->mm->exe_file,
                                        "security.bpf.shirudo")
     if caller_label == target_label (ct-cmp):   return 0  /* authorised */
     return -EACCES
     ```

     No string comparisons, no path resolution, no
     `bpf_d_path()`, no exposure to mount-namespace games. The
     xattr lives on the inode and survives renames,
     bind-mounts, and reshuffling of the filesystem tree; the
     only operations that change a label are explicit
     `setxattr`/`removexattr`, which the same LSM gates by the
     same identity rule.

     **Bootstrap of the xattrs.** The package installer runs
     `setfattr -n security.bpf.shirudo -v <VERSION_ID>` on the
     shirudo binary and any pre-shipped content under
     `/var/lib/shirudo/` at install time. The installer
     succeeds because either (a) this is a fresh install and
     the `bpf/seal.c` LSM isn't yet attached, or (b) it is
     attached but the installer is running from a shirudo
     binary that already has the right label (an upgrade from
     a same-`VERSION_ID` build — rare). For first-ever init on
     a new system, shirudo walks `/var/lib/shirudo/` and
     labels any unlabelled inode **before** loading
     `bpf/seal.c` — catches files written by intermediate
     bootstrap steps. After step 13 the seal LSM is enforcing;
     thereafter, every new file shirudo creates under
     `/var/lib/shirudo/` (e.g. `shirudo upatch load` writing a
     new `.upatch` to the archive) gets labelled by shirudo at
     creation time — shirudo's exe_file already has the right
     xattr, so the `setxattr` passes the LSM's identity check.

     **Upgrades** that change `SHIRUDO_VERSION_ID` (i.e. any
     non-trivial source/config change) require re-labelling
     `/var/lib/shirudo/*` from the old value to the new value.
     MVP procedure: the new shirudo's init detects the
     `VERSION_ID` mismatch on first run and walks the tree to
     re-label via the signed-loader kernel-context path (the
     `kernel == true` branch of the LSM authorises the
     transition). A polished `shirudo upgrade` subcommand is
     parked in Open Questions.

     This entirely subsumes the previously-deferred "Pin-file
     hardening" item. After step 11 attaches bpf2's
     `lsm/inode_unlink` hook (which protects the entire bpffs
     superblock against userspace unlink) and step 13 attaches
     seal (which adds finer-grained xattr-bound protection over
     `/var/lib/shirudo/` more broadly), even
     `rm /var/lib/shirudo/bpffs/lsm_link` returns `-EACCES` —
     the LSM is durable against any userspace tampering, with
     identity tied to inode-bound xattr labels rather than path
     strings.

  Binary-on-disk integrity — adversarial substitution of the
  installed shirudo binary, in-place patching of `.text`,
  bit-rot — is **not** addressed by an in-shirudo mechanism in
  MVP. A previous design (`util/self_check.c` + `tools/stamp/`,
  a post-link stamped self-hash compared at runtime) was
  considered and dropped: the stamping tool isn't a secret and
  SHA-256 isn't asymmetric, so a determined attacker
  re-stamps the patched binary and the check passes; against
  unsophisticated tampering it overlaps with the seal LSM
  (which physically prevents writes once `shirudo init` has
  run), and against adversarial substitution it provides no
  real defence. The right layers are distribution-level:
  signed packages (RPM-signed, dpkg-sig, cosign), IMA
  appraisal, fs-verity on the installed binary, and measured
  boot with TPM attestation of the userspace binary chain.
  These are documented as **recommended deployment-side
  hardening** in `Documentation/threat-model.rst` §"Binary
  integrity (on-disk shirudo)"; shirudo defers to them.
  `SHIRUDO_VERSION_ID` (architecture-stripped, source-state-
  derived) remains in the pre-flight check, but only as a
  **version-skew guard** — not a tamper detector. A malicious
  shirudo binary can return any version_id it wants.

  Together these two pieces address local-attacker scenarios
  that pure DAC (file permissions) and the existing LSM policy
  do not. None of them substitute for the existing primary
  defences (signed BPF, TPM chain, pre-flight gates) — they
  raise the bar for an attacker who has a foothold on the
  target and is trying to subvert shirudo's own operation.

- **Signed removal is just a rollout of an UNLOAD directive.**
  `shirudo build --unload <name>` produces a signed UNLOAD directive
  (`.upatch` with the `DIRECTIVE_UNLOAD` flag bit set); `shirudo
  rollout` pushes it like any other upatch over libssh (the flag, not
  a separate verb, makes the target run `upatch unload`); the target
  detaches the named link, unpins it, and extends the TPM2 NV-extend
  chain with
  `SHA256("shirudo-unload\0" \|\| payload_sha256 \|\| upatch_name)`. Load and unload are both
  forward progress in the TPM chain — the chain records *what
  happened*, not *current state*, so loading then unloading the
  same upatch leaves a permanent audit mark and does **not** return
  the chain to its pre-load value. This is the property an AI-driven
  fleet wants: every state transition is measured, and silent
  removal of a security-critical upatch is impossible. The chain
  is **persistent across reboots** (TPM2 NV-extend, not a PCR),
  so an operator's cached expected chain value survives target
  reboots — the chain advances by exactly one deterministic
  `"shirudo-init\0"` event per boot, which the operator can
  reproduce locally without round-tripping the target.

**Deferred (note in README, not implemented):**
- **(Done — `systemd/shirudo.service`.)** Reboot persistence via a
  `Type=oneshot` systemd unit that re-runs `shirudo init` as early as
  possible (`DefaultDependencies=no`, `After=local-fs.target`,
  `Before=sysinit.target`, `KeyringMode=inherit`), target-only
  (`make install-target`). An even-earlier initramfs stage remains
  future work (threat T5).
- **(Done in MVP — see "Target hardening" in Goals.)** Pin-file
  hardening, originally deferred, is now provided by the
  xattr-based filesystem-sealing LSM program `bpf/seal.c`, which
  attaches to `lsm/file_open`, `lsm/inode_unlink`,
  `lsm/inode_rename`, `lsm/inode_setxattr`,
  `lsm/inode_removexattr` and uses inode-bound
  `security.bpf.shirudo` labels (not paths) to authorise
  shirudo's own writes under `/var/lib/shirudo/`, including the
  private bpffs mount for pin files.
- `init --update` (re-sign + `BPF_LINK_UPDATE` for LSM upgrades).
- Kernel-side audit ringbuf — **on-demand polling, not push.** The LSM
  should emit denial events to a BPF ringbuf so they can be made visible
  to operators. The original sketch assumed a small long-lived drainer
  process on the target; that conflicts with the agentless-on-target
  invariant. The revised design: the ringbuf is consumed on demand by
  `shirudo status --include-audit`, which drains whatever has
  accumulated since the last drain into the journal in one shot and
  returns. Operators (or AI agents) poll at whatever cadence they want.
  Ringbuf back-pressure under high denial rates is the only real cost —
  events are dropped when the buffer is full; a `lost_events` counter in
  the status JSON reports the loss. Open question: whether to also
  offer an opportunistic drain on every `shirudo upatch load`. No
  daemon, no listening socket, invariant preserved.
- Multi-key support, key rotation, key revocation.

**Explicitly out of scope (not deferred — never shirudo's problem):**

- **SSH key management.** shirudo is a **libssh client**. It reads
  `~/.ssh/known_hosts` for host verification, talks to the
  operator's running ssh-agent (via `SSH_AUTH_SOCK`) for
  authentication, and falls back to default on-disk keys. **shirudo
  does not manage SSH keys in any way**: no key generation, no
  rotation, no agent-forwarding orchestration, no jump-host
  config, no `~/.ssh/config` interpretation beyond what libssh
  does, no helper for distributing public keys to targets'
  `authorized_keys`. Operators run whatever SSH infrastructure
  they already run — OpenSSH, signed-CA SSH, smart-card-backed
  keys, hardware tokens, bastion hosts, Vault SSH issuance,
  whatever. shirudo piggy-backs on it. If a fleet's SSH key
  story is healthy, shirudo's rollout/status work; if
  it's broken, shirudo refuses to connect (loudly, via libssh
  error reporting) and offers no opinion on how to fix it. This
  is the same posture `git push` takes toward SSH: it uses your
  SSH setup, it doesn't define it.

  This boundary is load-bearing for shirudo's design economy.
  Building a key-management layer would (a) duplicate
  functionality every operator already has, (b) put shirudo in
  the position of advising on SSH best practice, (c) expand the
  trust surface enormously, and (d) couple shirudo to whatever
  SSH-management opinions we picked. None of those help shirudo
  do its actual job. The threat model
  (`Documentation/threat-model.rst` §"SSH transport") inherits
  the operator's SSH posture as given.

- **Audit / log retention policy.** shirudo writes operational
  events via `syslog(3)` → systemd-journald (target *and* operator
  side), which already has a complete retention story
  (`SystemMaxUse=`, `SystemMaxFileSize=`, `MaxRetentionSec=`,
  `Storage=` in `journald.conf`; journal rotation; forwarding to
  remote collectors via `systemd-journal-upload`). shirudo does
  not duplicate any of that — no log rotation, no archival, no
  retention knobs, no "purge events older than N days"
  subcommand. Operators configure journald the way they
  configure it for everything else on their hosts. The
  cryptographic audit channel — the TPM NV chain — is
  intentionally **append-only and unbounded**: the chain is the
  authoritative immutable record of "what happened to this
  target since first install", and it's a single 32-byte value
  on a TPM with no rotation pressure. The on-disk
  `/var/lib/shirudo/eventlog` mirrors the chain in human-readable
  form for replay verification and for the operator's
  status output; if an operator wants long-term offline archives
  of it, they can `cp` the file out of band — but truncating or
  modifying it in place breaks the replay-against-chain
  invariant (and shirudo reports the resulting mismatch via the
  pre-flight check). The eventlog is small in practice (one
  JSON line per state transition; an active fleet target sees
  tens to hundreds of lines per day at most) so retention isn't
  a load concern.

- **Operator-host integrity.** Out of scope, same logic — that's
  what filesystem integrity tooling (IMA, dm-verity, measured
  boot) and signed package management exist for.

- **The kernel.** shirudo trusts the kernel. A compromised kernel
  defeats shirudo. Mitigations live one layer down.

- **Hardware attacks on the TPM.** Out of scope; mitigated by
  hardware vendors and TPM firmware updates, not by shirudo.

- **Confidential computing integration (SGX / SEV / TDX / CCA).**
  Out of scope for MVP. Confidential-VM environments expose a vTPM
  to the guest and shirudo works inside them as it does on any
  other Linux host — but the *attestation story* (binding the
  shirudo NV chain to a remote-attested guest measurement,
  surfacing the guest's launch quote alongside the shirudo chain,
  validating the platform's certifying authority) is a separate
  project. shirudo's chain remains a per-target ground truth; the
  CVM platform's attestation report is a complementary signal
  operators can correlate out of band. No work in MVP; revisit if
  CVM deployments become a major target audience.

## Architecture

> Cross-reference: the security rationale for every decision in
> this section — why the LSM policy is what it is, why the
> bootstrap sequence pins before doing fallible work, why the
> keyring is named, why `bool kernel` is the central discriminator
> — lives in `Documentation/threat-model.rst`. When implementing
> code in `bpf/bpf2.c` or the `init` bootstrap, check the
> corresponding threat (T1 through T13 are most relevant) and
> confirm the implementation enforces the documented invariant.

### Trusted compute base

Once `shirudo init` has run on a target, **the TCB is the Linux
kernel plus shirudo itself**. Everything else on the target —
every userspace process including root-owned ones, every other
service, every user, the network, the disk contents — is
*outside* the TCB and is constrained by it.

**On the target**, the TCB comprises:

- The kernel, with shirudo's BPF LSM programs (`bpf/bpf2.c` and
  `bpf/seal.c`) enforcing.
- The `shirudo` binary itself. Its on-disk integrity is the
  distribution layer's responsibility — signed packages, IMA
  appraisal, fs-verity, or measured boot — see
  `Documentation/threat-model.rst` §"Binary integrity (on-disk
  shirudo)". Once running, `bpf/seal.c` prevents writes to the
  binary inode.
- shirudo's signed BPF programs running in the kernel (signed-
  loader path, `excl_prog_hash` chain).
- The cert in the `shirudo` named keyring (the trust anchor for
  signature verification).
- The TPM hardware + firmware (records every state transition;
  cannot be reset by userspace).

**Outside the target's TCB**:

- Every root-owned userspace process other than shirudo itself.
  Root can do many things, but it cannot load unsigned BPF
  (LSM blocks), cannot modify shirudo's data files (LSM xattr
  sealing), cannot ptrace shirudo (`PR_SET_DUMPABLE`), and
  cannot forge TPM chain extensions (non-resettable NV-extend
  attribute). Binary-on-disk substitution before `shirudo init`
  has run is **not** caught in-shirudo — the distribution layer
  (signed packages, IMA, fs-verity, measured boot) is the right
  defence.
- The SSH channel from the operator. SSH is an
  **authentication channel** (proves the operator is who they
  say) but not a **continuously-trusted channel** — shirudo
  re-verifies every signed artifact cryptographically against
  the keyring regardless of which SSH session delivered it. A
  compromised SSH connection can only deliver artifacts that
  the cert in the keyring already accepts; it cannot bypass
  signature verification.
- The disk's filesystem layout, modulo deployment-side IMA /
  dm-verity / measured-boot that operators can choose to add.
- The network.

**On the operator**, the TCB comprises:

- The kernel.
- The `shirudo` and `shirudo-build` binaries.
- `clang` / `llvm` (since `shirudo build` exec'd it; it produces
  the bytes that get signed).
- The signing key (the most sensitive single asset in the
  system).
- The cert.
- `ssh-agent` + on-disk SSH keys + `~/.ssh/known_hosts`
  (operator's existing SSH posture).

The operator's TCB is meaningfully larger than the target's,
which is why the project's defense-in-depth recommendations
(HSM-backed keys, IMA appraisal of the shirudo + clang binaries,
restricted operator-host access, audit of every signing
operation) cluster on the operator side. Target hardening focuses
on **keeping the target TCB minimal**: kernel + shirudo + nothing
else. Every In-scope hardening primitive (the LSM policy, the
xattr filesystem sealing, the process hardening) exists to
defend that minimal target TCB from compromise by anything
outside it.

**Implications when designing or reviewing code**:

1. If a change brings new userspace components into the target's
   TCB (an agent, a helper daemon, a long-lived process), that's
   a TCB-growth red flag — the agentless-on-target invariant
   exists precisely to keep this from happening.
2. If a change makes shirudo dependent on a userspace process
   outside the TCB (e.g., a configuration daemon), that's
   inverted trust — outside the TCB should not influence
   in-TCB behaviour.
3. If a defense in shirudo turns out to require trusting
   something the threat model says is outside the TCB, the
   defense doesn't work — re-design.

### LSM enforcement policy (in `bpf/bpf2.c`)

`bpf/bpf2.c` is a multi-attach BPF object. **Two hooks**, both
attached at `shirudo init` time and protecting from the same
instant: `lsm/bpf` (gates `bpf()` syscalls) and `lsm/inode_unlink`
(gates VFS unlink on shirudo's bpffs mount, closing the
window between bpf2 attach and seal attach during which the
LSM pin file would otherwise be removable by `rm`).

One shared, frozen map `bpf2_bpffs_sb` (type `BPF_MAP_TYPE_ARRAY`,
one entry, key=0, value=`struct shirudo_sb_id { __u32 s_dev_major,
s_dev_minor; }`) records the superblock identity of shirudo's
private bpffs at `/var/lib/shirudo/bpffs/`. The userspace shirudo
init flow creates the map, `stat`s the bpffs mount to read its
`st_dev`, populates the map, and calls `BPF_MAP_FREEZE` on it —
**all of this happens before** `BPF_LINK_CREATE` of either bpf2
hook. After the freeze, no userspace caller can ever rewrite the
recorded sb identity; bpf2's hooks read it via
`bpf_map_lookup_elem` at every invocation.

#### Hook 1: `lsm/bpf`

```
if (kernel)                          /* nested syscall from signed loader */
    return 0;

switch (cmd) {
case BPF_PROG_LOAD:
    if (attr->prog_type != BPF_PROG_TYPE_SYSCALL)  return -EACCES;
    if (attr->signature_size == 0)                  return -EACCES;
    return 0;                        /* kernel verifies signature next */

/* tear-down / replace / corruption — denied (see threat T2) */
case BPF_MAP_DELETE_ELEM:
case BPF_MAP_DELETE_BATCH:
case BPF_MAP_UPDATE_BATCH:
case BPF_MAP_LOOKUP_AND_DELETE_ELEM:
case BPF_MAP_LOOKUP_AND_DELETE_BATCH:
case BPF_LINK_DETACH:
case BPF_LINK_UPDATE:
case BPF_PROG_ATTACH:
case BPF_PROG_DETACH:
case BPF_BTF_LOAD:
    return -EACCES;

/*
 * Attach + signed-loader data-map pattern — allowed from userspace.
 * Does not widen the trust boundary: a prog_fd can only be obtained
 * via the signature-gated BPF_PROG_LOAD above or GET_FD_BY_ID of an
 * already-vetted prog, so every attachable program is operator-signed.
 * shirudo needs these because gen_loader can't attach and
 * bpf_sys_bpf() can't OBJ_PIN (TODO.kernel 1-2): the signed loader
 * loads the upatch in kernel context, shirudo's CLI creates + pins
 * the link. BPF_OBJ_PIN falls through to default-allow.
 * Infra maps stay safe via BPF_MAP_FREEZE at creation, independent
 * of the LSM verdict.
 */
case BPF_LINK_CREATE:
case BPF_RAW_TRACEPOINT_OPEN:
case BPF_MAP_CREATE:
case BPF_MAP_UPDATE_ELEM:
case BPF_MAP_FREEZE:
    return 0;

default:                              /* read-only ops: BPF_OBJ_GET,
                                         BPF_*_GET_FD_BY_ID, BPF_MAP_LOOKUP_*,
                                         BPF_PROG_QUERY, BPF_OBJ_GET_INFO_BY_FD;
                                         plus BPF_OBJ_PIN, BPF_PROG_TEST_RUN.
                                         BPF_OBJ_UNPIN is not a bpf() cmd. */
    return 0;
}
```

Allowing read-only commands keeps observability working (`bpftool prog show`,
`bpftool map dump`, our own `shirudo status`). The signature-gated
`BPF_PROG_LOAD` is the trust boundary; attach and the signed-loader map
pattern are allowed (they cannot introduce unsigned code); tear-down,
replace, and map-corruption commands are denied. Loader progs that run
from kernel context bypass all denials because of the `kernel`
discriminator.

#### Hook 2: `lsm/inode_unlink`

The `lsm/inode_unlink` hook signature is `int(struct inode *dir,
struct dentry *victim)` — it does **not** receive a `kernel` arg
the way `lsm/bpf` does, because the unlink path is the same
regardless of caller context. shirudo identifies "is this a
shirudo-internal unlink?" by checking the calling task's
`mm->exe_file`'s xattr label — the same identity rule
`bpf/seal.c` uses for the broader filesystem tree. The hook's
policy:

```
target = victim->d_inode
if !target:                              return 0      /* nothing to protect */

recorded = bpf_map_lookup_elem(&bpf2_bpffs_sb, &idx_0)
if !recorded:                            return 0      /* map not yet populated;
                                                          init hasn't reached
                                                          the bpf2 attach step */

i_dev = BPF_CORE_READ(target, i_sb, s_dev)
if i_dev != MKDEV(recorded->s_dev_major,
                  recorded->s_dev_minor):
                                         return 0      /* not in shirudo's bpffs;
                                                          let other LSMs and the
                                                          VFS default decide */

/* target is in shirudo's bpffs — check caller identity */
task    = bpf_get_current_task_btf()
exe     = BPF_CORE_READ(task, mm, exe_file)
if !exe:                                 return -EACCES

n = bpf_get_inode_xattr(BPF_CORE_READ(exe, f_inode),
                        "security.bpf.shirudo",
                        caller_label, sizeof(caller_label))
if n != SHIRUDO_VERSION_ID_LEN:          return -EACCES

if constant_time_eq(caller_label,
                    shirudo_version_id_const,
                    n):                  return 0      /* shirudo's own unlink */

return -EACCES
```

This denies VFS unlink of any file in shirudo's bpffs by any
process whose `exe_file` doesn't carry the
`security.bpf.shirudo` xattr matching `SHIRUDO_VERSION_ID`.
shirudo's own process passes (the binary is labelled by the
package installer, verified at every init pre-flight). Every
other userspace process — root or not — is refused.

**This closes the step-11→step-12 race window from the prior
audit.** From the instant `BPF_LINK_CREATE` returns for the
inode_unlink hook in step 11, every file in shirudo's bpffs is
protected against unlink. The seal LSM attaches later at step
12 and provides broader per-inode xattr protection (covering
rename, setxattr, removexattr, file_open-for-write) over the
whole `/var/lib/shirudo/` tree; bpf2's inode_unlink coverage of
the bpffs superblock specifically is redundant once seal is up,
but harmless and helpful as defence in depth.

Note bpf2 deliberately does **not** hook `inode_setxattr` or
`inode_rename` itself — those would block shirudo's own
pin-then-label-no-gap setxattr calls during steps 11–13 (seal
isn't attached yet, so seal-style identity authorisation isn't
available, and rebuilding it inside bpf2 would duplicate logic).
seal owns those hooks; bpf2 owns unlink alone, which is the
only op that can structurally detach the LSM by dropping a
pin's refcount.

Program license: `Dual BSD/GPL` (LSM hooks reject non-GPL-compatible).

**Coexistence with stacked LSMs (SELinux, AppArmor, SMACK, Yama).**
The Linux LSM framework stacks: every active major LSM gets a turn at
every hook, and the **most-restrictive verdict wins** (a deny from
any LSM in the stack denies the operation). shirudo composes cleanly
with stacked LSMs:

- `bpf/bpf2.c` and `bpf/seal.c` only ever return `0` (allow,
  meaning "I have no objection") or a negative errno (deny). They
  never attempt to override another LSM's deny — that is structurally
  impossible in the LSM framework.
- If SELinux/AppArmor/SMACK denies a `bpf()` call before shirudo's
  hook runs, the caller sees that denial and shirudo never observes
  the attempt. shirudo's "only signed BPF runs" invariant is
  unaffected — the other LSM is **more** restrictive, not less.
- If SELinux/AppArmor/SMACK denies one of shirudo's own bootstrap
  operations (e.g. unconfined writes under `/var/lib/shirudo/`,
  loading a `BPF_PROG_TYPE_SYSCALL` program), `shirudo init` fails
  with the underlying errno surfaced in the report. Operators on
  policy-strict hosts must add the necessary SELinux booleans or
  AppArmor profile exceptions for the shirudo binary; shirudo does
  not ship those policies in MVP.
- Yama (`/proc/sys/kernel/yama/ptrace_scope`) interacts with
  shirudo's `PR_SET_PTRACER = 0` setting in `util/harden.c` —
  Yama level 1+ already blocks unrelated processes from ptracing
  shirudo even before `PR_SET_PTRACER` is consulted, so the two
  defences add up.

shirudo does not require any particular stack composition; the
target's existing LSM choices are inherited as part of the kernel
trust boundary (see TCB framing above). The threat model
(`Documentation/threat-model.rst`) does not assume any LSM beyond
`bpf` is active; if others are, they widen shirudo's coverage.

### Pre-flight checks (run by every `shirudo init`)

Before touching any kernel state, `shirudo init` runs an exhaustive
**pre-flight gate** over the infrastructure it needs. **All checks
run** — the operator sees the full list of failures at once rather
than fixing one and re-running to discover the next. If any
required check fails (modulo the single `--no-tpm` override), init
exits non-zero with `category: init_prereqs_missing`, names every
failed prerequisite in both human and JSON (`--report=`) forms, and
**touches nothing** — no syscalls beyond probing, no keyring
creation, no LSM load, no chain extension.

| # | Check | Hard? | How |
|---|---|---|---|
| 1 | Running as root | yes | `geteuid() == 0`; otherwise refuse — `bpf()`, `keyctl()`, bpffs mounts, and `/dev/tpmrm0` all require it. |
| 2 | `/sys/kernel/security/lsm` contains `bpf` | yes | One open + read of the file; substring search. No legacy-kernel feature probing — shirudo requires current upstream (Goals §"Bleeding-edge kernel and toolchain assumed"); if `bpf` is missing, the actionable message is "rebuild your kernel with `lsm=…,bpf`". |
| 3 | shirudo's **private bpffs** mounted (or mountable) at `/var/lib/shirudo/bpffs/` | yes | `statfs(2)` for `BPF_FS_MAGIC` at that path; if not present, `mkdir(2)` the parent and `mount(2)` with `-t bpf -o mode=0700,nosuid,nodev,noexec`. shirudo does **not** depend on the system-wide `/sys/fs/bpf` — it manages its own bpffs instance so pins live under `/var/lib/shirudo/` (covered by the filesystem-sealing LSM) rather than commingled with whatever else uses the system bpffs. |
| 4 | `/var/lib/shirudo/keys/cert.der` present and readable | yes | `access(R_OK)` + parse with `d2i_X509()` to confirm it's a valid DER cert. shirudo cannot bootstrap without the cert. |
| 5 | `/var/lib/shirudo/` writable, mode 0700 owned by root | yes | `stat(2)` + `mkdir(2)` for any missing subdirectory (`keys/`, `upatches/`, `incoming/`); enforce mode and owner. |
| 6 | `/var/lib/shirudo/bpffs/` creatable | yes | `mkdir(2)` if not present; ensure the pin parent exists before any `BPF_OBJ_PIN`. |
| 7 | Embedded pre-signed LSM loader present in binary | yes | `shirudo_bpf2_loader_o_end > shirudo_bpf2_loader_o` and `shirudo_bpf2_sig_end > shirudo_bpf2_sig`. Catches a packaging mistake where the operator's pre-signed loader didn't make it into the binary at build time. |
| 8 | `add_key()` / `keyctl()` syscalls available | yes | Probe `add_key(2)` with a sentinel — `ENOSYS` means kernel keyring support is compiled out (`!CONFIG_KEYS`), which shirudo cannot work around. |
| 9 | TPM2 reachable: `/dev/tpmrm0` exists, readable, and `Esys_NV_ReadPublic` of the shirudo NV index succeeds (index may not yet be defined, that's fine) | **yes**, with `--no-tpm` override | If absent: fail with `init_prereqs_missing` sub-reason `tpm_unavailable`. The operator can override with `--no-tpm` to proceed in **measurement-disabled mode** (LSM enforcement still works, chain measurement does not). The override is logged at `LOG_WARNING` on both the target and in the JSON report. |
| 10 | libtss2 ESAPI usable on the target's TPM model | gated by #9 | If `--no-tpm`, skip. Else `Esys_GetCapability` for SHA-256 PCR bank + NV-index attributes; refuse if the TPM doesn't support `TPMA_NV_EXTEND` with SHA-256; **confirm TPM 2.0** (refuse TPM 1.2 here, not in #9). |
| 11 | NV index `SHIRUDO_NV_INDEX` not already defined under foreign attributes | gated by #9 | If `--no-tpm`, skip. Read the index public area via `Esys_NV_ReadPublic`: ENOENT → fresh, will be defined in step 14 of bootstrap; success → assert `nvPublic.attributes` contains `TPMA_NV_EXTEND` and `nameAlg == TPM2_ALG_SHA256`, **and confirm the index responds to shirudo's derived `auth_value` (`SHA256("shirudo-nv-auth\0" \|\| cert_sha256)`)** by attempting a 0-byte authenticated read. If the index is defined with **different attributes** (a previous shirudo with another cert, or a foreign tool squatting on the index), refuse with sub-reason `tpm_index_conflict`; if the index responds but with a different auth_value, refuse with sub-reason `tpm_index_auth_mismatch`. Fix hint: the operator must either undefine the index with `tpm2 nvundefine` (out-of-band, under owner auth, lossy — chain restarts from zero) or pick a different `SHIRUDO_NV_INDEX` at build time. Never silently overwrite. |
| 12 | **bpffs supports `security.*` xattrs end-to-end** | **yes** | Load-bearing: shirudo's filesystem-sealing LSM (`bpf/seal.c`) authorises by reading `security.bpf.shirudo` on inodes, and the inodes that need protection most urgently are the LSM pin files themselves, which live on bpffs. If bpffs silently drops the xattr (accepts the `setxattr` but returns ENODATA from `getxattr`), the seal LSM sees no label, returns 0 (allow), and `rm /var/lib/shirudo/bpffs/lsm_link` succeeds — silently invalidating the entire pin-protection story. **The probe** (in `util/preflight.c`, gated to run only when `--no-tpm` and other earlier checks have passed): (a) `BPF_MAP_CREATE` a one-entry throwaway `BPF_MAP_TYPE_ARRAY`; (b) `BPF_OBJ_PIN` it to `/var/lib/shirudo/bpffs/.probe.<pid>.<random>`; (c) `setxattr(probe_path, "security.bpf.shirudo", probe_value, 16, XATTR_CREATE)` with a 16-byte random value freshly generated for this check; (d) `getxattr(probe_path, "security.bpf.shirudo", buf, 16)` and assert `memcmp(buf, probe_value, 16) == 0`; (e) unlink the probe path and close the map fd. Each sub-step's errno is captured. Refuse with sub-reason `bpffs_xattr_unsupported` if any sub-step fails or the round-trip mismatches — fix hint: "this kernel's bpffs does not support `security.*` xattrs; shirudo requires a current upstream kernel that does (see `kernel/bpf/inode.c::bpf_inode_xattr_*`). Older kernels and stripped-down builds without bpffs xattr support are not supported." The probe leaves no kernel state behind: the map fd closes on shirudo exit; the pin is unlinked before pre-flight returns. |

Implementation note: the checks live in `util/preflight.{c,h}` so
`shirudo status` can call them too. A `shirudo status` invocation
before `init` reports the same readiness picture as the pre-flight
gate — operators (or AI agents) can dry-run the gate without
committing to bootstrap. `shirudo init --check-only` runs the gate
and exits without bootstrapping, for CI sanity checks.

### Bootstrap sequence (`shirudo init`)

The target never holds the signing key. The LSM loader and the
`bpf/unload.bpf.o` directive template are **signed at build time on
the operator machine** (where the key lives) and embedded into the
shirudo binary as `(loader_insns, signature)` pairs via `.incbin` —
see "Build system" §"BPF object embedding". On the target, `shirudo
init` consumes these pre-signed pairs; it never invokes the signer.

The numbered sequence below runs **after** all pre-flight checks
above have passed (or been overridden):

```
1.  All pre-flight checks (above) passed. If any required check
    failed and was not overridden, control would not have reached
    this point — init would have exited with
    `category: init_prereqs_missing`.
2.  Mount shirudo's **private bpffs instance** at
    `/var/lib/shirudo/bpffs/` if not already mounted. Options:
    `-t bpf -o mode=0700,nosuid,nodev,noexec`. This is shirudo's
    own pinning filesystem; the system-wide `/sys/fs/bpf` is not
    used (and not required to exist). The private mount keeps all
    shirudo pins under `/var/lib/shirudo/`, which is also the
    tree the filesystem-sealing LSM (`bpf/seal.c`, step 13
    below) protects.
3.  Read `cert.der` from `/var/lib/shirudo/keys/`. The signing key
    is **not** on the target and is not consulted here.
4.  Create the named keyring:
    `add_key("keyring", "shirudo", NULL, 0, KEY_SPEC_USER_KEYRING)`
    → `keyring_serial`. If it already exists, reuse it.
5.  Link the cert:
    `add_key("asymmetric", "shirudo:<fingerprint>", cert_der,
    der_len, keyring_serial)`. Then **seal the keyring**
    (`KEYCTL_SETPERM` drops write/link/setattr, keeping
    view/read/search) so no further cert can be added this boot,
    and **pin `keyring_serial`** to
    `/var/lib/shirudo/keyring.serial` (sealed) for load-time
    swap detection (see "Keyring model"). The pin is (re)written
    on every init, including the idempotent already-present path.
6.  Determine the upatch set `S` to re-apply: scan
    `/var/lib/shirudo/upatches/` for `.upatch` files, sort by
    upatch name (lexicographic, by `<name>.upatch` basename).
7.  Read the embedded **pre-signed** LSM loader pair from the
    binary: `shirudo_bpf2_loader_o`, `shirudo_bpf2_loader_o_end`
    and the matching `shirudo_bpf2_sig`, `shirudo_bpf2_sig_end`
    (both produced at build time; see "Build system").
8.  **Create and populate the bpf2 superblock-identity map
    before the LSM attaches.** `BPF_MAP_CREATE` a
    `BPF_MAP_TYPE_ARRAY` map with `max_entries=1`, key=`__u32`,
    value=`struct shirudo_sb_id { __u32 s_dev_major,
    s_dev_minor; }`. `stat(2)` the bpffs mount at
    `/var/lib/shirudo/bpffs/`, decompose `statbuf.st_dev` into
    major/minor via `major(3)`/`minor(3)`, `BPF_MAP_UPDATE_ELEM`
    with key=0 and value=that pair. **`BPF_MAP_FREEZE` the map.**
    After this point the recorded sb identity is immutable for
    the lifetime of this boot; even the bpf2 LSM cannot rewrite
    it (freeze precedes the LSM attaching, so userspace-to-map
    writes were never gated by the LSM anyway, but the freeze
    is what makes them syscall-impossible thereafter).
9.  Raw `BPF_PROG_LOAD` syscall with
    `prog_type = BPF_PROG_TYPE_SYSCALL`,
    `insns = shirudo_bpf2_loader_o`,
    `signature = shirudo_bpf2_sig`, `signature_size = ...`,
    `keyring_id = keyring_serial`.
    The kernel's `bpf_prog_verify_signature()` (in
    `kernel/bpf/syscall.c`) runs against the cert; returns
    `prog_fd` on success or `-EKEYREJECTED` if the cert in the
    keyring does not match the key the operator signed with at
    build time.
10. `BPF_PROG_TEST_RUN` on `prog_fd` with the loader context —
    which carries **the bpf2_bpffs_sb map fd** so the gen_loader
    can patch it into the bpf2 program's instructions. The
    loader installs the actual LSM prog (from `bpf/bpf2.bpf.o`,
    embedded in the loader's `data`) and populates `ctx` with
    the resulting prog fd. The loader's embedded
    `excl_prog_hash` constrains it to exactly the bytes that
    were signed.
11. **Attach both bpf2 hooks atomically (from shirudo's
    perspective).** `BPF_LINK_CREATE` with `attach_type =
    BPF_LSM_MAC`, `target_btf_id` resolved from the `bpf` LSM
    hook name → `lsm_bpf_link_fd`. Then immediately
    `BPF_LINK_CREATE` with `target_btf_id` resolved from the
    `inode_unlink` LSM hook name → `inode_unlink_link_fd`. From
    the instant the second `BPF_LINK_CREATE` returns, bpf2 is
    enforcing **both** unsigned-BPF denial AND VFS-unlink
    denial on shirudo's bpffs superblock. There is no exploitable
    window where the bpf() syscall is guarded but the bpffs is
    not, because no pin files exist yet (the first
    `BPF_OBJ_PIN` is step 12).
12. **Pin both bpf2 links, label them as they're pinned.** For
    each link in turn: `BPF_OBJ_PIN` →
    `/var/lib/shirudo/bpffs/lsm_link` (resp.
    `/var/lib/shirudo/bpffs/inode_unlink_link`), **immediately
    followed by `setxattr("security.bpf.shirudo",
    SHIRUDO_VERSION_ID, 64, XATTR_CREATE)`** on the pin path
    with **no intervening syscalls between the two calls** (the
    `setxattr` is the very next statement after `BPF_OBJ_PIN`
    returns). The pin-then-label-no-gap rule. The inode_unlink
    hook itself protects these pins from VFS removal from the
    moment they exist — even between `BPF_OBJ_PIN` and the
    following `setxattr`, the pin is guarded by bpf2's bpffs
    superblock check (not yet by the xattr-bound check, but by
    the coarser sb-bound check which is sufficient against the
    rm-the-pin attack).

    From this point onward, the LSM is enforcing — any further
    `BPF_PROG_LOAD` from userspace must carry a valid signature,
    and any `rm` of a file under `/var/lib/shirudo/bpffs/` from
    a process whose exe_file doesn't carry the
    `security.bpf.shirudo` xattr is refused with `-EACCES`.
13. **Label-walk and install the filesystem-sealing LSM**
    (`bpf/seal.c`). Two parts:

    (a) **Pre-load xattr walk.** Walk `/var/lib/shirudo/`
    (excluding the bpffs mount, whose contents are kernel-
    managed) and ensure every inode carries the xattr
    `security.bpf.shirudo` set to `SHIRUDO_VERSION_ID`. Set the
    xattr on any that don't have it yet (the LSM isn't enforcing
    these hooks yet, so `setxattr` is unrestricted at this
    moment). Also confirm the shirudo binary itself
    (`/proc/self/exe`) has the same xattr — refuse to proceed if
    it doesn't (means package installation was incomplete).

    (b) **Install the LSM.** Read the embedded pre-signed loader
    pair for `seal.bpf.o`, load via the same `BPF_PROG_LOAD` +
    signature + `keyring_id` path, `BPF_PROG_TEST_RUN` the loader
    to install each sub-program, `BPF_LINK_CREATE` for each LSM
    hook (`lsm/file_open`, `lsm/inode_unlink`,
    `lsm/inode_rename`, `lsm/inode_setxattr`,
    `lsm/inode_removexattr`), and **for each hook:**
    `BPF_OBJ_PIN` the link to
    `/var/lib/shirudo/bpffs/seal_<hook>_link` **immediately
    followed (no intervening syscalls) by `setxattr` of
    `security.bpf.shirudo = SHIRUDO_VERSION_ID` on the pin
    path**. After this step, any write/unlink/rename/xattr
    modification on any inode carrying the
    `security.bpf.shirudo` xattr is refused with `-EACCES`
    unless the calling process's exe_file carries the same
    xattr value — including `rm` of the LSM pin files
    themselves. The protection is self-referential: the
    `seal.bpf.o` pins live under the same tree the program
    protects, and the labels were written under the same
    invariant (pin-then-label-no-gap).
14. **Re-apply boot-restore set `S`** (no-op if `S` is empty):
    for each upatch in sorted order, run the same code path
    `shirudo upatch load` uses (parse container, signature-
    verified `BPF_PROG_LOAD`, `BPF_PROG_TEST_RUN`, create + pin
    the upatch link under `/var/lib/shirudo/bpffs/upatches/<name>/link`,
    then `setxattr` of the `security.bpf.shirudo.payload`
    payload_sha256 on the pin directory `<name>/` — the unload
    `payload_mismatch` ground truth — re-established the same way a
    fresh load does it). Same pin-then-label-no-gap rule as for the
    LSM links above. **Per-upatch chain extensions are suppressed
    during boot-restore** — the chain extension happens once, at
    step 16.
15. Define the TPM NV-extend index if not yet defined
    (`Esys_NV_DefineSpace` with `TPMA_NV_EXTEND` attributes per
    PLAN.md §"TPM measurement"). Idempotent: subsequent runs
    find the index already defined and skip.
16. Compute `set_digest` over the **actually-loaded** set
    (canonical sorted listing, sha256sum-style). Compute
    `init_event_digest = SHA256("shirudo-init\0" ||
    cert_sha256 || set_digest)`. Issue one `Esys_NV_Extend`
    with `init_event_digest`. Append a single eventlog entry
    listing the set.
17. Close all fds; exit. The LSM remains attached via the bpffs
    pin; filesystem-sealing remains active via its own pins;
    upatches remain attached via their own pins. The private
    bpffs mount stays mounted.
```

If any step before step 11 fails, no kernel state is left behind
because the unpinned link's refcount drops to zero on fd close
(and the bpf2 superblock-identity map created at step 8 closes
when its fd does). If step 12 (pin + label of the bpf2 links)
fails after step 11 succeeded, bpf2 is attached but unpinned —
the link's fd is still in shirudo's process; on shirudo exit the
link detaches. Init is marked **incomplete** and the operator's
next attempt re-creates everything. If step 13 (seal install)
fails after step 12 succeeded, bpf2 is up and pinned but seal
is not — bpf2 protects against the rm-the-pin attack on the
bpffs mount, but the broader `/var/lib/shirudo/` tree is
unsealed; init is marked **incomplete** and the operator's next
pre-flight detects it. If any step between 14 and 16 fails, init
is marked **incomplete**: the LSM and filesystem-sealing are up
and some upatches may be loaded, but the chain has not advanced
to the expected `init_event_digest` value. The operator's next
pre-flight will see the chain mismatch and investigate. Manual
recovery is: fix the failing upatch, run `shirudo init` again
(idempotent — the LSM and filesystem-sealing programs are
already pinned, so step 11/12/13 detect that and skip; the
re-apply + extend retries).

### Keyring model

- Named keyring `shirudo` is created under `@u` (`KEY_SPEC_USER_KEYRING`).
  Visible: `keyctl list @u` shows `keyring: shirudo`.
- The X.509 cert is added as type `asymmetric` with description
  `shirudo:<sha256-of-cert>` (first 16 hex chars) so multiple keys can coexist
  and the `keys` subcommand can show fingerprints.
- The kernel only consults the keyring at `BPF_PROG_LOAD` time. Once the LSM
  link is pinned, the keyring is no longer needed for the LSM to remain
  enforcing — but it *is* needed for any future signed loader the operator
  loads.
- No kernel keyring persists across reboots. The cert/key on disk plus the
  `systemd/shirudo.service` unit re-running `shirudo init` is how persistence
  works.
- **Verification is scoped to the sealed keyring's serial, with a serial pin
  against substitution.** Every signed `BPF_PROG_LOAD` passes the `shirudo`
  keyring's serial as `attr.keyring_id` (not `KEY_SPEC_USER_KEYRING`), confining
  the kernel signer search to that one keyring — a cert planted elsewhere in
  `@u` is ignored (`ENOKEY`). Because find-by-name could still be redirected by
  a root attacker who unlinks the real keyring and links a fake same-named one,
  `init` pins the keyring serial to `/var/lib/shirudo/keyring.serial` (under the
  filesystem seal, labelled like the rest of the tree), and every load refuses
  with `category: tampered` unless the resolved-by-name serial still equals the
  pin (absent pin → warn + proceed; present-but-unreadable → `tampered`). This
  degrades the swap from a silent bypass into a fail-closed refusal. A complete
  fix (deny the swap outright) needs an `lsm/key_permission` hook plus a new
  `key_ref → struct key *` kfunc — see `TODO.kernel` item 9.

### Bootstrap chicken-and-egg, resolved

The shirudo LSM hooks `lsm/bpf` and rejects unsigned `BPF_PROG_LOAD`. shirudo
itself loads via a signed loader (step 11 above), so even the bootstrap call
flows through the same signing path that all future BPF will. The LSM cannot
unload itself once attached because `BPF_LINK_DETACH` and `BPF_OBJ_UNPIN` are
denied for userspace `bpf()` callers.

## Subcommands

`shirudo` is one binary, but each subcommand belongs to a specific side of
the operator/target split. Running a command on the wrong side is harmless
but pointless: `sign` without the private key just errors out, `init`
without root and a `bpf` LSM-capable kernel just errors out. The split is
enforced by what the command *reads* (private key vs kernel keyring), not
by a hostname flag.

### Operator-side — produces and pushes signed artifacts

Lives where the **private key** lives. Needs `libcrypto` and `libssh` linked
in (already part of the binary), the on-disk cert and key under
`/var/lib/shirudo/keys/`, and — for `rollout` — the operator's usual SSH
material under `~/.ssh/` (agent socket, keys, `known_hosts`). Never touches
a kernel keyring, never mounts a bpffs (the target manages its own private bpffs under `/var/lib/shirudo/bpffs/`), never fork+execs anything.

| Subcommand | Purpose |
|---|---|
| `shirudo genkey` | Generate the X.509 self-signed cert (2048-bit RSA, SHA-256, CN=`shirudo`, 10-year validity) into `/var/lib/shirudo/keys/{signing_key.pem,cert.der}`. Mirrors `tools/testing/selftests/bpf/verify_sig_setup.sh:genkey()`. Uses OpenSSL EVP / X509 APIs directly — no shelling out. **Algorithm/key-size are upgradable without code changes to anything outside `builtin-genkey.c`**: the kernel signature path consumes whatever the operator's cert and the signed CMS blob agree on, so a future `shirudo genkey --algorithm=ed25519` or `--rsa-bits=3072` only needs to flip the EVP_PKEY parameters. RSA-2048/SHA-256 is the MVP default — acceptable per NIST guidance through approximately 2030. Multi-key support and key rotation (Open questions) provide the runtime path for migrating a deployed fleet to a stronger algorithm without a flag day. |
| `shirudo build <input> [-o <output.upatch>] [-I <dir>...] [-D <macro>...] [--vmlinux <path>] [--extra-cflags '<flags>']` *or* `shirudo build --unload <name> [--payload-sha256=<hex>] [-o <output.upatch>]` | **The unified operator-side artifact-producing command** — compiles BPF source if needed, runs gen_loader, signs the loader bytes with the operator's private key, and serializes a `.upatch` container ready for `shirudo rollout`. **`-o` is optional**: when omitted, the output defaults to `<input>` with the trailing `.c`/`.o` replaced by `.upatch` (so `examples/foo.bpf.c` → `examples/foo.bpf.upatch`, written next to the input), and for `--unload` to `<name>.unload.upatch` in the current directory. Pass `-o` only to write elsewhere. **Implemented as a dispatch** to a separate binary `$(libexecdir)/shirudo/shirudo-build` (git-style — see git's `libexec/git-core/git-<foo>` layout); the core `shirudo` binary's `builtin-build.c` is a five-line `execv` wrapper. `shirudo-build` does the actual work, including the **sole subprocess exception in shirudo**: when the input is a `.bpf.c` source file, `shirudo-build` `execv`s `clang -target bpf -O2 -g -Wall -Wextra …` to compile it; for `.bpf.o` inputs it skips compilation. **Both `shirudo-build` and `clang` ship only with the operator package, never to a target** — on a target where `shirudo-build` is not installed, `shirudo build` returns exit 127 with a clear "operator-only subcommand" message. **Three input/output forms:** (a) `<source.bpf.c>` → compile + gen_loader + sign + package → LOAD `.upatch`; (b) `<file.bpf.o>` → gen_loader + sign + package → LOAD `.upatch` (skip compilation; useful when the operator has a pre-compiled object from a separate build farm); (c) `--unload <name>` → emit a signed UNLOAD directive `.upatch` with `flags & DIRECTIVE_UNLOAD` set, embedding the small hand-written unload BPF program (from `bpf/unload.bpf.c`) that opens the pin at `/var/lib/shirudo/bpffs/upatches/<name>/link`, verifies the loaded upatch's `payload_sha256` against the directive's expected value, then issues `BPF_LINK_DETACH` + `BPF_OBJ_UNPIN` from kernel context. For `.bpf.c` input shirudo auto-locates `vmlinux.h` (current directory first, then `/usr/share/shirudo/vmlinux.h`); `--vmlinux <path>` overrides. `--extra-cflags` is the operator's escape hatch. For `--unload`, `--payload-sha256=<hex>` pins the expected digest; if omitted, the operator's local upatch archive at `/var/lib/shirudo/upatches/` is consulted. |
| `shirudo rollout <upatch>... { <name>... | --selector=<expr> } [--report=<path>] [--sudo] [--expect-chain=<hex>] [--expect-version-id=<hex>] [--no-precheck] [--no-version-check] [--dry-run]` | Push one or more signed `.upatch` files to one or more destinations via **SFTP**, then apply each over an **SSH exec channel**. **Each file's `DIRECTIVE_UNLOAD` flag selects the remote verb**: a LOAD artifact runs `shirudo upatch load`, an UNLOAD directive runs `shirudo upatch unload` — so one rollout (and one mental model) covers both deploy and remove, and a batch may mix the two. **Targets are selected either by explicit registered names or by a label selector** (mutually exclusive — pick one form). Each `<name>` must be a registered remote name (via `shirudo remote add`). `--selector=<expr>` evaluates a label expression against every registered remote and selects the matching subset; expressions support equality (`key=value`), inequality (`key!=value`), existence (`key`), non-existence (`!key`), `&&` (AND, higher precedence), `||` (OR, lower precedence), and parentheses — e.g. `--selector='shirudo.nodes.type=production && shirudo.nodes.location=us-east-1'` or `--selector='(role=database || role=cache) && env!=staging'`. Empty match set is an error ("selector matched zero registered remotes"). Originally registered beforehand via `shirudo remote add <name> <user@host[:port]>`. Literal `user@host[:port]` arguments are **refused** with a clear "register first" error. This forces every state-changing operation through the auditable remote set, makes `shirudo nodes` complete by construction, and eliminates the fat-finger class of "I typed the wrong hostname" rollouts. By default `rollout` first issues `shirudo status --json --include-tpm` against each target on the same libssh session, captures that target's current chain value, and threads it through as `--expect-chain=<captured>` on the subsequent `upatch load` invocation — the target then refuses to extend unless its current chain still matches what `rollout` just observed (see "Pre-flight TPM state check"). `--expect-chain=<hex>` overrides the auto-derive with an explicit value (the AI-agent pattern: stash `chain_after` from each report, pass it as the next op's expected value, or compute the post-reboot value locally as `SHA256(chain_after || init_event_digest)` — where `init_event_digest = SHA256("shirudo-init\0" \|\| cert_sha256 \|\| set_digest)` and `set_digest` is the canonical hash of the loaded-upatch set the agent is tracking — when the target has rebooted in between). `--no-precheck` skips the check entirely (logged at `LOG_WARNING`; for first-time bootstrap or emergency recovery). Multiple destinations mix freely; all must be registered. Both transports go through **libssh** linked into the binary; shirudo never `fork+exec`s `ssh`, `scp`, or `sftp`. Authentication uses ssh-agent and the operator's default keys (`~/.ssh/id_ed25519`, `~/.ssh/id_rsa`); host verification reads `~/.ssh/known_hosts` under a strict policy — unknown or changed host keys fail loudly, never trust-on-first-use. `--report=<path>` emits an aggregate JSON document covering per-target results — **load-bearing input for AI agents driving the rollout loop**; see "Failure reporting for AI-driven rollouts". Failures are reported per-target so partial rollouts are visible. `--dry-run` resolves the destination set, parses every `.upatch` argument, opens libssh sessions to each target, runs the pre-flight checks (chain read, version-id compare, LSM-attached check), and emits the report with `"result": "ok-dryrun"` per target — **no SFTP upload, no `shirudo upatch load` invocation, no chain extension**. Useful for AI agents validating a planned operation before committing, for operator change-management approval, and for confirming a selector expression matches the intended target set. **There is no separate `rollback` verb** — a removal is a rollout of a signed UNLOAD-directive `.upatch`. For an UNLOAD directive the target's `upatch unload` verifies the directive's `payload_sha256` against the loaded upatch under that name (mismatch → `category: payload_mismatch`, refuse), extends the NV chain with `SHA256("shirudo-unload\0" \|\| payload_sha256 \|\| upatch_name)` on success (forward progress, not a rewind), and is idempotent (`already_unloaded` if no pin). |
| `shirudo remote add <name> <user@host[:port]> [--port N] [--user U] [--system] [--label key=value ...]` *(also `list`, `rm`, `rename`, `show`, `label`; bare `shirudo remote` defaults to `list`)* | Manage the operator-local **remote registry** so `rollout`/`nodes` can reference targets by name and by label selector. Each remote is one file under `$XDG_CONFIG_HOME/shirudo/remotes.d/<name>.conf` (per-user) or `/etc/shirudo/remotes.d/<name>.conf` (with `--system`). `--label key=value` (repeatable) attaches key=value labels to the remote — operator-chosen pairs used by `--selector` expressions on the operation subcommands. Common conventions: `shirudo.nodes.type=production`, `shirudo.nodes.location=us-east-1`, `shirudo.nodes.role=database`. No secrets in the registry — only routing metadata + labels; host-key verification still goes through `~/.ssh/known_hosts`, authentication still through ssh-agent. Labels can be mutated after registration via the dedicated `shirudo remote label {add,rm,clear}` sub-router (next row); editing the conf text by hand also works (the file is plain `key = value` text). See the "Remote registry" section for the full file format, lookup precedence, and selector grammar. |
| `shirudo remote label add { <name> \| --filter=<glob> \| --selector=<expr> } <key=value>...` *(also `rm <key>...`, `clear`)* | Mutate labels on one or more registered remotes after registration. Strict key→value semantics: re-adding an existing key overwrites its value (no multimap). Single-target form takes a positional `<name>`; fleet form takes `--filter=<glob>` (registry name glob, fnmatch(3)) and/or `--selector=<expr>` (label expression, same grammar as `rollout --selector`), mutually exclusive with the positional form. **Local-only**: labels live exclusively on the operator side, never pushed to targets. `add` is idempotent; `rm` on a missing key is a warning, not an error; `clear` removes every label (endpoint, user, port and `created =` are preserved). The atomic rewrite is `<conf>.tmp` + `rename(2)`. Only user-dir remotes are mutable; a `/etc` remote refuses with "no user-registered remote 'X'". Tab-completion derives the sub-router live via `shirudo remote label --list-cmds`. Bash completion picks up `add`/`rm`/`clear` without script edits. |

### Target-side — applies upatches under LSM enforcement

Lives where the **kernel keyring and the LSM** live. Needs root (for
`bpf()`, `keyctl()`, bpffs mounts), a kernel built with the options under
"Kernel config requirements", and the cert (no private key) on disk. Never
reads the private key, never produces a signed artifact.

| Subcommand | Purpose |
|---|---|
| `shirudo init [--no-tpm] [--check-only] [--report=<path>]` | Bootstrap sequence above. **Always runs the pre-flight check first** (see Architecture §"Pre-flight checks for `shirudo init`") — if any required prerequisite is absent (root privilege, BPF LSM in the kernel, bpffs mountable, cert on disk, embedded loader in the binary, TPM reachable), init exits non-zero with `category: init_prereqs_missing` and a full enumeration of failed prerequisites; **no kernel state is touched on failure**. `--no-tpm` is the single override: proceed without TPM measurement in degraded mode (LSM still enforces; chain not extended), logged `LOG_WARNING` at both target and report. `--check-only` runs the pre-flight gate and exits without bootstrapping — useful for CI sanity and operator dry-runs. `--report=<path>` (use `-` for stdout) emits the structured JSON readiness/result document. Otherwise idempotent: re-running on an already-initialised target is a no-op (the pre-flight still runs and confirms the system is still healthy). Reads `cert.der` from `/var/lib/shirudo/keys/` — the cert is typically copied to targets via `rollout` (or any out-of-band channel) without the matching private key. |
| `shirudo upatch load <file.upatch> [--report=<path>] [--expect-chain=<hex>] [--expect-version-id=<hex>] [--no-precheck] [--no-version-check]` | Load a signed LOAD `.upatch` into the kernel. **Pre-flight check first** (unless `--no-precheck`): read the current NV chain value, compare against `--expect-chain=<hex>` (which `shirudo rollout` always supplies; an operator running this command directly must supply it from a prior `shirudo status` observation, or use `--no-precheck`). Also confirm the LSM link is pinned at `/var/lib/shirudo/bpffs/lsm_link` and the `shirudo` keyring exists. On any mismatch: refuse with `category: tampered`, no `BPF_PROG_LOAD`, no chain extend, no eventlog write. On pass: parse the container, validate header/version and that `flags & DIRECTIVE_UNLOAD == 0`, issue `BPF_PROG_LOAD` with the embedded loader insns + signature + `keyring_id` set to the `shirudo` keyring serial. The kernel verifies the signature; on success, `BPF_PROG_TEST_RUN` invokes the loader, which installs the payload, shirudo pins the resulting link to `/var/lib/shirudo/bpffs/upatches/<name>/link` **and immediately (no intervening syscalls) labels the new pin with `setxattr(security.bpf.shirudo, SHIRUDO_VERSION_ID)`** — same pin-then-label-no-gap rule as the bootstrap pins. **Every map the loader created is then auto-pinned** under `/var/lib/shirudo/bpffs/upatches/<name>/maps/<map_name>` (mkdir-on-first-hit, `BPF_OBJ_PIN` per map): shirudo walks `cx->map_descs[].map_fd` (populated by gen_loader from kernel context), `BPF_OBJ_GET_INFO_BY_FD`-resolves the map name, and pins each map under `maps/`. The pins are covered by the same `bpf2.c` `inode_unlink` / `seal.c` LSM hooks that protect the link pin, so a non-shirudo `rm` is denied; pin failures are best-effort and logged (the upatch already loaded successfully). Read-back is via `shirudo upatch map` (target-local) and `shirudo status --include-maps` / `shirudo nodes show --include-maps` (operator over SSH). The source `.upatch` is then copied into `/var/lib/shirudo/upatches/` (also xattr-labelled at creation), and the TPM2 NV chain is extended (see "TPM measurement and remote attestation"). `--report=<path>` (use `-` for stdout) emits a per-upatch JSON document covering `result`, `phase`, `errno`, `category`, the full kernel **verifier log** on rejection, and the chain state on success — see "Failure reporting for AI-driven rollouts" for the schema. Refuses UNLOAD directives (use `upatch unload`). Invoked automatically by `shirudo rollout` over the SSH exec channel; available standalone for operators who have hand-copied a `.upatch`. |
| `shirudo upatch unload <file.upatch> [--report=<path>] [--expect-chain=<hex>] [--expect-version-id=<hex>] [--no-precheck] [--no-version-check]` | Apply a signed UNLOAD directive. **Pre-flight check first** (same protocol as `upatch load`): the target's current chain value must match `--expect-chain=<hex>`, the LSM must be pinned, the keyring must be present — mismatch → `category: tampered`, refuse. On pass: parses the container, validates `flags & DIRECTIVE_UNLOAD != 0`, issues `BPF_PROG_LOAD` with the embedded unload-prog insns + signature + `keyring_id`. The kernel verifies the signature; on success, `BPF_PROG_TEST_RUN` invokes the unload directive, which (a) opens `/var/lib/shirudo/bpffs/upatches/<name>/link`, (b) confirms the currently-pinned link's owning upatch has the expected `payload_sha256` (refuses with `category: payload_mismatch` on disagreement — protects against an attacker who substituted a different upatch under the same name), (c) issues `BPF_LINK_DETACH` then `BPF_OBJ_UNPIN` from kernel context (LSM allows because `kernel == true`). On success shirudo also removes `/var/lib/shirudo/upatches/<name>.upatch`, extends the TPM2 NV chain with `SHA256("shirudo-unload\0" \|\| payload_sha256 \|\| upatch_name)`, and appends an `"type":"upatch_unload"` eventlog entry. **Userspace cleanup descends into `maps/` first**: every map pin under `/var/lib/shirudo/bpffs/upatches/<name>/maps/` is `unlink(2)`'d (dropping each map's refcount; the kernel reclaims when no other holder remains), the `maps/` dir is rmdir'd, then the link pin is unlinked and the top dir rmdir'd. Same order on every unload so the parent dir isn't holding a non-empty subdir. If the pin is already absent: no detach, no chain extend, no eventlog write, but `result: ok, category: already_unloaded` — idempotent. Refuses LOAD `.upatch` files. |
| `shirudo upatch list [--json]` | **Local-only, read-only — runs on either side, touches no kernel state.** Cross-references the persisted archive (`/var/lib/shirudo/upatches/*.upatch` — what survives reboot) against the live bpffs pins (`/var/lib/shirudo/bpffs/upatches/<name>/link` — what is currently loaded). For each persisted upatch prints loaded-or-not, `LOAD`/`UNLOAD-directive` type, and `payload_sha256`; and flags **orphans** — a live pin with no persisted `.upatch` behind it (loaded but will not survive reboot) — so drift in either direction is visible. `--json` emits `{"schema":1,"upatches":[{name,type,loaded,persisted,payload_sha256}]}`. |
| `shirudo upatch info <file.upatch> [--json]` | **Local-only inspection of a `.upatch` file** — runs on either side; touches no kernel state. Reads the file from disk, parses the v1 container header, validates magic/version/section bounds, verifies the CMS signature against the on-disk cert (if available), and prints a structured description: `name`, `flags` (LOAD / UNLOAD-directive), `payload_sha256`, `loader_insns` size, `signature` size and signer (CMS-extracted), `metadata` (build host, build timestamp, source path, `vmlinux.h` source if recorded), `log_buf_sz`, and the **signing cert's** fingerprint + validity dates. **The signer-cert validity field reports a separate question from `shirudo nodes`' cert-expiry warning**: `nodes` flags the *target keyring's* cert (what the target trusts); `upatch info` flags the *signer's* cert (extracted from the CMS blob — what was used to produce this artifact). Both should match for the artifact to load against the target, but they answer different questions and shirudo reports both. Output line `cert: 84d (warn)` on the signer if the same 12-month threshold from `cert.expiry_warn_days` is breached. Useful for AI agents debugging a `.upatch` that an earlier `shirudo build` produced, operators sanity-checking an artifact before `rollout`, and CVE-response audit trails ("did we sign the right thing?"). `--json` emits a single document with `"schema": 1`; default human output is a two-column key/value table. **Does not** require a kernel keyring, root, or a TPM — `shirudo upatch info` works on any host with the shirudo binary and the file. **Also dumps the full program source** — the entire `.bpf.c` the build embedded verbatim in the artifact's *extras* blob: a numbered `source` block in human output, and a `source` string (plus `source_file` and `has_source`) in `--json`. Unlike `shirudo upatch get`'s kernel `line_info` (which shows only the sparse instruction-tagged lines `clang -O2` recorded), this is the **complete** source — comments, blank lines, every statement. This source is the artifact's **own, unsigned/advisory** copy (the extras trail the signature-covered sections); the authoritative view of what is *actually loaded* is the kernel's, via `shirudo upatch get` on the target. Absent for artifacts built from a `.bpf.o` (no source to embed) or in the pre-extras format. |
| `shirudo upatch get <name> [--json]` | **Target-side, read-only.** Dump the BPF `line_info` (source) of a currently-loaded upatch, read **from the kernel**: resolve the pinned link at `/var/lib/shirudo/bpffs/upatches/<name>/link` → its program → the program's `line_info` + `btf_id` (preserved through the signed gen_loader at load), load that BTF, and print the source grouped by file. Uses only read-only `bpf()` cmds — `BPF_OBJ_GET`, `*_GET_FD_BY_ID`, `BPF_OBJ_GET_INFO_BY_FD` — all permitted by the LSM. Unlike `upatch info` (the file's own unsigned copy), this is **authoritative**: the BTF was loaded into the kernel by the signed loader. Prints `(no line info)` when the program was built without `clang -g`. |
| `shirudo upatch map [<upatch>] [<map>] [--json] [--show-full]` | **Target-side, read-only.** Inspect the contents of an upatch's pinned maps. Three forms: bare `map` lists every pinned map across every loaded upatch (one row per `(upatch, map, type, max_entries)`); `map <upatch>` lists maps for one upatch; `map <upatch> <map>` dumps the map's contents. Reads from `/var/lib/shirudo/bpffs/upatches/<name>/maps/<map_name>` via `BPF_OBJ_GET` → `BPF_MAP_LOOKUP_ELEM` / `BPF_MAP_GET_NEXT_KEY` (ARRAY/PERCPU_ARRAY iterate indices; HASH/PERCPU_HASH/LRU walk via next-key). All commands are read-only and on the LSM allow-list; no signing involved. BTF type-aware: when the build embedded `-g`, key/value type names are resolved via `btf__name_by_offset()` and primitive integer types print as native numeric values; unknown types fall back to a capped (32-byte) hex dump. **Per-CPU types** are read across every online CPU and the human render shows a `sum=` aggregate plus a per-CPU breakdown; the JSON `values_per_cpu[]` array preserves the per-CPU detail. **Default truncation cap** is `SHIRUDO_MAP_ENTRIES_DEFAULT = 256` entries per map (for HASH iteration; ARRAY is bounded by `max_entries` directly); `--show-full` lifts the cap. When truncated, the output (and JSON `truncated: true, n_truncated_at: 256`) tells the operator how many entries were elided. **Skipped map types** (RINGBUF, PERF_EVENT_ARRAY, STACK_TRACE, PROG_ARRAY) are listed with a `skipped: "use shirudo upatch <verb> (future work)"` marker so they remain discoverable without forcing the simple verb to grow into a generic event-stream consumer. The new verb auto-appears in `shirudo upatch --list-cmds` and tab-completion via the same machinery as the other leaves. |

### Read-only inspection — runs on either side

`status` and `keys` are pure observers and safe to run anywhere shirudo
exists. On a target they introspect kernel state (LSM link, kernel
keyring, pinned upatches); on the operator machine they fall back to
on-disk artifacts (cert, key, staged `.upatch` files). Both modes are
deliberate so operators can spot-check the operator machine's signing
material with the same command they use to inspect a fleet member.

| Subcommand | Purpose |
|---|---|
| `shirudo status [--json] [--include-tpm] [--include-system] [--include-eventlog] [--include-kernel-log] [--include-modules] [--include-maps] [--show-full]` | **Local-only**, two modes auto-detected. **Default ("terse") output** is the operator-health summary only: Host, Roles, Status verdict, Version-ID, the **Conditions** block (`LsmAttached` / `KeyringSealed` / `ChainIntact` / `TpmMeasured`, each `OK`/`WARN`/`ALERT`), a **Keyring** detail block showing live serial + pinned serial + match status, an **Upatches loaded** table, and the **Assets** inventory under `/var/lib/shirudo/` (`keys/cert.der`, `keys/signing_key.pem`, `keyring.serial`, `eventlog` (+ size), `upatches/` count, `incoming/` staged count, `bpffs/` mounted). The Conditions block is derived by the shared `util/conditions.c` (used identically by `shirudo nodes show` over SSH). Every other section is opt-in by a flag. **`--include-system`** adds a **System Info** block: OS, kernel release + version, architecture, CPUs, **Memory: `used/total`** (human units; `used = MemTotal - MemAvailable` from `/proc/meminfo`), **Disk: `used/total`** (root filesystem, `statvfs("/")`), uptime, hostname, machine-id, boot-id — all via `/proc`/`/etc`/`uname(2)`, no subprocess (`util/sysinfo.c`). **`--include-tpm`** reads the live NV chain value and replays the eventlog, emitting a `TPM Measurement` section + a `tpm` JSON object. **`--include-eventlog`** dumps the full eventlog as a `tpm.eventlog.events[]` array (and a compact `TIME/TYPE/DIGEST/DETAIL` table). **`--include-kernel-log`** reads the last 10 records from `/dev/kmsg` directly (`util/kmsg.c` — no `dmesg` subprocess), converts each monotonic-µs timestamp to ISO-8601 UTC, and emits a `kernel_log[]` JSON array + a `Kernel log (last 10 lines, newest first)` block in human output. **`--include-modules`** parses `/proc/modules`, `stat()`s each `/sys/module/<name>/` for its sysfs mtime (= kernel kobject creation time = load time), and emits a `modules[]` JSON array (each entry carries `name`/`size`/`refcount`/`loaded_at`/`since_boot_sec`/`deps[]`) plus a top-level `boot_at` (ISO UTC) so an operator can correlate against the eventlog without doing wallclock math. The human render shows a `Loaded modules (total N, last 10 loads, newest first)` list with `[ISO]  name (size, refs=K, T since boot)` rows; with `--show-full` it additionally expands a full dependency tree (`util/kmodules.c` — roots = modules nothing else uses, children = what they depend on, shared subtrees print once with `(shared)` markers). **`--include-maps`** reads every map pinned under `/var/lib/shirudo/bpffs/upatches/*/maps/`, dispatches by `bpf_map_info.type` to a per-type reader (ARRAY/PERCPU_ARRAY iterate indices; HASH/PERCPU_HASH walk via `BPF_MAP_GET_NEXT_KEY`), resolves BTF type names via `btf__name_by_offset()` when present, and emits a top-level `upatch_maps[]` JSON array (one entry per upatch carrying a `maps[]` of `{name, type, max_entries, n_entries, n_cpus?, truncated, n_truncated_at?, btf?, entries[]}` objects — additive next to the existing `upatches_loaded[]` so older parsers keep working). Per-map content is auto-truncated at `SHIRUDO_MAP_ENTRIES_DEFAULT = 256` entries; `--show-full` lifts that cap. The human render adds a `Maps:` subsection under each row of `Upatches loaded:`. RINGBUF/PERF_EVENT_ARRAY/STACK_TRACE/PROG_ARRAY are listed with `skipped: "use shirudo upatch <verb> (future work)"` so they remain discoverable without forcing the simple verb to grow. **`--show-full`** is the kitchen-sink switch: it implies every `--include-*` flag and also expands the modules dep tree. `--json` produces machine-readable output of whatever the flag set selects; all additions are backward-compatible (the `nodes` drift-table parse is unaffected). Always emits the local `SHIRUDO_VERSION_ID`. Safe to run before `init`. **On the operator side** (cert/key present, no LSM): the same surface; sections that have no data degrade to "absent". **Fleet/remote-query mode has moved to `shirudo nodes`** — `status` is now strictly local and does not take destination arguments. |
| `shirudo nodes [<name>...] [--filter=<glob>] [--selector=<expr>] [--json] [--include-tpm] [--expect-sequence=<file>] [--parallel=<N>]` | **Operator-only fleet observability**: queries every registered remote (or a subset, by explicit names or a glob filter) and renders an aggregate status table. Iterates over `$XDG_CONFIG_HOME/shirudo/remotes.d/*.conf` and `/etc/shirudo/remotes.d/*.conf`; for each remote, opens a libssh session and runs `shirudo status --json --include-tpm` on the target; aggregates results into a per-row drift table — name, host, reachable yes/no, LSM attached, keyring cert fingerprint, target `SHIRUDO_VERSION_ID`, NV chain value, count of loaded upatches, **cert validity remaining** (e.g. `cert: 8.2y` / `cert: 84d (warn)` / `cert: -3d (EXPIRED)`), drift label (`OK` / `CERT-DRIFT` / `CHAIN-DRIFT` / `VERSION-DRIFT` / `CERT-EXPIRING` / `CERT-EXPIRED` / `UNREACHABLE` / `INIT-INCOMPLETE`). Cert expiry is computed by `shirudo status` on the target from the cert in the kernel keyring (no clock sync between operator and target needed — each target reports its own view). Warning threshold: 12 months remaining → `CERT-EXPIRING` label and `pr_warn` log on both target and operator; 0 days remaining → `CERT-EXPIRED` (and operations against the target start failing with `category: signature_rejected` once the kernel rejects loads against the expired cert). The thresholds (12 months / 0 days) are compile-time constants in `util/cert.c`; rationale: shirudo's `genkey` ships 10-year certs, so 12 months is a comfortable rotation lead time without being noisy on healthy fleets. `--json` produces the same aggregate as a structured document for AI agents and automation. `--include-tpm` is on by default (operators almost always want chain state); `--no-include-tpm` skips for faster polling. `--filter=<glob>` selects a subset by **name** (e.g. `--filter=prod-*`); `--selector=<expr>` selects a subset by **label expression** (e.g. `--selector='shirudo.nodes.type=production && location=us-east-1'`, see the rollout row and the "Label selectors" subsection in Remote registry for the full grammar); positional `<name>` arguments select specific remotes by exact match (and must be registered). When multiple selectors are supplied (`--filter` AND `--selector`, or names AND `--selector`) they intersect — useful for "all production targets in the us-east region": `--selector='type=production' --filter='us-east-*'`. `--expect-sequence=<file>` pins the canonical event sequence for the fleet; targets whose eventlog tail doesn't match are labelled `SEQUENCE-DRIFT`. `--parallel=<N>` runs up to N SSH sessions concurrently (default 16); shirudo never `fork+exec`s ssh — concurrency is libssh-level only. The exit status is non-zero if any target drifts or is unreachable, so this fits naturally into operator scripts and CI checks. This is the canonical "what's the state of my fleet?" command; pair with `--expect-sequence` for "is my fleet where I expect it to be?" |
| `shirudo nodes show [--json] [--show-full] <name>...` | **Operator-only single-node deep dive** — the per-node describe companion to the fleet table. For each named (registered) remote it opens one libssh session and runs `shirudo status --json --include-tpm --include-system --include-eventlog --include-kernel-log --include-modules --include-maps` (every section in one round-trip), then renders a sectioned report aimed at security operators: identity (name, endpoint, role derived from `is_target`/`is_operator`, version-id) and the operator-local **labels**; a **Reachability** block (resolved IP, ICMP RTT or `off` if `nodes.icmp_probes = 0`, SSH state) and the same **Conditions** block as `shirudo status`; **Addresses**, **System Info** (now includes `Memory: used/total` and `Disk: used/total` in human units), **Upatches loaded** (each row optionally carrying an inline `Maps:` subsection — one line per pinned map showing `name  type  N/M entries  sum=<value>` when the target reported `entries[0].sum`; per-map detail is one ssh hop away via `shirudo upatch map <upatch> <map>` on the target), **TPM Measurement**, **Eventlog (audit trail)**, **Assets** (the `/var/lib/shirudo/` inventory mirrored from `status`), **Kernel log (last 10 lines, newest first)**, and a **Loaded modules (total N, last 10 loads, newest first)** list. By default the modules block shows just the 10 most recently loaded modules and a hint that `--show-full` is available; **`--show-full`** appends the complete dependency tree under a `Dependency tree:` heading. `--json` emits a stable `{ "schema": 1, "nodes": [ { name, endpoint, role, reachable, labels, conditions[], report{...} } ] }` document; the `report.system` carries `mem_total_kb`/`mem_avail_kb`/`disk_total_kb`/`disk_used_kb`; the `report.kernel_log[]` and `report.modules[]` arrays mirror the target's, with `boot_at` at top level so consumers can compute "since boot" without sysfs access; `report.assets` mirrors the on-disk inventory. The Conditions block and Status verdict come from the shared `util/conditions.c` so a single source of truth feeds both `shirudo status` (local) and `nodes show` (fetched). Unreachable or unparseable nodes degrade cleanly: the operator-local registry fields still render (human) or an `error` field is set (JSON), and no remote sections are shown. Labels and role are operator-side metadata; everything else is fetched live from the target. |
| `shirudo config` | **Local-only, read-only.** Print the effective shirudo configuration in `shirudo.conf` syntax (key = value lines with docstring comments). Defaults are applied first, then overridden by whatever the on-disk `/etc/shirudo/shirudo.conf` carries, then by env vars (`SHIRUDO_TPM_OWNER_AUTH` for the secret, `SHIRUDO_TPM_TCTI` for the TCTI string). The output is usable as a starting-point template (`shirudo config > /etc/shirudo/shirudo.conf`); the header comment identifies whether the file existed (`effective, loaded from ...`) or defaults are shown (`no .../shirudo.conf present`). The `tpm.owner_auth` secret is **always redacted** — printed as a comment line `(set, NN bytes; redacted; from <source>)` when present, `(unset)` when not. Source attribution distinguishes file vs env, so an operator can tell which layer is in play. |
| `shirudo version [--version-id]` | Print version information. Without flags: human-readable release name plus the architecture-stripped `SHIRUDO_VERSION_ID` (64-char hex). With `--version-id`: just the hex, suitable for shell substitution into other commands. Reads the compiled-in `shirudo_version_id` constant; no syscalls, no network. |
| `shirudo keys` | Local-only inspection of the key material this host holds, reporting **each side independently** (both can coexist on one host, since `cert.der` is held by the target as well as the operator — so this is *not* an either/or mode pick on cert presence). Reports the on-disk cert and, if present, the signing key with a cert-match check from `/var/lib/shirudo/keys/`; **and** lists the asymmetric keys in the `shirudo` named kernel keyring (descriptions, fingerprints) once `shirudo init` has populated one, via `keyctl_read`/`KEYCTL_DESCRIBE` — no `keyutils` dependency, direct `syscall(__NR_keyctl, ...)`. A pure operator shows only the on-disk section; a pure target shows the cert plus the keyring; a both-roles host shows everything. Output is the same describe-style as `shirudo nodes show`, with three sections (Cert / Signing key / Keyring); the Keyring section surfaces the live serial and the pinned serial alongside a `(matches)` / `(MISMATCH -- swapped?)` annotation so the same-named-keyring swap residual (TODO.kernel item 9) is visible at a glance. |

### Tooling — `--list-cmds` and the help system

Two pieces of CLI infrastructure exist so adding a (sub)command in
C does not require editing a separate completion script:

- **`--list-cmds`** prints bare names, one per line, to stdout —
  top-level (`shirudo --list-cmds`) or per sub-router
  (`shirudo upatch --list-cmds`, `shirudo remote --list-cmds`,
  `shirudo remote label --list-cmds`, `shirudo nodes --list-cmds`).
  Each sub-router walks its `shirudo_help_item[]` table via
  `shirudo_print_subcmd_list()` (`util/help.c`). Bash completion
  pulls these live; updating the C dispatch table is enough.
- **Per-leaf help structs** (`struct shirudo_help`) carry `usage`,
  `summary`, optional `sections` (options table), and an
  `Examples:` footer. `shirudo_print_help()` word-wraps every
  item summary to a 90-col target with continuation lines
  aligned under the summary column, so adding a long flag
  description does not produce a 132-char wide line. Triggered
  on any of `help` / `--help` / `-h`, and also when a leaf is
  invoked with missing required positional args (no terse
  "usage: ..." one-liners left).

## Remote registry

`rollout` and `status` target the same hosts repeatedly; re-typing
`user@host:port` is error-prone, especially when AI agents drive
rollouts (they would re-derive the wrong string half the time). The
**remote registry** stores routing metadata on the operator machine —
git's `remote add` ergonomic — so the agent (or human) can reference
targets by name.

### Storage

One file per remote, drop-in style (systemd-style, no INI parser
needed):

- Per-user (default): `$XDG_CONFIG_HOME/shirudo/remotes.d/<name>.conf`
  — typically `~/.config/shirudo/remotes.d/<name>.conf`; the XDG
  fallback is `~/.config` when `$XDG_CONFIG_HOME` is unset.
- System-wide (with `--system`): `/etc/shirudo/remotes.d/<name>.conf`
  — for shared operator hosts.

### File format

`key = value` per line, `#` for comments, UTF-8. Required keys:

```
# ~/.config/shirudo/remotes.d/prod-fleet-a.conf
host = target-a.prod.example.com
user = root
port = 22
```

Optional keys (forward-compatible — unknown keys log a `LOG_DEBUG`
line and are ignored, not a parse error):

```
expect_sequence       = /home/op/.config/shirudo/expect/prod.upatches
identity_file         = ~/.ssh/id_ed25519_shirudo_prod
sudo                  = yes        # prefix remote commands with "sudo -n"

# Labels — key=value, repeatable, used by
# --selector expressions on rollout/nodes. Each label is
# its own line, prefixed `label.` and then the label key.
label.shirudo.nodes.type     = production
label.shirudo.nodes.location = us-east-1
label.shirudo.nodes.role     = database
label.team                   = platform
```

Defaults: `port = 22`, `sudo = no`, identity from ssh-agent /
default keys, no labels. The TPM NV index is a target-local
compile-time setting (see "TPM measurement and remote
attestation") and does not appear in the operator-side remote
config. `.conf` files are not C/H/shell/Make and therefore not
covered by the SPDX requirement; the file format is plain
configuration data, not code.

### Label selectors

`shirudo rollout` and `shirudo nodes` all
accept `--selector=<expr>` to select a subset of the registered
remote set by label expression. The grammar is small and
Kubernetes-flavoured:

```
expr   := term ('||' term)*
term   := atom ('&&' atom)*
atom   := key '=' value             # has this exact value
        | key '!=' value            # has a different value (key must exist)
        | key                       # has this label, any value
        | '!' key                   # does not have this label
        | '(' expr ')'              # grouping
```

Precedence: `&&` (AND) binds tighter than `||` (OR), as in C.
Whitespace around operators is permitted but not required. Keys
may contain `[A-Za-z0-9._-/]`; values are alphanumeric +
`_-.`. Quoting is not required for typical label values; for
unusual values use single quotes.

Examples:

```
shirudo rollout foo.upatch --selector='shirudo.nodes.type=production'
shirudo rollout foo.upatch --selector='type=staging && location=dallas'
shirudo rollout foo.unload.upatch \
    --selector='(role=database || role=cache) && env!=staging'
shirudo nodes --selector='!shirudo.nodes.maintenance'  # only nodes
                                                      # without a
                                                      # maintenance label
```

Empty result set is an error (`selector matched zero registered
remotes`) — the caller should know whether their selector is
expected to match. Selector parser and evaluator live in
`util/selector.{c,h}` (~150 LOC; recursive-descent parser, no
external library).

**Labels are operator-side metadata only.** They are not signed,
not synchronised to targets, not part of any security boundary.
A compromise of the operator's remotes.d/ files could let an
attacker change which set of targets `--selector=type=production`
expands to — but compromising those files also compromises the
operator's host, at which point the signing key is the much
bigger problem. Labels are an audit/operational-ergonomics layer,
not a trust layer.

### Lookup precedence

A destination argument to `rollout`/`nodes` resolves
**by name only** — there is no literal `user@host[:port]`
fallback. The resolver:

1. Searches `$XDG_CONFIG_HOME/shirudo/remotes.d/<arg>.conf` for
   a per-user entry.
2. If not found, searches `/etc/shirudo/remotes.d/<arg>.conf`
   for a system-wide entry.
3. If still not found, errors: `remote "<arg>" is not registered.
   Run \`shirudo remote add <arg> <user@host[:port]>\` first.`

**Strings containing `@` are not accepted** as destinations —
the resolver rejects them with the same "register first"
error. This is deliberate: forcing every state-changing operation
through the registered remote set gives `shirudo nodes` complete
coverage of the fleet by construction, makes audit trails
straightforward (every rollout in the journal references a
known name), and eliminates the fat-finger class of "I typed
the wrong hostname into a `shirudo rollout` command at 2am"
incidents. The friction is one extra `shirudo remote add` call
the first time a target is touched.

### Commands

- `shirudo remote add <name> <user@host[:port]> [--port N] [--user U] [--system] [--label k=v ...]`
- `shirudo remote list [--json] [--filter=<glob>] [--selector=<expr>]`
  *(also the default form when no subcommand is given)*
- `shirudo remote show <name>` — describe one registered remote
  (endpoint, labels, registration timestamp, age, conf path).
- `shirudo remote rm <name>`
- `shirudo remote rename <old> <new>`
- `shirudo remote label add { <name> | --filter=<glob> | --selector=<expr> } <k=v>...`
  — set/update labels (strict key→value; overwrite on collision).
- `shirudo remote label rm { <name> | --filter=<glob> | --selector=<expr> } <key>...`
  — remove labels by key (missing keys are warnings, not errors).
- `shirudo remote label clear { <name> | --filter=<glob> | --selector=<expr> }`
  — remove every label (endpoint, user, port, `created =` are preserved).

### No daemon state, no cache, no secrets

The registry contains no keys, no passwords, no host-key
fingerprints. Host-key verification still goes through
`~/.ssh/known_hosts`; authentication still through ssh-agent and
on-disk SSH keys. Compromising the registry lets an attacker
mis-route a `rollout` to a different (still ssh-authorised) host —
they cannot exfiltrate keys, and the target's BPF signature check
still rejects unsigned upatches.

### AI-agent ergonomics

`shirudo remote list --json` emits:

```json
{
  "remotes": [
    {"name":"prod-a","host":"target-a.prod","user":"root",
     "port":22,"source":"user"},
    {"name":"staging","host":"staging","user":"ops",
     "port":2222,"source":"system"}
  ]
}
```

…so an AI agent iterates over names rather than parsing
human-readable output. `source` is `"user"` or `"system"` depending
on which directory the file came from.

## Site config — `/etc/shirudo/shirudo.conf`

A single optional configuration file at `/etc/shirudo/shirudo.conf`
holds **site-wide, target-local** knobs that operators may want to
tune without recompiling shirudo. The file is **target-side** (it
configures runtime behaviour on a target) and **operator-side** (it
configures local CLI behaviour on an operator host); each key
specifies which side it applies to. The format is the same
`key = value` syntax as the remote registry — no parsing library
needed (see `util/conf.{c,h}`, ~80 LOC).

The file is **optional**: shirudo functions fully with compile-time
defaults if it does not exist. Settings here override compile-time
defaults; CLI flags override both.

```
# /etc/shirudo/shirudo.conf -- shirudo site configuration.
# All keys are optional; defaults shown.

# === Target-side keys ===

# Index for the NV-extend chain. Owner-defined NV range
# (0x01800000..0x01bfffff). Change only if 0x01818E00 collides with
# another tool on this platform; see PLAN.md "TPM measurement".
# Type: 32-bit hex. Default: 0x01818E00.
tpm.nv_index = 0x01818E00

# Owner (storage) hierarchy authorization, used only to *define* the
# NV index (DefineSpace for an owner-range index is authorised by the
# owner hierarchy). Needed on TPMs whose owner auth is set (many cloud
# vTPMs and any TPM a prior tool has taken ownership of); leave empty
# for a fresh TPM, swtpm, or most VMs. If the owner auth is set and not
# supplied here, `shirudo init` cannot create the index and degrades to
# unmeasured mode with a `tpm: ... owner-hierarchy authorization
# failed` diagnostic. A literal passphrase, or "hex:<even-hex>" for a
# binary auth value. The env var SHIRUDO_TPM_OWNER_AUTH overrides this
# (handy for not persisting the secret to disk). The per-index auth
# (read/extend) is always the derived value and is NOT this key.
# Type: string | hex:<hex> | empty. Default: empty.
tpm.owner_auth =

# TCTI string consumed by util/tpm.c. Empty (default) means
# `device:/dev/tpmrm0`, i.e. the kernel TPM resource manager.
# A non-empty value (e.g. `swtpm:host=127.0.0.1,port=2321`)
# redirects to a software TPM emulator for dev/CI without real
# hardware -- the pre-flight skips the `/dev/tpmrm0` access
# check when this is set, and util/tpm.c hands the string to
# Tss2_TctiLdr_Initialize directly. Override is dev-only: the
# operator-side chain expectation still rejects values a fake
# TPM produces, so a malicious target swapping in a controlled
# swtpm cannot manufacture a "matches" verdict against a real
# operator-pinned --expect-chain. The SHIRUDO_TPM_TCTI env var
# overrides this key in turn; see Documentation/getting-
# started.rst "TPM in development" for a worked recipe.
# Type: string | empty. Default: empty.
tpm.tcti =

# Verifier log buffer size, in bytes, allocated inside the in-kernel
# signed loader for every upatch load. Larger values capture larger
# verifier rejections without truncation; cost is one allocation
# per load. See PLAN.md "Failure reporting -- truncation marker".
# Type: positive integer; min 65536, max 16777216. Default: 1048576.
verifier.log_buf_bytes = 1048576

# Soft cap on the on-disk eventlog. When the file would exceed this
# size, shirudo **refuses the state-changing operation entirely** --
# no BPF_PROG_LOAD, no NV_Extend, no eventlog append. The chain and
# the eventlog stay synchronised by construction: an extension that
# cannot be logged is not performed. Failure category:
# `eventlog_full`. The operator's remediation is to rotate the
# eventlog out of band (cp it to long-term storage, truncate the
# in-place file under shirudo's own xattr-sealed permissions via
# `shirudo eventlog rotate` -- deferred subcommand) and retry.
# Type: positive integer. Default: 0 (unlimited; recommended -- the
# eventlog is small in practice, one JSON line per state transition).
eventlog.max_bytes = 0

# Whether shirudo init re-mounts /var/lib/shirudo/bpffs/ if found
# mounted but with non-strict options. Set to "no" to inherit the
# existing mount unchanged (rare; mainly for embedded targets with
# read-only roots that mount bpffs from initramfs).
# Type: yes | no. Default: yes.
bpffs.remount_if_lax = yes

# === Operator-side keys ===

# Default --parallel value for `shirudo nodes` and `shirudo rollout`
# when not given on the CLI. Higher values fan out faster at the
# cost of more concurrent libssh sessions. Type: positive integer.
# Default: 16.
fleet.parallel = 16

# `shirudo nodes` ICMP probe budget per target. Best-effort
# unprivileged dgram ICMP (no CAP_NET_RAW; operator gid must be
# in net.ipv4.ping_group_range) -- the drift table still renders
# (with PING = n/a) when the probe is blocked. Set
# nodes.icmp_probes = 0 to disable ICMP entirely (no socket
# opened, PING column shows `off`, `shirudo nodes show` renders
# `ICMP: off (disabled in shirudo.conf: nodes.icmp_probes = 0)`);
# JSON consumers see `icmp.disabled: true` to distinguish from a
# probe failure. Type: 0..16. Default: 1.
nodes.icmp_probes = 1

# Per-probe timeout in milliseconds. Default: 1000.
nodes.icmp_timeout_ms = 1000

# Default report path template for rollout when --report
# is not given on the CLI. The literal token "{rollout_id}" is
# substituted with the UUID shirudo generated; "{ts}" is the
# RFC 3339 timestamp. Empty string disables auto-report.
# Type: filesystem path or empty. Default: "" (no auto-report).
rollout.auto_report = ""

# === Either-side keys ===

# Cert-expiry warning threshold, in days. shirudo nodes / status
# flag any cert with fewer than this many days remaining as
# CERT-EXPIRING. Type: positive integer. Default: 365.
cert.expiry_warn_days = 365
```

**Lookup precedence**: CLI flag → `/etc/shirudo/shirudo.conf` →
compile-time default. There is **no per-user config file** for
`shirudo.conf` settings — the registry already covers operator
per-user state, and target-side knobs are deliberately host-wide.

**Format invariants** (enforced by `util/conf.c`):

1. UTF-8, `#` for comments to end-of-line.
2. Unknown keys log `LOG_DEBUG` and are ignored (forward-compatible).
3. Out-of-range numeric values are a **fatal parse error** — shirudo
   refuses to start, so silent off-by-one defaults can never sneak
   in.
4. The file is read at most once per shirudo invocation; mutation
   while shirudo is running has no effect on the current process.
5. Mode must be `0644` or stricter (`0600`), owner root. The
   pre-flight check enforces this — laxer permissions are a fatal
   error.

The `.conf` file is not C/H/shell/Make and is therefore **not**
covered by the SPDX header requirement (see "Source file headers").
It is plain configuration data, not code. The default
`/etc/shirudo/shirudo.conf` shipped with the operator and target
packages is the example above, with every line commented out — so
the file documents itself and operators uncomment the keys they
want to override.

## `.upatch` artifact format

A `.upatch` is the portable, signed unit produced on the operator machine
and consumed on the target. It must contain everything `BPF_PROG_LOAD` needs for a
signed loader prog plus enough metadata to re-issue the call on a different
machine. Layout (little-endian throughout):

```
offset  size            field
0       8               magic           = "SHIRUDO\0"
8       4               version         = 1
12      4               flags           (bit 0 = DIRECTIVE_UNLOAD; other bits reserved)
16      32              payload_sha256  (SHA-256 of payload — see notes below)
48      8               loader_insns_off
56      8               loader_insns_sz
64      8               loader_data_off
72      8               loader_data_sz
80      8               signature_off
88      8               signature_sz
96      8               metadata_off
104     8               metadata_sz
112     8               log_buf_off
120     8               log_buf_sz      (typically 1 MiB)
128     ...             <sections, in any order, referenced by offsets above>
```

- **flags**: bit 0 is `DIRECTIVE_UNLOAD` — when set, the artifact is a
  signed unload directive instead of a load. Bits 1–31 are reserved and
  must be zero. The bit changes the semantics of `loader_insns` and
  `payload_sha256` (see below) but nothing about the container layout,
  signature path, or kernel verification — both directive types go
  through the same `BPF_PROG_LOAD + signature + keyring_id` check.
- **loader_insns / loader_data**: the bytes from `gen_loader_opts.insns` /
  `gen_loader_opts.data` after `bpf_object__gen_loader()` + `bpf_object__load()`
  on the operator machine. The loader is parameterized by `data`, so both must
  travel together. For UNLOAD directives, `loader_insns` is not a gen_loader
  output but the compiled bytes of a small hand-written SYSCALL-type BPF
  program that opens the pin at `/var/lib/shirudo/bpffs/upatches/<name>/link`,
  verifies the loaded upatch's payload digest, and issues `BPF_LINK_DETACH`
  + `BPF_OBJ_UNPIN` from kernel context. `loader_data` carries the expected
  `payload_sha256` and the embedded name. Source lives at `bpf/unload.bpf.c`.
- **signature**: CMS/PKCS#7 detached signature over `loader_insns`, produced by
  the same code path bpftool uses (`tools/bpf/bpftool/sign.c`).
- **payload_sha256**: For LOAD directives, SHA-256 of the original payload
  BPF — matches what the loader carries internally as `excl_prog_hash`.
  For UNLOAD directives, the *expected* `payload_sha256` of the loaded
  upatch the directive intends to remove; the target refuses to detach if
  the actually-loaded upatch under that name has a different digest.
  In both cases this lets `shirudo upatch list` and `shirudo status`
  identify upatches without parsing the instruction stream.
- **metadata** (TLV): name, version string, build host, build timestamp, target
  LSM hook name (informational; not security-relevant). UTF-8, length-prefixed
  records.
- **extras (embedded C source)**: an optional trailing blob (header
  `struct shirudo_upatch_extras` = magic + `format` + `name_len` +
  `source_len`, then the source path string, then the verbatim `.bpf.c`
  source bytes), pointed to by the header `extra_off` field — the slot
  that was `reserved` in the original layout, so this is **additive and
  backward-compatible**: a reader that predates it sees `extra_off == 0`
  and ignores the trailing bytes, and the extras follow every
  signature-covered section. For a `.bpf.c` input `shirudo build` embeds
  the full source so `shirudo upatch info` can print the **complete**
  program offline (comments and all) — not just the sparse
  instruction-tagged `line_info` lines. The extras are **not
  signature-covered** — informational only; the authoritative view of
  what is loaded is the kernel's `line_info` (the signed loader installs
  the BTF), surfaced by `shirudo upatch get`.
- **log_buf**: a zero-initialised region (typically 1 MiB) that the
  in-kernel signed loader treats as `log_buf` for the inner
  `BPF_PROG_LOAD`. After `BPF_PROG_TEST_RUN`, userspace reads this region
  back and surfaces its contents as the `verifier_log` field of the
  JSON failure report (see "Failure reporting for AI-driven rollouts").
  Not covered by the signature — `loader_insns` is the only signed
  section. The `log_buf` region is loader-owned scratch; tampering with
  it changes only the report, not behavior.

The format is intentionally trivial — no encryption, no compression. Integrity
is provided entirely by the kernel's PKCS#7 verification of `loader_insns`
against the target's `shirudo` keyring; tampering with any other section either
breaks parsing or causes the loader's runtime `excl_prog_hash` check to fail.

A header file `include/shirudo/upatch.h` defines the on-disk layout for both
sides.

## `rollout` flow

`shirudo rollout file1.upatch file2.upatch prod-a prod-b` (where
`prod-a` and `prod-b` are registered remote names — see the
"Remote registry" section's lookup precedence), performed
entirely via libssh — no `fork`, no `execve`, no subprocesses:

1. Validate each input file's `.upatch` magic/version locally so we fail
   fast before touching the network.
2. Per target, open a libssh session: `ssh_new()`, `ssh_options_set()` for
   `SSH_OPTIONS_HOST` / `SSH_OPTIONS_USER` / `SSH_OPTIONS_PORT` /
   `SSH_OPTIONS_KNOWNHOSTS`, then `ssh_connect()`.
3. Verify the host key against `~/.ssh/known_hosts` with
   `ssh_session_is_known_server()`. Refuse the connection on
   `SSH_KNOWN_HOSTS_UNKNOWN`, `SSH_KNOWN_HOSTS_CHANGED`, or
   `SSH_KNOWN_HOSTS_ERROR`. There is no trust-on-first-use mode — the
   operator must `ssh-keyscan` the host into `known_hosts` first, just
   like for any other production tooling.
4. Authenticate: try `ssh_userauth_agent()` first; on failure fall back to
   `ssh_userauth_publickey_auto()` (default on-disk keys). Password and
   keyboard-interactive auth are deliberately not attempted — fleet
   automation is expected to be key-based.
5. Open an SFTP subchannel: `sftp_new()` + `sftp_init()`. Ensure
   `/var/lib/shirudo/incoming/` exists via `sftp_mkdir()` (ignore
   `SSH_FX_FILE_ALREADY_EXISTS`). For each upatch, `sftp_open()` with
   `O_WRONLY|O_CREAT|O_TRUNC` and mode `0600`, stream the bytes via
   `sftp_write()` in chunks, `sftp_close()`. Verify the remote size
   matches the local size before proceeding.
6. **Pre-status the target for chain and version observation**
   (unless both `--expect-chain=<hex>` and `--expect-version-id=<hex>`
   were supplied explicitly, or `--no-precheck` was passed). Open an
   exec channel, run `shirudo status --json --include-tpm`, capture
   the target's current NV chain value and `version_id` from the
   JSON. Close the channel. Both values are threaded through as
   `--expect-chain=` and `--expect-version-id=` on the next step.
   The operator's own `SHIRUDO_VERSION_ID` is the value used for the
   version check (unless `--expect-version-id` is supplied
   explicitly to override it).
7. For each pushed file, open a fresh exec channel: `ssh_channel_new()`,
   `ssh_channel_open_session()`, `ssh_channel_request_exec()` with the
   command `shirudo upatch load --expect-chain=<captured>
   --expect-version-id=<operator-version-id>
   /var/lib/shirudo/incoming/fileN.upatch` (prefixed with `sudo -n`
   iff `--sudo` was passed). Drain stdout and
   stderr via `ssh_channel_read()` / `ssh_channel_read_stderr()` until the
   far end half-closes, then capture exit status with
   `ssh_channel_get_exit_status()`. Quote the command via a small
   argv-style serializer (`shell_quote()` in `util/ssh.c`) — never paste
   user-controlled strings raw into the command, even though everything
   on the operator side is already trusted.
8. Tear down deterministically: `ssh_channel_send_eof` +
   `ssh_channel_close` + `ssh_channel_free` per channel, `sftp_free`,
   `ssh_disconnect`, `ssh_free`. All libssh errors propagate to the
   caller via shirudo's normal `pr_err()` + non-zero return; no leaked
   sessions, no orphaned fds.
9. Report a per-target summary; non-zero exit if any upatch failed to load
   on any target (a `tampered` category fails the same way — and is the
   signal operators should investigate first, not retry). Remote
   `stderr` snippets are surfaced verbatim so the operator sees the same
   message that landed in `journalctl -t shirudo` on the target.

Authentication material — keys, ssh-agent socket, `~/.ssh/known_hosts` —
is read by libssh from the operator's home directory; shirudo never invokes
`ssh-keygen` or `ssh-add`, never prompts for passwords, and never touches
private SSH material directly.

`rollout` has no special privileges on the operator machine — it is just a
libssh client. This keeps the trust boundary clear: the operator machine
signs; the target verifies cryptographically.

## Removal flow (a rollout of an UNLOAD directive)

There is no separate `rollback` verb. `shirudo rollout
file1.unload.upatch prod-a prod-b` is the same command as any rollout —
same libssh session setup, `known_hosts` verification, ssh-agent auth,
SFTP push to `/var/lib/shirudo/incoming/`, exec channel for the apply
step. The file's `DIRECTIVE_UNLOAD` flag is what differs:

1. Operator-side: rollout reads each `.upatch`'s flag and chooses the
   remote verb — `upatch load` for a LOAD artifact, `upatch unload`
   for an UNLOAD directive. A batch may mix the two. (The artifact is
   self-describing, so there is nothing to "match" against a verb and
   nothing to fat-finger.)
2. Target-side: `shirudo upatch unload` runs over the SSH exec
   channel. The **pre-flight checks run first** (`--expect-chain` —
   auto-derived from a pre-status or passed explicitly — must match
   the current NV chain; the LSM must be pinned; the keyring must be
   present). On mismatch → `category: tampered`, refuse. On pass: the
   kernel verifies the directive's signature against the `shirudo`
   keyring (the authorization gate). The detach itself happens in
   **userspace**, not in the signed BPF: the kernel's `bpf_sys_bpf()`
   cannot `BPF_LINK_DETACH`/`OBJ_GET`/`OBJ_PIN` (`TODO.kernel` #6), so
   shirudo VFS-unlinks the named pin under
   `/var/lib/shirudo/bpffs/upatches/<name>/` (the refcount drop
   detaches the program), permitted because bpf2's `inode_unlink`
   recognises shirudo's own `exe_file` identity and denies every
   other caller.
3. On success: `/var/lib/shirudo/upatches/<name>.upatch` is removed
   (so boot-restore won't re-apply it), the NV chain extends with the
   unload digest, and a `"type":"upatch_unload"` eventlog entry is
   appended.

The per-target aggregate report uses the same JSON schema as any
rollout. Operators (or AI agents) driving a recovery interleave load
and unload rollouts freely; the TPM chain records each as forward
progress, so the resulting chain value uniquely identifies the full
ordered history of state changes over the machine's lifetime.

Idempotency: a rollout of an UNLOAD directive for an already-unloaded
upatch is a no-op on the target (`result: ok, category:
already_unloaded`, **no chain extend**, no eventlog entry). The chain
only records actual state transitions; an unload that finds nothing to
remove adds nothing to the chain. This matters for the replay
invariant — the eventlog tail (since the last `shirudo-init` event)
and the chain must agree on what happened, and a no-op unload genuinely
did not happen.

### How `payload_sha256` is verified at unload

The unload directive's `payload_mismatch` check is the property
that protects against an attacker who managed to substitute a
different signed upatch under the same name. The ground truth for
"what is currently loaded under name X" is a **bpffs extended
attribute on the pin directory**, not a BPF map. Concretely:

- At every successful `shirudo upatch load`, **after** the program
  is attached and its link pinned, target-side shirudo records the
  loaded upatch's 32-byte `payload_sha256` (the SHA-256 of the
  signed `loader_insns`, the same value in the eventlog) as the
  `security.bpf.shirudo.payload` xattr on the pin directory
  `/var/lib/shirudo/bpffs/upatches/<name>/`. It is written last, so
  the recorded value always reflects an actually-loaded upatch and
  there is no rollback window if a step fails.
- The value is **authentic without an in-kernel write**: the kernel
  already verified, at the signature-gated `BPF_PROG_LOAD`, that the
  loaded loader's hash equals `payload_sha256` (the `excl_prog_hash`
  binding on `__loader.map`). So the header value userspace writes is
  cryptographically bound to what ran.
- The value is **immutable / unforgeable** via the bpf2
  `lsm/inode_setxattr` and `lsm/inode_removexattr` hooks: scoped to
  shirudo's private bpffs superblock and gated on the same exe
  identity as `inode_unlink`, they let only shirudo's own executable
  set or remove xattrs there. A root attacker who substitutes a
  different upatch under name X cannot also rewrite the xattr to lie
  (the substitute's own load already wrote the substitute's payload,
  and the attacker cannot overwrite it). Replacing the pin directory
  is likewise blocked (`inode_unlink`).
- `shirudo upatch unload` reads the xattr with `getxattr` and
  constant-time compares it against the directive's expected payload.
  Match → proceed to detach (userspace VFS-unlink of the pin, per
  TODO.kernel item 6). Mismatch → refuse with
  `category: payload_mismatch`, detaching nothing. The check is
  skipped (warning; detach proceeds) when the directive carries no
  expected payload or the xattr is unavailable.
- **Residual.** The *stored* value is unforgeable (excl_prog_hash +
  bpf2 setxattr guard), but the *expected* value the userspace compare
  uses comes from the directive's metadata, which — like the target
  name — is not signature-covered (TODO.kernel item 6). So a root
  attacker who edits the unsigned metadata can realign the two. The
  same value is also baked into the signed unload program's `.rodata`
  (signature-covered); moving the comparison into that in-kernel BPF
  (which needs the `bpf_sys_bpf` detach ops) is what closes the gap.
  Until then `payload_mismatch` reliably catches honest/accidental
  substitution and any non-tampering path.

`BPF_PROG_GET_INFO_BY_FD.tag` is an 8-byte truncated SHA-1 of program
instructions, not a SHA-256 of the upatch payload, and would not match
the directive's expectation — the pin-directory xattr exists precisely
to bridge that gap.

The xattr is **per-boot ephemeral** (bpffs is RAM-backed; xattrs are
held in an in-memory `simple_xattrs` store and vanish with the mount)
and is re-set by `shirudo init`'s boot-restore step from
`/var/lib/shirudo/upatches/` through the same load path, before the
single boot-restore chain extension. The restored set is what becomes
`set_digest`.

**Kernel/libbpf prerequisites.** This rests on the bpffs-xattr kernel
patch (TODO.kernel item 7); without it `setxattr`/`getxattr` on bpffs
return `-EOPNOTSUPP` and the check degrades to *unavailable* (the load
and unload still work, the comparison is skipped) — never *wrong*. The
originally-planned single shared, frozen `upatches_registry` BPF map
written by signed in-kernel BPF was abandoned because a frozen map
cannot grow per-load (freeze is one-way) and a signed gen_loader'd
program cannot bind a shared pre-pinned map in its signable
instruction stream (TODO.kernel item 8); the xattr-on-pin delivers the
same guarantee, co-located with the object it describes, on a stock
libbpf.

## Failure reporting for AI-driven rollouts

BPF upatches are produced by AI agents that iterate against the kernel
verifier — write some BPF, sign it, push it, read the rejection, fix the
source, repeat. The rollout path is therefore *the* hot loop for an AI
agent, and the failure message has to be in a form the agent can parse
and condition on. Stderr scraping is too fragile; stderr stays for human
progress; structured JSON goes to stdout (or a file) via `--report=`.

### `shirudo upatch load --report=<path>` (target-side)

Emits a single JSON document for both success and failure. `<path>` may
be `-` for stdout. Schema:

```json
{
  "schema":   1,
  "result":   "ok" | "failed",
  "phase":    "pre_flight" | "parse" | "signed_loader_load"
            | "payload_load" | "link_create" | "pin" | "tpm_extend",
  "errno":    <int or null>,
  "errno_name": "EKEYREJECTED",
  "category": "lsm_denied" | "signature_rejected"
            | "keyring_missing" | "verifier_rejected"
            | "btf_mismatch" | "attach_target_missing"
            | "parser_rejected" | "tpm_error" | "tampered"
            | "version_mismatch" | "init_incomplete"
            | "init_prereqs_missing"
            | "already_unloaded" | "payload_mismatch"
            | "detach_failed" | "eventlog_full" | "unknown",
  "message":  "<human one-liner>",
  "verifier_log": "<verbatim, up to 1 MiB>",
  "loader_return": <int>,
  "upatch": {
    "path": "...", "name": "...", "payload_sha256": "<hex>",
    "build_host": "...", "build_timestamp": "..."
  },
  "kernel": {
    "release":    "...",
    "lsm_active": ["...", "bpf"]
  },
  "tpm": {                          /* success only; null if no TPM */
    "nv_index":    "0x01818E00",    /* configurable via SHIRUDO_NV_INDEX */
    "chain_after": "<hex>"          /* 32 bytes hex, post-extend */
  },
  "journal_excerpt": ["..."],       /* shirudo events for this load (deferred) */
  "dmesg_excerpt":   ["..."]        /* /dev/kmsg replay (deferred) */
}
```

The **verifier log is the load-bearing field for AI iteration**. shirudo
allocates a 1 MiB `log_buf` region inside the in-kernel signed loader's
`loader_data` (see the `.upatch` format extension), and the in-kernel
loader writes the inner `BPF_PROG_LOAD`'s verifier output there.
Userspace reads the region back after `BPF_PROG_TEST_RUN` and copies it
verbatim into the report's `verifier_log`. For failures that happen
*before* the inner load (LSM denial, signature rejection), the log is
empty — and `category` is what tells the agent it's a policy problem,
not a code problem.

**`verifier_log` is BPF-author-controlled text.** The verifier
emits disassembly, line-number references, and symbol/structure
names taken from the BPF program's debug info — content the BPF
author chooses. AI agents reading the log to iterate on source
should treat it the same way they treat compiler output from
third-party code: untrusted text inside an untrusted-text wrapper.
shirudo escapes the field for JSON safety; downstream prompt-
injection defence (system-prompt isolation, structured output
constraints) is the agent pipeline's responsibility. See
`Documentation/threat-model.rst` §"Residual risks summary" #15.

**Truncation marker.** The kernel verifier fills the `log_buf` up to
its capacity and then truncates without warning; very large rejected
programs routinely overflow 1 MiB. When shirudo detects truncation
(the kernel sets `EFAULT` on overflow, or the buffer is byte-exact
full with no `\0` terminator inside the last 16 bytes), the report
**appends a sentinel line** to `verifier_log`:

```
\n... (verifier_log truncated at 1 MiB; rebuild with --extra-cflags='-DSHIRUDO_LOG_BUF=4194304' to raise)
```

The sentinel is appended **after** the truncated content so AI agents
can detect truncation by string-matching the literal `"verifier_log
truncated at "` prefix without parsing kernel verifier syntax. The
`.upatch` header's `log_buf_sz` field records the actual buffer size
the build used; agents can read it back via `shirudo upatch info` to
decide whether to rebuild with a larger buffer. Sentinel text is
**not** subject to log-injection sanitisation (it is shirudo-emitted,
not attacker-controlled) but contains no shell metacharacters and is
safe for JSON encoding.

### `category` taxonomy — the agent's decision input

| `category` | Phase | errno | Agent action |
|---|---|---|---|
| `verifier_rejected` | `payload_load` | EINVAL/EACCES/EFAULT with verifier text in log | Read `verifier_log`, fix the BPF source, re-sign, retry. |
| `btf_mismatch` | `payload_load` | EINVAL with BTF text in log | Regenerate `vmlinux.h` on the operator, rebuild, retry. |
| `attach_target_missing` | `link_create` | ENOENT | Named hook/symbol does not exist on this target's kernel. Pick another or pin a kernel version. |
| `signature_rejected` | `signed_loader_load` | EKEYREJECTED | Target trusts a different signing key. **Not a BPF problem** — surface to a human. |
| `keyring_missing` | `signed_loader_load` | ENOKEY | Target has not been `shirudo init`-ed. Surface to a human. |
| `lsm_denied` | any | EACCES (no verifier text) | shirudo LSM rejected; upatch is misformed or policy has a bug. Surface to a human. |
| `parser_rejected` | `parse` | — | Malformed `.upatch` before the kernel ever saw it; operator-side build bug. Agent re-runs `shirudo build`. |
| `tpm_error` | `tpm_extend` | — | BPF loaded fine, NV chain is now out of sync with on-target reality. Surface to a human (see "TPM measurement"). |
| `version_mismatch` | `pre_flight` | `EPERM` | Operator's `SHIRUDO_VERSION_ID` does not match the target's. Either the operator binary was upgraded and the target wasn't (or vice versa), or the operator is pointing a development build at a production target. **Hard stop** — no fleet operation should proceed across a version skew, even though the affected components might happen to be compatible. Re-deploy a matching shirudo binary to either side, or override with `--no-version-check` (logged at `LOG_WARNING`). |
| `tampered` | `pre_flight` | `EPERM` | Target's pre-flight state doesn't match the operator's expectation (chain drift, LSM detached, keyring missing). The BPF was **never loaded** — no `BPF_PROG_LOAD` was issued, no chain extend, no eventlog entry. **Hard stop, not a retry signal**: agents should not iterate on the BPF source, since the BPF is not the problem. Re-run `shirudo status`, investigate, then decide whether to re-issue with a refreshed `--expect-chain=`. The report's `message` names which check failed: `chain_drift`, `lsm_detached`, or `keyring_missing`. |
| `init_prereqs_missing` | `pre_flight` (init only) | varies | `shirudo init`'s pre-flight gate found one or more missing prerequisites (not root; BPF LSM absent; bpffs unmountable; cert missing; `/var/lib/shirudo/` unwritable; embedded LSM loader missing from the binary; `add_key` unsupported; TPM unreachable). The report's `failed_checks` array enumerates each missing item with a short fix hint. **No state was changed**. Override with `--no-tpm` is available only for the TPM-absence case; everything else is hard. AI agents should refuse to retry until a human has confirmed the target's infrastructure. |
| `already_unloaded` | `parse` or `payload_load` (unload directive) | `ENOENT` | Target has no pin for this upatch — the unload is a no-op. Idempotent; `result: ok`, no chain extend, no eventlog entry. Agent moves on. |
| `payload_mismatch` | `payload_load` (unload directive) | `EPERM` | The pin exists but the loaded upatch's `payload_sha256` doesn't match what the unload directive expects. Either an attacker substituted a different upatch under the same name, or the operator's unload directive is stale. Refuse to detach. Surface to a human. |
| `detach_failed` | `payload_load` (unload directive) | varies | The unload directive ran but `BPF_LINK_DETACH` or `BPF_OBJ_UNPIN` returned an error from the kernel. Unusual; surface to a human with the errno. |
| `eventlog_full` | `pre_flight` or `tpm_extend` | `ENOSPC` | shirudo's eventlog has reached `eventlog.max_bytes` from `/etc/shirudo/shirudo.conf` and the operation would write a new entry. **No state was changed**: the BPF was not loaded, the chain was not extended, the file was not appended. Required so that the chain and the eventlog never drift — a chain extension without a logged event would defeat replay verification. The operator must rotate the eventlog out of band (copy/move and re-create empty), then retry. Surface to a human. |
| `unknown` | — | — | Catch-all; surface to a human. |

An agent driving rollouts conditions on `category`: it iterates
autonomously for `verifier_rejected`, `btf_mismatch`,
`attach_target_missing`, `parser_rejected`; it pages a human for the
key/policy categories.

### `shirudo rollout --report=<path>` (operator-side)

The operator-side wrapper runs `shirudo upatch load --report=-` over the
libssh exec channel per (target, upatch) pair, parses each per-target
report, and emits an aggregate JSON to `--report=<path>`:

```json
{
  "schema":       1,
  "rollout_id":   "<uuid>",
  "started_at":   "...",
  "completed_at": "...",
  "upatches":     ["foo.upatch", "bar.upatch"],
  "targets": [
    {
      "host":                 "user@target.local",
      "host_chain_before":    "<hex>",
      "host_chain_after":     "<hex>",
      "reports":          [<per-upatch report>, ...],
      "result":           "ok" | "failed"
    }
  ],
  "result": "ok" | "partial" | "failed"
}
```

Non-zero exit if any per-target result is `failed`. An AI agent reads
the aggregate, learns which upatches failed on which targets and why,
and iterates. The loop closes without humans for `verifier_rejected` /
`btf_mismatch` / `attach_target_missing`; humans are paged for
`lsm_denied` / `signature_rejected` / `keyring_missing` / `tpm_error`.

### No subprocess shell-outs in the report path

Per the "No subprocesses at runtime" invariant: JSON assembly uses
shirudo's own emitter under `util/report.c` (a small BSD-2-Clause
whiteroom — git's `json-writer.c` is GPL-2.0, same vendoring rule).
The `dmesg_excerpt` and `journal_excerpt` fields are **deferred** (not
emitted in MVP); the report carries them as `null`. When implemented,
`/dev/kmsg` excerpts will come from direct file I/O, never `dmesg(1)`,
and journal excerpts from the `sd_journal_*` API if linked — never a
`journalctl(1)` invocation. No shell-out either way.

## TPM measurement and remote attestation

shirudo's story so far is *only signed BPF runs*. TPM measurement extends
that story to *every state transition is recorded into a hardware-protected
hash chain*: after the dust settles, the chain value on a target is a
cryptographic commitment to (a) the cert shirudo was initialised with and
(b) every upatch loaded since, in the exact order they were loaded.

> Cross-reference: the threats this section's mechanisms address —
> chain tampering (T4), reboot escape (T5), audit suppression (T9),
> replay (T10), TPM absence (T11), and the cross-cutting deployment-
> range constraints — are documented in
> `Documentation/threat-model.rst`. Implementations of
> `util/tpm.c`, `util/eventlog.c`, and the pre-flight check must
> hold the invariants enumerated there.

### Why an NV-extend index, not a PCR

The systemd / uapi-group "Linux TPM PCR registry" allocates most
PCRs already:

| PCR | Owner |
|---|---|
| 0–7 | UEFI firmware (SRTM) |
| 8 | grub (bootloader config) |
| 9 | grub (kernel + initrd) |
| 10 | Linux IMA |
| 11 | systemd-stub (UKI image) |
| 12 | systemd (kernel cmdline, credentials, confext) |
| 13 | systemd (sysext) |
| 14 | shim / grub `BOOT_LOADER_CODE` |
| 15 | systemd-cryptenroll, systemd-homed |
| 16 | debug — resettable from locality 0 |
| 17–22 | DRTM (Intel TXT / AMD SKINIT) |
| 23 | application-specific — resettable from locality 0 |

PCRs 8–15 are taken. PCRs 17–22 are DRTM-reserved. PCRs 16 and 23
are application-resettable, which defeats the extend-only chain
guarantee that anchors shirudo's tamper evidence: a root attacker
can `TPM2_PCR_Reset` either and wipe the chain. **None of the PCRs
on a stock Linux + systemd + grub + IMA system are usable.**

shirudo therefore measures into a **TPM2 NV-extend index** with
`TPMA_NV_EXTEND` set — the standard mechanism for application-level
extend-only state. The index lives in the owner-defined NV range
(default `0x01818E00`, configurable via the compile-time
`SHIRUDO_NV_INDEX` macro). Resetting an NV-extend index requires
`TPM2_NV_UndefineSpace` + `TPM2_NV_DefineSpace`, which need
platform-hierarchy auth that is effectively unavailable post-boot
on a normal Linux machine. systemd does not use the owner-defined
NV range for measurement, so collision is not a concern.

`shirudo init` defines the index on first run with attributes:

```
TPMA_NV_EXTEND          /* every write is hash-extend, not overwrite */
TPMA_NV_AUTHWRITE       /* writes require shirudo's index auth_value */
TPMA_NV_AUTHREAD        /* reads require shirudo's index auth_value */
TPMA_NV_NO_DA           /* failures don't count against TPM lockout */
TPMA_NV_NO_WIPE         /* survives clear of the storage hierarchy */
size = 32, alg = SHA-256
auth_value = SHA256("shirudo-nv-auth\0" || cert_sha256)
```

The `auth_value` is **deterministic from the target's installed
cert** — derived locally at NV-define time and at every `Esys_NV_Extend`
call. Without `auth_value`, any local process with access to
`/dev/tpmrm0` (typically root, but on misconfigured systems any
member of group `tss`) could call `TPM2_NV_Extend` on the shirudo
index with arbitrary bytes, advancing the chain to a value that does
not replay against the eventlog and **silently invalidating every
operator's cached expectation** (chain-DoS). With the auth_value
gate, an attacker has to either (a) read the target's installed
`cert.der` (sealed under the filesystem-sealing LSM after init,
unsealed before — see threat-model.rst §"Initial cert distribution
trust window"), or (b) read it out of the shirudo binary's memory
via `/proc/<pid>/mem` (blocked by `PR_SET_DUMPABLE = 0`), or (c)
extract it from the binary on disk (also sealed after init).
**Defense-in-depth, not cryptographic** — an attacker who can read
`cert.der` already defeats the seal — but it raises the chain-DoS
bar from "one syscall by any TPM-access process" to "an attacker
who already has substantial filesystem access to the target".

Pre-flight check #11 verifies an existing index's auth-write attribute
matches the expected value derived from the current cert. A mismatch
indicates either a foreign tool squatting on the index, or a cert
rotation that didn't re-define the index. Sub-reason
`tpm_index_auth_mismatch`. Recovery: undefine and re-define (lossy —
chain restarts from zero) or rotate `SHIRUDO_NV_INDEX`.

Subsequent `init` runs (after reboot, or rerun manually) find the
index already defined and skip the `TPM2_NV_DefineSpace` step. The
index — and therefore the chain — is **persistent across reboots**.

### Target-side — NV-extend on every state transition

Extensions are in the SHA-256 bank only — no SHA-1, no SM3. There
are three event types; each extends the chain by exactly one
digest. **Boot-time re-apply is a single set-valued event, not N
per-upatch events** — see "Boot-restore protocol" below for the
rationale.

| Event | Extended digest |
|---|---|
| `shirudo init` succeeds (LSM pinned, currently-loaded set restored if any) | `SHA256("shirudo-init\0" \|\| cert_sha256 \|\| set_digest)` |
| `shirudo upatch load <foo>` succeeds — **operator-driven**, not boot-time re-apply | `SHA256("shirudo-upatch\0" \|\| payload_sha256 \|\| upatch_name)` |
| `shirudo upatch unload <foo>` succeeds (link detached, pin removed) | `SHA256("shirudo-unload\0" \|\| payload_sha256 \|\| upatch_name)` |

The leading tagged string (`"shirudo-init\0"`, `"shirudo-upatch\0"`,
`"shirudo-unload\0"`) provides domain separation — an attacker
cannot replay one event type as another.

**`set_digest` is the SHA-256 of the canonical sorted listing of
upatches currently loaded at the moment the init event extends the
chain.** Canonical form is sha256sum-style, one upatch per line:

```
<payload_sha256_hex> <upatch_name>\n
<payload_sha256_hex> <upatch_name>\n
...
```

Sorted lexicographically by `upatch_name`. Empty set (first-ever
`shirudo init` with no upatches yet, or a target with all upatches
unloaded then rebooted) hashes the empty string, producing the
well-known constant
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

**Load and unload are both forward progress.** The unload event
extends the chain with a *new* digest — it does not reverse the
prior load. Loading upatch X and then unloading it leaves the
chain at a value that is *neither* the pre-load nor the original
post-load value; it is the new third value
`SHA256(post-load-chain \|\| unload_digest)`. The chain therefore
records the full history of state transitions, not just the
current state. Replay logic on the operator side reduces the
chain to "currently loaded set" by walking events: each load adds
to the set, each unload removes from it. The chain itself is
append-only and idempotency-free — every operation that touches
state contributes.

### Boot-restore protocol

On every boot, the deferred reboot-persistence systemd unit
re-runs `shirudo init`. The protocol is **all-or-nothing**:

1. Read the upatch set `S` from `/var/lib/shirudo/upatches/` (the
   on-disk record of intent), sorted by upatch name.
2. Set up the `shirudo` keyring with the cert from
   `/var/lib/shirudo/keys/cert.der`.
3. Load the embedded pre-signed LSM via `BPF_PROG_LOAD` +
   `BPF_PROG_TEST_RUN`, create the LSM link, pin it to
   `/var/lib/shirudo/bpffs/lsm_link`.
4. Re-apply each upatch in `S` in sorted order through the same
   signed-loader path used by `shirudo upatch load`. The LSM is
   enforcing for these loads (each goes through the kernel's
   signature verification), but the chain is **not extended per
   upatch** during boot-restore.
5. If all re-applies succeed: compute `set_digest` over the
   actually-loaded set, then `init_event_digest = SHA256(
   "shirudo-init\0" || cert_sha256 || set_digest)`, then
   NV-extend the chain by `init_event_digest` and append a
   **single** eventlog entry listing the full set.
6. If any re-apply fails: do **not** extend the chain, do **not**
   append the eventlog, mark init as incomplete. Status output
   carries `init_complete: false` and the operator's next pre-flight
   sees a chain that hasn't advanced to match the expected
   post-init value — drift is visible.

Why one event per boot rather than N: a reboot+re-apply restores
state, it does not add new state. The chain encodes operator
intent (which has not changed); the per-event granularity belongs
to *operator-driven* operations (load, unload), each of which is a
distinct intent. Coalescing boot-restore into one set-valued event
keeps the chain bounded (one extension per boot regardless of
upatch count), makes operator prediction trivial
(`Y = SHA256(X || init_event_digest)`, a single SHA-256), and
matches the semantic: a reboot is one event, even if it restores
many upatches.

**Cross-reboot prediction.** The operator (or AI agent) who knows
the pre-reboot chain value `X`, the cert, and the set `S` of
upatches loaded on the target can compute the post-reboot chain
locally without round-tripping the target:

```
set_digest_S    = SHA256(canonical-sorted-listing-of-S)
init_event      = SHA256("shirudo-init\0" || cert_sha256 || set_digest_S)
Y               = SHA256(X || init_event)
```

This is **one SHA-256 per reboot**, regardless of how many upatches
are in `S`. Operators driving high-frequency state machines can
maintain a cached `expected_chain` that advances locally on every
reboot they observe (via `boot_id` change in status), without ever
needing to round-trip the target to refresh.

**Fleet comparison across homogeneous machines** does not require
matching reboot histories. Operators compare each target's
**eventlog tail since the most recent `shirudo-init` event** —
that's the set of upatches loaded in the current boot. The chain
integrity-checks the eventlog (replay must reproduce the live
chain value), so the tail is trustworthy as long as the chain
matches. For "have these N hosts applied the same upatches this
boot?" the operator inspects each host's most-recent init-event
`set_digest` (recorded in the eventlog) and compares directly —
two hosts that have the same loaded set at the same boot have
identical `set_digest` values, regardless of how many reboots
came before.

### Failure semantics — the chain follows reality

The chain is extended **only after the underlying operation has
succeeded**. Operator-driven `upatch load` / `upatch unload` extend
once the new link is pinned (or once the unload directive has
detached + unpinned). Boot-restore `shirudo init` extends once
**all** upatches in `/var/lib/shirudo/upatches/` have been
successfully re-applied and the LSM is pinned. From the
failure-report phase ordering (`pre_flight → parse →
signed_loader_load → payload_load → link_create → pin →
tpm_extend`):

- A failure at any phase **before** `tpm_extend` means the
  intended operation did not complete. The chain is not extended,
  the eventlog is not appended, and the on-target state stays as
  it was (modulo any partial side-effects, e.g. a re-applied
  upatch during boot before another upatch failed). The chain
  remains internally consistent — the failed attempt is invisible
  to it.
- A failure **at** `tpm_extend` is the awkward case: the BPF is
  already loaded and pinned, the kernel is enforcing it, but the
  chain is silently out of sync with the on-target reality. shirudo
  reports this as `category: tpm_error`, logs `LOG_ERR`, and **does
  not append the eventlog** (the eventlog's invariant is that
  replaying it reproduces the chain — appending without extending
  would break it). The operator or AI agent is expected to surface
  this to a human, since the agent cannot fix a TPM-chain
  divergence by iterating on the BPF source. The next
  `shirudo status` from the operator will show `CHAIN-DRIFT` and
  `init_complete: false`.
- Boot-restore mid-failure: if the LSM is up but a re-apply in
  step 13 of the bootstrap sequence fails, the init event in
  step 15 does **not** extend the chain. The target is in
  partial-init state; `shirudo status` reports
  `init_complete: false`. The operator must intervene (typically:
  remove or fix the offending `.upatch` file, then re-run
  `shirudo init`).

The net invariant: **the chain is monotone with respect to
actually-applied state transitions over the machine's lifetime.**
Every chain extension corresponds to a successful operator-driven
load/unload or a successful boot-restore that really happened in
full; every successful state transition is in the chain (or is
loudly reported as missing via `tpm_error` / `init_complete:
false`).

### Eventlog — `/var/lib/shirudo/eventlog`

The chain value is opaque. The eventlog records what extended it,
append-only, JSON-lines, mode 0600. One line per chain extension —
which is one line per operator-driven `upatch load`/`upatch unload`,
and **one line per `shirudo init`** (boot-restore is collapsed into
a single eventlog entry listing the full restored set):

```json
{"schema":1,"ts":"2026-05-13T10:14:33Z","nv_index":"0x01818E00",
 "alg":"sha256","digest":"<hex>","type":"upatch_load",
 "upatch":{"name":"foo","payload_sha256":"<hex>"}}

{"schema":1,"ts":"2026-05-13T10:15:02Z","nv_index":"0x01818E00",
 "alg":"sha256","digest":"<hex>","type":"init","boot_id":"<uuid>",
 "cert_sha256":"<hex>","set_digest":"<hex>",
 "set":[{"name":"foo","payload_sha256":"<hex>"},
        {"name":"bar","payload_sha256":"<hex>"},
        {"name":"baz","payload_sha256":"<hex>"}]}
```

Every eventlog entry carries a top-level `schema` integer
(currently `1`) so that a future format change can co-exist with old
entries: replay tooling fails closed on an unknown schema version and
asks for an upgrade, rather than silently mis-parsing fields. The
same versioning convention applies to the per-upatch and aggregate
JSON reports — `--report=` documents carry `"schema": 1` in their
top-level object too, so AI agents can detect skew between the
shirudo version they expect and the one that produced a report.

The init event's `set` array enumerates the upatches restored
during this boot in canonical (sorted-by-name) order. The
operator can recompute `set_digest` from the array and confirm
it matches the recorded `digest`'s set portion, and can recompute
the chain extension to confirm `digest` matches the live NV
value.

The eventlog is **not trusted on its own** — root can rewrite it.
What makes it useful is that **replaying the full eventlog must
reproduce the live NV chain value**. A tamper is detected by the
operator's remote-status check (below): if the chain doesn't match
the eventlog replay, or if neither matches the operator's
`--expect=` value, either the target is compromised or the log is
fabricated. Because the NV index is non-resettable from userspace,
the chain itself is the durable cryptographic ground truth — an
attacker who rewrites the eventlog without being able to forge a
matching chain extension simply produces a mismatch the operator
sees immediately.

Eventlog entries from earlier boots are kept for audit history.
Operators interested in "what's loaded *this boot*" walk the tail
from the most recent `shirudo-init` entry forward — that subset
identifies the current loaded set after replay.

### Library — tpm2-tss (BSD-2-Clause)

The target binary links **libtss2-esys** (the Enhanced System API) and
**libtss2-tcti-device** (TCTI for `/dev/tpmrm0`) dynamic. Both are
**BSD-2-Clause** — the tpm2-tss project is BSD-2-Clause throughout, so
no whiteroom and no GPL contamination. shirudo's TPM surface is tiny:

- `Esys_NV_DefineSpace()` — once, on first-ever `shirudo init` for
  this cert (idempotent: subsequent runs find the index already
  defined and skip).
- `Esys_NV_Extend()` — one call per state transition.
- `Esys_NV_Read()` / `Esys_NV_ReadPublic()` — for status queries.

TPM access goes through `/dev/tpmrm0` (the kernel's TPM resource
manager) via the `device` TCTI. No direct character-device byte-banging,
no command marshalling by hand. The `SHIRUDO_TPM_TCTI` environment
variable overrides the TCTI string (e.g.
`swtpm:host=127.0.0.1,port=2321`) for VMs/CI whose `/dev/tpmrm0` is
owner-provisioned and for tests against `swtpm`; it does not weaken the
trust model, since the operator verifies chain values against
locally-computed expectations and a redirected/fake TPM produces values
the check rejects. The pre-flight in `util/preflight.c` honors the
same env var: when `SHIRUDO_TPM_TCTI` is set the `/dev/tpmrm0` access
check is skipped (the override is the operator's declared intent that
the kernel resource manager isn't in play), and any real
connectivity problem with the swtpm socket surfaces at TPM-open time
with a precise error. See Documentation/getting-started.rst "TPM in
development" for a worked swtpm recipe.

### Graceful degradation

If `/dev/tpmrm0` is absent at `shirudo init` time (VMs without vTPM,
test environments, very old hosts), or if the NV index cannot be
defined (owner auth set to a non-default password, NV storage
exhausted), shirudo logs a `LOG_WARNING` `"tpm not present,
measurement disabled"` and proceeds. Subsequent `upatch load`s
skip the extend step; their report carries `"tpm": null` instead
of a chain value. The absence is observable to the operator
through `shirudo status`.

### Pre-flight state check on every state-changing operation

Every operation that would extend the chain — `shirudo upatch load`,
`shirudo upatch unload` — performs a **pre-flight check** before
it touches the kernel. The check is atomic from any attacker's
perspective (one shirudo process, no IPC, sequential syscalls):

1. **Version-identity match.** Compare the target's
   `SHIRUDO_VERSION_ID` (compiled-in constant) against
   `--expect-version-id=<hex>` supplied by the caller (the
   operator's own `SHIRUDO_VERSION_ID`, threaded through by
   `rollout` automatically — see below). On mismatch:
   refuse with `category: version_mismatch`, no other checks
   attempted, no kernel state touched. This is the cheapest
   pre-flight gate and runs first because a version-skewed pair
   has no business doing the rest of the dance.
2. **Chain match.** Read the current NV chain value via
   `Esys_NV_Read`. Compare, constant-time, against
   `--expect-chain=<hex>` supplied by the caller. The expected
   value is what the operator (or AI agent) last observed for this
   target via `shirudo status`, optionally extended locally by
   `SHA256(prev || init_event_digest)` if a reboot has occurred —
   where `init_event_digest = SHA256("shirudo-init\0" ||
   cert_sha256 || set_digest)` and `set_digest` is the canonical
   hash of the loaded-upatch set the operator knows is on the
   target. Both inputs are operator-known (cert from the keyring,
   set from the operator's audit), so the operator can reproduce
   the post-reboot chain locally without round-tripping the
   target. Mismatch → refuse.
3. **LSM still pinned.** `bpf_obj_get("/var/lib/shirudo/bpffs/lsm_link")`
   must succeed. Detached LSM → refuse: the kernel's signature
   verifier still works without the LSM (which is why `bpf()` would
   not visibly fail), but shirudo's "only signed BPF runs" property
   is gone for the duration. Refusing here is conservative and
   correct.
4. **Keyring present.** The named `shirudo` keyring must exist with
   the expected cert inside (cert SHA-256 is also implicit in the
   chain via the init event, so this is a sanity belt-and-suspenders).

Any failure short-circuits the operation: **no `BPF_PROG_LOAD`,
no chain extend, no eventlog entry, no link install or detach.**
The report category is `version_mismatch` if the version-identity
check failed (a separate category from `tampered` because the action
the operator must take is different — re-deploy a matching binary,
not investigate a possibly-compromised target). Otherwise the
category is `tampered` and the message names the specific check
that failed (`chain_drift`, `lsm_detached`, `keyring_missing`). The
exit code is non-zero. An AI agent receiving this should **not
iterate on the BPF source** — the BPF was never even loaded; the
problem is target-side state, and a human (or a re-status + manual
investigation) is the right next step.

**Where the expected PCR comes from:**

- *Default for `rollout`*: shirudo on the operator first
  opens an SSH exec channel running `shirudo status --json
  --include-tpm`, captures the target's current chain value, then
  opens a second exec channel running `shirudo upatch load
  --expect-chain=<captured>`. Two channels on one libssh session,
  microsecond gap. Anything that changes the target's chain in
  that gap (a concurrent legitimate operator, or active tampering)
  causes the second call to fail with `tampered`, and the operator
  re-statuses + retries.
- *Explicit*: operators or AI agents pass `--expect-chain=<hex>`
  directly. AI agents stash `chain_after`, `boot_id`, and the
  loaded-upatch set from each successful operation's report and
  pass `chain_after` as the next operation's `--expect-chain=`.
  This serializes the agent's operations against the chain
  without an extra status round-trip per call. **Across
  legitimate reboots**, the agent detects the reboot via
  `boot_id` change (status output includes the kernel's
  `boot_id` from `/proc/sys/kernel/random/boot_id`) and updates
  the cached value locally as
  `Y = SHA256(chain_after || init_event_digest)`, where
  `init_event_digest = SHA256("shirudo-init\0" || cert_sha256 ||
  set_digest)` and `set_digest` is the canonical hash of the set
  the agent knows is loaded on the target (one SHA-256 per reboot,
  regardless of how many upatches — see "Boot-restore protocol").
  This is the property that makes the persistent-chain design
  robust for AI-driven workflows: reboots don't false-positive
  the pre-flight check, and the operator pays one local SHA-256
  per reboot rather than a round-trip.
- *Disabled*: `--no-precheck` skips the check; only sensible for
  first-time bootstrap before any chain history exists (the very
  first `upatch load` after `init`), or emergency recovery. Logged
  at `LOG_WARNING` on the target.

**`init` is exempt** from operator-driven pre-flight: it is
target-local, runs once per boot via the deferred systemd unit,
and has its own pre-flight protocol — if the LSM is already
attached and pinned, no-op (the chain stays where it is);
otherwise shirudo defines the NV index if not yet defined,
attaches the LSM, pins the link, and extends the chain by exactly
one deterministic init event (`SHA256("shirudo-init\0" ||
cert_sha256)`). No operator-supplied `--expect-chain` is involved,
since the operator isn't in the loop for boot-time init.

**Why this matters:** the chain is now load-bearing not just for
post-hoc audit but for *every operation in flight*. Concurrent
operators serialize through the chain. An attacker who manipulates
target state — even via a path shirudo's LSM allows, like
`unlink` of the LSM pin — cannot then quietly have shirudo apply
or revert an upatch on top of the tampered state, because the
next operation refuses. The "tamper is silent unless someone
looks" failure mode of plain post-hoc attestation is
closed.

### Operator-side — `shirudo status` remote-query mode

`shirudo status` gains a remote-query invocation: given one or more
host arguments (or registered remote names — see "Remote registry"),
it connects over the existing libssh path and runs:

```
shirudo status --json --include-tpm
```

…on each target. Per-target output covers:

- LSM link status (attached / pinned / prog id)
- Keyring serial + cert SHA-256
- Loaded upatches (name, `payload_sha256`, link id, pin path)
- **Current NV chain value** (32 bytes from `Esys_NV_Read`)
- **NV index** (hex, for operator visibility — typically `0x01818E00`)
- **Eventlog digest** — SHA-256 of `/var/lib/shirudo/eventlog`
- **Eventlog tail** — last N entries since the most recent
  `shirudo-init` event, configurable, default 32 — this is the
  current-boot view operators use for fleet drift detection across
  homogeneous machines
- **`boot_id`** — the kernel's `/proc/sys/kernel/random/boot_id`
  UUID. Operators / AI agents cache this alongside `chain_after`
  to detect reboots; a changed `boot_id` is the signal to compute
  the post-reboot chain value locally
  (`Y = SHA256(prev || init_event_digest)`) before issuing the
  next operation.
- **`init_complete`** — boolean. `true` if the most recent
  `shirudo init` finished all the way through the chain
  extension; `false` if init aborted between LSM pin and chain
  extension (a re-apply failed). When `false`, operators should
  treat the target as needing manual recovery — see the
  bootstrap sequence's "all-or-nothing" semantics.

The operator aggregates into a fleet drift table:

```
host       lsm   keyring        chain                    upatches  status
host-a     OK    <fp>:abcd…     <hex>                    5         OK
host-b     OK    <fp>:abcd…     <hex>                    5         OK
host-c     OK    <fp>:efgh…     <hex>                    4         CERT-DRIFT
host-d     OK    <fp>:abcd…     <different hex>          5         CHAIN-DRIFT
```

Two comparison modes:

- **By chain value**: `--expect=<hex>` pins a single canonical
  chain. Useful when targets are truly identical (same cert, same
  upatch sequence, same reboot history). Most useful for narrow
  fleets where lifetimes converge.
- **By event sequence**: `--expect-sequence=<file>` pins an
  expected init+load+unload event sequence; shirudo replays each
  target's eventlog tail since its most recent init and compares
  the sequence (not the chain digest). This is the natural cross-
  fleet comparison since it tolerates different reboot counts
  between machines — what matters is "have they applied the same
  upatches this boot", which is exactly the eventlog tail.

Each target is labelled OK / CERT-DRIFT / CHAIN-DRIFT (chain
doesn't match `--expect=`) / SEQUENCE-DRIFT (eventlog tail doesn't
match `--expect-sequence=`). The command exits non-zero if any
target drifts.

### Limits in MVP

- **Chain value comes back over SSH.** The SSH connection is the
  trust boundary. A compromised target can lie about the chain.
  The proper fix is **`TPM2_NV_Certify` with an Attestation Key**
  (the NV-index analogue of `TPM2_Quote`: an AK-signed certificate
  over the NV index contents, with a nonce chosen by the
  operator) — deferred, see "Open questions / future work". AK
  provisioning, EK certificate validation, and AK trust policy on
  the operator are non-trivial and bring meaningful complexity
  (AK storage, AK revocation, EK chains, vendor CA roots).
- **Unload directives are signed BPF**, which means rolling one out
  produces a verifier log too. Most unload directives are tiny and
  well-tested (a fixed template per kernel version), so verifier
  failures on an unload should be rare; when they happen, the
  same `category: verifier_rejected` path applies and AI agents
  iterate on the unload-directive template rather than on the
  user-authored BPF.

## Logging to the systemd journal

shirudo logs significant events via `syslog(3)` with
`openlog("shirudo", LOG_PID | LOG_NDELAY, LOG_AUTHPRIV)`. systemd-journald
picks these up automatically, and operators can filter cleanly:

```
journalctl -t shirudo                  # all shirudo events, current boot
journalctl -t shirudo --since "1h ago"
journalctl -t shirudo -p warning       # warnings and above
```

No `libsystemd` dependency — `syslog(3)` is libc and works with journald,
rsyslog, or any classic syslog daemon.

A `util/log.c`/`log.h` module wraps this with the perf/bpftool-style
`pr_info()` / `pr_warn()` / `pr_err()` macros, plus a `pr_audit()` macro that
maps to `LOG_NOTICE` for security-relevant events. Each callsite uses a short,
greppable tag — e.g.:

| Event | Level | Example message |
|---|---|---|
| LSM bootstrap success | `LOG_NOTICE` | `init: lsm attached, link pinned at /var/lib/shirudo/bpffs/lsm_link, keyring=shirudo (serial=%d), cert_sha256=%s` |
| LSM bootstrap failure | `LOG_ERR` | `init: failed at step %s: %s` |
| Keyring created / cert added | `LOG_NOTICE` | `keyring: added asymmetric key %s (serial=%d) to keyring shirudo (serial=%d)` |
| Upatch load (success) | `LOG_NOTICE` | `upatch: loaded %s, payload_sha256=%s, prog_id=%u, link_id=%u, pin=%s` |
| Upatch load (rejected by kernel) | `LOG_WARNING` | `upatch: load %s rejected: %s` (BPF_PROG_LOAD errno) |
| `genkey` | `LOG_NOTICE` | `genkey: generated %s (sha256=%s, valid_until=%s)` |
| `rollout` start/per-target/finish | `LOG_INFO`/`LOG_NOTICE` | `rollout: target=%s, pushed=%zu upatches, succeeded=%zu, failed=%zu` |

For machine-readable filtering, shirudo also includes `KEY=VALUE` pairs after
the human-readable prefix where relevant (e.g. `prog_id=42`); journald exposes
these as structured fields searchable via `journalctl SHIRUDO_PROG_ID=42` if
the user later wants to add proper `sd_journal_send()` calls. The MVP sticks
to plain `syslog(3)` for minimum dependencies; structured-field upgrade is a
future enhancement.

**Log-injection sanitisation.** Every string that may originate from an
untrusted source (upatch names from a parsed `.upatch`, kernel
errno-stringification under attacker-influenced load, verifier-log
excerpts before they go into a JSON report, file paths an operator
typed) is passed through `util/log.c`'s `pr_safe()` helper before it
reaches a format string. `pr_safe()` replaces every byte that is not
in `[ -~]` (printable ASCII plus space) and not in `\t` with a
hex-escape `\xNN`, truncates at 4 KiB, and refuses embedded NULs. This
denies the classic "newline-injection into syslog" trick where an
attacker-controlled name like `foo\nshirudo: init: ROOTKIT INSTALLED`
fakes additional log lines. The JSON emitter in `util/report.c`
escapes per RFC 8259 independently (`\u00XX` for non-printable, `\"`
and `\\` for the JSON metacharacters), so structured reports are safe
without `pr_safe()`. The two paths are kept distinct on purpose:
syslog is line-oriented and trusts the formatter; JSON is structured
and trusts the encoder.

LSM in-kernel denials are *not* logged in MVP. They surface to the rejected
caller as `-EACCES` only. A future ringbuf+drainer can stream denials to the
journal — noted in deferred work above.

## Documentation

A `Documentation/` tree in **reStructuredText**, matching the kernel's
convention (`Documentation/*.rst`). Sphinx-renderable, plain-text
readable in a terminal. Three documents in MVP, plus an index:

- **`Documentation/threat-model.rst`** — already written; the
  **authoritative security design document**. Covers operator-node
  and target-node threats, adversary classes (A-net, A-user,
  A-root, A-root-op, A-physical, A-kernel), trust boundaries,
  assets per node, deployment-range constraints
  (datacenter-fleet scale down to single embedded devices), and
  residual risks/deferred mitigations. **Consult this document
  before designing or implementing any security-relevant code
  path** — it names the threats each defense exists to address,
  and the residual risks each MVP decision accepts. When a code
  path makes a choice that affects a documented threat (e.g.
  changing how the LSM hook classifies an op, changing how the
  TPM chain is extended, changing what the pre-flight check
  verifies), the threat-model entry is the spec to satisfy.
- `Documentation/architecture.rst` — the timeless, contributor-facing
  architecture description: operator/target split, LSM enforcement policy,
  bootstrap sequence, signature-verification path, keyring model,
  `.upatch` container format, BPF program structure (`bpf/bpf2.c` and the
  one-file-per-LSM-attach-target convention), logging model, the
  no-subprocess invariant, the BSD-2-Clause/whiteroom policy. Derived from
  PLAN.md once the implementation has settled. PLAN.md itself remains the
  implementation *plan* (MVP scope, deferred work, open questions) and is
  not the user-facing doc.
- `Documentation/getting-started.rst` — operator quickstart, roughly one
  page, walking the happy path end-to-end:
    1. install runtime deps (`libcrypto`, `libssh`),
    2. check kernel config (`/sys/kernel/security/lsm` contains `bpf`,
       `keyring_id` supported),
    3. clone + build (`git submodule update --init`, `make`),
    4. on the operator machine: `shirudo genkey`,
    5. copy `cert.der` to the target (out-of-band the first time),
    6. on the target: `shirudo init`,
    7. on the operator machine: `shirudo build myhook.bpf.c -o myhook.upatch`,
    8. `shirudo rollout myhook.upatch user@target`,
    9. verify on the target with `shirudo status` and
       `journalctl _EXE=/usr/local/bin/shirudo` (trusted-field filter, not
       `-t shirudo`).
- `Documentation/index.rst` — Sphinx `toctree` listing the three
  documents above. No `conf.py` is shipped in MVP — the `.rst`
  files are written to read cleanly as plain text in a pager;
  anyone who wants HTML can drop in a stock kernel-style `conf.py`
  or invoke `rst2html` ad-hoc.

The split is deliberate: `threat-model.rst` is the *what shirudo
defends against and why*, the security spec for implementers and
reviewers; `architecture.rst` is the *what shirudo is*, written for
someone who has never seen the codebase; `getting-started.rst` is
the *what an operator types*, written for someone who just wants
the LSM running on a host. CLAUDE.md continues to point new
sessions at both `PLAN.md` and `Documentation/` so the right entry
points are always discoverable.

## Project layout

Modeled on `tools/perf/` but minimal:

```
shirudo/
├── LICENSE                       # BSD-2-Clause
├── README.md
├── Documentation/                # reST docs, see "Documentation" §
│   ├── index.rst                 # Sphinx toctree (no conf.py shipped)
│   ├── threat-model.rst          # authoritative security design doc —
│   │                             #   consult before designing or
│   │                             #   implementing any security-relevant
│   │                             #   code path
│   ├── architecture.rst          # contributor-facing design / internals
│   └── getting-started.rst       # operator quickstart, happy path
├── Makefile                      # top-level parallel-build wrapper
├── Makefile.shirudo              # main rules (CC, linking, BPF compile)
├── Makefile.config               # feature probes: libcrypto, libssh,
│                                 #   libtss2 (esys + tcti-device), libelf,
│                                 #   kernel uapi (not libssl — no TLS in
│                                 #   shirudo)
├── .gitmodules
├── include/shirudo/
│   └── upatch.h                  # on-disk .upatch layout, shared by sign/load
├── shirudo.c                     # main(), cmd_struct[] dispatch
├── builtin.h
├── builtin-init.c
├── builtin-genkey.c
├── builtin-status.c
├── builtin-keys.c
├── builtin-upatch.c              # upatch list / load (subcommand router)
├── builtin-rollout.c             # rollout (libssh SFTP push + exec channel)
├── builtin-nodes.c               # fleet observability: iterates over
│                                 #   $XDG_CONFIG_HOME/shirudo/remotes.d/
│                                 #   (and /etc/shirudo/remotes.d/),
│                                 #   opens up to --parallel libssh
│                                 #   sessions, runs `shirudo status
│                                 #   --json --include-tpm` on each
│                                 #   target, aggregates into a drift
│                                 #   table. Reuses util/remotes.c for
│                                 #   the registry walk and util/ssh.c
│                                 #   for the libssh sessions.
├── builtin-build.c               # 5-line execv dispatch to
│                                 #   $(libexecdir)/shirudo/shirudo-build;
│                                 #   the SOLE execv site in the core
│                                 #   binary (no PATH lookup, one specific
│                                 #   target path). On systems without
│                                 #   shirudo-build installed, returns
│                                 #   exit 127 with an operator-only
│                                 #   message.
├── util/
│   ├── parse-options.c / parse-options.h
│   │                             # BSD-2-Clause whiteroom of the subset of
│   │                             #   libsubcmd's OPT_*/parse_options() that
│   │                             #   shirudo uses. NOT a copy of libsubcmd
│   │                             #   (GPL-2.0). Implementor may instead
│   │                             #   wrap POSIX getopt_long(3); same role.
│   ├── loader.c / loader.h       # bpf_object__gen_loader wrappers; .incbin
│   │                             #   of each bpf/*.o, one symbol pair per prog
│   ├── sign.c   / sign.h         # CMS signing — vendored from bpftool's
│   │                             #   sign.c, which is dual-licensed
│   │                             #   (GPL-2.0-only OR BSD-2-Clause); SPDX
│   │                             #   line and original copyright preserved
│   │                             #   verbatim at the top of util/sign.c.
│   │                             #   **Linked only into shirudo-build**
│   │                             #   (operator-only); the core shirudo
│   │                             #   binary does not include it, since
│   │                             #   neither operator (via `shirudo build`
│   │                             #   dispatch) nor target ever needs to
│   │                             #   sign from the core binary.
│   ├── upatch.c / upatch.h       # .upatch container serializer / parser
│   ├── keyring.c / keyring.h     # add_key/keyctl raw syscalls
│   ├── paths.c   / paths.h       # /var/lib/shirudo/{keys,upatches,bpffs,…}
│   ├── harden.c   / harden.h     # process-hardening primitives called
│   │                             #   from shirudo.c main() before any
│   │                             #   subcommand: PR_SET_DUMPABLE=0,
│   │                             #   PR_SET_NO_NEW_PRIVS, PR_SET_PTRACER,
│   │                             #   setrlimit(RLIMIT_CORE,0). Plus
│   │                             #   mlock + madvise(MADV_DONTDUMP) +
│   │                             #   explicit_bzero helpers for sensitive
│   │                             #   buffers. ~50 LOC, no library deps
│   │                             #   beyond libc.
│   ├── preflight.c / preflight.h # exhaustive infrastructure-prerequisite
│   │                             #   gate run by `shirudo init` (and
│   │                             #   `shirudo status` for dry-run
│   │                             #   readiness reports). Each check is
│   │                             #   a small function returning
│   │                             #   { ok | fail + diagnostic }; the
│   │                             #   driver runs all of them and
│   │                             #   collects failures so the operator
│   │                             #   sees the full list at once. See
│   │                             #   Architecture §"Pre-flight checks".
│   ├── ssh.c     / ssh.h         # libssh wrappers: session/known_hosts/auth,
│   │                             #   SFTP push, SSH exec channel. shirudo
│   │                             #   links libssh; it never fork+execs
│   │                             #   ssh/scp/sftp.
│   ├── log.c     / log.h         # syslog wrappers: pr_err/pr_warn/pr_info/pr_audit
│   ├── tpm.c     / tpm.h         # libtss2 wrappers: Esys_NV_DefineSpace,
│   │                             #   Esys_NV_Extend, Esys_NV_Read. Uses a
│   │                             #   shirudo-owned TPM2 NV-extend index
│   │                             #   (default 0x01818E00) — persistent
│   │                             #   across reboots, no collision with
│   │                             #   the systemd PCR registry. See "TPM
│   │                             #   measurement". Target-only at
│   │                             #   runtime, built unconditionally.
│   │                             #   BSD-2-Clause.
│   ├── eventlog.c / eventlog.h   # /var/lib/shirudo/eventlog appender,
│   │                             #   reader, replay (chain reconstruction
│   │                             #   from the log). Used by tpm.c and by
│   │                             #   shirudo status --include-tpm.
│   ├── json.c   / json.h         # in-tree JSON emitter + bounded-
│   │                             #   schema parser (BSD-2-Clause,
│   │                             #   ~400 LOC). Used by every
│   │                             #   --report=/--json path AND by
│   │                             #   rollout/nodes for aggregating
│   │                             #   per-target JSON received over
│   │                             #   SSH. Parser is schema-callback
│   │                             #   driven, NOT a generic
│   │                             #   deserialiser — see Build system
│   │                             #   §"In-tree JSON parser and
│   │                             #   emitter" for the contract.
│   ├── report.c  / report.h      # JSON failure-report assembly for
│   │                             #   `upatch load --report` and
│   │                             #   `rollout --report`. Layers on
│   │                             #   top of util/json.c; defines the
│   │                             #   per-document schemas and field
│   │                             #   sets.
│   ├── version_id.c              # AUTO-GENERATED at build time: the
│   │                             #   architecture-independent
│   │                             #   SHIRUDO_VERSION_ID constant.
│   │                             #   Regenerated on every `make`; never
│   │                             #   committed to git. See "Build system
│   │                             #   — Version identity" subsection.
│   ├── selector.c / selector.h   # label-selector parser+evaluator for
│   │                             #   `--selector` on rollout/
│   │                             #   nodes. ~150 LOC recursive-descent
│   │                             #   parser for the grammar
│   │                             #   `expr ::= term ('||' term)*`,
│   │                             #   `term ::= atom ('&&' atom)*`,
│   │                             #   `atom ::= key ('=' value | '!=' value
│   │                             #             | <existence> | '!' <existence>)
│   │                             #           | '(' expr ')'`. Evaluator
│   │                             #   takes a parsed AST and a remote's
│   │                             #   {key→value} label map, returns
│   │                             #   bool. No external library; standard
│   │                             #   C. Used by builtin-rollout
│   │                             #   and builtin-nodes.
│   └── remotes.c / remotes.h     # remote registry: read/write
│                                 #   $XDG_CONFIG_HOME/shirudo/remotes.d/
│                                 #   with /etc/shirudo/remotes.d/ as the
│                                 #   system-wide fallback. Resolves a
│                                 #   "remote-or-literal" string to a
│                                 #   {host, user, port, pcr, …} struct
│                                 #   used by rollout and status.
│                                 #   Whiteroom key=value parser, ~50 LOC.
├── bpf/
│   ├── bpf2.c                    # Two-hook LSM program: attaches to
│   │                             #   lsm/bpf (gates bpf() syscall — the
│   │                             #   central "BPF on BPF" enforcement)
│   │                             #   AND lsm/inode_unlink (denies VFS
│   │                             #   unlink on shirudo's bpffs
│   │                             #   superblock unless the caller is
│   │                             #   shirudo itself — closes the race
│   │                             #   window between bpf2 attach and
│   │                             #   seal attach for the rm-the-pin
│   │                             #   attack). One frozen
│   │                             #   BPF_MAP_TYPE_ARRAY records the
│   │                             #   bpffs sb identity, populated and
│   │                             #   frozen by userspace BEFORE the
│   │                             #   first BPF_LINK_CREATE. Future LSM
│   │                             #   attach targets get their own
│   │                             #   sibling files (seal.c is the
│   │                             #   next one).
│   ├── unload.bpf.c              # signed UNLOAD directive template
│   │                             #   (SYSCALL-type prog). Compiled once at
│   │                             #   build time; `shirudo build --unload`
│   │                             #   parameterises it with the target name
│   │                             #   + expected payload_sha256, signs the
│   │                             #   result, and emits a .upatch with the
│   │                             #   DIRECTIVE_UNLOAD flag bit set.
│   ├── seal.c                    # the FILESYSTEM-SEALING LSM program,
│   │                             #   sibling of bpf2.c. Attaches to
│   │                             #   lsm/file_open (write), lsm/inode_unlink,
│   │                             #   lsm/inode_rename, lsm/inode_setxattr,
│   │                             #   lsm/inode_removexattr. Uses
│   │                             #   bpf_get_inode_xattr() to read the
│   │                             #   "security.bpf.shirudo" xattr from both
│   │                             #   the target inode and the calling
│   │                             #   process's exe_file inode; allows
│   │                             #   operation iff both labels match (the
│   │                             #   value is SHIRUDO_VERSION_ID, same
│   │                             #   constant used by the version-id
│   │                             #   pre-flight). **No paths anywhere** —
│   │                             #   path-based comparison is tamperable
│   │                             #   via bind-mounts and namespaces, so
│   │                             #   shirudo's LSM is built on
│   │                             #   inode-bound labels. Pre-signed at
│   │                             #   build time, loaded by `shirudo init`
│   │                             #   immediately after bpf2.c.
│   └── lib/                      # reusable BPF code, include-only. Headers
│                                 #   with static-inline helpers, shared
│                                 #   macros, and tables (e.g. bpf() cmd
│                                 #   classification) consumed via #include
│                                 #   from bpf/*.c. Nothing here is compiled
│                                 #   standalone.
├── tools/                        # auxiliary binaries that live OUTSIDE the
│   │                             #   core shirudo binary.
│   └── shirudo-build/            # the OPERATOR-ONLY artifact-producing
│       │                         #   dispatcher: compiles, signs, packages.
│       ├── README.md             # design + why this is a separate binary
│       ├── shirudo-build.c       # main(): arg parse, dispatch to compile
│       │                         #   path (.bpf.c input) or sign-only path
│       │                         #   (.bpf.o input) or unload-directive
│       │                         #   path (--unload). Holds the SINGLE
│       │                         #   subprocess exception (execv clang
│       │                         #   for .bpf.c inputs).
│       ├── compile.{c,h}         # execv clang for .bpf.c → .bpf.o. The
│       │                         #   one subprocess site in all of
│       │                         #   shirudo. Hardcoded clang path
│       │                         #   resolution (PATH lookup explicitly
│       │                         #   disabled).
│       ├── package.{c,h}         # link against util/sign.c + libbpf
│       │                         #   gen_loader + util/upatch.c to produce
│       │                         #   a .upatch from a .bpf.o (LOAD) or
│       │                         #   from an unload-directive template
│       │                         #   (--unload).
│       └── vmlinux.{c,h}         # locate vmlinux.h via the documented
│                                 #   search order (./vmlinux.h, then
│                                 #   /usr/share/shirudo/vmlinux.h, then
│                                 #   --vmlinux override). No
│                                 #   auto-generation; bpftool is the
│                                 #   operator's job.
│       # Installs to $(libexecdir)/shirudo/shirudo-build,
│       # typically /usr/libexec/shirudo/. See Build system
│       # §"Operator-only binaries and dual install targets".
├── examples/                     # reference BPF upatches, ready to sign and
│                                 #   roll out. Templates for operator-
│                                 #   authored upatches; the first canonical
│                                 #   example is the CVE-2026-31431 AF_ALG
│                                 #   blocker.
│   ├── README.md                 # how to build, sign, and roll out
│   ├── Makefile                  # builds each *.bpf.c → *.bpf.o
│   └── cve-2026-31431.bpf.c      # block AF_ALG socket_create via
│                                 #   lsm/socket_create — mitigation for
│                                 #   CVE-2026-31431. Returns -EPERM when
│                                 #   family == AF_ALG; allows otherwise.
├── t/                            # automated test suite, see "Testing and CI" §
│   ├── test-lib.sh               # BSD-2-Clause whiteroom of TAP framework
│   ├── tNNNN-*.sh                # numbered shell tests, four-digit prefix
│   └── helper/                   # small C programs invoked from shell
│                                 #   tests — security-critical negative
│                                 #   paths (raw bpf(), tamper, race, …)
├── (ci/ and .github/ -- DEFERRED, not in tree; see "Testing and CI" §)
└── third_party/
    └── bpf-next/                 # git submodule
```

`util/parse-options.{c,h}` provides shirudo's CLI parser — a small
BSD-2-Clause whiteroom of the subset of libsubcmd's `OPT_*` /
`parse_options()` API the subcommands actually use. **libsubcmd itself is
not linked**; see "Vendoring and whiteroom reimplementation" for why.
Implementors who prefer it may instead wrap POSIX `getopt_long(3)` — the
choice is local, what matters is that the API `builtin-*.c` files call
into is owned by this repo under BSD-2-Clause.

## Build system

### Makefile layout

Three Makefiles cooperate, all in the kernel/perf style:

| File | Role |
|---|---|
| `Makefile` | Top-level entry point. Parses `make` flags, includes `Makefile.config` for feature probes, then defers to `Makefile.shirudo` for actual rules. Roughly 30 lines. Goals: `all` (default), `install`, `clean`, `distclean`, `check`, `test`, `examples` (delegates to `examples/Makefile`). |
| `Makefile.config` | Feature-detection logic (pkg-config probes for libcrypto / libssh / libtss2 / libelf, presence of `keyring_id` in `<linux/bpf.h>`, presence of `clang -target bpf`, etc.). Outputs a generated `config.mk` consumed by `Makefile.shirudo`. Re-runs on `make distclean`; cached otherwise. |
| `Makefile.shirudo` | The actual build graph. Defines targets for each `builtin-*.o`, each `util/*.o`, the static `libbpf.a` and `libelf.a` inside `third_party/bpf-next/`, the `bpf/*.o` BPF objects, the embedded blobs in `util/loader.o`, the final `shirudo` link, install rules, test rules. |

The split keeps the top-level entry point tiny and operationally
familiar (run `make` from the repo root; everything else is
automatic), while the detail lives in files reviewers can read
without paging through hundreds of lines of conditional logic.

### Build phases (dependency order)

Builds proceed in five strict phases — each consumes only artifacts
from earlier phases, never from later ones. This makes the build
parallelisable inside a phase and avoids implicit ordering bugs.

```
phase 1 — submodule libraries        # third_party/bpf-next/build/
   ├── libbpf.a            (static, BSD-2-Clause branch)
   ├── libelf.a            (static)
   └── bpftool             (build-time tool only, not installed)

phase 2 — generated headers           # build artifacts only
   └── bpf/vmlinux.h       (bpftool btf dump file vmlinux format c)

phase 3 — compiled objects (parallel within phase)
   ├── util/*.o            (CC against config.mk, no BPF)
   ├── builtin-*.o         (CC against util/ headers)
   ├── shirudo.o           (CC main + dispatch)
   └── bpf/*.bpf.o         (clang -target bpf against vmlinux.h)

phase 4 — embedded BPF
   └── util/loader.o       (CC, .incbin-references each bpf/*.bpf.o)

phase 5 — link
   └── shirudo             (LD util/*.o + builtin-*.o + shirudo.o +
                            third_party/.../libbpf.a + libelf.a + zlib
                            + dynamic-link libcrypto, libssh,
                            libtss2-esys, libtss2-tcti-device)
```

`util/loader.o` in phase 4 has a Makefile-level dependency on every
`bpf/*.bpf.o` it `.incbin`'s — without that, parallel builds race.

### BPF object embedding (`.incbin`)

Each `bpf/<name>.bpf.o` is embedded into the binary as a `.rodata`
blob. The pattern in `util/loader.c`:

```c
// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 */

asm(".section .rodata, \"a\"\n"
    ".global shirudo_bpf2_o; shirudo_bpf2_o:\n"
    ".incbin \"bpf/bpf2.bpf.o\"\n"
    ".global shirudo_bpf2_o_end; shirudo_bpf2_o_end:\n"
    ".previous\n");

asm(".section .rodata, \"a\"\n"
    ".global shirudo_unload_bpf_o; shirudo_unload_bpf_o:\n"
    ".incbin \"bpf/unload.bpf.o\"\n"
    ".global shirudo_unload_bpf_o_end; shirudo_unload_bpf_o_end:\n"
    ".previous\n");

extern const char shirudo_bpf2_o[], shirudo_bpf2_o_end[];
extern const char shirudo_unload_bpf_o[], shirudo_unload_bpf_o_end[];
```

Consumption from C:

```c
size_t sz = shirudo_bpf2_o_end - shirudo_bpf2_o;
struct bpf_object *obj = bpf_object__open_mem(shirudo_bpf2_o, sz, NULL);
```

Adding a new BPF program is two lines of `util/loader.c` plus one
Makefile line listing the source under `BPF_SRCS`. No skeleton
header generation, no separate header file, no per-program glue
code in `util/`.

### `vmlinux.h` generation

`bpf/vmlinux.h` is generated **once at build time** by `bpftool`
(from phase 1) dumping the host's BTF:

```make
bpf/vmlinux.h: third_party/bpf-next/tools/bpf/bpftool/bpftool
	$< btf dump file /sys/kernel/btf/vmlinux format c > $@
```

This means shirudo is built against the **build host's** kernel BTF,
which is typically what you want for a binary that targets the
machine you're building on. For cross-compile or for shipping a
binary against an older kernel:

- Either supply a pre-generated `bpf/vmlinux.h` from the target
  kernel's BTF (override the rule via `VMLINUX_H=path make`),
- Or run the build *on* the target.

CO-RE (Compile Once, Run Everywhere) BPF relocation in libbpf
handles the modest BTF drift between current upstream kernels and
their immediate predecessors — relevant when an operator builds
on one bleeding-edge kernel and the target is on a slightly
different bleeding-edge release. shirudo does not aim to support
multi-kernel-generation portability in one binary; the
bleeding-edge requirement (Goals §"Bleeding-edge kernel and
toolchain assumed") makes that a non-goal.

### Feature detection (`Makefile.config`)

`Makefile.config` emits a `config.mk` with cached probe results. The
probes:

```make
# In Makefile.config — illustrative; actual rules use $(shell) +
# pkg-config + a small probe-compile pattern.

probe-libcrypto := $(shell pkg-config --exists libcrypto && echo yes)
probe-libssh    := $(shell pkg-config --exists "libssh >= 0.10" && echo yes)
probe-libtss2   := $(shell pkg-config --exists "tss2-esys >= 4.0 tss2-tcti-device" && echo yes)
probe-libelf    := $(shell pkg-config --exists libelf && echo yes)
probe-clang-bpf := $(shell echo 'int main(void){return 0;}' | \
                     clang -target bpf -x c -c -o /dev/null - 2>/dev/null && echo yes)
probe-keyring-id := $(shell echo '#include <linux/bpf.h>' \
                     'int x = offsetof(union bpf_attr, keyring_id);' | \
                     $(CC) -xc -c -o /dev/null - 2>/dev/null && echo yes)
```

Failures are loud and actionable, and the build refuses to proceed
on any kernel/toolchain older than the current upstream — there is
no legacy-fallback path. Missing `libcrypto` halts with "install
libcrypto / openssl-dev"; missing `keyring_id` support halts with
"this kernel's UAPI headers are too old for shirudo — install
current upstream kernel headers"; missing BPF token support, missing
BPF LSM hook definitions, or any other prerequisite the current
shirudo source assumes triggers the same fail-fast pattern.

The probes run once; results are cached in `config.mk` until
`make distclean`. Editing `Makefile.config` invalidates the cache
on next `make`.

### Cross-compile

The standard kernel-style knobs apply:

```sh
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
     VMLINUX_H=path/to/target-vmlinux.h \
     PKG_CONFIG_PATH=/path/to/target-sysroot/usr/lib/pkgconfig
```

- `CROSS_COMPILE=<prefix>-` selects the compiler for userspace C.
  The toolchain must include a libelf, libcrypto, libssh, and
  libtss2 for the target architecture.
- BPF compilation uses host `clang` (not cross-compiled), with
  `-target bpf` — BPF bytecode is architecture-independent.
- `bpftool` is built for the **host** architecture (it runs on the
  build host), but only used to dump the **target** kernel's BTF
  via `VMLINUX_H`.
- For embedded targets without pkg-config or with a custom toolchain
  layout, individual `*_CFLAGS` / `*_LIBS` make variables override
  pkg-config-derived values.

`make distclean && make ARCH=... CROSS_COMPILE=... ...` from a clean
state is the supported reset. shirudo does not aim for incremental
cross-build correctness across native and cross builds in the same
tree.

### Version identity (`SHIRUDO_VERSION_ID`)

A 64-character hex SHA-256 computed at build time, embedded in the
binary as a `const char[]`, used by the pre-flight check to confirm
operator and target are running compatible versions.

It is **not** a hash of the binary file. A literal binary hash would
differ between x86_64 and arm64 builds of the same source, which
defeats the cross-architecture fleet management story. Instead the
hash captures **architecture-independent inputs** so x86_64 and
arm64 builds of the same source agree:

```make
# In Makefile.shirudo — illustrative; actual rule uses $(shell)
# defensively and handles missing git / tarball builds.

GIT_REV     := $(shell git rev-parse HEAD 2>/dev/null || cat VERSION)
GIT_DIRTY   := $(shell git diff-index --quiet HEAD 2>/dev/null || echo -dirty)
CFG_DIGEST  := $(shell sha256sum config.mk Makefile.shirudo | sha256sum | cut -c1-16)

SHIRUDO_VERSION_ID := $(shell \
    printf '%s%s|%s' "$(GIT_REV)$(GIT_DIRTY)" "$(CFG_DIGEST)" | \
    sha256sum | cut -d' ' -f1)
```

The result is written into a generated `util/version_id.c`:

```c
// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 * AUTO-GENERATED at build time. Do not edit. Do not commit.
 */

const char shirudo_version_id[] = "<64-char hex>";
```

`util/version_id.c` is rebuilt every time `make` runs (it's
`.PHONY`-equivalent — its recipe depends on git state, which the
Makefile can't easily declare). The cost is one `sha256sum`
invocation per build, sub-millisecond.

**Properties:**

- **Architecture-independent.** Same source + same `Makefile.config`
  output → same `SHIRUDO_VERSION_ID` on x86_64 and arm64. This is
  the whole point.
- **Captures source state.** `git rev-parse HEAD` is the dominant
  input. Released versions (no git tree) fall back to a `VERSION`
  file shipped in the source tarball.
- **Captures local modifications.** `git diff-index --quiet`
  appends `-dirty` to the input if the working tree has
  uncommitted changes, so a dev build with edits gets a different
  version-id from the clean commit it was based on. Dirty builds
  can only roll out against other targets running the same dirty
  build (in practice: each developer's own test target).
- **Captures build config.** `sha256sum config.mk Makefile.shirudo`
  ensures that changing feature flags (different libssh version
  requirement, different TPM index, etc.) produces a different
  version-id even if the git revision is identical.
- **Not a security boundary.** A malicious shirudo on a target can
  return any `version_id` it wants. The check exists to detect
  benign version skew, not adversarial substitution. Adversarial
  substitution requires distribution-level binary signing (RPM /
  dpkg-sig / cosign / measured boot) — see threat-model.rst.

**Exposed via:** `shirudo version --version-id`, `shirudo status
--json` includes `"version_id": "..."`, and every failure report's
JSON includes the target's `version_id` for audit traceability.

### In-tree JSON parser and emitter

shirudo refuses general-purpose JSON libraries (`cJSON`, `json-c`,
…) for the supply-chain reasons listed in
§"Goals & non-goals — Minimal vetted library dependencies", and
instead ships a small in-tree pair under `util/json.{c,h}`
(BSD-2-Clause, ~400 LOC together):

- **Emitter** (`json_emit_*` API) — used by every `--report=`
  path, by `shirudo upatch info --json`, by `shirudo status
  --json`, by `shirudo nodes --json`, by `shirudo remote list
  --json`, and by the eventlog writer. Streaming, RFC 8259-
  compliant, escapes per spec, does not allocate (caller
  supplies the output buffer). Refuses to emit non-UTF-8 byte
  sequences in string values — the caller must pre-sanitise
  via `pr_safe()` (Logging section) before handing arbitrary
  bytes to the emitter.
- **Bounded-schema parser** (`json_parse_*` API) — used **only**
  to parse JSON shirudo itself emitted on the other end of an
  SSH channel: the per-target `shirudo upatch load --report=-`
  documents that `shirudo rollout` aggregates into its own
  report; the `shirudo status --json --include-tpm` documents
  that `shirudo nodes` aggregates over libssh exec channels;
  the eventlog lines that boot-restore consults. The parser is
  **not** a generic JSON deserialiser:

  - It is invoked through a *schema callback* — the caller
    declares the expected key-name / type for each field, and
    the parser dispatches found values into the caller's
    fields. Unknown keys are skipped silently (forward-
    compatible), missing required keys are a parse error,
    type-mismatched values are a parse error.
  - Maximum input size is a compile-time `SHIRUDO_JSON_MAX_BYTES`
    (default 8 MiB — large enough for a 1 MiB verifier log
    plus surrounding fields, small enough to bound memory).
  - Maximum nesting depth is `SHIRUDO_JSON_MAX_DEPTH`
    (default 32). Deeper inputs are rejected.
  - Number values are parsed as `int64_t`; floats are not
    supported (shirudo doesn't emit them either).
  - Strings are bounded to `SHIRUDO_JSON_MAX_STRING_BYTES`
    (default 16 MiB, raised for the verifier_log field via a
    per-key override mechanism in the schema).

  These bounds make the parser non-recursive in practice
  (depth-bounded loop) and bound the memory + CPU cost of any
  single document. Pairing with the fuzzer harness in
  `t/helper/test-json-parser.c` (LLVMFuzzer-compatible, ~30
  LOC) makes the input-handling surface continuously
  testable.

- **What the parser does not do**: it does not deserialise
  arbitrary JSON into a generic tree. It does not handle JSON
  Pointer, JSON Patch, JSON Schema, or any other JSON-adjacent
  spec. It does not parse YAML or TOML — those formats are not
  used anywhere in shirudo.

The two halves (emitter, parser) link into both the core
`shirudo` binary and `shirudo-build`. They have no external
dependencies beyond `libc`. The parser's schema-callback API
keeps every consumer of inbound JSON pinned to a specific
field set at compile time, which is what makes the in-tree
approach defensible — the parser is small because the consumer
side is constrained.

**Why not a third-party parser**: every general-purpose JSON
parser shirudo could link (`cJSON`, `json-c`, `jansson`,
`yyjson`) carries one or more historical CVEs in its
deserialisation path, and the API surface includes
features shirudo doesn't need (deep-nest stack-overflow
defenses, allocator hooks, comment parsing, BOM handling,
streaming, etc). The cost of writing ~400 LOC of BSD-2-Clause
parser-emitter pair, fuzzed, paired with a fixed schema, is
lower than the cost of vetting and tracking a third-party
parser's release cycle and CVE feed.

### Cross-architecture support

shirudo's MVP supports **x86_64** and **arm64** target nodes, with
either architecture on either side of the operator/target split.
Both are little-endian, which makes the on-disk `.upatch` format
(defined as little-endian throughout) interchangeable. JSON over
SSH is text and architecture-neutral. SHA-256, RSA, and the kernel
BPF signature path are all architecture-neutral.

**riscv64 is deferred**, not blocked. It is also little-endian; the
same build approach should work; the only reason to defer is that
nobody has put a riscv64 target into the CI matrix yet, and the
test surface needs that signal before shirudo claims support.

What the cross-arch story does **not** include:

- Big-endian targets (s390x, classic ppc64, some MIPS). The
  `.upatch` format would need byte-swapping at parse time, and the
  in-kernel signature verification path's behaviour on BE targets
  needs validation. Adding BE is a separate project.
- 32-bit targets. shirudo's userspace assumes 64-bit `size_t` and
  `uint64_t` offsets in `.upatch` headers. 32-bit support would
  require auditing every cast.

Inside an architecture, the build is hermetic:

- `clang -target bpf` produces architecture-independent BPF
  bytecode; the same `bpf/bpf2.bpf.o` runs on both x86_64 and arm64
  targets.
- Userspace C is cross-compiled the standard way
  (`make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- ...`); see the
  "Build system" subsection on cross-compile.
- The CI matrix runs the full test suite on both x86_64 and arm64
  on every push, with one cross-arch scenario (operator x86_64
  → target arm64) exercised end-to-end.

**CO-RE is mandatory for `.upatch` cross-architecture portability.**
The `bpf/bpf2.bpf.o` and `bpf/seal.bpf.o` programs that ship inside
shirudo, and every BPF program built into an `.upatch` via
`shirudo build`, must use **CO-RE relocations** (`BPF_CORE_READ`,
`__builtin_preserve_access_index`, the `vmlinux.h` macros) rather
than hard-coded struct offsets. Without this, an `.upatch` built on
operator-x86_64 against an x86_64 `vmlinux.h` will fail BTF
relocation when loaded on an arm64 target with a different `struct`
layout — surfaced as `category: btf_mismatch` rather than silent
corruption, but a build-time concern nonetheless. The
`examples/cve-2026-31431.bpf.c` example demonstrates the pattern;
`Documentation/architecture.rst` §"BPF programs" discusses the
authoring rules. `shirudo build` does **not** enforce CO-RE usage —
that is the BPF author's responsibility, and BPF that hard-codes
offsets builds and signs fine but breaks at load time on
non-matching kernels.

### Operator-only binaries and dual install targets

shirudo's "one binary, two roles" invariant covers the core
`shirudo` binary. **One auxiliary binary, `shirudo-build`, is
operator-only** — physically separate so that the no-subprocess
invariant remains absolute on every target-side code path.

The dispatch architecture is modelled on git:

| Component | Role | Ships to operator? | Ships to target? |
|---|---|---|---|
| `shirudo` | Main binary; library-only at runtime except for the single `execv` dispatch in `builtin-build.c`. | Yes | Yes |
| `shirudo-build` | The unified artifact pipeline: when given `.bpf.c`, `execv`s `clang -target bpf …` to compile (the SOLE subprocess in shirudo); when given `.bpf.o` or `--unload <name>`, skips compilation. In all three modes runs libbpf gen_loader, CMS-signs the loader bytes (links against `util/sign.c`, NOT linked into the core `shirudo` binary), serialises the `.upatch` container, writes to `-o <output>`. Installed to `$(libexecdir)/shirudo/shirudo-build`. | **Yes** | **No** |
| `clang` (+ llvm tools) | Compiles BPF source. Runtime dep of `shirudo-build`. | Yes | No |
| `vmlinux.h` | Optional, generated by the operator from the build host's BTF or supplied per-target. | Yes | No |

The core `shirudo` binary's `builtin-build.c` is intentionally
trivial — a five-line wrapper that `access()`s the libexec path and
`execv`s it (no `$PATH` lookup, no arbitrary-name resolution; one
specific target binary path, hard-coded at build time):

```c
// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */
/*
 * builtin-build.c -- dispatch to the operator-only shirudo-build.
 *
 * This is the SOLE execv site in the core shirudo binary. See
 * PLAN.md Goals & non-goals, the no-subprocess invariant, for
 * why this is the one named exception.
 */
#include "builtin.h"
#include "util/paths.h"
#include "util/log.h"
#include <unistd.h>
#include <errno.h>
#include <string.h>

int cmd_build(int argc, const char **argv)
{
	const char *path = SHIRUDO_LIBEXEC_DIR "/shirudo-build";
	char **a = (char **)argv;

	if (access(path, X_OK) != 0) {
		pr_err("'build' is an operator-only subcommand; "
		       "'%s' is not installed. Install the shirudo-build "
		       "package on the operator machine (the one with the "
		       "signing key) and re-run there.\n",
		       path);
		return 127;
	}

	a[0] = (char *)path;
	execv(path, a);
	pr_err("exec %s: %s\n", path, strerror(errno));
	return 127;
}
```

`SHIRUDO_LIBEXEC_DIR` is a compile-time constant resolved from
`Makefile.config` (`/usr/local/libexec/shirudo` by default;
overridable via `LIBEXECDIR=/usr/libexec/shirudo make` for
distribution packagers). It is **not** looked up in `$PATH`, **not**
configurable at runtime, **not** subject to environment
manipulation — it is a single immutable string baked into the
binary at build time.

#### `shirudo-build` internals

`shirudo-build` itself is ~150 LOC of plain C, structured as:

1. Parse the small argument set (input source, `-o`, `-I`, `-D`,
   `--vmlinux`, `--extra-cflags`) using shirudo's own
   `util/parse-options.{c,h}`.
2. Locate `vmlinux.h`: explicit `--vmlinux` wins, else
   `./vmlinux.h`, else `/usr/share/shirudo/vmlinux.h` (if the
   operator ran `bpftool btf dump … > /usr/share/shirudo/vmlinux.h`
   at install time), else fail with a clear error.
3. Construct the `clang` argv:

   ```
   clang -target bpf -O2 -g -Wall -Wextra
         -I <dir-of-vmlinux.h>
         -I /usr/include/bpf      (or operator-overridden path)
         <-I/-D from user>
         -c <source> -o <output>
         <--extra-cflags split on whitespace>
   ```

4. `execv` clang (one more subprocess, terminating the chain).

`shirudo-build` does **not** wrap `bpftool`, does **not** try to
auto-generate `vmlinux.h`, does **not** invoke `strip` or any
post-processing — keep the wrapper thin so the failure modes are
clang's, not shirudo's.

#### Dual install targets

```
make help                 # overview of all targets + tunable variables

make install              # common install: 'shirudo' + bash completion
                          # → /usr/local/bin/shirudo

make install-target       # install + the systemd reboot-persistence unit
                          # → /usr/lib/systemd/system/shirudo.service

make install-operator     # operator install: 'shirudo' + 'shirudo-build'
                          # → /usr/local/bin/shirudo
                          # → /usr/local/libexec/shirudo/shirudo-build

make bindeb-pkg           # build two binary .deb packages (prefix=/usr):
                          # → shirudo-target.deb   (shirudo + systemd unit)
                          # → shirudo-operator.deb (shirudo + shirudo-build)
```

Distribution packagers split into two packages:

- `shirudo` (Depends: libcrypto, libssh, libtss2) — installs the
  core binary, suitable for targets.
- `shirudo-build` (Depends: shirudo, clang, llvm) — adds the
  operator dispatcher and pulls in the toolchain.

A development workstation typically installs both; a production
target installs only `shirudo`. This packaging-level split is
load-bearing: it is what makes the "one named subprocess
exception" property physically true on every target.

The in-tree `make bindeb-pkg` target produces exactly this split
as two binary `.deb`s (mirroring the kernel's `make bindeb-pkg`):
`shirudo-target.deb` = the core binary + the systemd reboot unit
(`install-target`), and `shirudo-operator.deb` = the core binary +
`shirudo-build` + the BPF headers with `Depends: …, clang, llvm`
and **no** systemd unit (`install-operator`). It rebuilds from clean
with `prefix=/usr` so the libexec dispatch path compiled into the
binary matches where the operator package installs `shirudo-build`;
the two packages `Conflicts`/`Replaces` each other since both carry
`/usr/bin/shirudo`. The target package's `postinst` only enables the
unit — binary xattr-labelling is done by `shirudo init` itself
(it seals its own `/proc/self/exe`), so no `setfattr` hook is needed.
Dependencies are derived from the built binaries via `dpkg -S`
(`packaging/deb/depends.sh`); a distribution maintainer wanting
versioned/`shlibdeps`-quality dependencies and full archive policy
would still wrap this in a proper source package.

#### Why a separate binary instead of a compile-time flag

A compile-time flag (`make CONFIG_BUILD=1`) producing one
build-includes-clang variant and one build-no-clang variant
would also work, but it produces **two different shirudo
binaries** — losing the "one binary, two roles" invariant.
Keeping the dispatcher in a sibling binary preserves the
invariant: every target and every operator runs the exact same
`shirudo` binary; the only difference is whether the auxiliary
`shirudo-build` is installed alongside it.

### Linkage and runtime dependencies

The final `shirudo` binary is **not fully static** — that would
require static-linking libcrypto, libssh, and libtss2, all of which
distros prefer to ship dynamically (and which have their own
runtime data files). Instead:

- **Static-linked**: libbpf, libelf, libsubcmd (whiteroom), zlib.
- **Dynamic-linked**: libcrypto, libssh, libtss2-esys, libtss2-tcti-device.

ldd output on a built binary should show exactly four dynamic
dependencies (plus libc and the dynamic loader). Any more is a
build-system bug.

There is no runtime dependency on the OpenSSH client binaries
(`ssh`, `scp`, `sftp`), the tpm2-tools CLI (`tpm2_pcrextend`,
`tpm2_pcrread`), `bpftool`, `journalctl`, `dmesg`, or any other
external program — shirudo never `fork+exec`s. This is the
"No subprocesses at runtime" invariant enforced at the binary level.

The same binary ships on both sides: libssh is exercised only by
`rollout`/`status --remote` on the operator side, and
libtss2 is exercised only by `init`/`upatch load`/`upatch unload`/
`status --include-tpm` on the target side, but linking them
unconditionally keeps the build trivial and avoids `dlopen`/weak-
symbol gymnastics.

## Kernel config requirements

Required, all in the **current upstream kernel** (see Goals
§"Bleeding-edge kernel and toolchain assumed"):

```
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_LSM=y                       # and `bpf` listed in CONFIG_LSM=...
CONFIG_DEBUG_INFO_BTF=y
CONFIG_KEYS=y
CONFIG_ASYMMETRIC_KEY_TYPE=y
CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE=y
CONFIG_X509_CERTIFICATE_PARSER=y
CONFIG_PKCS7_MESSAGE_PARSER=y
CONFIG_SYSTEM_DATA_VERIFICATION=y
CONFIG_TCG_TPM=y                       # or =m, for TPM measurement
CONFIG_TCG_TIS=y                       # or similar TPM driver for the
                                       # platform (vTPM for VMs)
CONFIG_TCG_TPM2_HMAC=y                 # session security for tpm2-tss
```

**TPM 2.0 is required**, not TPM 1.2. shirudo uses `TPMA_NV_EXTEND`
NV indices and the SHA-256 NV bank, both of which are TPM 2.0
features unavailable in TPM 1.2. Hosts with only TPM 1.2 cannot
participate in shirudo's measurement chain and must use the
`--no-tpm` override (degraded mode — LSM enforces, chain not
extended). The pre-flight check (#10 in `shirudo init`) calls
`Esys_GetCapability` to confirm TPM 2.0 and refuses TPM 1.2 even if
the device node exists. Virtual TPMs (swtpm under QEMU/KVM,
Hyper-V vTPM, AWS Nitro TPM, GCP vTPM, Azure vTPM) are TPM 2.0 and
fully supported — the CI matrix exercises swtpm under QEMU on
x86_64 and arm64 to keep the vTPM path green.

The only **runtime** check at `shirudo init` is that
`/sys/kernel/security/lsm` contains `bpf`. There is no feature
probe for `keyring_id` in `union bpf_attr`, no `-E2BIG`-style
old-kernel fallback, no graceful degradation for a kernel that
lacks the signed-loader path. shirudo targets one kernel
generation — the current upstream — and refuses to attempt to
operate on anything older. Vendors who can't ship a current
kernel are not in shirudo's user base.

Build-time check: `Makefile.config` confirms that the kernel UAPI
headers expose the structures shirudo references (`keyring_id` in
`union bpf_attr`, the LSM hook signatures, the TPM character device
nodes). Missing fields fail the build with a clear "upgrade your
kernel headers to current upstream" message.

## Packaging requirements

Distributions packaging shirudo MUST honour two contracts that
shirudo's runtime depends on but which are not enforceable from
inside shirudo itself. Failing either contract leaves shirudo
unable to bootstrap on the target.

### Contract 1 — xattr-label the binary and any pre-shipped tree

After installing files under `/usr/local/bin/shirudo` (or wherever
the package places the binary) and `/var/lib/shirudo/`, the
post-install hook **must** apply the xattr
`security.bpf.shirudo` with the value of the **compiled-in**
`SHIRUDO_VERSION_ID` (64-char hex):

```sh
SHIRUDO_VERSION_ID=$(/usr/local/bin/shirudo version --version-id)
setfattr -n security.bpf.shirudo -v "$SHIRUDO_VERSION_ID" \
    /usr/local/bin/shirudo
find /var/lib/shirudo -type f -exec \
    setfattr -n security.bpf.shirudo -v "$SHIRUDO_VERSION_ID" {} \;
```

This is **load-bearing**: shirudo's filesystem-sealing LSM
(`bpf/seal.c`) authorises by reading this xattr, and shirudo's
`init` step 13(a) refuses to install seal if the shirudo binary
itself lacks the label (because that would seal shirudo out of
its own data tree on the next operation). The check fails with
`category: init_incomplete`, sub-reason
`shirudo_binary_unlabelled`, and a fix hint pointing at this
section.

The same applies to the `shirudo-build` package on the operator
side — `/usr/local/libexec/shirudo/shirudo-build` carries the
same xattr value. The two packages share the SHIRUDO_VERSION_ID
when built from the same source tree (the version-id is
architecture-stripped — see "Build system §"Version identity"").

### Contract 2 — two separate packages, one shirudo source tree

Distributions MUST ship two packages from the same shirudo source
tree:

| Package | Contents | Installs to |
|---|---|---|
| `shirudo` (core) | The `shirudo` binary, the LSM BPF programs (embedded via `.incbin`, not separate files), `/etc/shirudo/shirudo.conf.example`. | Operator host **and** target host. |
| `shirudo-build` (operator-only) | The `shirudo-build` binary at `$(libexecdir)/shirudo/shirudo-build`. Depends on `clang` / `llvm-bpf` from the distribution. | Operator host **only**. |

Reasons:

- **No subprocess invariant on the target.** `shirudo-build`
  `execv`s `clang`; if `shirudo-build` is installed on a target,
  even though the core shirudo binary won't call it, a stray
  invocation of `/usr/local/libexec/shirudo/shirudo-build` from
  somewhere else on the target would `execv` `clang`. Physical
  separation removes the possibility.
- **Smaller target surface.** A typical target without
  `shirudo-build` doesn't need `clang`, `llvm`, `libelf-devel`,
  or `linux-libc-dev`. The target package's dependency closure is
  significantly smaller, which matters on embedded edge devices.
- **Reduced operator-host risk on misconfigured targets.** If a
  target is somehow tricked into building an upatch (which would
  fail without a signing key), the operator's private signing key
  is still nowhere on the target.

The core `shirudo` binary's `builtin-build.c` is a five-line
`execv` dispatch to the hardcoded path
`$(libexecdir)/shirudo/shirudo-build`. On a target where the
`shirudo-build` package is not installed, the dispatch returns
exit 127 with a clear `'build' is an operator-only subcommand`
message. **Distributions MUST NOT** rewrite `builtin-build.c` to
fall back to `$PATH` lookup, accept a runtime override, or
auto-install `shirudo-build` as a dependency of the core
package. Those changes would defeat the physical-separation
property.

### Packaging is a distribution concern, not a shirudo concern

The shirudo project does **not** ship distribution packaging
manifests (`.spec` files, `debian/` trees, `PKGBUILD`s,
`APKBUILD`s) in-tree. The one convenience exception is the
kernel-style `make bindeb-pkg`, which assembles two binary
`.deb`s directly with `dpkg-deb` and control files generated on
the fly (`packaging/deb/`) — it ships no `debian/` source tree
and is **not** a substitute for distro-maintained source
packaging (versioned `shlibdeps` dependencies, multiarch, archive
policy remain the distribution's job). Beyond that convenience,
packaging — including the `setfattr` post-install hook that
satisfies Contract 1 — is the responsibility of each
distribution's packagers, the same way it is for every other
userspace project. shirudo's
in-tree responsibility ends at the two contracts above; how
they get satisfied is up to whoever maintains the distribution
manifests.

If a distribution's packagers want a sanity check that their
post-install hook is correct, `shirudo init`'s pre-flight
will surface a labelled-binary failure (`init_incomplete`,
sub-reason `shirudo_binary_unlabelled`) on first run — that
is the contract test.

## Critical files to reference / vendor

- `/root/bpf-next/tools/bpf/bpftool/sign.c` — **copy with attribution** as
  `util/sign.c`. Single-file CMS signer; OpenSSL deps only. Drop the
  `xlated_dumper.h`-style bpftool-local includes.
- `/root/bpf-next/tools/lib/bpf/skel_internal.h:390-410` — exact `BPF_PROG_LOAD`
  attr layout used by signed loaders.
- `/root/bpf-next/tools/lib/bpf/libbpf.h` (around `gen_loader_opts`) — API
  contract for `bpf_object__gen_loader()` (must call before `bpf_object__load()`;
  `opts.gen_hash = true` required for `excl_prog_hash`).
- `/root/bpf-next/tools/bpf/bpftool/gen.c:687-707` — reference for the
  `gen_loader` + `bpf_object__load` + sign sequence.
- `/root/bpf-next/kernel/bpf/syscall.c:2801` — signature verification path,
  confirms `keyring_id` is a serial number (not a name).
- `/root/bpf-next/include/linux/lsm_hook_defs.h:441` — `lsm/bpf` hook signature
  with `bool kernel` arg.
- `/root/bpf-next/tools/testing/selftests/bpf/verify_sig_setup.sh` — openssl
  recipe for `genkey` (2048-bit RSA, SHA-256, X.509 self-signed). Adapt the
  shell logic into C using `EVP_PKEY_keygen` + `X509_sign` directly so shirudo
  doesn't shell out to `openssl`.
- `/root/bpf-next/tools/perf/perf.c` — `cmd_struct[]` dispatch table
  **pattern** to model `shirudo.c` after. perf is GPL-2.0 (no SPDX, kernel
  default); copy nothing — the array-of-`{name, handler, help}` plus a small
  dispatch is a free idea, the bytes are ours.
- `/root/bpf-next/tools/lib/subcmd/parse-options.{h,c}` — **API model only**
  for the `OPT_*` macros and `parse_options()` entry point. Read for the
  contract; **do not copy or link** — libsubcmd is GPL-2.0. shirudo
  whiteroom-implements the subset it needs under `util/parse-options.{c,h}`
  (or wraps POSIX `getopt_long(3)`). See "Vendoring and whiteroom
  reimplementation".
- `/root/bpf-next/Documentation/process/coding-style.rst` — coding style for
  all userspace and BPF C in shirudo.
- `/root/git/` — git's own source tree, **GPL-2.0**. Consult it for
  *patterns*: porcelain/plumbing split, the `builtin/` command dispatch
  layout, signed-object handling in `gpg-interface.c`, `wt-status`-style
  structured operator output, the way `transport.c` abstracts protocols.
  shirudo's CLI deliberately echoes git's shape (`init`, `status`,
  `rollout` ≈ `push`, `keys`, `sign`), so when an interaction question is
  ambiguous the default answer is "do what git does." **Never copy git
  code or link any git library** — apply the clean-room procedure from
  "Vendoring and whiteroom reimplementation". Two further caveats: git
  shells out freely (`run-command.c`, remote helpers) — that part of its
  design is **not** a model for shirudo (see "No subprocesses at
  runtime"); and git's `parse-options.{c,h}` is libsubcmd-derived,
  GPL-2.0, same no-copy rule.

## On the code itself

Write C like it belongs in the kernel tree. Pedantic where it counts: every
error path checked, every `goto` target named for what it cleans up, no
silent fallthroughs, no trailing whitespace, no clever macros that obscure
control flow. Elegant in the kernel sense, not the academic sense — one
boring way to express each thing, and that way is the one used everywhere
else in the file.

If a snippet feels clever, delete it and write the boring version. The bar
is Linus's review aesthetic: would this merge quietly, or would there be a
thread?

For any security-relevant code path — every line of `bpf/bpf2.c`,
every `bpf()` call in `util/loader.c`, `util/sign.c`, `util/upatch.c`,
`util/keyring.c`, every TPM operation in `util/tpm.c`/`util/eventlog.c`,
the pre-flight check, the SSH path in `util/ssh.c`, the unload
directive in `bpf/unload.bpf.c` — **read the matching entry in**
`Documentation/threat-model.rst` **before writing the code, and
again at review time.** The threat model names the adversary class
each defense exists to stop and the residual risk each MVP shortcut
accepts. If the implementation does not enforce the documented
invariant, either the implementation is wrong or the threat model
is wrong — fix one of the two; never let them drift apart silently.

## Source file headers

Every C source and header file in the tree begins with an **SPDX license
identifier on the very first line**, kernel-style — no leading blank, no
file-level docstring above it, no `/* */` block when the C99 `//` form
will do. Directly below the SPDX line, a **single collective copyright
line** — `Copyright (c) 2026 Authors of shirudo` — attributing the project
as a whole. Individual contributors are recorded by git history (the
authoritative source), not by adding names to file headers. Pattern:

```c
// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 */

#include <...>
```

Makefiles and shell scripts follow the same shape with `#` comments:

```make
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
```

The lowercase `(c)` form is used uniformly (matches libbpf and most modern
kernel-tree files; uppercase `(C)` would be equally valid but consistency
matters more than the choice). The year is the year of file creation;
files do not get re-stamped on every edit — git records modification
history.

The identifier depends on what the file is:

| Path | SPDX identifier |
|---|---|
| `shirudo.c`, `builtin-*.c`, `util/*.{c,h}` (except `sign.c`), `include/shirudo/*.h`, `t/helper/*.c` | `BSD-2-Clause` |
| `bpf/bpf2.c`, `bpf/lib/*.h`, any future `bpf/*.c` | `(GPL-2.0 OR BSD-2-Clause)` — must match the runtime `_license` string the BPF verifier inspects, so the LSM hook accepts the program |
| `util/sign.c` (vendored from `/root/bpf-next/tools/bpf/bpftool/sign.c`) | `(GPL-2.0-only OR BSD-2-Clause)` — copied from upstream. **Two copyright lines** are retained in the file header, in this order: first the upstream `Copyright (C) 2025 Google LLC.` (preserved verbatim as required vendoring attribution), then `Copyright (c) 2026 Authors of shirudo` for our local edits (dropping bpftool-local includes, integrating with shirudo's logging). A trailing `/* Vendored into shirudo; see PLAN.md "Vendoring and whiteroom reimplementation". */` comment in the same block records the provenance. |
| `Makefile`, `Makefile.shirudo`, `Makefile.config`, `t/test-lib.sh`, `t/*.sh`, `ci/*.sh` | `# SPDX-License-Identifier: BSD-2-Clause` (after any `#!` shebang) |

Use the C99 `// …` form for C and headers, `# …` for Makefiles and shell
scripts. The identifier must be a single line and must use an expression
recognized by `/root/bpf-next/LICENSES/` — `(A OR B)` for dual-licensing,
never `A / B` or `A; B`. Canonical reference for the convention is the
kernel's `Documentation/process/license-rules.rst`. New files without a
valid SPDX line on line one are a review-blocker, same as missing kernel
coding style.

## Vendoring and whiteroom reimplementation

shirudo's project license is BSD-2-Clause. To keep it that way, every line
of code that ends up in the shirudo binary must be either:

(a) written fresh in this repo under BSD-2-Clause, or
(b) vendored from an upstream that is BSD-2-Clause **or has a BSD-2-Clause
    OR-branch** — e.g. libbpf at `(LGPL-2.1 OR BSD-2-Clause)`, bpftool's
    `sign.c` at `(GPL-2.0-only OR BSD-2-Clause)` — with the original SPDX
    line and copyright preserved verbatim.

Code from **perf** (`/root/bpf-next/tools/perf/`), **libsubcmd**
(`/root/bpf-next/tools/lib/subcmd/`), and **git** (`/root/git/`) is
**GPL-2.0-only**. None of it may be copied into shirudo, and none of it may
be statically linked into the shirudo binary — static-linking GPL-2.0
would relicense the whole binary. When shirudo needs functionality those
sources provide, apply the clean-room procedure:

1. **Read** the upstream source — understand the public API, the
   algorithm, the edge cases. Take notes on the *what*, not the *how*.
2. **Close** the upstream file in your editor before writing shirudo's
   version. No paste, no side-by-side comparison, no re-typing.
3. **Write** the implementation under `util/<name>.{c,h}` with a
   `// SPDX-License-Identifier: BSD-2-Clause` header. The bytes are ours;
   the implementation choices are ours.
4. **Subset.** Implement only what shirudo's subcommands actually call.
   We are not maintaining a parallel libsubcmd, run-command.c, or
   strbuf.c — we are providing the few entry points we need and no more.

US copyright protects expression, not ideas; APIs and algorithms are
ideas. The read-then-close-then-write loop is the standard clean-room
procedure used by every BSD reimplementation of a GNU/Linux utility since
the 1990s — apply it without shortcuts.

**Patterns** and architectural ideas are free to borrow openly: perf's
`cmd_struct[]` dispatch array, git's porcelain/plumbing split, the
`builtin-FOO.c` per-subcommand file layout, `wt-status`-style structured
output. Those are not copyrightable and we lean on them deliberately.

### Concrete whiteroom items in MVP

| Functionality needed | Upstream (do not copy) | shirudo file (BSD-2-Clause) |
|---|---|---|
| Subcommand option parsing — `OPT_BOOL`/`OPT_STRING`/`OPT_INTEGER`/`OPT_END`/`parse_options()` + usage/error printing | `tools/lib/subcmd/parse-options.{h,c}` (GPL-2.0) | `util/parse-options.{c,h}` — a small whiteroom of only the subset shirudo's subcommands call. **Alternative:** wrap POSIX `getopt_long(3)` (in libc, no license issue) and skip the `OPT_*` macros entirely. Either is acceptable as long as the result is BSD-2-Clause and the API our `builtin-*.c` files use is local to this repo. |
| Subcommand dispatch (`{name, fn, help}` array + main `switch`) | `tools/perf/perf.c` (GPL-2.0) | `shirudo.c` — write directly. The "array of subcommand descriptors plus a small dispatch loop" pattern is uncopyrightable. |
| String buffer / dynamic-array helpers (if needed) | git's `strbuf.c`, perf's `util/`, libsubcmd's `subcmd-util.h` (all GPL-2.0) | `util/strbuf.{c,h}` whiteroom, or just open-code with `realloc`. Don't `#include` upstream. |

## Verification (end-to-end)

After `make` succeeds and the resulting `shirudo` binary is built. Steps 1–6
run on a single target machine. Steps 7–9 demonstrate the operator/target
split.

1. **Pre-init dry run.** `./shirudo status` should report: LSM not loaded,
   keyring absent, kernel config OK (or list any missing CONFIG_). The
   action should also appear in the journal:
   `journalctl -t shirudo --since "1m ago"`.

2. **Generate keys** (operator machine).
   ```
   ./shirudo genkey
   ls -l /var/lib/shirudo/keys/   # signing_key.pem, cert.der
   openssl x509 -in /var/lib/shirudo/keys/cert.der -inform DER -text -noout
   journalctl -t shirudo          # should show genkey NOTICE entry
   ```

3. **Initialize the target.** On a target machine, with `cert.der` already
   copied to `/var/lib/shirudo/keys/` (the private key is NOT present):
   ```
   ./shirudo init
   ls -l /var/lib/shirudo/bpffs/lsm_link
   keyctl list @u                  # should show "keyring: shirudo"
   keyctl list "$(keyctl search @u keyring shirudo)"
                                   # should show one asymmetric key
   journalctl -t shirudo           # should show init NOTICE entry with
                                   # keyring serial and cert fingerprint
   ```

4. **Verify enforcement.** From userspace, try to load any unsigned BPF
   program — should fail with `EACCES`:
   ```
   ./third_party/bpf-next/tools/testing/selftests/bpf/test_progs -t bpf_iter
   # or any libbpf-based loader without signing — must fail at BPF_PROG_LOAD
   ```
   `bpftool prog show` (read-only) should still succeed.
   `BPF_OBJ_UNPIN` via the syscall must fail with `EACCES` (deferred:
   `rm /var/lib/shirudo/bpffs/lsm_link` still works today).

5. **`shirudo keys`.** Lists the cert with description, SHA-256 fingerprint,
   and validity dates.

6. **`shirudo status`.** Reports LSM attached (with prog id, link id, attach
   point), keyring present (serial + key count), kernel config OK, no
   upatches loaded.

7. **Produce a `.upatch`** (operator machine).
   ```
   ./shirudo build t/dummy.bpf.o -o t/dummy.upatch
   xxd t/dummy.upatch | head    # verify magic "SHIRUDO\0", version 1
   ```

8. **Rollout end-to-end** (operator → target).
   ```
   ./shirudo rollout t/dummy.upatch root@target.local
   ssh root@target.local 'shirudo upatch list'
                                    # shows dummy with payload_sha256 + loaded=yes
   ssh root@target.local 'journalctl -t shirudo --since "1m ago"'
                                    # shows upatch load NOTICE
   ```

9. **Tamper test** (negative). Flip one byte in `t/dummy.upatch`'s
   `loader_insns` section and re-run `shirudo upatch load` on the target.
   The kernel should reject `BPF_PROG_LOAD` with `-EKEYREJECTED`; shirudo
   should log a `LOG_WARNING` upatch-rejected event and exit non-zero.

An end-to-end smoke walk-through lives as `t/t9000-smoke.sh` in the numbered
suite (see "Testing and CI"); without `--target` set in the environment it
skips steps 7–8 and runs locally.

## Testing and CI

> **Status (deferred):** the test suite under `t/` is present and live
> (`make check`). The **CI runner infra** — the `ci/` shell tree and
> `.github/workflows/ci.yml` described in this section — has been
> **removed for now and deferred**; it needs a privileged,
> shirudo-capable (bpffs-xattr) kernel with `shirudo init` run to host
> the opt-in integration suite, which stock GitHub runners cannot
> provide. The design below is the plan for when CI is restored. See
> `TODO.claude`.

shirudo ships an automated test suite and a portable CI surface modeled on
git's design — shell-driven tests, TAP-emitting, callable from a one-screen
CI YAML on any provider. Scope for MVP is intentionally narrow: numbered
shell scripts, a tiny BSD-2-Clause test-lib, C helpers for the
security-critical negative paths, and a shared `ci/` shell tree with thin
per-provider YAML wrappers. Chainlint, `DEVELOPER=1`-style strict-warning
gating, and `GIT_TEST_*`-style configuration matrices are explicitly
deferred.

### Test suite — `t/`

Numbered shell scripts, `tNNNN-name.sh`, four-digit zero-padded prefix.
Numbering bands group by area, leaving room between for future inserts:

| Band | Area |
|---|---|
| `t00xx` | Basics, framework self-tests, util library (`util/json.{c,h}` parser + emitter round-trip, `util/selector.{c,h}` grammar, `util/parse-options.{c,h}`, `util/log.c` `pr_safe()` sanitiser, `util/conf.c` parser of `/etc/shirudo/shirudo.conf`) |
| `t01xx` | `shirudo genkey` and on-disk key material (cert+key written, modes correct, validity dates, cert-expiry threshold logic) |
| `t02xx` | `shirudo init` bootstrap: pre-flight gate (every check #1–12 exercised, including bpffs xattr round-trip probe #12 and NV-auth-attribute check #11); bpf2_bpffs_sb map create+populate+`BPF_MAP_FREEZE`; both bpf2 hook attach + pin + label (pin-then-label-no-gap invariant); seal label-walk + install; boot-restore set re-apply (per-upatch chain extensions suppressed); NV-index define with derived `auth_value`; init event extension; cross-init idempotency |
| `t03xx` | LSM enforcement: unsigned `BPF_PROG_LOAD` from userspace rejected; signed-SYSCALL-prog accepted; read-only ops survive (`BPF_PROG_QUERY`, `*_GET_FD_BY_ID`, `BPF_OBJ_GET_INFO_BY_FD`); bpf2's `lsm/inode_unlink` denies `rm` of any inode in shirudo's bpffs from non-shirudo callers; seal denies write/unlink/rename/setxattr/removexattr on `/var/lib/shirudo/` for non-shirudo callers; `kernel == true` callers always allowed (negative test under signed-loader path); LSM stacking interop with active SELinux/AppArmor on the runner |
| `t04xx` | `.upatch` container: parse / sign / load round-trip; v1 header offsets; tamper test (flip one byte → kernel rejects); LOAD vs UNLOAD-directive `flags` discrimination; `log_buf` region carries verifier output verbatim on rejection; `shirudo upatch info` reads the same field set as the writer wrote; CMS signer-cert expiry warning |
| `t05xx` | Local-observability subcommands: `shirudo status` (both target and operator modes), `shirudo keys` (keyring listing on target, on-disk cert on operator), `shirudo upatch list` (archive vs active cross-reference), `shirudo upatch info <file>` (header + signature + metadata + signer-cert validity), `shirudo version --version-id` |
| `t06xx` | `rollout` (operator → target via libssh): SFTP push, SSH exec channel, `--expect-chain` auto-derive from pre-status, `--expect-version-id` auto-derive, `--no-precheck` opt-out, `--dry-run` (resolves + pre-flights + reports without committing); strict `known_hosts` (no TOFU); refuses literal `user@host:port` (requires registered remote); per-file verb dispatch on the `DIRECTIVE_UNLOAD` flag (LOAD → `upatch load`, UNLOAD directive → `upatch unload`, batches may mix); signed-unload path: payload_sha256 match + `payload_mismatch` (via the `security.bpf.shirudo.payload` pin xattr), idempotent `already_unloaded` |
| `t07xx` | AI failure reporting: every `category` in the taxonomy produces the right JSON (`verifier_rejected`, `btf_mismatch`, `attach_target_missing`, `signature_rejected`, `keyring_missing`, `lsm_denied`, `parser_rejected`, `tpm_error`, `tampered`, `version_mismatch`, `init_incomplete`, `init_prereqs_missing`, `already_unloaded`, `payload_mismatch`, `detach_failed`, `eventlog_full`, `unknown`); verifier-log truncation marker; schema-versioned JSON documents; `util/json.{c,h}` LLVMFuzzer harness ingests adversarial inputs without crash or OOB |
| `t08xx` | TPM measurement: NV-index define with derived `auth_value`; NV-index conflict and auth-mismatch detection at pre-flight; `Esys_NV_Extend` with all three event tags (`init`, `upatch`, `unload`); pre-flight `--expect-chain` mismatch refuses extend; eventlog append atomicity; **eventlog-vs-chain replay reproduces the live NV value**; `eventlog_full` refusal; boot-restore single-event semantics (one extension regardless of set size); chain-DoS attempt by external `tpm2_nvextend` blocked by `auth_value`; swtpm under QEMU exercises the full happy path on both x86_64 and arm64 runners |
| `t09xx` | Remote registry + label selectors: `shirudo remote add/list/rm/rename/show`, drop-in `.conf` parsing, per-user vs `--system` precedence, `--label` repeatability; `util/selector.{c,h}` grammar accepts all valid expressions (`=`, `!=`, existence, non-existence, `&&`, `||`, parens), rejects malformed inputs without unbounded recursion; selector evaluation on synthetic registry sets; depth-bound on parser; `shirudo nodes` aggregation and drift labels |
| `t10xx` | `shirudo build` and `shirudo-build` dispatch: core-binary `execv` to libexec path is one-shot, no `$PATH` lookup, exits 127 when libexec is absent; `.bpf.c` → compile + gen_loader + sign + package end-to-end; `.bpf.o` → skip-compile path; `--unload <name>` directive emission; auto-located `vmlinux.h`; `--vmlinux` override; `--extra-cflags`; signing-key memory hygiene (`explicit_bzero` on `EVP_PKEY` buffers); deterministic SHIRUDO_VERSION_ID across two builds from the same source |
| `t11xx` | Third-party interop and external invariants (e.g. `bpftool prog show` works while LSM is enforcing; SELinux/AppArmor coexistence on runners with strict policy; vTPM under swtpm; CO-RE relocations exercised on a vmlinux.h from a different kernel version) |

Each script is self-contained, sources `t/test-lib.sh`, and runs in its own
trash directory under `t/trash directory.<name>/`. Tests emit **TAP** (Test
Anything Protocol), so any TAP harness drives the suite. Recommended local
runner is `prove(1)`:

```
make test                      # one-shot, sequential
prove -j 8 ./t[0-9]*.sh        # parallel, colourised progress
```

Test grammar — a shirudo-original whiteroom of git's idiom (git's
`t/test-lib.sh` is GPL-2.0; see "Vendoring and whiteroom reimplementation"):

```sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

test_description='shirudo init attaches the LSM and pins the link'

. ./test-lib.sh

test_expect_success 'genkey produces cert+key on disk' '
	shirudo genkey &&
	test -f /var/lib/shirudo/keys/signing_key.pem &&
	test -f /var/lib/shirudo/keys/cert.der
'

test_expect_success 'init attaches lsm/bpf and pins the link' '
	shirudo init &&
	test -e /var/lib/shirudo/bpffs/lsm_link
'

test_done
```

`t/test-lib.sh` provides `test_expect_success`, `test_expect_failure`,
`test_when_finished`, `test_cmp`, `test_cmp_bin`, `test_done`, and emits
TAP. The implementation is shirudo-original under BSD-2-Clause — no copy
of git's framework.

### C helpers — `t/helper/`

*The center of gravity for a security project.* Shell scripts driving the
CLI cover the happy paths and observable side effects; the *interesting*
part of testing shirudo is the negative paths — what happens when an
attacker hands the kernel a malformed signature, the wrong keyring, a
tampered loader, a malformed `.upatch` header, or a concurrent unpin
attempt. None of those are reachable from `shirudo upatch load` because
the CLI is built to do the right thing; they require raw syscalls and
byte-level artifact manipulation. The C helpers are where those tests
live.

**For a security platform, `t/helper/` is not an afterthought — it is the
primary place where enforcement is proven.**

MVP helper inventory:

**Kernel rejection — raw `bpf()` paths:**

- `test-bpf-load.c` — issues `BPF_PROG_LOAD` with caller-chosen
  `signature` / `signature_size` / `keyring_id`. Drives assertions for
  every kernel error path the verifier produces:
  - `-EKEYREJECTED` on bit-flipped signature
  - `-EKEYREJECTED` after `keyctl_unlink` removes the cert
  - `-ENOKEY` on `keyring_id` pointing at a wrong/empty keyring
  - `-EACCES` from the shirudo LSM on `prog_type != SYSCALL` or
    `signature_size == 0`
- `test-lsm-probe.c` — exhaustive userspace walk over every `bpf()`
  command, asserts `EACCES` for mutating ops (`BPF_MAP_CREATE`,
  `BPF_MAP_UPDATE_ELEM`, `BPF_LINK_CREATE`, `BPF_OBJ_PIN`,
  `BPF_OBJ_UNPIN`, `BPF_PROG_ATTACH`, `BPF_BTF_LOAD`,
  `BPF_RAW_TRACEPOINT_OPEN`, …) and success for read-only ops
  (`BPF_OBJ_GET`, `BPF_*_GET_FD_BY_ID`, `BPF_MAP_LOOKUP_*`,
  `BPF_PROG_QUERY`, `BPF_OBJ_GET_INFO_BY_FD`). This is the test that
  **codifies the LSM policy switch in `bpf/bpf2.c` as an executable
  contract** — drift between the BPF program and the test is a CI
  failure.
- `test-unpin-attempt.c` — `BPF_OBJ_UNPIN` and `unlink(2)` on
  `/var/lib/shirudo/bpffs/lsm_link`; first must fail with `EACCES` from
  the LSM, the second is documented as still working in MVP. Codifies
  the gap so the deferred "Pin-file hardening" item has a regression
  target.

**Artifact tampering:**

- `test-upatch-mutate.c` — reads a valid `.upatch`, mutates a chosen
  section (`loader_insns`, `signature`, `metadata`, header fields) at
  a chosen byte offset with a chosen value, writes it back. Driver
  for every tamper test: each shell test that asserts "kernel rejects
  this" pairs with one `test-upatch-mutate.c` invocation that crafts
  the mutation.
- `test-upatch-parse.c` — feeds bytes into `util/upatch.c`'s parser
  with malformed headers (bad magic, version mismatch, section
  offsets/sizes that overflow `size_t`, sections that overlap each
  other or the header, zero-length signature with nonzero offset, …).
  Asserts the parser fails cleanly without reading out of bounds.
  **Doubles as a libFuzzer entry point**: the same TU exposes
  `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t sz)` wrapping
  `upatch_parse()`. Compiled with `-fsanitize=fuzzer,address,undefined`
  for ad-hoc fuzz runs; not invoked by CI in MVP, but the harness lives
  in-tree so it is one `clang` flag away.

**Direct util exercise:**

- `test-keyring.c` — exercises `util/keyring.c` end-to-end without
  `shirudo init`: create the `shirudo` named keyring, add an
  asymmetric key, describe it, assert duplicate-add is detected,
  assert wrong-type rejection, assert the serial returned to userspace
  matches what `keyctl list` sees.
- `test-sign-roundtrip.c` — exercises `util/sign.c`: sign a buffer
  with a known key, verify the resulting CMS blob parses, verify the
  kernel accepts it under the same keyring. Catches regressions in the
  vendored sign.c after upstream sync.

**Race / privilege:**

- `test-init-race.c` — N threads (not processes — keep the
  no-subprocess invariant) racing the bootstrap sequence; asserts
  idempotency under concurrency: only one keyring gets created, only
  one link gets pinned, all other callers see "already initialised"
  rather than partial state.
- `test-uid-drop.c` — drops effective UID to a non-root value and
  walks `test-lsm-probe.c`'s matrix; confirms `CAP_SYS_ADMIN` is not
  load-bearing for the *deny* paths (the LSM rejects mutating ops
  regardless of caller privilege) and that read-only ops still work
  for unprivileged callers where the kernel would normally allow them.

Helpers link against the same `util/` static archive shirudo's binary
uses — one implementation of `util/sign.c`, `util/upatch.c`,
`util/keyring.c`, no parallel implementations in the test tree. A test
that wants to misbehave does so by passing hostile inputs to the
production code path, not by reimplementing it.

**Invariant for new features:** every mutating-side feature lands with at
least one `t/helper/test-*.c` exercising its rejection path. Adding a new
`bpf()` cmd handler in `bpf/bpf2.c` without a corresponding line in
`test-lsm-probe.c` is a review-blocker.

### CI — shell-driven, thin YAML

The same shape as git's `ci/` tree: real CI logic lives in shell, YAML is
glue. Switching providers becomes a YAML translation, not a rewrite.

```
ci/
├── lib.sh                    # job-name dispatch, distro detection
├── install-dependencies.sh   # apt/dnf/pacman: libssh, libcrypto,
│                             #   libelf, libtss2, clang, kernel-headers
├── run-build-and-tests.sh    # single entry point each provider calls
├── print-test-failures.sh    # on failure: dump t/test-results/*.out
└── run-static-checks.sh      # clang-format, sparse if available
```

The GitHub Actions workflow at `.github/workflows/ci.yml` is roughly one
screen: set `$jobname`, install deps, call `ci/run-build-and-tests.sh`.
Likewise GitLab CI or Cirrus, when they're added later. No CI provider
holds shirudo-specific logic.

**CI matrix (MVP):**

| Job | Runner | TPM | Notes |
|---|---|---|---|
| `linux-x86_64-clang` | Ubuntu 24.04 x86_64 | swtpm (vTPM under QEMU) | Primary functional and unit-test matrix; t08xx exercises chain extension end-to-end against swtpm. |
| `linux-arm64-clang` | Ubuntu 24.04 arm64 | swtpm under QEMU-arm64 | Second-arch coverage; same test suite. Cross-arch scenario (operator x86_64 → target arm64) exercised here. |
| `linux-x86_64-vtpm` | Ubuntu 24.04 x86_64 | swtpm only (no hardware path) | Pure-vTPM sanity to keep the cloud-deployment path green — most shirudo deployments in cloud environments see a vTPM, not a discrete TPM 2.0 chip. |
| static-checks | Ubuntu 24.04 x86_64 | n/a | clang-format, sparse (when available), `cargo deny`-style supply-chain lint of the static dependency set. |

Hardware-TPM coverage (discrete dTPM 2.0 chips, fTPM in firmware) is
not part of upstream CI — runners with real TPMs aren't readily
available to GitHub's free tier. Operators with hardware TPMs are
expected to run the `t08xx` band locally before deploying to a new
host class; the test suite is hermetic enough to do this without
shirudo-specific infrastructure.

## First-implementation order

Dependency-ordered plan for the first implementer. Each phase
consumes only artifacts from earlier phases; finishing a phase
leaves the tree in a buildable, testable state. The phases are
sized so that each one produces something the implementer can
demo (binary builds; subcommand prints help; subcommand
end-to-end works on a single test target; …).

Numbered phases are required to be implemented in order. Within a
phase, items can proceed in parallel.

### Phase 0 — Scaffolding (no shirudo functionality yet)

Goal: `make` succeeds, produces a `shirudo` binary that prints a
usage and exits.

- `LICENSE` (BSD-2-Clause text).
- `README.md` (brief, pointing at PLAN.md / Documentation/).
- `.gitignore`.
- `.gitmodules` referencing `/root/bpf-next` as `third_party/bpf-next/`.
- `Makefile`, `Makefile.config`, `Makefile.shirudo` (per
  "Build system" section above) — minimum needed to compile a
  single `shirudo.c` and link it. The version-id generation rule
  (writing `util/version_id.c`) ships in this phase even though
  there's nothing yet to consume it — `shirudo version` is the
  first meaningful subcommand and depends on it.
- `shirudo.c` with an empty `cmd_struct[]` and a stub `main()`
  that prints `usage: shirudo <command>` and exits.
- `builtin.h` with the forward declarations.
- `Documentation/index.rst` (referencing the existing
  `architecture.rst`, `getting-started.rst`, `threat-model.rst`).

Verification: `make && ./shirudo` prints usage and exits 1.

### Phase 1 — Foundational util library

Goal: every higher-level module has its primitives available.

- `util/log.{c,h}` — `syslog(3)` wrappers; `pr_info/warn/err/audit`.
  Everything else logs through this.
- `util/paths.{c,h}` — constant strings for
  `/var/lib/shirudo/...`, `/var/lib/shirudo/bpffs/...`,
  `~/.config/shirudo/...`, `/etc/shirudo/...`. One place to
  change all paths.
- `util/parse-options.{c,h}` — whiteroom of the OPT_BOOL,
  OPT_STRING, OPT_INTEGER, OPT_END, `parse_options()` subset
  shirudo's subcommands actually use. ~200–400 LOC BSD-2-Clause.
  Alternatively wrap POSIX `getopt_long(3)` — the choice is
  internal, the API exposed to builtins is what matters.
- `util/json.{c,h}` — in-tree JSON emitter + bounded-schema parser
  (BSD-2-Clause, ~400 LOC). Schema-callback driven, with size and
  depth bounds enforced at parse time (`SHIRUDO_JSON_MAX_BYTES`,
  `SHIRUDO_JSON_MAX_DEPTH`, `SHIRUDO_JSON_MAX_STRING_BYTES`). Paired
  with `t/helper/test-json-parser.c` (LLVMFuzzer-compatible harness)
  from the start. See "Build system §"In-tree JSON parser and
  emitter"" for the design rationale.
- `util/report.{c,h}` — failure-report assembly. Layers on top of
  `util/json.{c,h}` — defines the per-document schemas and field
  sets used by every `--report=` flow. No JSON code of its own;
  just the shirudo-specific shape.

Verification: a tiny unit-test C program under `t/helper/` that
exercises each module.

### Phase 2 — Artifact container and signing primitives

Goal: round-trip `.upatch` artifacts on disk (no kernel yet).

- `include/shirudo/upatch.h` — on-disk header definitions, magic,
  flags, offsets/sizes. Shared by every consumer of the format.
- `util/upatch.{c,h}` — parser, writer, validator (every
  malformed-input case the parser must reject). Implementation
  paired with `t/helper/test-upatch-parse.c` from the very
  beginning — the parser is the most security-sensitive piece of
  pure-userspace code in shirudo.
- `util/sign.{c,h}` — vendored from
  `/root/bpf-next/tools/bpf/bpftool/sign.c`. Drop bpftool-local
  includes; integrate with shirudo's log/error helpers. Preserve
  the dual SPDX header and Google copyright per PLAN.md "SPDX".

Verification: a `t/t04xx-*` shell test signs a fixed byte string
with a generated cert, parses the resulting `.upatch`, and
asserts the structure round-trips.

### Phase 3 — Operator-side artifact production

Goal: an operator can generate keys and produce signed `.upatch`
artifacts end-to-end without involving a target. All
artifact-producing logic lives in the operator-only `shirudo-build`
binary; the core `shirudo` binary's `builtin-build.c` is just an
`execv` dispatch (and remains the sole subprocess site).

- `builtin-genkey.c` — OpenSSL `EVP_PKEY_keygen` + `X509_sign`
  (no shelling out to `openssl(1)`). Mirrors
  `tools/testing/selftests/bpf/verify_sig_setup.sh:genkey()` in
  C. Writes `/var/lib/shirudo/keys/{signing_key.pem,cert.der}`
  with mode 0600. This is the one operator-side builtin that
  lives in the core binary — it doesn't need clang or the
  dispatcher.
- `builtin-build.c` (core binary) — five-line `execv` dispatch
  to `$(libexecdir)/shirudo/shirudo-build`. Hardcoded path, no
  `$PATH` lookup, no environment dependency. Returns exit 127
  with a clear "operator-only" message if the dispatcher is
  absent. See "Operator-only binaries and dual install targets"
  in Build system.
- `tools/shirudo-build/main.c` + `compile.c` + `package.c` +
  `vmlinux.c` — the operator-only worker binary that does the
  actual heavy lifting. Three input forms:
  1. **`.bpf.c` source** → `compile.c` `execv`s clang (the sole
     subprocess in the entire shirudo codebase) to produce a
     `.bpf.o`, then proceeds to step 2.
  2. **`.bpf.o` object** → `package.c` uses libbpf
     `bpf_object__open_mem` + `bpf_object__gen_loader` +
     `bpf_object__load` to produce loader insns, calls
     `util/sign.c` (linked here only — NOT into the core
     binary) for CMS signing, serialises a LOAD `.upatch` via
     `util/upatch.c`.
  3. **`--unload <name>`** → `package.c` reads the bundled
     `bpf/unload.bpf.o` (compiled from `bpf/unload.bpf.c` in
     phase 7), parameterises it with the target name and
     expected `payload_sha256`, signs, serialises a `.upatch`
     with the `DIRECTIVE_UNLOAD` flag bit set.
- Build-system change: `util/sign.c` is **linked only into
  `shirudo-build`**, not into the core `shirudo` binary. The
  core binary's link list excludes it. This keeps the core
  binary smaller on targets and isolates the CMS dependency to
  the operator side.

Verification: `shirudo genkey && shirudo build foo.bpf.c -o
foo.upatch && hexdump -C foo.upatch | head` shows the expected
SHIRUDO header. Also: `shirudo build foo.bpf.o -o foo.upatch`
(skip-compile path) and `shirudo build --unload foo -o
foo.unload.upatch` (unload path) both produce well-formed
`.upatch` files distinguishable by their `flags` field.

### Phase 4 — Kernel keyring and config probes

Goal: target machine can be inspected via shirudo (no LSM yet).

- The LSM/bpffs feature probes (`/sys/kernel/security/lsm` contains
  `bpf`, kernel release string) live in `util/preflight.{c,h}` — no
  legacy feature probing, shirudo assumes a current upstream kernel
  (see Goals §"Bleeding-edge kernel and toolchain assumed"). (A
  separate `util/kconfig.{c,h}` was folded into preflight.)
- `util/keyring.{c,h}` — raw `add_key(2)` / `keyctl(2)` syscalls
  via `syscall(__NR_keyctl, ...)` (no `libkeyutils` dep).
  Create/lookup/describe.
- A `/dev/kmsg` replay-window helper for the failure-report
  `dmesg_excerpt` field is **deferred** (the field is not emitted in
  MVP); when added it will be direct file I/O, no `dmesg(1)`.

Verification: `t/helper/test-keyring` creates the `shirudo`
keyring, adds an asymmetric key with the cert from phase 3,
describes it, asserts the serial matches `keyctl list @u`.

### Phase 5 — BPF LSM enforcement program

Goal: `shirudo init` runs its pre-flight gate, then (if all
checks pass) attaches the LSM and pins it.

- `util/preflight.{c,h}` — the infrastructure-prerequisite gate
  per PLAN.md §"Pre-flight checks (run by every `shirudo
  init`)". Each check is a small function returning
  `{ok|fail + diagnostic}`; the driver runs all of them and
  collects failures so the operator sees the full list at once.
  At this phase, the TPM check (#9, #10) is stubbed out as
  "unconditionally pass" and wired up properly in phase 6.
- `bpf/lib/cmd_class.h` — table classifying every `bpf()` cmd as
  read-only, mutating, or PROG_LOAD. Consumed by `bpf/bpf2.c`.
- `bpf/bpf2.c` — the LSM enforcement program itself. The policy
  table is the security spec (PLAN.md §"LSM enforcement
  policy"); cross-reference Documentation/threat-model.rst T1
  before writing this.
- `util/loader.{c,h}` — `.incbin` glue for `bpf/*.bpf.o`,
  `bpf_object__gen_loader` wrappers, the
  `BPF_PROG_LOAD + signature + BPF_PROG_TEST_RUN` sequence used
  by every signed-loader operation.
- `builtin-init.c` — driver: runs the pre-flight gate first,
  exits with `category: init_prereqs_missing` and structured
  JSON if anything failed (modulo `--no-tpm` override);
  otherwise executes the bootstrap sequence per PLAN.md
  §"Bootstrap sequence". Pin the LSM link **first**, then
  everything else may fail safely.

Verification: `shirudo init --check-only` on a test VM reports
all green; on a misconfigured VM (missing cert, no bpffs, …)
exits non-zero with the full failure list, no state changes.
`shirudo init` on a healthy VM attaches the LSM, pins it, and
from then on unsigned `bpf()` calls return EACCES. Run
`t/helper/test-lsm-probe` to walk every `bpf()` cmd and confirm
the policy.

### Phase 6 — TPM measurement

Goal: state transitions extend the NV chain; status reads it
back.

- `util/tpm.{c,h}` — `Esys_NV_DefineSpace`, `Esys_NV_Extend`,
  `Esys_NV_Read` wrappers over libtss2. Single TCTI: `device` →
  `/dev/tpmrm0`. Pure C, no `tpm2_*` CLI shell-outs.
- `util/eventlog.{c,h}` — append-only JSON-lines writer plus
  reader/replayer that reconstructs the expected chain from the
  log.
- Integrate into `builtin-init.c`: on first init, define the NV
  index; on every init, compute `set_digest` over the loaded
  upatch set (empty for first init), then extend with
  `init_event_digest = SHA256("shirudo-init\0" || cert_sha256 ||
  set_digest)`. Append the matching eventlog entry listing the
  set. See PLAN.md §"Boot-restore protocol".

Verification: after `shirudo init` (no upatches yet), the NV
chain reads as `init_event_digest` with the empty-set digest.
After a second `shirudo init` (same cert, still empty set), the
chain reads as `SHA256(first_chain || init_event_digest)`.
Eventlog replay reproduces both. With phase 7 in place, a third
`shirudo init` (cert + non-empty set restored on boot) extends
once with `init_event_digest` carrying the set's `set_digest`.

### Phase 7 — Upatch lifecycle (load + unload, with pre-flight)

Goal: a signed upatch can be loaded and unloaded under full
enforcement, measurement, and pre-flight checking.

- `bpf/unload.bpf.c` — the SYSCALL-type BPF program that opens
  a pin, verifies `payload_sha256`, and issues
  `BPF_LINK_DETACH` + `BPF_OBJ_UNPIN` from kernel context. Tiny
  (~50 LOC of BPF C). Must be implemented before `shirudo build --unload`
  can produce real UNLOAD directives (phase 3 placeholder gets
  replaced).
- `builtin-upatch.c` — router for `upatch list` / `upatch load` /
  `upatch unload`. Each subcommand:
  1. Runs the **pre-flight check** (PCR/chain read, LSM-link
     presence, keyring presence, compare against
     `--expect-chain=`).
  2. Issues `BPF_PROG_LOAD` with signature + keyring_id, runs
     loader via `BPF_PROG_TEST_RUN`.
  3. Pins the resulting link.
  4. Extends the chain.
  5. Writes the report.
- Integrate the verifier-log capture path: the
  `gen_loader_opts.log_buf` region lives inside the `.upatch`
  artifact's `log_buf` section; the in-kernel loader writes to
  it; userspace reads it back into the report's `verifier_log`
  field on rejection.

Verification: `shirudo upatch load foo.upatch` from the target
shell loads the upatch, extends the chain, writes the eventlog.
Tampering with `foo.upatch` (via `t/helper/test-upatch-mutate`)
results in `category: signature_rejected` and the chain stays
unchanged.

### Phase 8 — Network operations (libssh)

Goal: operator can push to one or more targets without touching
the targets' shells directly.

- `util/ssh.{c,h}` — libssh wrappers per PLAN.md §"rollout flow".
  Session setup, `known_hosts` verification (strict, no TOFU),
  ssh-agent auth + key fallback, SFTP push, SSH exec channel.
  Shell-quote helper for command construction.
- `util/remotes.{c,h}` — `~/.config/shirudo/remotes.d/` parser
  and writer; resolves a registered remote name to a
  `{host, user, port, labels, ...}` struct (refuses literal
  `user@host` arguments; see PLAN.md §"Remote registry — Lookup
  precedence"). Reads `label.<key>=<value>` lines into a
  `{key→value}` map per remote.
- `util/selector.{c,h}` — label-selector parser + evaluator
  per PLAN.md §"Label selectors". Recursive-descent parser
  producing an AST of `{AND, OR, atom}` nodes; evaluator takes
  the AST and a remote's label map, returns bool. ~150 LOC,
  no external dependency.
- `builtin-remote.c` — `remote add/list/rm/rename/show` plus
  the `--label key=value` repeatable flag on `add`.
- `builtin-rollout.c` — the rollout flow (load and unload, dispatched
  per file by the `DIRECTIVE_UNLOAD` flag; no separate rollback):
  resolve destinations from explicit names or `--selector` (intersect
  with `util/selector.c`), validate input artifacts, per-target SSH
  session, pre-status to capture `expected_chain`, SFTP push,
  exec `shirudo upatch load --expect-chain=...`, aggregate
  reports, return non-zero on any failure.

Verification: `shirudo remote add prod-a user@target
--label type=production`, then `shirudo rollout foo.upatch
--selector='type=production'` pushes to the registered subset.
`shirudo rollout foo.upatch user@target.local` (literal) is
**refused** with the "register first" error. End-to-end status
drift detection works via `shirudo nodes` (phase 9).

### Phase 9 — Status inspection

Goal: operators and AI agents can introspect state, locally and
remotely.

- `builtin-status.c` — three modes (local target, local
  operator, remote fan-out). On the target: read LSM link state,
  keyring, upatch list, NV chain, eventlog. On the operator:
  on-disk artifact inspection. Remote: SSH fan-out, aggregate
  drift table.
- `builtin-keys.c` — list asymmetric keys in the `shirudo`
  keyring (target) or on disk (operator).
- `--expect=<hex>` and `--expect-sequence=<file>` drift
  comparison in `status`.

Verification: `shirudo status host-a host-b host-c` renders the
drift table per PLAN.md §"Operator-side — `shirudo status`
remote-query mode". Forcing a CHAIN-DRIFT (by extending the
chain out-of-band) makes the status exit non-zero with the
drifted host labelled.

### Phase 10 — Test suite + CI

Goal: every security-critical path has at least one regression
test; CI runs them on every push.

- `t/test-lib.sh` — whiteroom of the TAP framework.
- `t/helper/test-bpf-load.c`, `test-lsm-probe.c`,
  `test-upatch-parse.c`, `test-upatch-mutate.c`,
  `test-keyring.c`, `test-sign-roundtrip.c`,
  `test-unpin-attempt.c`, `test-init-race.c`, `test-uid-drop.c`.
- `t/tNNNN-*.sh` shell tests per the banding table in
  PLAN.md §"Testing and CI".
- `ci/lib.sh`, `install-dependencies.sh`,
  `run-build-and-tests.sh`, `print-test-failures.sh`,
  `run-static-checks.sh`.
- `.github/workflows/ci.yml` (~30 lines). The matrix runs the
  full test suite on both **x86_64** and **arm64** runners on
  every push, plus one cross-arch scenario (operator on x86_64,
  target on arm64) to exercise the architecture-stripped
  `SHIRUDO_VERSION_ID` and the SFTP/SSH round-trip across arch
  boundaries.

Verification: `make test` locally and CI on push both pass.
`test-lsm-probe.c` enforces the LSM policy table as a
regression check.

### Phase 11 — Documentation finalisation

Goal: docs match the implemented behavior; nothing stale.

- Audit `architecture.rst`, `getting-started.rst`, and
  `threat-model.rst` against the implemented code. Update
  command-line examples, file paths, version numbers, and
  failure-category lists if anything drifted.
- Trim PLAN.md: remove "Open questions" entries that have been
  resolved during implementation; move resolved deferred items
  to a "Done in MVP" section if useful for review.
- Top-level `README.md` becomes the canonical entry point,
  pointing at the three Documentation/ files and PLAN.md.

Verification: a fresh reader can install, build, init, sign,
roll out, and roll back following only `getting-started.rst`,
without consulting PLAN.md or source.

### Estimated effort

Rough order-of-magnitude effort, in person-days for a single
experienced kernel/BPF C developer:

- Phases 0–4: ~5 days. Mostly mechanical scaffolding plus the
  OpenSSL X.509 code and the keyring/preflight glue.
- Phases 5–7: ~10 days. The LSM enforcement program needs careful
  review against threat-model.rst; gen_loader integration and
  TPM measurement each have their own complexity.
- Phase 8: ~5 days. libssh has a moderate learning curve; the
  remote registry is straightforward.
- Phases 9–10: ~5 days. Status logic plus initial test coverage.
- Phase 11: ~2 days.

Total: ~4 weeks of focused work for MVP. Multiple developers can
parallelise within phases (e.g., one on the BPF program while
another on the TPM integration in phase 5–6).

## Open questions / future work (not blocking MVP)

- **Reboot persistence — DONE.** `systemd/shirudo.service` (target-only,
  installed by `make install-target`) runs `shirudo init` early in boot
  (`DefaultDependencies=no`, `After=local-fs.target`,
  `Before=sysinit.target`, `KeyringMode=inherit`). Remaining future work:
  an initramfs-stage `shirudo init` to enforce before local-fs is even
  up, fully closing threat T5.
- **Update flow.** `shirudo init --update` would re-sign a new LSM, call
  `BPF_LINK_UPDATE`, and atomically swap the program without an enforcement gap.
- **`shirudo upgrade` workflow.** Smooth in-place upgrade when
  `SHIRUDO_VERSION_ID` changes — currently the operator does a
  manual reboot or the new shirudo's init re-walks
  `/var/lib/shirudo/*` via signed-loader kernel context to
  relabel all xattrs from old to new value. A polished
  subcommand would coordinate this end-to-end and avoid the
  manual step.
- **Token integration.** `lsm/bpf_token_*` hooks could be added later to
  restrict delegated capabilities via the BPF token mechanism in
  the current upstream kernel.
- **Multi-key / rotation.** Support multiple certs in the `shirudo` keyring,
  with rotation via `shirudo keys add/remove`.
- **`TPM2_NV_Certify` attestation.** The MVP TPM design reads the
  NV chain over an SSH connection that operators trust. A
  compromised target can lie. The proper fix is `TPM2_NV_Certify`
  (the NV-index analogue of `TPM2_Quote`) signed by a
  target-resident **Attestation Key (AK)** that the operator trusts
  in advance, with a nonce supplied by the operator to prevent
  replay. Brings real complexity — AK provisioning, EK certificate
  validation, AK trust policy on the operator (vendor CA roots,
  AK revocation, AK storage). Worth it once the fleet grows past
  the size where the SSH trust boundary stops being acceptable.
- **Remote groups / wildcards.** `shirudo remote add` registers one
  remote at a time. For fleet-scale operation, a `--group` attribute
  on remotes plus `shirudo rollout foo.upatch @prod` expansion (or
  shell-glob-style `prod-*`) is the natural next step. MVP composes
  via shell loops or by listing multiple names.
- **`shirudo eventlog rotate` subcommand.** The on-disk eventlog at
  `/var/lib/shirudo/eventlog` is append-only and bounded by
  `eventlog.max_bytes` (default unlimited). When operators hit the
  bound, they currently rotate by hand (copy out, truncate in
  place under the sealed xattr permissions). A built-in
  `shirudo eventlog rotate [--archive=<path>]` subcommand would
  atomically (a) snapshot the live eventlog to the archive path,
  (b) truncate the in-place file, (c) write a single
  `"type":"eventlog_rotated"` JSON line at the new head pointing
  to the archive's path and SHA-256, (d) extend the TPM chain
  with `SHA256("shirudo-rotate\0" || archive_sha256)` so the
  rotation event is itself measured. Replay-correctness is
  preserved because the rotate event tags both ends of the
  cut — the chain after rotation incorporates the digest of the
  archived prefix, so operators can reproduce the historical
  chain by re-reading the archive. Deferred because today's
  manual rotation is sufficient for any reasonable fleet's
  eventlog growth rate (one JSON line per state transition;
  even an aggressively rolled-out fleet sees kilobytes per
  target per day).
- **Heterogeneous-fleet kernel attestation.** The current label
  scheme (`kernel="linux-6.8.0@<sha>"`) is operator-supplied
  metadata, not attested. A target running a different kernel
  than its label claims is undetected by shirudo. A follow-on
  could surface the target's actual kernel identity from
  `/proc/version` and `/sys/kernel/btf/vmlinux` BTF identity at
  `shirudo status` time, with `shirudo nodes` raising
  `KERNEL-DRIFT` when the operator's recorded label disagrees
  with the target's self-report. Not in MVP because labels are
  operational-ergonomics-only by design (PLAN.md §"Label
  selectors") and adding an attested kernel-identity layer
  would shift labels into the trust boundary.

### Stronger operator-host binding (alternatives to multi-key)

These two items are **alternatives** to the planned multi-key
support — different ways to tighten the operator-target binding
beyond the current "whoever holds the signing key is the
operator". Multi-key remains the primary planned path; these
are listed for completeness and for the case where multi-key
isn't sufficient for an organisation's threat model. See
`Documentation/threat-model.rst` §"Operator-target binding"
for the design framing.

- **SSH peer-key authorisation on the target.** Adds an
  OS-layer gate independent of the signing model: the target
  carries an allowlist of authorised operator-host SSH
  pubkeys at `/var/lib/shirudo/peers.d/<name>.conf`, populated
  by `shirudo peer add` (analogous to `shirudo remote add` on
  the operator side). At every `shirudo upatch load`/`upatch
  unload` invocation, the target reads sshd's
  `SSH_AUTH_INFO_0` / `SSH_CONNECTION` / `SSH_USER` env vars,
  extracts the connecting peer's pubkey fingerprint, and
  refuses to run if it isn't in `peers.d/`. Files sealed by
  `bpf/seal.c`. Adds operator-host identity to the target's
  enforcement layer **without** requiring per-operator certs.
  Survives signing-key sharing: even if two operator hosts
  hold copies of `signing_key.pem`, only those whose SSH
  pubkey is listed can issue operations against the target.

  Tradeoffs: (a) the env-var contract is sshd-specific
  (`SSH_AUTH_INFO_0` is an OpenSSH convention; libssh
  servers and other SSHd variants may differ); (b) shifts
  SSH key identity into shirudo's trust path — partial
  conflict with the project boundary "shirudo does not
  manage SSH keys" (see PLAN.md §"Explicitly out of scope").
  We use SSH peer info purely as an **authorisation gate**,
  not as the cryptographic trust root (the cert in the
  keyring stays the trust root). Even so, the
  out-of-scope boundary is partially crossed and that
  cost has to be paid explicitly. (c) Does not defend
  against an attacker who has root on the operator host
  — they can SSH from there using the legitimate operator's
  pubkey.

  Useful in: organisations with one shared signing key across
  many operator hosts (e.g., bastion + several admin
  workstations), where it's desirable to bind each target to
  the specific bastion that manages it.

- **Per-operator counter-signing.** The heaviest option, with
  the strongest binding. Each rollout is signed **twice**:
  once with the long-term fleet signing key (today's MVP
  flow), and once with an **ephemeral per-operator-host
  session key** whose pubkey was registered with the target
  at `shirudo init` time (or via `shirudo peer add`
  out-of-band). The target verifies both signatures: the
  fleet cert against the keyring, the session cert against a
  per-operator-host registry.

  Survives: signing-key compromise alone (attacker has the
  fleet key but not the session key of any registered
  operator); operator-host SSH compromise alone (attacker
  has SSH access but no signing key).

  Defeats: attacker who has both the fleet key AND access to
  an operator host where session-signing happens.

  Tradeoffs: doubles the signing cost per rollout (ephemeral
  keys are cheap so this is small); requires per-operator-host
  session-key generation, rotation, distribution to targets;
  requires extending `.upatch` v1 format to carry a second
  signature (or shipping a sidecar second signature). Probably
  overkill for most threat models — listed here for
  completeness and for the case where multi-key + SSH
  peer-key authorisation are both insufficient.

  Useful in: deployments where the fleet signing key is in an
  HSM (so its compromise is presumed harder than operator-host
  compromise, inverting the usual residual #1 ordering) AND
  per-operator-host attribution and revocation are mandatory.
