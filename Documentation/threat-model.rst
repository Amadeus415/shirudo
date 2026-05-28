.. SPDX-License-Identifier: BSD-2-Clause
.. Copyright (c) 2026 Authors of shirudo

==============================
shirudo security threat model
==============================

This document enumerates the threats shirudo defends against, the threats
it explicitly does not defend against, and the residual risks that remain
even when shirudo is deployed correctly. It is organized by the two
nodes in shirudo's git-style split — the **operator node**, which holds
the private signing key and produces signed BPF artifacts, and the
**target node**, which holds only the public cert and enforces "only
signed BPF runs" via a BPF LSM. Cross-cutting threats (SSH transport,
TPM, supply chain) get their own section.

Read this together with ``PLAN.md`` — the threat model assumes the
design described there.

Scope
=====

shirudo's security goal in one sentence: **on a target machine where
shirudo is active, no BPF program can be loaded, attached, or otherwise
made to mutate kernel BPF state from userspace unless it carries a valid
PKCS#7 signature against a cert held in the target's** ``shirudo``
**keyring.** The cert is installed by ``shirudo init`` and is the
operator's published trust root.

Everything in shirudo serves that property — the LSM, the signed-loader
artifact format, the keyring, the rollout/rollback path, the TPM-backed
event chain. Threats are evaluated against whether they could violate
that property or cause it to fail silently.

In scope
--------

- Unauthorized BPF load by any local user, including root.
- Unauthorized rollback of a security-critical upatch.
- Silent tampering with shirudo's runtime state between operator
  observations (TPM-backed pre-flight check).
- Concurrent operator interference and stale operator views (resolved
  through the same pre-flight check).
- Substitution of a different upatch under the same name during
  rollback (caught by ``payload_sha256`` mismatch).

Explicitly out of scope
-----------------------

- Compromise of the operator node itself. shirudo's signing key is held
  on the operator; an attacker with root on the operator can sign
  arbitrary upatches. Mitigations (HSM-backed key, multi-key,
  rotation) are listed in `Deferred mitigations`_.
- Kernel exploits — BPF verifier escape, TPM driver bug, LSM hook
  bypass via kernel vulnerability. shirudo trusts the kernel.
- Hardware attacks on the TPM (probing the chip, glitching, side
  channels). shirudo trusts the TPM.
- Supply-chain compromise of compilers (``clang``, ``gcc``), of
  libraries shirudo links (``libbpf``, ``libssh``, ``libcrypto``,
  ``libtss2``), or of the host distribution.
- Denial of service — neither against the BPF subsystem nor against
  shirudo itself. The LSM may refuse legitimate operations under
  attack; that is a feature, not a bug, but it is not protection
  against DoS.
- Network availability between operator and target. SSH is not
  available, ``rollout`` fails closed. shirudo does not provide a
  store-and-forward channel.
- Side channels in the cert/keyring/eventlog files (e.g., observing
  ``stat()`` access times). These leak operational metadata that
  shirudo does not consider sensitive.
- Confidential computing platform integrity (SEV-SNP, TDX, ARM CCA).
  shirudo runs unmodified inside a confidential VM and treats the
  platform's vTPM as a TPM 2.0 device, but does not attest to the
  CVM's launch measurement, EK/AK provisioning, or
  hypervisor-platform attestation report. Operators using shirudo
  inside CVMs are expected to correlate shirudo's chain with the
  platform's attestation out of band. See `Residual risks summary`_
  entry 11.

Target deployment range
=======================

shirudo's target nodes span an enormous range of Linux systems, and
the design is intentional about not optimising for one end at the
expense of the other. Two reference points anchor the spectrum.

Datacenter-scale fleets
-----------------------

Tens of thousands to millions of Linux servers across multiple
regions, in the style of hyperscaler production (Google, Meta,
AWS, …). **Heterogeneous in practice, not homogeneous.** Even
within a single operator's fleet, targets routinely run different
kernel versions (staged kernel rollouts, vendor-specific patches,
hardware-driven driver requirements, deferred reboots after
package upgrades), different distributions (Debian-derived,
Fedora-derived, Alpine, custom in-house builds), different
architectures (x86_64 alongside arm64 — see the embedded section
below for why operator-x86_64-to-target-arm64 is a first-class
case for this project, not a workaround), and different BPF
feature sets (older kernels missing hooks that newer ones expose).
shirudo is designed to operate across that heterogeneity as a
matter of routine — selectors over operator-supplied labels
(``--selector='kernel.release=6.8.0'``,
``--selector='kernel="linux-6.8.0@<sha>"'``) are how operators
target the specific subset that is affected by a CVE, ready for
a workaround, or compatible with a given upatch's hooks. See
PLAN.md §"Label selectors" for the operator-side semantics.

Operators — increasingly AI agents acting on their behalf — push
BPF upatches across the fleet many times per day for performance
experiments, security mitigations, observability hooks, and
partial kernel-bug workarounds.

Constraints at this scale:

- **Fleet-wide rollouts are almost never fleet-wide.** Most
  rollouts target a label-selected subset (a specific kernel
  release, a specific role, a specific region) because the
  upatch's preconditions are subset-specific. The selector
  grammar is the primary fleet-management surface.
- Fleet-wide rollouts must parallelise across operator-driven
  concurrency; per-node overhead is multiplied by fleet size.
- Per-node management state must be near zero — no agents to
  install, monitor, version-pin, or upgrade in lockstep across the
  fleet.
- Operations must be observable and auditable per-node, since the
  probability of at least one partial failure on any given
  fleet-wide rollout approaches certainty, especially under
  heterogeneity.
- The trust root (the signing key) must be a single point of
  cryptographic authority, not a per-fleet or per-region
  certificate dance.
- **No assumption of kernel uniformity.** A CVE mitigation upatch
  authored against the verifier behaviour of kernel X may fail
  ``btf_mismatch`` or ``attach_target_missing`` against kernel Y
  in the same fleet. shirudo's failure-reporting taxonomy and
  per-target reports surface this per-host so an AI agent can
  decide whether to author a kernel-Y variant, narrow the
  selector to kernel-X targets only, or wait for kernel-Y to roll
  forward to a version that exposes the needed hook.

Operator label conventions for kernel identity
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

shirudo deliberately leaves the *taxonomy* of labels to the
operator (PLAN.md §"Label selectors"), but the following
convention is recommended and assumed by the worked examples in
``getting-started.rst``:

==========================================  =======================================================
Label                                       Example value
==========================================  =======================================================
``kernel``                                  ``linux-6.8.0@c1fa0bb633e4a6b11e83ffc57fa5abe8ebb87891``
``kernel.release``                          ``6.8.0``
``kernel.arch``                             ``x86_64``
``kernel.flavor``                           ``cloud`` / ``rt`` / ``hardened`` / ``custom``
``shirudo.nodes.type``                      ``production`` / ``staging`` / ``canary``
``shirudo.nodes.location``                  ``us-east-1`` / ``eu-west-2`` / ``factory-floor-3``
``shirudo.nodes.role``                      ``database`` / ``cache`` / ``ingress`` / ``robot``
==========================================  =======================================================

The composite ``kernel`` label (``linux-<release>@<sha>``) is the
load-bearing one for CVE response — it captures the **exact
kernel source revision** the target is running, not just the
marketing release string. In operator-managed fleets that build
their own kernels, the SHA component identifies the precise
commit at the tip of the kernel branch the binary was built from
(``git -C linux rev-parse HEAD`` at build time); in vendor-kernel
deployments, it can be the vendor's published source-tarball
hash or a synthetic identifier the operator maintains.

Labels are operator-supplied and operator-trusted — see PLAN.md
§"Label selectors" for the security framing. A target running a
different kernel than its label claims is undetected by shirudo
in MVP (deferred Open Question: heterogeneous-fleet kernel
attestation). Operators must keep their config-management tool
in sync with reality, the same way they keep
``shirudo.nodes.type=production`` accurate.

Embedded Linux at the edge
--------------------------

Network switch control planes, humanoid robots, drones, industrial
controllers, telephony appliances, vehicles. shirudo's bleeding-edge
kernel requirement (see PLAN.md §"Bleeding-edge kernel and toolchain
assumed") applies equally here — embedded devices using shirudo
run **current upstream Linux**, not old vendor forks. What
distinguishes the embedded case is not kernel age but
operational reboot cost:

- Kernels are pinned to a specific (current) release for driver,
  certification, or upstream-vendor support reasons;
- Kernel updates require coordinated reboots, which are
  expensive — taking a top-of-rack switch out of service, a
  robot offline, or a drone out of the air has direct operational
  cost and may need scheduling weeks in advance.

BPF is uniquely valuable here as a **kernel-patching mechanism that
does not require a reboot**: shirudo can push a signed BPF upatch
that mitigates a newly disclosed kernel vulnerability, works around
a specific kernel bug, or adapts behaviour to a new requirement,
**without rebooting the device**. The device runs the upatch under
shirudo's signature-verified path; if the mitigation is later
superseded or rolled into a kernel update, a signed UNLOAD directive
(``shirudo upatch unload``, pushed by the same ``rollout``) removes it
cleanly, again without restart. Operators get a
kernel-fix lifecycle that is decoupled from the kernel-reboot
lifecycle, even though both ends are on current kernels.

Constraints at the edge:

- Resource footprint: every kilobyte of RAM and every microsecond
  of boot time matters. A daemon shirudo runs continuously on the
  target would be a non-starter on a 64 MB control-plane CPU or a
  battery-constrained drone.
- Reboots are expensive, sometimes forbidden by SLA. Operations
  must work without restart; rollback must work without restart.
- Connectivity is intermittent. Operators must tolerate targets
  that are reachable only in short windows, possibly behind NAT or
  carrier-grade middleboxes.
- The same trust model that scales to a datacenter fleet must
  apply at single-device scale without per-device customisation —
  no operator wants to maintain a separate threat model for the
  switch in closet 12 versus the rack in row 4.

Design properties that span both ranges
---------------------------------------

shirudo's invariants (in ``PLAN.md`` ``Goals & non-goals``) were
chosen to suit both extremes simultaneously rather than to
optimise for one and tolerate the other:

- **Agentless on the target.** No long-lived shirudo process. No
  shirudo-owned listening socket. No always-on memory baseline.
  Embedded devices pay nothing when shirudo is idle; datacenter
  operators have nothing to monitor, restart, or upgrade in
  lockstep. The only always-on infrastructure shirudo requires is
  ``sshd``, which both environments already run for general
  administration.

- **No subprocesses at runtime.** Every external operation goes
  through a linked library — OpenSSL, libssh, libtss2, libbpf. The
  runtime footprint is bounded deterministically to "the shirudo
  binary plus its dependencies" — no shell on the path, no ``ssh``
  or ``scp`` binary required, no ``tpm2_pcrread`` CLI. Predictable
  even on glibc-less embedded distributions (musl, uClibc), as long
  as the relevant library ABIs are available.

- **One signed binary, two roles.** The same shirudo binary runs on
  operator and target; role separation is by *which artifacts are
  present locally* (private key on operator, cert in the keyring on
  target), not by separate builds. Distributions package one binary
  per architecture, not one per role. **MVP supports x86_64 and
  arm64**; both are little-endian, so the on-disk artifact format
  and wire protocols work uncompromised across them. The
  ``SHIRUDO_VERSION_ID`` pre-flight check (per-build hash over
  architecture-stripped inputs) confirms operator and target are
  the same version across the arch boundary. riscv64 is deferred;
  big-endian and 32-bit targets are out of scope.

- **TPM is observable in absence, not required.** Embedded devices
  without a TPM still get the BPF-signature-enforcement guarantee;
  they lose only the chain-tamper-evidence layer (see threat T11).
  Datacenter targets with vTPM or firmware TPM get both. shirudo
  logs which mode it is in; operators can require TPM presence as
  a fleet-level policy decision rather than a shirudo-level
  hard dependency.

- **Operator/target split scales linearly.** The operator does not
  maintain per-target *state* beyond a small entry in
  ``remotes.d/``. ``shirudo rollout`` is a fan-out over libssh
  sessions; pushing to ten targets and pushing to ten million
  targets are the same operation, parallelised by the operator's
  choice of concurrency (xargs-style, GNU parallel, custom AI
  orchestrator, the operator's own thread pool). Per-target
  serialisation through the TPM chain (the pre-flight check)
  prevents concurrent operators from corrupting each other's view
  regardless of fleet size.

- **No assumption about reboots.** ``shirudo upatch load`` and
  ``shirudo upatch unload`` take effect immediately and persist until
  explicitly reverted. The reboot-persistence systemd unit is a
  deferred enhancement, not a load-bearing dependency. shirudo
  works on a system that never reboots (an in-service control
  plane) and on a system that reboots hourly (a CI fleet)
  with the same trust model.

- **TPM chain is cumulative across reboots.** A long-lived edge
  device that has been running for months accumulates a chain
  that records every state transition since first install — load,
  unload, every reboot's init event. Operators auditing
  "what has happened to this drone in the last six months?" walk
  the chain from a known root. The same property serves a
  datacenter target that rebooted twenty minutes ago: the chain
  is still continuous, the operator's expected value advances by
  a single deterministic init digest, no false-positive on the
  pre-flight check.

Threats that scale, threats that don't
--------------------------------------

Most threats in this document apply identically across the
spectrum. A handful scale differently:

- **A-root-op** (operator-host compromise) becomes catastrophic at
  fleet scale: a single compromise affects every target in the
  fleet. HSM-backed signing keys
  (see `Deferred mitigations`_) are far more important for
  large fleets than for single-device deployments.

- **A-root** on a target is per-target; the impact does not scale
  with fleet size, but the *probability of at least one
  compromised target* approaches certainty as the fleet grows.
  The TPM chain's per-target tamper evidence becomes a critical
  asset for sifting healthy from compromised hosts at scale.

- **A-physical** is concentrated at the edge — shipped devices in
  the field, customer premises, vehicles, drones in flight.
  Datacenter targets are physically defended at the perimeter;
  edge targets often are not. shirudo's TPM-backed evidence helps
  *detect* (not prevent) physical tampering; it does not
  substitute for hardware security measures appropriate to the
  form factor (secure boot, anti-tamper enclosures, secure-element
  key storage).

- **Supply chain attacks on the operator's build** are equally
  serious at any scale, but harder to recover from at fleet scale,
  since the same bad binary may have signed thousands of
  artifacts. Distribution-level operator-binary signing
  (referenced in `Trust boundaries`_) gains importance as fleet
  size and rollout frequency grow.

- **Network unreachability** is endemic at the edge and rare in
  the datacenter. The agentless model handles this gracefully —
  unreachable targets fall out of a ``rollout`` with a per-target
  failure; subsequent retries (when the target is reachable
  again) work normally. No queueing infrastructure is required.

Trust boundaries and the trusted compute base
=============================================

Once ``shirudo init`` has run on a target, **the trusted compute
base (TCB) is the Linux kernel plus shirudo itself**. Everything
else on the target — every userspace process including root-owned
ones, every other service, every user, the network, the disk
contents — is *outside* the TCB and is constrained by it.

Target-side TCB
---------------

The components that, if compromised, defeat shirudo's guarantees:

1. **The kernel.** shirudo's signature-verification path runs
   in-kernel (``bpf_prog_verify_signature()``); the LSM hooks
   that enforce policy run in-kernel; the TPM resource manager
   runs in-kernel. A compromised kernel defeats everything.
   The kernel is the platform you have, not a layer shirudo
   replaces — which is why the bleeding-edge-kernel requirement
   exists (see PLAN.md §"Bleeding-edge kernel and toolchain
   assumed"): a smaller kernel attack surface helps the whole
   stack.

2. **The shirudo binary itself.** Binary-on-disk integrity is
   **not** verified by an in-shirudo mechanism in MVP; the
   right defenses live at the distribution layer — signed
   packages, IMA appraisal, fs-verity, or measured boot — see
   "Binary integrity (on-disk shirudo)" below. Once shirudo
   has been started and ``shirudo init`` has run, the seal LSM
   (``bpf/seal.c``) prevents writes to the binary inode, and
   the process-hardening primitives in ``util/harden.c``
   prevent the running process from being ptraced or core-
   dumped by non-``CAP_SYS_PTRACE`` callers.

3. **shirudo's signed BPF programs running in the kernel.**
   ``bpf/bpf2.c`` (LSM policy) and ``bpf/seal.c`` (xattr
   filesystem sealing). Verified by the kernel's signature path
   against the cert in the keyring before loading.

4. **The cert in the** ``shirudo`` **named keyring.** The trust
   anchor that proves "this signed loader was signed by the
   right operator". Loaded by ``shirudo init`` from
   ``/var/lib/shirudo/keys/cert.der``.

5. **The TPM hardware and firmware.** Records every state
   transition into the NV-extend chain. Cannot be reset by
   userspace. Hardware attacks (probing, glitching) are out of
   scope — TPM vendors' problem.

Anything outside this list is **outside the target TCB** and
must be assumed potentially hostile to shirudo's operation:

- Every userspace process other than shirudo, including
  root-owned processes. Constrained by: LSM blocks unsigned BPF;
  xattr filesystem sealing blocks tampering with
  ``/var/lib/shirudo/``; ptrace defenses block process
  inspection; TPM chain records any state change.
- The **SSH channel from the operator**. SSH is an
  *authentication channel* — it proves the operator is who they
  say — but not a *continuously-trusted channel*. shirudo
  re-verifies every signed artifact cryptographically against
  the keyring regardless of which SSH session delivered it. A
  compromised SSH connection can only deliver artifacts the
  cert in the keyring already accepts; it cannot bypass
  signature verification.
- The disk's filesystem layout (modulo deployment-side IMA /
  dm-verity / measured-boot, which are deployment choices, not
  shirudo's).
- The network.

Operator-side TCB
-----------------

The operator TCB is meaningfully larger than the target TCB:

1. **The kernel.**
2. **The** ``shirudo`` **and** ``shirudo-build`` **binaries.**
3. **clang / llvm**, exec'd by ``shirudo-build`` — it produces
   the BPF bytes that ``shirudo build`` then signs, so it is in
   the trust path.
4. **The signing key**
   (``/var/lib/shirudo/keys/signing_key.pem``). The single most
   sensitive asset in the entire system. Anyone with access can
   produce arbitrary signed upatches that every target in the
   fleet will accept. shirudo does not protect the key beyond
   standard filesystem permissions (mode ``0600``, owner
   ``root``). Operators deploying at scale should plan to move
   the key into an HSM or equivalent — listed in
   `Deferred mitigations`_.
5. **The cert.**
6. **The operator's SSH posture** — ``ssh-agent``, on-disk SSH
   keys, ``~/.ssh/known_hosts``. shirudo inherits this as-is
   (SSH key management is explicitly out of scope, see PLAN.md
   §"Explicitly out of scope").

Most of shirudo's project-wide hardening recommendations (HSM
keys, IMA appraisal of the operator binary chain, restricted
operator-host access, audit of every signing operation) cluster
on the operator side, because the operator TCB is the larger
target.

Why the framing matters
-----------------------

Anything *in* the TCB can compromise the whole system; the goal
is to keep the TCB **minimal**, **understood**, and **hardened**.
Anything *outside* the TCB is constrained by the in-TCB
components.

Specifically:

- If a proposed change brings new userspace components into the
  target's TCB (an agent, a helper daemon, a long-lived
  process), that's a TCB-growth red flag — the
  agentless-on-target invariant (PLAN.md §"Goals & non-goals")
  exists precisely to keep this from happening.
- If a defense in shirudo turns out to require trusting
  something the threat model says is outside the TCB, the
  defense doesn't work — redesign.
- The bleeding-edge-kernel assumption is a TCB-size argument:
  current kernels have a smaller attack surface than maintaining
  legacy fallback paths would imply, and shirudo's TCB
  shrinks accordingly.

Operator-target binding
-----------------------

A common question, worth answering explicitly: *"how does the
target ensure that BPF upatches come from the operator it was
registered with?"*

In shirudo's MVP, **the binding is cryptographic, against the
signing cert installed in the target's kernel keyring**, and
operational, against whoever has SSH access. There is no
separate "operator host identity" concept in shirudo — the
target trusts whichever party holds the private key matching
the cert it carries.

The registration moment
~~~~~~~~~~~~~~~~~~~~~~~

The binding is established at **first** ``shirudo init`` on the
target:

1. The operator delivers ``cert.der`` to
   ``/var/lib/shirudo/keys/cert.der`` on the target. This is the
   only trust-establishing step that happens out-of-band (see
   `Residual risks summary`_ entry 13). After this moment,
   filesystem sealing protects the cert from in-place tamper.
2. ``shirudo init`` loads ``cert.der`` into a named kernel
   keyring (``shirudo``) under the user keyring.
3. From this instant the target's kernel signature-verification
   path consults that single cert for every
   ``BPF_PROG_LOAD``. Anything signed by the matching private
   key is accepted; anything else is refused with
   ``-EKEYREJECTED``.

The keyring holds **one** asymmetric cert in MVP. The cert IS
the operator authority. Whoever holds the matching private key
is the operator; there is no further identity check.

What this binding does and doesn't protect against
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Protected** (cryptographically, independent of SSH access):

- An attacker with root + SSH access to the target, but no
  signing key, **cannot install BPF**. The kernel rejects all
  unsigned loads; the bpf2 LSM rejects all non-SYSCALL-prog
  loads from userspace; the cert in the keyring is the only
  acceptable signer.
- An attacker who substitutes ``cert.der`` on disk **after**
  ``shirudo init`` has attached the filesystem-sealing LSM
  cannot — seal denies the write. Substitution **before** init
  attaches is residual #13.
- An attacker who tries to install their own cert into the
  ``shirudo`` keyring at runtime via ``add_key(2)``: blocked
  two ways. (1) ``shirudo init`` **seals** the keyring
  (``KEYCTL_SETPERM`` drops link/write/setattr), so no cert can
  be added to it for the boot. (2) Verification is **scoped to
  the keyring's serial** — every signed ``BPF_PROG_LOAD`` passes
  the ``shirudo`` keyring serial as ``attr.keyring_id`` rather
  than ``KEY_SPEC_USER_KEYRING``, so a cert planted *elsewhere*
  in ``@u`` is never consulted (verified: a foreign-signed
  upatch → ``ENOKEY``).
- The remaining angle is **keyring substitution**: because
  shirudo is agentless, each load re-resolves ``shirudo`` by
  *name* (``KEYCTL_SEARCH`` — there is no long-lived process
  caching the serial), so a root attacker who unlinks the real
  keyring from ``@u`` and links a fake same-named one could
  redirect that resolution. This is **mitigated**, not fully
  closed: ``init`` pins the keyring serial to
  ``/var/lib/shirudo/keyring.serial`` (under the seal) and every
  load refuses with ``category: tampered`` unless the
  resolved-by-name serial still equals the pin, converting the
  swap from a silent bypass into a fail-closed refusal. A
  complete fix needs an ``lsm/key_permission`` hook plus a new
  ``key_ref → struct key *`` kfunc — see residual #16 and
  PLAN.md §"Keyring model".

**Not protected** (operational, layered defences apply):

- An attacker who holds **a copy** of the signing key is
  indistinguishable from the legitimate operator. This is
  residual #1 (compromised operator). The target has no way to
  distinguish "the operator host that delivered ``cert.der``"
  from "any other host holding the same key".
- An attacker on the operator host itself (the host that holds
  ``signing_key.pem``) can produce arbitrary signed artifacts.
  Operator-host integrity is the deployment layer's job —
  signed packages, HSM-backed keys (deferred), restricted
  operator-host access. See `Operator-only attack surface`_.

Single-operator vs multi-operator fleets
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The MVP design assumes **one signing key per fleet** — the
fleet's targets carry that key's cert, the operator(s) holding
copies of the matching ``signing_key.pem`` are collectively
the operator authority. This is the simple, well-understood
case.

For organisations wanting **cryptographic isolation between
operators** (e.g., SRE team A manages fleet A, SRE team B
manages fleet B, and B's targets should not accept signatures
from A's key), the MVP answer is: **separate ``shirudo
genkey`` invocations per fleet**, with each fleet's targets
carrying only its own cert. Cryptographic isolation is then
free; A's key cannot produce signatures B's targets accept.
Operator hosts that manage both fleets simply hold two
``signing_key.pem`` files (under different paths or different
``$SHIRUDO_KEY_DIR``) and invoke ``shirudo build`` with the
relevant key for each rollout.

For organisations wanting **multiple operators co-managing one
fleet, each with their own revocable key** (e.g., operator A
leaves; revoke their access without rotating everyone's keys),
shirudo's MVP does not directly support it. Each target's
keyring holds one cert, and there is no in-shirudo revocation
channel. The deferred work item *Multi-key support, key
rotation, key revocation* (see `Deferred mitigations`_) covers
this case: the keyring holds N certs, each load is verified
against any of them, ``shirudo keys add/remove/rotate``
manages the lifecycle, and the eventlog records which specific
cert (and therefore which operator) was used per operation.
This shifts the "who is the operator" question from "whoever
holds *the* key" to "whoever holds *any currently-active
key*", with per-operator attribution and revocation.

Until multi-key lands, organisations that need per-operator
revocation without fleet-wide key rotation can approximate it
by using one signing key per (operator, fleet) pairing — the
isolation is real, the cost is N times the number of certs to
distribute and manage.

Operator-host identity vs signing-key holder
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A subtle but important point: **the target trusts the
signing-key holder, not a specific operator host**. If the
signing key lives on operator host O₁ and is then copied to
O₂, both hosts are equally authorised by the kernel — the
target cannot tell which host an ``.upatch`` originated from.

The SSH transport layer adds an operator-host identity check
**at session establishment**: the target's sshd authenticates
the SSH peer's pubkey against ``authorized_keys`` (the OS
layer), and shirudo on the target inherits that
authentication. So SSH provides "which operator user/host can
*invoke* ``shirudo upatch load``", and the signing cert
provides "which artifacts will be *accepted* once invoked".
The two layers compose: an attacker needs both SSH access
AND the signing key to push a successful load. shirudo
explicitly **does not** read the SSH peer's identity at
``upatch load`` time and tie it to a per-host allowlist;
that would draw SSH key management into shirudo's TCB,
which the project boundary refuses (see PLAN.md §"Explicitly
out of scope — SSH key management").

For deployments wanting a target-side enforcement of *which
operator hosts* may issue rollouts (even when the signing
key is shared across multiple hosts), two design alternatives
are tracked under `Deferred mitigations`_ — SSH peer-key
authorisation, and per-operator counter-signing. Both add
operator-host identity to the target's enforcement layer,
each with its own tradeoffs.

Implications for the deployment story
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Treat the signing key like a CA root**: one organisation,
  one (or a small number of) signing keys. Operator hosts that
  hold it are equally trusted. Key compromise is fleet-wide
  and is residual #1.
- **Separate signing keys per fleet** if you need
  cross-fleet isolation. This is free and works in MVP.
- **Multi-operator revocation is deferred** to multi-key
  support. Today's stand-in: separate keys per (operator,
  fleet) pairing.
- **SSH access is the operator-host identity layer**, not
  shirudo's responsibility. Operators who want per-host
  enforcement on the target side should look at OS-layer
  primitives (``authorized_keys``'s ``from=`` and
  ``command=`` restrictions, signed-CA SSH with per-principal
  scopes) until the deferred SSH peer-key authorisation work
  lands.

LSM coexistence with SELinux / AppArmor / SMACK / Yama
------------------------------------------------------

The Linux LSM framework stacks: every active major LSM gets a turn
at every hook, and the **most-restrictive verdict wins** — a deny
from any active LSM denies the operation regardless of what the
others would have allowed. shirudo composes cleanly with the other
major Linux LSMs:

- **shirudo never overrides another LSM's deny**, and structurally
  cannot — its hooks return either ``0`` (allow, meaning "I have no
  objection") or a negative errno (deny). The framework combines
  verdicts; shirudo's verdict is one input among several.
- **If SELinux / AppArmor / SMACK denies a** ``bpf()`` **call
  before shirudo's hook runs**, the caller sees that denial and
  shirudo never observes the attempt. shirudo's "only signed BPF
  runs" guarantee is unaffected — the stacked LSM is *more*
  restrictive, not less.
- **If a stacked LSM denies shirudo's own bootstrap operations**
  (e.g., a strict SELinux policy that doesn't allow the shirudo
  binary to write under ``/var/lib/shirudo/`` or load a
  ``BPF_PROG_TYPE_SYSCALL`` program), ``shirudo init`` fails with
  the underlying errno surfaced in the JSON report. Operators on
  policy-strict hosts must add the necessary SELinux booleans,
  AppArmor profile entries, or SMACK labels for the shirudo
  binary; shirudo ships no per-distro policy fragments in MVP.
- **Yama** (``/proc/sys/kernel/yama/ptrace_scope``) augments
  shirudo's ``PR_SET_DUMPABLE = 0`` / ``PR_SET_PTRACER = 0``
  defences in ``util/harden.c``. At Yama level ``1`` ("restricted
  ptrace") or higher, unrelated processes cannot ptrace shirudo
  even before shirudo asks Yama not to be ptraced. The two
  mechanisms compose additively.

shirudo's threat model **does not assume any LSM beyond** ``bpf``
**is active**. If others are active, they widen shirudo's effective
coverage; they do not narrow it. Conversely, if a stacked LSM
imposes broader restrictions on a target than shirudo's policy
does — e.g., SELinux blocks read-only ``bpf()`` ops that shirudo
allows — observability tools that depend on those reads stop
working on that target, but shirudo's mutating-op denial is
unaffected. The two LSMs do not need to agree on the read-only
policy.

The bleeding-edge-kernel assumption (PLAN.md §"Bleeding-edge kernel
and toolchain assumed") covers LSM stacking too: shirudo expects
the kernel to support the **major LSM stacking** model, which is
the upstream default. Single-LSM-only kernels are out of shirudo's
deployment range.

Assets
======

On the operator node
--------------------

- **The signing key** (``/var/lib/shirudo/keys/signing_key.pem``).
- **The cert** (``/var/lib/shirudo/keys/cert.der``); not secret, but
  its fingerprint identifies the operator to its fleet.
- **The remote registry** (``$XDG_CONFIG_HOME/shirudo/remotes.d/``
  and ``/etc/shirudo/remotes.d/``); routing metadata only, no
  secrets.
- **Operator's SSH credentials** (``~/.ssh/``), used to reach
  targets.
- **The set of signed but not-yet-distributed** ``.upatch`` **files**,
  if the operator pre-signs and stages.

On the target node
------------------

- **The cert** (``/var/lib/shirudo/keys/cert.der``); also stored in
  the kernel keyring after ``shirudo init``.
- **The named kernel keyring** ``shirudo`` (under ``@u``), holding
  the cert.
- **The pinned LSM link** at ``/var/lib/shirudo/bpffs/lsm_link``.
- **Per-upatch pinned links** at
  ``/var/lib/shirudo/bpffs/upatches/<name>/link``.
- **The TPM2 NV-extend index** at the configured ``SHIRUDO_NV_INDEX``
  (default ``0x01818E00``); persistent across reboots, append-only,
  non-resettable without platform auth.
- **The eventlog** (``/var/lib/shirudo/eventlog``), append-only JSON
  lines, integrity-checked by the NV chain.

The signing **private** key is never present on a target.

Adversary classes
=================

Throughout the rest of the document, the following adversary classes
are referenced by short tag:

:A-net: **Network attacker.** Can observe and inject packets between
   operator and target, but has no credentials at either end.
:A-user: **Unprivileged user on the target.** Has shell access but
   no ``CAP_SYS_ADMIN`` and not ``uid 0``.
:A-root: **Root on the target.** Full local privileges short of a
   kernel exploit. Can read and write any file, issue any syscall
   not blocked by the LSM, talk to the TPM at locality 0, kill
   processes, modify ``/etc``.
:A-root-op: **Root on the operator node.** Full local privileges on
   the operator. Has access to the signing key.
:A-physical: **Physical access to a target.** Can power-cycle,
   replace storage, attach hardware debuggers. shirudo does not
   defend against this class except where the TPM does.
:A-kernel: **Kernel-level compromise of the target.** Out of scope
   for shirudo defenses.

Operator node
=============

The operator node is where signed artifacts are produced. shirudo's
threat model assumes the operator is a single-tenant administrative
workstation or CI runner, accessible only to authorized personnel.

Threat O1 — Theft of the signing key
------------------------------------

Adversary: A-root-op, or A-user (operator) escalating to root.

Goal: Sign arbitrary BPF and load it on any target the operator's
cert is installed on, indistinguishably from legitimate operator
activity.

shirudo defense: **None beyond filesystem permissions.** The key
file is mode ``0600``, owner root. shirudo offers no key escrow,
no HSM integration, no kernel-keyring sealing in MVP.

Residual risk: **High.** This is the single most important asset
in the system. Operators should:

- Restrict who can become root on the operator machine.
- Audit operator-node access (sshd logs, ``sudo`` logs).
- Plan to move the key to an HSM as soon as practical (see
  `Deferred mitigations`_).

Threat O2 — Forgery of an unsigned upatch as signed
---------------------------------------------------

Adversary: any.

Goal: Produce a ``.upatch`` file that any target accepts without
holding the operator's private key.

shirudo defense: **PKCS#7 signature over** ``loader_insns``, **verified
in-kernel against the** ``shirudo`` **named keyring.** The kernel's
existing signature verification (``bpf_prog_verify_signature()`` in
``kernel/bpf/syscall.c``) runs before any LSM hook and is the same
code path used by the signed-skeleton loader pattern in upstream
``bpftool``. Tampering with ``loader_insns`` produces an
``-EKEYREJECTED`` from the kernel.

Residual risk: **Cryptographic.** Forgery would require breaking
RSA-2048 / SHA-256 (the default cert algorithm) or compromising the
key (O1).

Threat O3 — Malicious upatch from a compromised AI agent
--------------------------------------------------------

Adversary: A-root-op disguised as legitimate workflow; or a
compromised AI agent that has access to ``shirudo build``.

Goal: Sign an upatch that legitimately verifies but does something
harmful at runtime.

shirudo defense: **None directly.** ``shirudo build`` signs
whatever it is told to build; it does not understand BPF
semantics. Defense is out-of-band:

- Code review of BPF source before signing.
- Verifier-log inspection (the ``--report=`` JSON includes the full
  verifier log on rejection; on success, the operator can request a
  dry-run build + load to inspect the verifier output).
- Operator-side policy on which BPF programs are signable (e.g.,
  AI-generated BPF goes through a review queue before reaching
  ``shirudo build``).
- Future: SELinux/AppArmor policy on the operator restricting which
  files can be passed to ``shirudo build``.

Residual risk: **High** for AI-driven workflows. Mitigated by
process, not by shirudo. The TPM chain on each target records
exactly which upatch was applied when, so post-hoc attribution is
strong even when prevention isn't.

Threat O4 — Tampering with the remote registry
----------------------------------------------

Adversary: A-user (operator), targeting an operator running as a
different user.

Goal: Redirect a ``shirudo rollout prod-a`` to a host the attacker
controls, intercepting upatches in flight.

shirudo defense: **SSH host verification still applies.** The
remote registry contains only routing metadata
(``host``, ``user``, ``port``). The actual SSH session validates
the target's host key against ``~/.ssh/known_hosts``; an attacker
redirecting to a different host fails host verification and the
session is refused. The upatch is never transmitted.

The registry files are mode ``0600`` (per-user) or owned by root
(system-wide); standard filesystem permissions apply.

Residual risk: **Low.** Worst case is operational disruption (the
operator's rollouts fail), not data exfiltration or unauthorized
loading.

Threat O5 — Stale or replayed signed upatch
-------------------------------------------

Adversary: A-net obtaining a copy of a previously-issued
``.upatch`` file (e.g., from a target's
``/var/lib/shirudo/upatches/`` directory, which is world-readable
in MVP).

Goal: Re-apply an old upatch to a target that has since rolled it
back, restoring a previously-removed behavior.

shirudo defense: **Pre-flight TPM check.** The target's NV chain
records both the original load and the subsequent unload. The
operator's expected chain value, when issuing a fresh rollout,
reflects the current chain (with the unload event in it). An
attempt by an attacker to push the old ``.upatch`` would need to
also supply a matching ``--expect-chain=`` for the *current* chain
state — and the attacker would have to come from a valid SSH
session (they have no SSH credentials, see A-net).

If the attacker somehow has SSH access (i.e., they are no longer
A-net but A-root-op or equivalent), re-applying the old upatch
produces a new chain extension that the operator sees on the next
status check. The TPM chain is forward-progress only; replay is
recorded, not hidden.

Residual risk: **Low** as long as SSH access is controlled.
``payload_sha256`` is in the artifact header, so the operator can
also dedupe at audit time.

Threat O6 — Version skew between operator and target
----------------------------------------------------

Adversary: not adversarial — operational drift. The operator's
binary has been upgraded; some targets have not. Or the operator
is pointing a development build at a production target.

Goal: confirm the two ends are running compatible code before any
state-changing operation proceeds.

shirudo defense: **The pre-flight version-identity check.** Each
shirudo binary embeds a ``SHIRUDO_VERSION_ID`` computed at build
time from architecture-independent inputs (git commit + build
config + dirty marker). The operator's ``rollout``
auto-derives the target's ``version_id`` from a
pre-status read and includes the operator's own ``version_id`` as
the expected value when invoking ``shirudo upatch load`` on the
target. The target compares the supplied value against its own
compiled-in ``shirudo_version_id``; mismatch returns
``category: version_mismatch`` and refuses.

Residual risk: **None for benign version skew.** The check is
the cheapest pre-flight gate and runs first because a version-
skewed pair has no business doing the rest of the dance.

**This check is not a security boundary.** A malicious shirudo
binary on the target can return any ``version_id`` string it
wants — the operator has no cryptographic authority over the
target's reported value. The check addresses the routine
operational hazard, not adversarial substitution.

For adversarial binary substitution, see the cross-cutting
"Binary integrity" subsection below — distribution-level
signing, measured boot, and a TPM-attested binary identity are
the right defenses; shirudo defers to them.

Target node
===========

The target node is the production machine running the BPF LSM. Most
of shirudo's defenses are concentrated here — the assumption is that
many parties (including AI agents) interact with targets routinely,
and tampering at the target boundary must be visible.

Threat T1 — Load of unsigned BPF from userspace
-----------------------------------------------

Adversary: A-user or A-root.

Goal: Run arbitrary BPF on the target.

shirudo defense: **The** ``lsm/bpf`` **hook in** ``bpf/bpf2.c``.
For every userspace ``bpf()`` call (where the LSM hook sees
``kernel == false``), shirudo:

- Allows read-only commands (``BPF_OBJ_GET``, ``BPF_*_GET_FD_BY_ID``,
  ``BPF_MAP_LOOKUP_*``, ``BPF_PROG_QUERY``,
  ``BPF_OBJ_GET_INFO_BY_FD``) — observability stays functional.
- For ``BPF_PROG_LOAD``: denies unless ``prog_type ==
  BPF_PROG_TYPE_SYSCALL`` and ``signature_size > 0``. The kernel's
  signature verifier then runs against the ``shirudo`` keyring; a
  bad signature returns ``-EKEYREJECTED``. **This is the trust
  boundary** — no program enters the kernel from userspace without a
  valid signature.
- Allows ``BPF_LINK_CREATE`` and ``BPF_RAW_TRACEPOINT_OPEN`` (attach)
  and ``BPF_MAP_CREATE`` / ``BPF_MAP_UPDATE_ELEM`` / ``BPF_MAP_FREEZE``
  (the signed-loader data-map pattern). These are mutating, but they
  do not widen the trust boundary: attaching a program requires a
  ``prog_fd``, and the only ``prog_fd`` an adversary can obtain is for
  a program that was either signed (``BPF_PROG_LOAD`` above) or loaded
  in kernel context by a signed loader. Every attachable program is
  therefore operator-vetted; attaching one grants no new
  code-execution capability. shirudo must allow these from userspace
  because ``gen_loader`` cannot attach the program it loads and
  ``bpf_sys_bpf()`` cannot ``BPF_OBJ_PIN`` (see ``TODO.kernel`` items
  1–2): the signed loader loads the upatch program in kernel context,
  but shirudo's one-shot CLI creates and pins the link.
- Denies, with ``-EACCES`` regardless of caller privilege, **every
  command not on the allow-list above** — the policy is fail-closed
  (explicit allow-list, ``default`` denies). This includes the
  tear-down / replace and map-corruption commands
  (``BPF_LINK_DETACH``, ``BPF_LINK_UPDATE``, ``BPF_PROG_DETACH``,
  ``BPF_MAP_DELETE_ELEM``, the ``*_BATCH`` and
  ``LOOKUP_AND_DELETE`` variants, ``BPF_BTF_LOAD``) — these are how an
  adversary would detach shirudo's own links or corrupt existing state
  (see T2) — and any command a newer kernel adds that shirudo has not
  explicitly vetted (e.g. ``BPF_TOKEN_CREATE``, ``BPF_PROG_BIND_MAP``,
  ``BPF_ITER_CREATE``, ``BPF_PROG_ASSOC_STRUCT_OPS``), so a future
  mutating cmd cannot silently widen the syscall surface.
  shirudo's own infrastructure maps add a second, LSM-independent
  guard: they are ``BPF_MAP_FREEZE``-d at creation, so a userspace
  ``BPF_OBJ_GET``-then-update hits the frozen-map ``-EPERM`` even if
  the LSM verdict were bypassed.

A signed loader prog running in kernel context (``kernel == true``)
is allowed to issue any ``bpf()`` command — that is how shirudo's own
``upatch load`` / ``upatch unload`` paths load programs without
contradicting the policy.

Residual risk: **Cryptographic** for forged signatures; **none**
for direct unsigned ``bpf()`` calls. A narrow residual remains from
allowing userspace attach: an adversary with ``GET_FD_BY_ID`` access
to an already-loaded signed program could re-attach it (for program
types whose attach target is chosen at link time rather than fixed at
load — not LSM/tracing, where ``attach_btf_id`` is baked in). This
re-triggers operator-vetted code, not adversary code. A future kernel
that lets the signed loader attach + pin from kernel context
(``TODO.kernel`` item 1), or an ``exe_file``-scoped identity check on
the attach commands (the model ``bpf/seal.c`` already uses), would let
shirudo deny userspace attach again and close this residual.

Threat T2 — Detach / unpin via the LSM-allowed kernel path
----------------------------------------------------------

Adversary: A-root.

Goal: Remove a security-critical upatch (or the LSM itself) without
producing a signed UNLOAD directive.

shirudo defense: **The LSM denies** ``BPF_LINK_DETACH``,
``BPF_LINK_UPDATE``, ``BPF_OBJ_UNPIN``, ``BPF_PROG_DETACH``, and
similar mutating commands from userspace. Even root cannot drop the
link refcount through these paths.

The remaining way to drop a link refcount is to ``unlink(2)`` its
bpffs pin. ``bpf2``'s ``inode_unlink`` hook permits that **only** for
shirudo's own executable: it compares the unlinking task's
``current->mm->exe_file`` ``(dev, ino)`` against the identity recorded
in the frozen identity map at ``shirudo init``, and denies every other
caller — so root ``rm`` of the LSM pin or any upatch pin is refused,
while ``shirudo upatch unload`` (which removes a pin to detach a
program) is allowed. This is the interim, inode-flavoured form of the
``security.bpf.shirudo`` xattr identity ``bpf/seal.c`` will use; both
are defeatable only with ``CAP_SYS_RESOURCE`` ``exe_file`` spoofing
(residual #12). Because the detach happens in userspace rather than
inside the signed unload BPF (the kernel's ``bpf_sys_bpf()`` cannot
``LINK_DETACH``/``OBJ_GET``/``OBJ_PIN`` — TODO.kernel #6), a residual
remains: a root attacker holding *any* validly-signed UNLOAD directive
could repoint it to a different upatch name (unsigned unload is still
prevented; target-specificity is not yet cryptographically bound).

Residual risk in MVP: the **bpffs pins** (the LSM link and every
upatch pin) are protected **today** by ``bpf2`` itself — its
``inode_unlink`` hook refuses ``rm`` of any pin in shirudo's bpffs
from a non-shirudo executable, and ``inode_setxattr`` /
``inode_removexattr`` likewise protect each pin's
``security.bpf.shirudo.payload`` xattr. bpf2 deliberately scopes
these hooks to the bpffs superblock only.

The broader regular-fs tree under ``/var/lib/shirudo/`` (the cert,
persisted ``.upatch`` files, the eventlog) is sealed by a second LSM,
``bpf/seal.c``, attached at init just before ``lsm/bpf``:
``unlink(2)`` / ``rename(2)`` / write-mode ``open(2)`` / ``setxattr(2)``
/ ``removexattr(2)`` on any inode there from a process whose executable
does not carry the same ``security.bpf.shirudo`` label returns
``-EACCES``. ``shirudo init`` labels the binary and walks the tree
(skipping the bpffs mount) before attaching seal, and labels each new
file it later creates. So root ``rm``/``dd``/``setfattr`` of the cert,
a ``.upatch`` or the eventlog is refused, while shirudo's own binary
(which carries the label) operates normally. Distribution-layer
integrity (signed packages, IMA, dm-verity) is still what protects the
binary itself against substitution; seal protects the runtime state.

**The LSM is xattr-based, not path-based**, by deliberate design.
Path-based identity (``bpf_d_path()`` and string comparison) is
tamperable: a root attacker can present a different filesystem
view to the LSM via bind-mounts, symlinks, mount namespaces, or
TOCTOU races between path lookup and the actual operation. Inode
xattrs survive all of these — the label lives with the inode,
the LSM hook receives the inode directly, no string parsing
happens at any point. Specifically, ``bpf/seal.c`` uses
``bpf_get_dentry_xattr()`` / ``bpf_get_file_xattr()`` to read
``security.bpf.shirudo`` from both the target and the calling task's
``exe_file`` (obtained as a trusted reference via
``bpf_get_task_exe_file()``), and allows the operation iff the two
labels match (constant-time compare). The
shared value is ``SHIRUDO_VERSION_ID`` — the same constant the
operator/target version check uses — so one xattr serves both
purposes: "is this binary the authorised shirudo?" and "is this
inode under that shirudo's protection?"

This LSM does **not** defend against an attacker who replaces
the shirudo binary on disk before ``shirudo init`` has run
(threat T13 below); that gap is the distribution layer's
responsibility — signed packages, IMA appraisal, fs-verity,
measured boot.

Additional layer: every subsequent state-changing operation
triggers the **pre-flight check**, which catches any drift —

- The LSM is no longer attached at ``/var/lib/shirudo/bpffs/lsm_link``
  → ``category: tampered``, sub-message ``lsm_detached``.
- The NV chain still records the old loads/unloads but the target
  state no longer matches → operator's expected chain becomes
  invalid against the *current* state on next observation.

So even if the filesystem-sealing LSM is bypassed (it has not
been to date in shirudo's design, but as defense-in-depth we
assume it could fail), the operator's next operation refuses,
shirudo notices, investigation follows.

Threat T3 — Substitution of upatch under the same name
------------------------------------------------------

Adversary: A-root, who has detached an upatch via T2 and wants to
re-load a different (unsigned or differently-signed) program under
the same name without the operator noticing.

shirudo defense: **Two layers.**

- The detached state itself is visible via T2's detection paths
  (the NV chain recorded the original load/unload sequence; the
  attacker's re-load extends it again, so the operator's expected
  chain mismatches on next observation).
- If the attacker manages to re-load something (which would require
  a valid signature — see T1), that load records *its own*
  ``payload_sha256`` as the ``security.bpf.shirudo.payload`` xattr
  on the pin directory. A subsequent ``shirudo upatch unload``
  against the original name reads that xattr and constant-time
  compares it against the directive's expected ``payload_sha256``;
  mismatch → ``category: payload_mismatch``, detaching nothing. The
  stored value is **unforgeable**: ``bpf2``'s ``inode_setxattr`` /
  ``inode_removexattr`` hooks (the same exe-identity gate as
  ``inode_unlink``) let only shirudo's own executable set or remove
  xattrs on its bpffs, so the attacker cannot rewrite it to lie.
  (Requires the bpffs-xattr kernel patch, TODO.kernel item 7; without
  it the check degrades to *unavailable*, never wrong.)

Residual risk: two.

- The operator must observe the chain mismatch (or
  ``payload_mismatch``) promptly — as with T2.
- The *stored* payload is unforgeable, but the *expected* value the
  userspace unload compares against comes from the directive's
  metadata, which — like the target name — is **not**
  signature-covered (TODO.kernel #6). A root attacker who edits the
  unsigned metadata can realign the two. Closing this means moving
  the compare into the signed unload BPF (against its
  signature-covered ``.rodata``), which awaits the in-kernel detach
  ops. Until then ``payload_mismatch`` reliably catches
  honest/accidental substitution and any non-tampering path.

Threat T4 — TPM chain tampering
-------------------------------

Adversary: A-root.

Goal: Rewrite shirudo's measurement state so that fleet drift
detection or pre-flight checks miss tampering.

shirudo defense: **The NV-extend index.** shirudo measures into a
TPM2 NV index with ``TPMA_NV_EXTEND`` in the owner-defined range
(default ``0x01818E00``). The index:

- Is append-only by construction — every write is a hash extend,
  not an overwrite.
- Cannot be reset without ``TPM2_NV_UndefineSpace`` +
  ``TPM2_NV_DefineSpace``, which require platform-hierarchy
  authorization. On a Linux system, platform auth is set by
  firmware at boot and is **effectively unavailable post-boot** —
  there is no userspace path to platform auth.
- Survives clear of the storage hierarchy (``TPMA_NV_NO_WIPE``).

A root attacker cannot reset the chain. They can:

- Rewrite the on-disk eventlog (``/var/lib/shirudo/eventlog``).
  Caught at next status check — eventlog replay must reproduce the
  on-TPM chain; a rewritten log produces a mismatch.
- Power-cycle the machine. The chain survives. On boot, the
  deferred reboot-persistence systemd unit re-runs ``shirudo init``,
  which extends the chain by exactly one event:
  ``SHA256("shirudo-init\0" || cert_sha256 || set_digest)`` where
  ``set_digest`` is the canonical hash of the re-applied upatch
  set. An operator who knows the cert and the set on the target
  can locally compute the post-reboot chain value without
  round-tripping the target — one SHA-256 regardless of how many
  upatches.

Residual risk: **Low.** Defeating the chain requires either a TPM
firmware vulnerability (A-kernel-class, out of scope) or finding a
SHA-256 preimage for an arbitrary target value (cryptographic).

Threat T5 — Reboot to escape enforcement
----------------------------------------

Adversary: A-root.

Goal: Power-cycle to a state where shirudo's LSM is not yet
attached, then load unsigned BPF before shirudo init runs.

shirudo defense: **The deferred reboot-persistence systemd unit.**
``shirudo init`` is configured to run early in boot
(``Before=basic.target``, ``DefaultDependencies=no``), before any
other BPF-using service can call ``bpf()``. In MVP, this unit is
documented but not shipped — for now operators must arrange
ordering manually.

There is a residual **early-boot window**: between TPM init
(``TPM2_Startup``) and shirudo init completing, BPF is unrestricted.
On a normal Linux boot this window is sub-second, and nothing in a
fresh boot has shell access in it; A-root would need to have
arranged code running very early (initramfs hook, kernel parameter
abuse). That requires either a prior compromise or a UEFI/firmware
backdoor — both A-kernel-class or A-physical-class.

Future mitigation: move ``shirudo init`` into the initramfs so the
LSM is up before any pivot_root. Tracked in
``Open questions / future work``.

**Chain interaction.** Every successful boot-time init extends the
NV chain by **exactly one** event: ``SHA256("shirudo-init\0" ||
cert_sha256 || set_digest)`` where ``set_digest`` is the SHA-256
of the upatch set re-applied. The operator can predict this
extension locally (one SHA-256 per reboot, regardless of upatch
count), so legitimate reboots do not false-positive the pre-flight
chain check. A boot in which some re-apply fails leaves the chain
unchanged and ``init_complete: false`` in status — visible drift,
not silent escape.

Residual risk: **Time-bounded** to a sub-second early-boot window on
properly-configured systems; **medium** until pin-path hardening
and initramfs init land.

Threat T6 — Reset of the LSM link or upatches via filesystem
------------------------------------------------------------

See T2. Same threat, same mitigation, same deferred hardening.

Threat T7 — Concurrent operator interference
--------------------------------------------

Adversary: not adversarial per se — two legitimate operators (or AI
agents) issuing operations against the same target at overlapping
times.

Goal: Demonstrate that shirudo serializes correctly without
operator coordination.

shirudo defense: **Pre-flight TPM state check.** Each operation
embeds the operator's last-observed chain value as ``--expect-chain``.
Between two concurrent operators, the second one to act finds the
chain has advanced (because the first one's operation extended it),
mismatches the expected value, and refuses with ``category:
tampered``. The second operator then re-statuses and re-issues
with the updated expected chain.

This is optimistic concurrency control via the TPM chain. It works
without locks, without coordination, and without trusting the
operators to coordinate explicitly.

Residual risk: **None for correctness.** Operational friction: an
operator who races and loses has to redo the work. For high-volume
AI agents, this is normal — they update their expected chain from
the last report and retry.

Threat T8 — Forgery of a signed UNLOAD directive
------------------------------------------------

Adversary: A-net, A-user, or A-root on the target.

Goal: Cause shirudo to unload a security-critical upatch on a
target without operator action.

shirudo defense: **Same as T1.** UNLOAD directives are signed
``.upatch`` artifacts with the ``DIRECTIVE_UNLOAD`` flag bit. The
kernel verifies the signature against the same keyring; the target
refuses unsigned or wrongly-signed UNLOAD attempts.

Residual risk: Same cryptographic boundary as for LOAD.

Threat T9 — Suppression of audit / log events
---------------------------------------------

Adversary: A-root.

Goal: Hide shirudo's record of state changes from operators or
auditors.

shirudo defense: **The TPM chain is the durable audit record.**
The on-disk eventlog can be rewritten, but its integrity is
checked against the chain. Userspace journal logs can be rewritten
or truncated, but the chain cannot.

Residual risk: **Eventlog readability** can be denied (root
``rm /var/lib/shirudo/eventlog`` leaves the chain intact but
removes the human-readable record). Mitigation: forward
``journalctl -t shirudo`` events to a remote syslog collector;
configurable via standard systemd-journald upload, out of shirudo
scope.

In-kernel LSM denial events are currently not surfaced
(``Deferred`` in ``PLAN.md``: on-demand ringbuf drain via ``shirudo
status --include-audit``). Until that lands, an attacker who
attempts forbidden ``bpf()`` calls gets ``-EACCES`` but leaves no
shirudo-visible trace beyond the kernel's own audit log.

Threat T10 — Replay of a captured signed UNLOAD directive
---------------------------------------------------------

Adversary: A-root (or anyone who recovers a previously-issued
UNLOAD ``.upatch`` from disk).

Goal: Re-apply an old unload that the operator since reverted, or
unload an upatch that the operator currently wants loaded.

shirudo defense: **Pre-flight TPM check + payload_sha256 match.**
A captured UNLOAD references a specific ``payload_sha256`` and
``upatch_name``. If the named upatch is currently absent →
``already_unloaded`` (idempotent, no chain extend, no eventlog
entry — replay is a no-op). If the named upatch is present and the
``payload_sha256`` matches → unload succeeds, chain extends. But
the operator's pre-flight expected chain will not match if a
different operation has happened since the captured directive was
issued, so a directive-replay-without-corresponding-status-replay
fails ``tampered``.

Residual risk: **Low.** The TPM chain serializes operations; a
captured artifact is only re-applicable from an SSH-authenticated
session, and any re-application is visible in the chain.

Threat T11 — TPM absence or unavailability
------------------------------------------

Adversary: not adversarial per se — a target legitimately has no
TPM (VM without vTPM, bare-metal with TPM disabled in firmware).

Goal: Confirm shirudo degrades gracefully.

shirudo defense: **Graceful degradation.** If ``/dev/tpmrm0`` is
absent at ``shirudo init`` time, or if NV index definition fails,
shirudo logs ``LOG_WARNING "tpm not present, measurement disabled"``
and proceeds. Subsequent operations skip the TPM extend step and
the pre-flight chain check; the BPF signature path still
enforces.

This means a target without a TPM still has the "only signed BPF
runs" guarantee, but **loses the pre-flight tamper detection and
the cross-operator serialization**. Operators should treat
TPM-less targets as a separate trust tier.

Residual risk: **No regression** vs. the no-TPM baseline; **less
tamper evidence** vs. TPM-equipped targets. Operators concerned
about this can require TPMs in production.

Threat T12 — Inspection or hijack of the shirudo process via ptrace/debugger
----------------------------------------------------------------------------

Adversary: A-root.

Goal: Read shirudo's in-memory state (cert bytes, in-flight
signature buffers, embedded loader insns), inject code into
shirudo's address space, single-step through shirudo to alter
its control flow, or freeze and resume it at a chosen moment.

shirudo defense: **Process hardening** (``util/harden.c``, called
from ``main()`` before any subcommand runs):

- ``prctl(PR_SET_DUMPABLE, 0)`` — denies ptrace from any
  process without ``CAP_SYS_PTRACE``; makes
  ``/proc/<pid>/{mem,environ,maps}`` root-only.
- ``prctl(PR_SET_NO_NEW_PRIVS, 1)`` — blocks setuid escalation.
- ``prctl(PR_SET_PTRACER, 0)`` — Yama ptrace scope.
- ``setrlimit(RLIMIT_CORE, 0)`` — no core dumps.
- ``mlock`` + ``madvise(MADV_DONTDUMP)`` on sensitive buffers;
  ``explicit_bzero`` after use.

Residual risk: **Medium**. A-root with explicit ``CAP_SYS_PTRACE``
can still attach, and root with the ability to install a
malicious kernel module obviously bypasses everything. The bar
moves from "trivially attachable by any root process" to
"requires explicit ptrace privilege"; useful in CAP-restricted
environments (containers, capsh-dropped processes) and as
defense-in-depth for full-root scenarios. **This is not a
substitute for binary integrity** — an attacker who replaces
the shirudo binary on disk before ``shirudo init`` runs doesn't
need to ptrace anything (T13 below); the distribution layer is
the right defence there.

Threat T13 — In-place binary patching of the shirudo executable
----------------------------------------------------------------

Adversary: A-root with filesystem write access to
``/usr/local/bin/shirudo`` (or wherever shirudo is installed).

Goal: Modify the shirudo binary on disk to alter its behaviour —
e.g., to silently accept unsigned BPF, lie about chain values,
or substitute a different shirudo with its own keyring.

shirudo defense, runtime: **the seal LSM** (``bpf/seal.c``)
prevents writes to the shirudo binary inode once
``shirudo init`` has attached it. From that moment on, the
installed binary is immutable to any userspace caller that
isn't the running shirudo itself (matched by ``exe_file``
xattr label, constant-time compare). An attacker with root
who writes to the binary file after init runs is denied at
the LSM layer with ``-EACCES``.

shirudo defense, identity skew: ``SHIRUDO_VERSION_ID`` (a
source-state-derived constant compiled into the binary) is
compared between operator and target on every state-changing
operation; mismatch raises ``category: version_mismatch``.
**This is a version-skew guard, not a tamper detector** — a
malicious shirudo binary can return any ``version_id`` it
wants. It catches the operational hazard of "operator and
target on different builds", not adversarial substitution.

shirudo does **not** ship an in-binary self-tamper check
(no ``util/self_check.c``, no post-link stamping tool). An
earlier design considered embedding a build-time-stamped
self-hash and verifying it at startup, but the stamping tool
would not be a secret and SHA-256 is not asymmetric — a
determined attacker re-stamps the patched binary and the
check passes. Against unsophisticated tampering it would
overlap with the seal LSM; against adversarial substitution
it would provide no real defence. The complexity (a post-link
stamp tool, a ``shirudo_self_hash`` symbol with a zero-region
carve-out, a runtime sha256 of the entire binary on every
invocation) was deemed not worth the marginal value, and the
problem is delegated to the distribution layer in full.

Gap: **the window between package install and first**
``shirudo init`` **run**. During this window the binary is
on disk but the seal LSM isn't yet attached, so an attacker
with root and filesystem access can rewrite the binary or
substitute it wholesale. Once init runs, that window closes.

For the install-window gap and adversarial substitution
generally, the right defences live at the distribution
layer — see "Binary integrity (on-disk shirudo)" under
"Cross-cutting concerns" below: distribution-level package
signing (RPM-signed, dpkg-sig, cosign), IMA appraisal,
fs-verity on the installed binary, and measured boot with
TPM attestation of the userspace binary chain. shirudo
defers to them; the project does not duplicate functionality
the OS layer already provides better.

Residual risk: **Medium for adversarial substitution before
first init**, **closed by the seal LSM thereafter**. Operators
deploying shirudo are expected to install from signed
packages and to enable IMA appraisal / fs-verity / measured
boot per the deployment-hardening runbook.

Cross-cutting concerns
======================

SSH transport
-------------

shirudo uses ``libssh`` linked into the operator binary. Every
operator→target interaction goes through this path:

- **Host verification.** ``ssh_session_is_known_server()`` against
  ``~/.ssh/known_hosts``, with ``SSH_KNOWN_HOSTS_UNKNOWN`` and
  ``SSH_KNOWN_HOSTS_CHANGED`` treated as fatal. **There is no
  trust-on-first-use mode.** Operators must populate
  ``known_hosts`` via ``ssh-keyscan`` (or an out-of-band channel)
  before the first rollout to a new host.
- **Operator authentication.** ssh-agent first, then default
  on-disk keys (``~/.ssh/id_ed25519``, ``~/.ssh/id_rsa``). Password
  and keyboard-interactive auth are not attempted.
- **Target authentication.** Whatever sshd is configured to do —
  ``authorized_keys``, PAM, etc. shirudo defers entirely to sshd.

Threats inherited from SSH: anything that compromises ssh-agent,
``known_hosts``, the operator's keys, or sshd on the target.
shirudo adds no new SSH-level exposure beyond running as a libssh
client.

**SSH key management is explicitly out of scope for shirudo.** The
project is a libssh *client*, not an SSH infrastructure provider.
shirudo does not generate keys, rotate them, distribute public
keys to targets' ``authorized_keys``, manage agent forwarding,
configure jump hosts, parse ``~/.ssh/config`` beyond what libssh
does natively, or have any opinion on whether operators should be
using OpenSSH-CA-signed certificates, smart cards, hardware
tokens, Vault SSH issuance, or anything else. Operators run
whatever SSH posture they already run; shirudo piggy-backs on it,
exactly the way ``git push`` does. This is a deliberate scoping
decision (see PLAN.md §"Explicitly out of scope") — building an
SSH-management layer would duplicate functionality every operator
already has and would put shirudo in the position of having
opinions about SSH best practice, which is not its job.

The practical implication: a fleet with a healthy SSH story (keys
provisioned, ``known_hosts`` populated via whatever channel,
agent socket reachable) can use shirudo's rollout/nodes/status
without any additional setup; a fleet with a broken SSH story
sees rollout/nodes/status fail with libssh's error messages
and gets no help from shirudo on what to do next, because that
help would be SSH-domain advice that doesn't belong here.

TPM
---

shirudo uses ``libtss2-esys`` to talk to ``/dev/tpmrm0`` via the
``device`` TCTI. Threats from the TPM stack itself:

- **TPM firmware bugs.** Out of shirudo's control. Vendor firmware
  updates apply.
- **Hardware attacks on the TPM** (probing, glitching). A-physical;
  out of scope.
- **A weakly-seeded EK or AK** on a cloned/cloned-image VM. Affects
  future ``TPM2_NV_Certify`` attestation (deferred), not MVP NV
  chain integrity.
- **TPM resource manager flakiness.** ``/dev/tpmrm0`` queuing
  failures cause ``Esys_NV_Extend`` to return errors after a
  successful BPF load → ``category: tpm_error``, the BPF is loaded
  but the chain is out of sync. The operator surfaces this to a
  human; recovery is either to live with the gap (and re-extend
  manually after diagnosis) or to redefine the index.

Build and distribution
----------------------

shirudo's threat model assumes the operator binary on the operator
machine and the operator binary on the target machine are the
*same* binary — built from the same source tree, with the same
compiler, against the same libraries. Substitution of either is
out of scope (supply chain).

Specifically out of scope:

- Malicious ``clang`` / ``gcc`` / ``llvm`` — including the
  ``clang`` that the operator-side ``shirudo build`` dispatcher
  invokes. **On the operator, clang is in the trusted compute
  base alongside the signing key**: a compromised clang produces
  malicious ``.bpf.o`` artifacts that the operator then signs and
  ships fleet-wide. Mitigation lives at the operator-host-
  integrity layer (signed compiler binaries, reproducible builds,
  source-level review of BPF programs before signing) rather than
  inside shirudo. On the **target**, clang and the
  ``shirudo-build`` dispatcher are not installed at all — see
  `Operator-only attack surface`_ below.
- Malicious ``libbpf``, ``libssh``, ``libcrypto``, ``libtss2``,
  ``libelf``, ``zlib`` — the seven libraries shirudo links
  (plus ``libc``) per the explicit allowlist in PLAN.md
  §"Minimal, vetted library dependencies". Compromising any
  of these defeats shirudo, but the list is **deliberately
  small** to keep that attack surface bounded: shirudo refuses
  to take on convenience dependencies, so the supply-chain
  surface is the set of well-vetted core system libraries that
  distribution security teams already track and update on CVE
  alerts.
- Distribution package manager compromise.
- Malicious ``bpftool`` used as a build-time tool to generate
  ``vmlinux.h``.

shirudo's defense against these is process: minimal vetted
dependencies (see PLAN.md §"Minimal, vetted library
dependencies" for the explicit allowlist and the criteria used
to vet additions), build from a known source tree, link against
known versions, sign and verify the
resulting binary out-of-band (distribution-level signing).

Operator-only attack surface
----------------------------

shirudo's no-subprocess invariant has one named exception: the
operator-side ``shirudo build`` subcommand dispatches via
``execv`` to a separate ``shirudo-build`` binary, which in turn
``execv``s ``clang`` to compile BPF source. To preserve the
invariant on every target, this exception is **physically
isolated** by packaging: ``shirudo-build`` and ``clang`` ship
only with the operator package; target installs receive only the
core ``shirudo`` binary, which has no ``execv`` of any kind in
its security-critical code paths.

Consequence for the threat model:

- On the **operator**: clang, llvm, and ``shirudo-build`` are in
  the trusted compute base. A compromise of any of them is a
  compromise of the operator (threat O1 / O3 / supply-chain).
  The signing key is on the same host, so the marginal damage
  from clang compromise is bounded by what was already possible
  with operator-host compromise.
- On the **target**: zero additional attack surface. ``shirudo``
  on a target has exactly the same security properties as it
  did before ``shirudo build`` was added — the dispatcher
  binary doesn't exist, the `clang` binary doesn't exist, and
  the core ``shirudo`` binary's ``builtin-build.c`` returns
  exit 127 immediately if invoked.

Operators concerned about supply-chain risk should:

1. Install ``clang`` from signed distribution packages (catch
   pre-install tampering).
2. Use reproducible-build infrastructure if shipping their own
   ``shirudo-build`` package.
3. Review BPF source before passing it to ``shirudo build`` —
   shirudo signs whatever it is given to build; semantic review
   is out of band.
4. Consider operator-host integrity tooling (IMA appraisal,
   dm-verity, measured boot) to detect compiler substitution.

Binary integrity (on-disk shirudo)
----------------------------------

shirudo's ``SHIRUDO_VERSION_ID`` pre-flight check detects benign
version skew (operator upgraded, target didn't) but **does not
detect adversarial binary substitution**. A malicious shirudo
binary installed on the target — by an attacker who has root and
filesystem access — can simply lie about its ``version_id``,
report whatever chain value the operator expects, and silently do
whatever it wants with incoming upatches.

This is out of scope for shirudo itself. The right defenses live
at lower layers:

- **Distribution-level package signing.** Install shirudo from
  signed packages (RPM-signed, dpkg-sig, cosign-signed
  containers, vendor-signed Debian repos). Refuse to install or
  update from unsigned sources. Catch tampering at install time.
- **Filesystem integrity.** ``dm-verity`` on a read-only root
  partition, or IMA appraisal with policy that requires
  ``/usr/local/bin/shirudo`` to be measured and signed. Catch
  tampering at every read.
- **Measured boot with TPM attestation.** The kernel's IMA
  subsystem can extend PCRs with hashes of executed binaries; a
  remote attester (separate from shirudo, e.g.
  ``keylime``) can verify the PCR state via ``TPM2_Quote`` and
  confirm a known-good shirudo binary is running. Catch tampering
  at attest time.

shirudo's own NV-chain measurement records *what shirudo did*, but
relies on a non-compromised shirudo to do the measuring. Closing
the loop — proving the shirudo *binary* itself hasn't been swapped
— requires one of the layers above.

The MVP recommendation: ship shirudo via signed distribution
packages, document the recommended IMA or dm-verity setup in
operations runbooks, and treat ``version_mismatch`` as a routine-
operational signal rather than an adversarial one.

Operator-host integrity
-----------------------

shirudo does not protect the operator host. If A-root-op is in
play, the signing key is compromised and every target in the
fleet is at risk. Operators must:

- Limit who can become root on the operator machine.
- Audit operator-host access via sshd/sudo logs.
- Treat the operator host as a CA — same operational rigor.
- Plan toward HSM-backed keys (see `Deferred mitigations`_).

The shirudo project intentionally does not try to defend the
operator host with software running on the operator host —
that's the wrong layer.

Residual risks summary
======================

The residual risks shirudo's MVP design does **not** mitigate:

1. **A-root-op (compromised operator).** The signing key can be
   used to produce arbitrary signed artifacts. Defense is at the
   operator-host security layer, not in shirudo. Long-term:
   HSM-backed keys, multi-key with rotation.
2. **A-root using bpffs** ``unlink(2)`` **on pin files.**
   **Closed in MVP** by the xattr-based filesystem-sealing LSM
   (``bpf/seal.c``, threat T2 above). ``rm`` of any pin file in
   ``/var/lib/shirudo/bpffs/`` from a process whose executable
   doesn't carry ``security.bpf.shirudo`` is refused with
   ``-EACCES``. Residual: an attacker with the ability to also
   patch shirudo's own binary on disk **before** ``shirudo init``
   has attached the seal LSM can substitute a different binary
   with a different exe_file xattr label; once init has run,
   the seal LSM denies writes to the shirudo binary inode
   itself. For adversarial substitution in the install window,
   the right defence is the distribution layer — signed
   packages, IMA appraisal, fs-verity, measured boot (see
   T13).
3. **Early-boot window before** ``shirudo init`` **runs.** From
   ``TPM2_Startup`` through systemd reaching the deferred
   reboot-persistence unit, BPF is unrestricted. Long-term:
   ``shirudo init`` in initramfs.
4. **PCR (eventlog) tampering with TPM intact** — the chain
   integrity-checks the eventlog, so this is detectable but only
   at the next status check; an attacker may have a window before
   the operator notices.
5. **In-kernel LSM denials are not surfaced to userspace.**
   Long-term: on-demand ringbuf drain via ``shirudo status
   --include-audit``.
6. **SSH-trust-only attestation.** The chain value is reported to
   the operator over SSH; a compromised target can lie. Long-term:
   ``TPM2_NV_Certify`` quote with an Attestation Key.
7. **No cross-fleet rate-limiting or anomaly detection.** shirudo
   does not detect "an operator is signing too many upatches per
   hour" or similar behavioral anomalies; that is an operational
   layer above shirudo.
8. **DoS via the** ``shirudo`` **LSM itself.** A flood of
   ``bpf()`` syscalls causes a flood of LSM hook invocations, each
   of which runs the policy switch. The hook is constant-time
   though, so the practical impact is no different from a flood
   of any other syscall.
9. **Supply-chain integrity** of compiler, libraries, build-time
   tools. Out of shirudo's control.
10. **Cert revocation latency.** The MVP keyring model has one
    cert and no revocation channel. If the signing key is found
    to be compromised, the operator must (a) re-issue ``cert.der``
    on each target out of band, (b) re-run ``shirudo init`` on
    every target to re-populate the kernel keyring, and (c) accept
    that any artifact signed before the revocation, including
    legitimate ones, is invalidated wholesale. There is no in-band
    "revoke this cert" command; CRLs and OCSP are not consulted by
    the kernel signature path; ``shirudo nodes`` flags certs
    approaching expiry (12-month warning, see PLAN.md "shirudo
    nodes"), but does not detect an out-of-band revocation
    announcement. **Residual risk: cryptographic + operational** —
    a compromised key remains usable until the operator drives the
    cert replacement everywhere. Long-term mitigation: multi-key
    keyring with cert rotation (deferred, residual #1 above), plus
    a short-lived signing-cert pattern where the operator's
    long-lived root cert signs short-lived working certs.
11. **Confidential VM platform integrity.** Where shirudo runs
    inside an SEV/TDX/CCA confidential VM, the in-VM TPM is a
    vTPM provided by the platform; the platform itself can in
    principle observe or interfere with the vTPM's behaviour
    (cold-boot of the VM, vTPM state migration). shirudo treats
    the vTPM as a TPM 2.0 device and inherits the platform's
    trust posture without amplifying or weakening it. **Residual
    risk: equivalent to the underlying CVM's trust model.**
    Long-term: integrate platform-attested vTPM endorsement keys
    so shirudo's chain can be bound to a platform attestation
    quote (deferred — see PLAN.md "out of scope" entry on
    confidential computing).
12. **A-root using** ``PR_SET_MM_EXE_FILE`` **to spoof shirudo's
    identity to the filesystem-sealing LSM.** The
    ``bpf/seal.c`` LSM authorises by comparing
    ``current->mm->exe_file``'s ``security.bpf.shirudo`` xattr
    against the target inode's. ``prctl(PR_SET_MM_EXE_FILE)``
    lets a process with ``CAP_SYS_RESOURCE`` swap its
    ``mm->exe_file`` to any executable file the kernel will
    open — including the genuine shirudo binary, which has the
    expected xattr value. An attacker pointing at shirudo's
    inode passes the LSM identity check even though the
    process's actual code is theirs. **Mitigation:** none in
    MVP that doesn't add a long-lived in-kernel mechanism
    (and an immutable "what was actually exec'd" facility is
    not exposed to BPF by the upstream kernel today). The
    realistic defence is bounding ``CAP_SYS_RESOURCE`` out of
    untrusted-root contexts at the deployment layer (systemd
    unit ``CapabilityBoundingSet=``, container capability
    profiles, SELinux/AppArmor process types). Residual risk:
    **Medium for A-root with** ``CAP_SYS_RESOURCE``,
    **None otherwise** — the prctl call requires that
    capability and a working ``execve``-style file open path.
    Deferred mitigation: track upstream BPF helper proposals
    that expose ``task->exec_id`` or equivalent for
    ground-truth identity.
13. **Initial cert distribution window.** Before the first
    ``shirudo init`` runs on a target,
    ``/var/lib/shirudo/keys/cert.der`` is **not** sealed by
    ``bpf/seal.c`` (the sealing LSM is what ``shirudo init``
    *attaches*). An attacker with root on the target before
    the first init can substitute their own cert; the
    legitimate ``shirudo init`` then installs the attacker's
    cert into the kernel keyring as the trust anchor, and
    every subsequent legitimate rollout fails
    ``signature_rejected``. The threat is essentially T5
    (early-boot window) narrowed to first-install: the
    operator can run ``shirudo init`` from an initramfs
    context where attacker root is presumed-absent, or rely
    on distribution-level package signing + IMA / dm-verity
    to ensure cert.der's integrity at first install.
    Residual risk: **High in unhardened first-install
    environments, None when paired with signed-package + IMA
    deployment**. Deferred mitigation: TPM-sealed initial
    cert that only unseals against an attested boot
    measurement.
14. **Replay and downgrade of signed artifacts.** A captured
    signed ``.upatch`` (LOAD or UNLOAD) can be re-issued
    against the target later. The kernel still accepts the
    signature (it is valid), the LSM still allows the
    operation, the chain extends. The operator detects the
    out-of-band activity on the **next** ``shirudo nodes``
    or ``shirudo rollout`` invocation via ``chain_drift``,
    but cannot prevent the replay itself. **Detection, not
    prevention.** The fundamental tradeoff is that signed
    artifacts are reusable across the target fleet (one
    signing operation, many rollouts) — adding a per-target
    nonce in the signed bytes would force per-target signing
    and remove that property. AI agents driving rollouts
    treat ``chain_drift`` on operations they did not issue
    as a real security signal, not as ordinary concurrency
    friction.
15. **Verifier log as AI prompt-injection channel.** The
    kernel BPF verifier writes its rejection messages into
    the ``.upatch``'s ``log_buf`` region, which shirudo
    surfaces verbatim in failure reports' ``verifier_log``
    field. The verifier text includes BPF disassembly and
    line-number references derived from the BPF program's
    debug info — both of which are under the **BPF author's
    control**. An AI agent reading the verifier log to
    decide how to iterate on the source could in principle
    be steered by an adversarial author who embeds prompt-
    injection strings in BPF symbol names, comments, or
    structure-field names that bleed through into verifier
    output. **Mitigation:** treat ``verifier_log`` content
    as untrusted text on the operator side, the same way one
    treats compiler output from third-party code. shirudo
    itself escapes the field for JSON safety; downstream AI
    pipelines are responsible for prompt-injection defence
    of their own (system-prompt isolation,
    instruction/response separation, structured output
    enforcement). This is not new — every compiler-driven AI
    workflow has the same property.
16. **Same-named keyring substitution.** Because shirudo is
    agentless, each load re-resolves the ``shirudo`` keyring by
    *name* (``KEYCTL_SEARCH`` on ``@u``). A root attacker can
    unlink the real keyring from ``@u`` and link a fake
    same-named one (or link a fake, which displaces the real one
    in ``@u``'s by-name index), redirecting that resolution to a
    keyring holding the attacker's cert. **Mitigated, not
    closed:** ``shirudo init`` pins the keyring serial to
    ``/var/lib/shirudo/keyring.serial`` (under the seal), and
    every load refuses with ``category: tampered`` unless the
    resolved-by-name serial still equals the pin — so the swap
    becomes a fail-closed refusal (the attacker can DoS by
    removing the keyring but cannot get BPF they signed loaded),
    and ``shirudo status`` reports the mismatch. The pin's
    integrity rests on the same seal as the rest of the tree, so
    it inherits residual #12 (``CAP_SYS_RESOURCE`` exe-spoof). A
    complete fix (deny the swap outright) needs **new kernel
    code**: ``lsm/key_permission`` is attachable from BPF LSM,
    but its ``key_ref_t`` argument is opaque (no kfunc converts
    it to ``struct key *``), so the hook cannot identify the
    shirudo keyring without a new ``bpf_key_ref_to_key()``-style
    kfunc; the displace-by-link half also needs gating link into
    ``@u``. Residual risk: **Low** (fail-closed, observable).
    See PLAN.md §"Keyring model" and TODO.kernel item 9.

Deferred mitigations
====================

Listed in approximate priority order for post-MVP work:

- **Initramfs-stage** ``shirudo init`` (T5). Run before pivot_root,
  closing the early-boot enforcement window.
- **``TPM2_NV_Certify`` attestation.** AK-signed reads of the NV
  index, with operator-supplied nonce. Closes the SSH-trust gap.
  Requires AK/EK provisioning machinery.
- **HSM-backed signing key** (O1, residual #1). PKCS#11 or
  TPM-resident key. Out-of-tree work; not a shirudo source
  change so much as an operational decision and a key-handling
  module.
- **Multi-key / cert rotation** (O1). Multiple certs in the
  ``shirudo`` keyring; ``shirudo keys rotate`` workflow.
- **In-kernel LSM denial event ringbuf** (T9, residual #5). On-
  demand drain via ``shirudo status --include-audit``; no
  long-lived target-side process required (per the
  agentless-on-target invariant).
- **``shirudo init --update``** for atomic LSM upgrades via
  ``BPF_LINK_UPDATE``.
- **``lsm/key_permission`` keyring guard** (residual #16). Deny
  unlink/displace of the ``shirudo`` keyring in ``@u`` by
  exe-identity, turning the serial-pin mitigation into outright
  prevention. Needs a new ``key_ref → struct key *`` kfunc
  first (TODO.kernel item 9).
- **Remote groups / wildcards** in the registry, for fleet-scale
  operation.

References
==========

- ``PLAN.md`` in the repository root — the design source of truth.
- Linux kernel ``Documentation/process/coding-style.rst`` — shirudo
  follows this for all C.
- ``kernel/bpf/syscall.c:bpf_prog_verify_signature()`` — the
  in-kernel signature verifier shirudo depends on.
- ``include/linux/lsm_hook_defs.h`` — the LSM hook signature
  (with the load-bearing ``bool kernel`` discriminator).
- TCG TPM 2.0 Library Specification, Part 1 (Architecture) and
  Part 3 (Commands) — for NV-extend semantics.
- UAPI Group's "Linux TPM PCR Registry" — for the PCR allocation
  table that motivated shirudo's choice of NV-extend over a PCR.
