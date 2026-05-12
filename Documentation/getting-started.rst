.. SPDX-License-Identifier: BSD-2-Clause
.. Copyright (c) 2026 Authors of shirudo

==========================
Getting started with shirudo
==========================

A first-time walk-through for operators standing up shirudo on a new
fleet. Roughly one page of commands; allow about 15 minutes for the
end-to-end happy path. Two machines are involved:

- The **operator machine** — your workstation or a CI runner. Holds
  the private signing key; signs `.upatch` artifacts; pushes them
  out.
- The **target machine** — a server, a switch control plane, an
  embedded device, anywhere shirudo's BPF LSM will run. Holds only
  the public cert.

The same core shirudo binary runs on both. What separates the two
roles is which artifacts are present locally, not which build you
installed — **but the operator additionally needs a second
package**, ``shirudo-build``, which contains the artifact-signing
binary. ``shirudo-build`` and its ``clang`` dependency are
operator-only; they never ship to a target.

==========================  =======================  =================
Package                     Operator host?           Target host?
==========================  =======================  =================
``shirudo`` (core)          yes                      yes
``shirudo-build``           yes                      **no**
``clang`` / ``llvm``        yes (build-time dep)     no
==========================  =======================  =================

For the *why* behind any of this, read ``architecture.rst`` and
``threat-model.rst`` in the same directory.

Operator-side first-time setup
==============================

On a fresh operator host:

1. Install both packages from your distribution::

       # Debian/Ubuntu
       apt-get install shirudo shirudo-build clang

       # Fedora
       dnf install shirudo shirudo-build clang

       # Arch
       pacman -S shirudo shirudo-build clang

2. Generate the signing key (step 4 below — one-time per fleet).
3. Set up ``ssh-agent`` with whatever SSH keys you already use to
   reach your target fleet. shirudo inherits your SSH posture
   as-is (no key management on shirudo's part — see
   ``threat-model.rst`` §"Explicitly out of scope").
4. Optional: ``shirudo remote add`` your targets as you onboard
   each (step 8 below — repeatable per target).

That's all. There is no shirudo service to start, no daemon to
supervise, no listening socket to firewall, no operator-side
state beyond the contents of ``/var/lib/shirudo/keys/`` and
``$XDG_CONFIG_HOME/shirudo/remotes.d/``.

1. Install runtime dependencies
================================

shirudo dynamic-links a small number of libraries. On a Debian-family
target:

.. code-block:: sh

    apt-get install libssl3 libssh-4 libtss2-esys-3.0.2-0 libtss2-tcti-device0

On a Fedora-family target:

.. code-block:: sh

    dnf install openssl-libs libssh tpm2-tss

Both the operator machine and the target need ``libcrypto`` and
``libssh``. The target additionally needs ``libtss2`` for TPM
measurement.

shirudo's MVP supports **x86_64 and arm64** targets. Both
architectures are little-endian, and the on-disk ``.upatch`` format
and wire protocols are architecture-neutral, so the operator can be
on either architecture and push to targets on either — the
``x86_64 operator → arm64 fleet`` direction is a first-class
deployment shape, not a workaround. riscv64 is not yet in the
test matrix.

shirudo does **not** depend on the ``openssh-clients``,
``tpm2-tools``, or any other command-line utility — it never
``fork+exec``s. The libraries above are sufficient.

2. Verify kernel support on the target
=======================================

shirudo runs on **current upstream Linux kernels**. There is no
legacy-kernel support; older kernels are not supported and not
detected gracefully (see PLAN.md §"Bleeding-edge kernel and
toolchain assumed"). Confirm the target's kernel meets the bar:

.. code-block:: sh

    cat /sys/kernel/security/lsm        # must contain 'bpf'
    grep -E '^(CONFIG_BPF_LSM|CONFIG_KEYS|CONFIG_ASYMMETRIC_KEY_TYPE|CONFIG_X509_CERTIFICATE_PARSER|CONFIG_PKCS7_MESSAGE_PARSER|CONFIG_SYSTEM_DATA_VERIFICATION|CONFIG_DEBUG_INFO_BTF|CONFIG_TCG_TPM)=y' /boot/config-$(uname -r)

If ``bpf`` is missing from ``/sys/kernel/security/lsm`` even though
``CONFIG_BPF_LSM=y``, your boot command line is excluding it. Add
``lsm=bpf,...`` (preserving any LSMs already listed) and reboot.

If your kernel is older than current upstream, your options are:
upgrade the kernel, or use a different security platform.
shirudo's design has no fallback path for older kernels — the
``keyring_id`` BPF signature-verification interface, BPF LSM
hooks, TPM2 NV-extend support, and a number of other current
features are all hard prerequisites.

3. Build shirudo
=================

shirudo builds from source as a single static-link-most-things binary:

.. code-block:: sh

    git clone https://github.com/<TBD>/shirudo
    cd shirudo
    git submodule update --init    # pulls third_party/bpf-next
    make -j

The first build is slow — it compiles libbpf, libelf, and ``bpftool``
(build-time only) from the bpf-next submodule. Subsequent rebuilds
are fast.

Install with:

.. code-block:: sh

    sudo make install              # places shirudo in /usr/local/bin

Cross-compile for an embedded target by setting ``CROSS_COMPILE`` and
``ARCH`` as you would for any kernel-style build. See PLAN.md
"Build system" for details.

4. Generate the signing key (operator machine, one time)
=========================================================

The operator machine is the only place the private key ever exists.
Generate the key pair and self-signed cert:

.. code-block:: sh

    sudo shirudo genkey

This produces:

- ``/var/lib/shirudo/keys/signing_key.pem`` (mode 0600, root-owned)
- ``/var/lib/shirudo/keys/cert.der``

Defaults are RSA-2048, SHA-256, CN ``shirudo``, 10-year validity.
You can inspect the cert with the usual ``openssl x509 -in cert.der
-inform DER -text -noout``.

**Back up** ``signing_key.pem`` **somewhere secure.** If you lose it,
every target initialised with the corresponding cert becomes
permanently un-administrable until ``shirudo init`` is re-run with a
new cert — and that re-init requires physical or root access to each
target.

5. Distribute the cert to each target (out-of-band, first time only)
=====================================================================

Copy ``cert.der`` to ``/var/lib/shirudo/keys/cert.der`` on each
target. The **first** time you do this it must be out-of-band —
shirudo isn't running yet, so the cert can't ride a signed upatch.
After ``shirudo init``, subsequent operations flow through libssh.

.. code-block:: sh

    scp /var/lib/shirudo/keys/cert.der user@target:/var/lib/shirudo/keys/cert.der

Standard ``scp`` here, since shirudo isn't yet in the picture. This
is one of the few times you'll use ``scp`` directly — once ``init``
has run, ``shirudo rollout`` handles everything.

6. Initialise the target
=========================

On the target, with ``cert.der`` in place:

.. code-block:: sh

    sudo shirudo init

This:

- Creates the named kernel keyring ``shirudo`` under the user
  keyring.
- Loads ``cert.der`` into the keyring as an asymmetric key.
- Loads shirudo's BPF LSM program via the signed-loader path,
  pins it at ``/var/lib/shirudo/bpffs/lsm_link``.
- Defines the TPM2 NV-extend index (if a TPM is present) and
  extends it with the first ``"shirudo-init\0"`` event.

After this completes the LSM is enforcing: any further unsigned
``BPF_PROG_LOAD`` from userspace returns ``-EACCES``. Verify:

.. code-block:: sh

    sudo shirudo status
    # → LSM attached, keyring serial N, cert <fp>, TPM chain <hex>, 0 upatches

``shirudo init`` is **idempotent**. Running it again on a target
that's already initialised is a no-op.

7. Build a signed BPF upatch (operator machine)
================================================

One command on the operator machine compiles BPF source and
produces a signed ``.upatch`` artifact ready for rollout:

.. code-block:: sh

    sudo shirudo build myhook.bpf.c -o myhook.upatch

``shirudo build`` is implemented as a dispatch (git-style) to a
separate ``shirudo-build`` binary at
``$(libexecdir)/shirudo/shirudo-build`` that holds the **single
subprocess exception** in shirudo. ``shirudo-build`` ``execv``s
``clang -target bpf -O2 -g …`` to compile, then runs libbpf's
gen_loader and CMS signing in-process to produce the final
``.upatch``. Both ``shirudo-build`` and ``clang`` ship only with
the operator package — they do not exist on targets. Invoking
``shirudo build`` on a target returns a clear "operator-only"
error.

If you've already compiled the source (e.g., a separate build
farm produced the ``.bpf.o``), skip compilation:

.. code-block:: sh

    sudo shirudo build myhook.bpf.o -o myhook.upatch

The output ``myhook.upatch`` is self-contained: it carries the
generated loader program, the signature, the payload hash, and a
1 MiB log buffer for verifier output (filled in only on rejection,
empty on success).

8. Register the remote (operator machine, required)
====================================================

``shirudo rollout``, ``shirudo rollback``, and ``shirudo nodes``
**only accept registered remote names** — literal
``user@host:port`` is refused with a "register first" error. So
the operator's first interaction with each target is to register
it:

.. code-block:: sh

    shirudo remote add prod-a root@target-a.prod.example.com:22 \
        --label shirudo.nodes.type=production \
        --label shirudo.nodes.location=us-east-1 \
        --label shirudo.nodes.role=database

``--label key=value`` is repeatable and attaches Kubernetes-style
labels for selector-based fleet operations (see step 9). Common
conventions: namespace your keys (``shirudo.nodes.type``,
``team.foo``, …); keep values simple
(``production``/``staging``/…); add as many as helps.

The entry lives at ``~/.config/shirudo/remotes.d/prod-a.conf`` (or
``/etc/shirudo/remotes.d/prod-a.conf`` with ``--system``). It's
plain text — ``host = ...``, ``user = ...``, ``port = ...``, one
``label.<key> = <value>`` line per label — and contains no
secrets. Authentication still flows through ssh-agent and
``~/.ssh/known_hosts``. To modify labels later, edit the conf
file directly; shirudo intentionally doesn't provide a
``set-label`` subcommand.

Make sure ``target-a.prod.example.com``'s host key is already in
your ``~/.ssh/known_hosts`` (``ssh-keyscan -H target-a.prod.example.com
>> ~/.ssh/known_hosts``). shirudo will **refuse** to connect to a
host whose key it has not seen before — there is no trust-on-first-
use.

9. Roll out
============

Push the upatch — **using the registered remote name** (literal
``user@host:port`` is no longer accepted; register the target
first if you haven't):

.. code-block:: sh

    shirudo rollout myhook.upatch prod-a

Behind the scenes ``shirudo rollout``:

1. Resolves ``prod-a`` against the registered remote set.
   Refuses with a clear "register first" error if the name
   isn't registered.
2. Opens a libssh session to the target, verifies the host key.
3. Authenticates via ssh-agent (or default on-disk keys).
4. Pre-status the target — captures its current TPM chain value.
5. SFTPs ``myhook.upatch`` to ``/var/lib/shirudo/incoming/`` on
   the target.
6. Runs ``shirudo upatch load /var/lib/shirudo/incoming/myhook.upatch
   --expect-chain=<captured>`` over an SSH exec channel.
7. The target verifies the signature, runs the signed loader, pins
   the resulting link, extends the TPM chain.
8. Reports per-target results.

Multiple targets in one command (all names must be registered):

.. code-block:: sh

    shirudo rollout myhook.upatch prod-a prod-b staging

Or **by label selector**, which picks the matching subset from
the registered remote set:

.. code-block:: sh

    # All production targets:
    shirudo rollout myhook.upatch \
        --selector='shirudo.nodes.type=production'

    # Production in a specific region:
    shirudo rollout myhook.upatch \
        --selector='shirudo.nodes.type=production && shirudo.nodes.location=us-east-1'

    # Multiple roles in non-staging environments:
    shirudo rollout myhook.upatch \
        --selector='(role=database || role=cache) && env!=staging'

Selectors support equality (``=``), inequality (``!=``),
existence (``key``), non-existence (``!key``), ``&&`` (AND;
higher precedence), ``||`` (OR; lower precedence), and
parentheses. Empty match → error (the operator should know
whether their selector is expected to match). Names and
``--selector`` are mutually exclusive on rollout/rollback —
pick one form.

For AI-agent workflows, add ``--report=report.json`` to get a
structured JSON document covering every target's result, errno,
``category`` (one of ``verifier_rejected``, ``btf_mismatch``,
``signature_rejected``, ``tampered``, …), and the full kernel
verifier log on any rejection.

10. Inspect the fleet
======================

For the fleet-wide view of every registered target, use
``shirudo nodes``:

.. code-block:: sh

    shirudo nodes
    # name    host                  reachable  lsm  keyring     version   chain      upatches  status
    # prod-a  prod-a.example.com    yes        OK   <fp>:abcd…  abc123…   <hex>      5         OK
    # prod-b  prod-b.example.com    yes        OK   <fp>:abcd…  abc123…   <hex>      5         OK
    # prod-c  prod-c.example.com    no         -    -           -         -          -         UNREACHABLE
    # staging staging.example.com   yes        OK   <fp>:efgh…  abc123…   <hex>      4         CERT-DRIFT

By default ``shirudo nodes`` queries every registered remote in
parallel (``--parallel=16``) and includes TPM chain state
(``--include-tpm``). For a subset use names, a glob filter, or
a label selector:

.. code-block:: sh

    shirudo nodes prod-a prod-b              # specific names
    shirudo nodes --filter='prod-*'          # glob on name
    shirudo nodes --selector='type=production'  # label selector
    shirudo nodes --filter='us-east-*' \      # glob AND selector
                  --selector='role=database'    # combined (intersection)

For drift detection against a pinned event sequence:

.. code-block:: sh

    shirudo nodes --expect-sequence=expected.upatches

The command exits non-zero if any target has drifted (any of the
labels other than ``OK``) — useful for AI agents and CI that
need a binary "is the fleet healthy?" signal. ``--json`` produces
the same aggregate as a structured document for machine
consumption.

For local introspection on a single host, ``shirudo status``
(no destination argument — it's local-only) reports that host's
own state. On the target it reads kernel state; on the operator
it reports local on-disk artifacts.

For the operational log, the journal has the events:

.. code-block:: sh

    journalctl _EXE=/usr/local/bin/shirudo --since '5 min ago'

Filter by ``_EXE`` and ``_UID`` (trusted journald fields), not by
``-t shirudo`` (which is forgeable by any process).

11. Roll back
==============

To remove an upatch:

.. code-block:: sh

    # On the operator machine:
    shirudo build --unload myhook -o myhook.unload.upatch
    shirudo rollback myhook.unload.upatch prod-a

The unload artifact is itself a signed `.upatch` — there is no
out-of-band "destroy" path. The target verifies the signature,
verifies that the named upatch is currently loaded with the
expected ``payload_sha256``, detaches the link, removes the pin,
and extends the TPM chain with a ``"shirudo-unload\0"`` event.

Rollback is **idempotent**: removing an upatch that isn't loaded
returns ``result: ok, category: already_unloaded`` with no chain
extension.

CVE response playbook
=====================

The motivating shirudo use case is "a CVE in the running kernel is
disclosed; you need a fleet-wide mitigation in production within
hours, without rebooting hundreds or thousands of hosts." This
section walks the end-to-end procedure for a typical kernel CVE.

The worked example in ``examples/cve-2026-31431.bpf.c`` follows
this playbook; refer to it alongside this section.

1. **Triage the CVE.**

   - Read the advisory. Identify the kernel attack surface
     (syscall, hook, capability). If the surface is reachable only
     from kernel code paths shirudo cannot intercept (e.g., a bug
     in the page allocator triggered by ordinary userspace
     activity), shirudo is **not** the right mitigation — wait
     for the upstream patch.
   - Identify a BPF LSM hook that gates the surface. The kernel's
     LSM hook list (``include/linux/lsm_hook_defs.h``) is
     exhaustive; common candidates are ``socket_create``,
     ``bpf_prog``, ``file_open``, ``bprm_check_security``,
     ``inode_unlink``.
   - Decide the policy: *deny the entire surface to all userspace*
     (broad but simple, e.g. block AF_ALG socket creation) vs.
     *deny under a specific precondition* (narrow but
     case-specific). For most CVE response, the broad form is
     correct — operational pain (one or two services lose access
     to a feature) is acceptable for a few days while the upstream
     fix rolls out.

2. **Author the BPF mitigation.**

   - Copy ``examples/cve-2026-31431.bpf.c`` as a starting point —
     it shows the minimum SPDX/license header, the
     ``BPF_PROG`` macro, returning ``-EPERM`` for the denial path,
     returning ``0`` for the allow path, and the
     ``Dual BSD/GPL`` license string the LSM framework requires.
   - Use **CO-RE relocations** (``BPF_CORE_READ`` etc., from
     ``vmlinux.h``) wherever you touch kernel structs, so the
     same ``.upatch`` runs on x86_64 and arm64 targets without
     rebuilding. The architecture doc covers this; the
     CVE-2026-31431 example deliberately avoids struct access
     because the hook arguments are scalars.
   - **Test locally first.** Build the upatch, ``shirudo rollout``
     it to a staging target, verify the intended path is blocked
     and unintended paths are not. ``--dry-run`` previews the
     rollout without committing it; the staging matrix you select
     via ``--selector=shirudo.nodes.type=staging`` should be
     short-lived and labelled accordingly.

3. **Sign and package on the operator.**

   ::

       shirudo build cve-2026-31431.bpf.c -o cve-2026-31431.upatch
       shirudo upatch info cve-2026-31431.upatch    # sanity check

   ``shirudo upatch info`` confirms the magic, signature, and
   metadata of the produced artifact before you push it to a
   fleet. The signing key never leaves the operator host.

4. **Stage rollout — production canary first.**

   Pick a small named subset of production (one or two hosts,
   ideally with redundant traffic) and roll out there alone:

   ::

       shirudo rollout cve-2026-31431.upatch prod-canary-a prod-canary-b

   Monitor for **2–4 hours**: check application metrics, error
   rates, and ``shirudo nodes --selector=shirudo.nodes.type=production``
   for any drift labels. The TPM chain records the load; if the
   canary's chain advances cleanly, the artifact is healthy.

5. **Fleet-wide rollout, by label selector.**

   ::

       shirudo rollout cve-2026-31431.upatch \\
           --selector='shirudo.nodes.type=production' \\
           --parallel=64 \\
           --report=cve-2026-31431.rollout.json

   The report JSON is the audit artifact — keep it alongside the
   CVE ticket. Per-target results, chain-before/after values,
   timing, and any failures are in there.

   Investigate any ``result: failed`` entries individually.
   ``category: tampered`` means the target's chain drifted while
   the rollout was in flight — common when another operator is
   touching the same fleet; re-run ``shirudo nodes`` and retry
   the affected targets. ``category: verifier_rejected`` indicates
   a real BPF problem and **stops the rollout for that target**;
   review the verifier log, fix the BPF source, rebuild, and
   restart the per-target rollout.

6. **Verify enforcement on the fleet.**

   ::

       shirudo nodes --selector='shirudo.nodes.type=production' \\
           --include-tpm

   Every healthy production target should now list
   ``cve-2026-31431`` in its loaded set, with a chain value that
   incorporates the load. ``CERT-DRIFT`` / ``CHAIN-DRIFT`` /
   ``VERSION-DRIFT`` labels here are red flags that pre-existed
   the rollout; the CVE response surfaces them.

7. **Roll back once the upstream fix is deployed.**

   When the kernel containing the upstream fix is in production
   fleet-wide, retire the upatch:

   ::

       shirudo build --unload cve-2026-31431 -o cve-2026-31431.unload.upatch
       shirudo rollback cve-2026-31431.unload.upatch \\
           --selector='shirudo.nodes.type=production'

   The unload directive is signed (same operator key, same
   keyring on the target), and the chain extends with a
   ``shirudo-unload`` event recording the removal. The eventlog
   has the full history: load → run → unload, with timestamps
   and chain values at each step.

8. **File the audit record.**

   For each CVE response, keep:

   - The rollout report (``cve-NNNN.rollout.json``) and rollback
     report.
   - A copy of the ``.upatch`` and ``.unload.upatch`` files (they
     embed source path and build timestamp via
     ``shirudo upatch info``).
   - The before/after TPM chain values from one or two canary
     targets, for post-hoc replay verification.

   These are sufficient to reconstruct what was deployed, when,
   and to which targets — the operational analogue of "every
   state transition is measured" applied to incident response.

**What this playbook does not do**: it does not fix the underlying
kernel bug, it does not prevent kernel-internal exploitation that
doesn't transit a hookable surface, and it does not absolve the
operator from running upstream-supported kernels. shirudo is a
**bridge between disclosure and reboot**, not a substitute for
either.

Onboarding another target
=========================

Once your fleet has more than one target, this is the repeatable
sequence — five steps, runs against a fresh box::

    # 1. Install the shirudo package on the target.
    #    The distribution's package post-install hook MUST also
    #    `setfattr -n security.bpf.shirudo -v <SHIRUDO_VERSION_ID>`
    #    on /usr/local/bin/shirudo (or wherever the binary lands)
    #    and on any pre-shipped content under /var/lib/shirudo/.
    #    Without this, `shirudo init` refuses to install the seal
    #    LSM. See PLAN.md "Packaging requirements" for the
    #    contract on distributions.
    ssh target apt-get install shirudo

    # 2. Distribute the cert (operator -> target, out-of-band the
    #    first time for this target). Use scp until shirudo is
    #    enforcing on the target; after that, shirudo's own
    #    sealed filesystem protects the cert from in-place tamper.
    scp /var/lib/shirudo/keys/cert.der target:/var/lib/shirudo/keys/

    # 3. Bootstrap the target's LSM.
    ssh target shirudo init

    # 4. Register the remote on the operator. Add labels so
    #    `--selector` expressions on rollout/nodes can target this
    #    box by role / location / kernel / etc. (See "Heterogeneous
    #    fleets" below.)
    shirudo remote add target1 root@target.prod:22 \
        --label shirudo.nodes.type=production \
        --label shirudo.nodes.location=us-east-1 \
        --label shirudo.nodes.role=database \
        --label kernel="linux-6.8.0@c1fa0bb633e4a6b11e83ffc57fa5abe8ebb87891"

    # 5. Verify.
    shirudo nodes target1 --include-tpm
    # Expected: LSM attached, keyring present, chain extended once
    # for init, zero upatches loaded.

Bulk onboarding is the same five steps in a loop. shirudo
deliberately does not provide a "remote provisioner" — your
existing config-management tool (Ansible, Chef, Puppet, Salt,
NixOS, …) drives steps 1–3 across the fleet; the operator
runs steps 4–5 locally.

Heterogeneous fleets and kernel-version labels
==============================================

The shirudo design does **not** assume a homogeneous fleet. Different
targets in the same fleet routinely run different kernel versions
(staged rollouts, vendor variants, hardware-specific patches,
deferred reboots after package upgrades), different distributions,
different architectures (operator x86_64 → target arm64 is a
first-class case), and different BPF feature sets.

The recommended convention is to label every registered remote with
its **kernel identity** — at minimum its release string, and where
operators ship custom kernels, the top-of-tree commit SHA the
kernel was built from::

    shirudo remote add target1 root@target.prod \
        --label kernel="linux-6.8.0@c1fa0bb633e4a6b11e83ffc57fa5abe8ebb87891" \
        --label kernel.release=6.8.0 \
        --label kernel.arch=x86_64

``--selector`` expressions then let CVE response and feature
rollouts target the specific subset that's affected and ready::

    # Roll a CVE mitigation only to the kernel revs that haven't
    # yet picked up the upstream fix.
    shirudo rollout cve-2026-31431.upatch \
        --selector='kernel.release=6.8.0 || kernel.release=6.9.0'

    # Roll an arm64-only mitigation that uses arch-specific BTF.
    shirudo rollout sve-mitigation.upatch \
        --selector='kernel.arch=arm64'

    # Drain a single kernel revision out of production by rolling
    # back a workaround that was specific to it.
    shirudo rollback workaround.unload.upatch \
        --selector='kernel="linux-6.8.0@c1fa0bb633e4a6b11e83ffc57fa5abe8ebb87891"'

Labels are operator-chosen plain text — shirudo doesn't validate
the kernel string against ``uname -r`` on the target, doesn't
synchronise it on reboots, doesn't treat the label as a security
boundary (see PLAN.md §"Label selectors"). Keeping the label
in sync with the actual deployed kernel is the operator's
responsibility, the same way ``shirudo.nodes.type=production`` is.
The convention exists so that ``shirudo nodes --selector=…``
gives operators a way to express CVE-response surgery cleanly:
"the bug is in kernels X and Y, push the mitigation there, not
elsewhere".

Reboot handling in MVP
======================

shirudo's reboot-persistence systemd unit is **deferred** (see
PLAN.md "Open questions"). Until it lands:

- A target reboot drops the bpffs mount, the kernel keyring, the
  LSM attachment, the ``upatches_registry`` map, and every
  ``.upatch`` link. The target is unenforced from boot until
  someone runs ``shirudo init`` again.
- The TPM NV chain is the **only** state that survives the
  reboot — by design. ``Esys_NV_ReadPublic`` returns the
  chain value as it was at the moment of the last extension.
- The next ``shirudo nodes`` against the target will show
  ``UNREACHABLE`` or ``INIT-INCOMPLETE`` depending on whether
  sshd is up.

What to do about it: drive ``shirudo init`` from your existing
config-management or boot tooling. Ansible playbook, systemd
unit you ship yourself, kexec hook, init.d entry, ``cloud-init``
``runcmd`` — anything that fires once per boot, early. The
operator-supplied unit should be ``Type=oneshot`` and ordered
``Before=network.target`` (or earlier) to minimise the
unenforced window. Once the in-tree shirudo systemd unit
lands, drop your local unit.

Operators that need closed-loop monitoring of "is shirudo
running where it should be?" should poll ``shirudo nodes
--selector=… --json`` from their existing fleet-monitoring
tool and alert on ``INIT-INCOMPLETE`` / ``UNREACHABLE`` /
``CHAIN-DRIFT`` labels.

What to read next
==================

- ``Documentation/architecture.rst`` — the conceptual model:
  operator/target split, signed-loader path, LSM enforcement, TPM
  measurement, rollback symmetry. Read this if you want to
  understand *what shirudo is doing under the hood*.
- ``Documentation/threat-model.rst`` — what shirudo defends
  against, the threats per node, residual risks, deferred
  mitigations. Read this if you are reviewing shirudo for
  security purposes or operating it in a hardened environment.
- ``PLAN.md`` (repository root) — the implementation plan:
  subcommand reference, ``.upatch`` format, build system,
  failure-report schema, deferred work. Read this if you are
  hacking on shirudo itself.

Troubleshooting
===============

``shirudo init`` exits with ``category: init_prereqs_missing``
   ``shirudo init`` runs an infrastructure pre-flight gate
   before touching any state. The report's ``failed_checks``
   array enumerates every missing prerequisite with a fix hint.
   Common causes:

   - **not_running_as_root** — run with ``sudo``.
   - **bpf_lsm_not_active** — ``bpf`` missing from
     ``/sys/kernel/security/lsm``. Either ``CONFIG_BPF_LSM`` is
     off (rebuild kernel) or the boot command line excludes
     ``bpf`` (add ``lsm=bpf,...``, reboot).
   - **bpffs_mount_failed** — shirudo could not mount its
     private bpffs at ``/var/lib/shirudo/bpffs/``. Causes:
     kernel built without ``CONFIG_BPF_SYSCALL`` (rebuild
     kernel), ``/var/lib/shirudo/`` not writable (check
     permissions, mode 0700), or running in a container that
     forbids new mount points. shirudo does **not** use the
     system-wide ``/sys/fs/bpf`` — it manages its own mount
     under ``/var/lib/shirudo/`` so its pins are covered by
     the filesystem-sealing LSM.
   - **cert_missing** — ``/var/lib/shirudo/keys/cert.der``
     not present or unreadable. Copy the cert from the
     operator (see step 5).
   - **embedded_loader_missing** — the shirudo binary on this
     target was built without the operator's pre-signed LSM
     loader. Rebuild the operator package on a host with the
     signing key in place.
   - **tpm_unavailable** — ``/dev/tpmrm0`` missing or
     unusable. Either install/enable a TPM (recommended) or
     pass ``--no-tpm`` to proceed in measurement-disabled
     mode (LSM enforcement still works; chain measurement
     does not).

   Run ``shirudo init --check-only`` (or ``shirudo status``)
   to inspect the readiness picture without attempting
   bootstrap.

``shirudo upatch load`` returns ``category: signature_rejected``
   The target's cert does not match the operator's signing key.
   Either the wrong cert was deployed, or the operator is signing
   with a different key. Re-distribute ``cert.der`` and re-run
   ``shirudo init``.

``shirudo upatch load`` returns ``category: verifier_rejected``
   The BPF source has a verifier error. Read ``verifier_log`` in
   the report; fix the source; re-sign; re-rollout. AI agents
   should iterate on this category automatically.

``shirudo rollout`` returns ``category: version_mismatch``
   The operator and target binaries are different versions (the
   ``SHIRUDO_VERSION_ID`` embedded at build time doesn't match).
   Either you upgraded shirudo on the operator and forgot to roll
   the new binary out to the target, or you're pointing a
   development build at a production target. Re-deploy a matching
   binary to either side. Check with ``shirudo version --version-id``
   on each end and compare. If you genuinely need to proceed across
   a version skew, pass ``--no-version-check`` — this is logged at
   ``LOG_WARNING`` on the target and should be a deliberate
   exception, not a routine workaround. The version-id check
   protects against operational version skew, not adversarial
   binary substitution; if you suspect the latter, the answer is
   distribution-level binary integrity (signed packages, IMA
   appraisal, dm-verity, or measured boot — see
   ``threat-model.rst``).

``shirudo rollout`` returns ``category: tampered`` with
``message: chain_drift``
   The target's TPM state advanced between your last observation
   and this rollout. Either a concurrent operator acted, or
   something on the target tampered with the chain. Re-run
   ``shirudo status`` to see the new state, decide whether it's
   legitimate, then re-issue with the refreshed expected chain.

``shirudo rollout`` returns ``category: tampered`` with
``message: lsm_detached``
   The LSM link pin file has been removed (``rm`` on the bpffs
   path). The LSM is no longer enforcing. This is a security
   incident — investigate before doing anything else. After
   investigation, re-run ``shirudo init`` to re-attach.

``shirudo status`` reports ``TPM not present, measurement disabled``
   The target has no TPM, or ``/dev/tpmrm0`` is inaccessible.
   shirudo's BPF signature enforcement still works; only the
   chain-tamper-evidence layer is disabled. Consider this a
   separate trust tier for your fleet.

``shirudo init`` reports ``failed_checks: [bpffs_xattr_unsupported]``
   The target's bpffs implementation doesn't support
   ``security.*`` xattrs end-to-end (setxattr appears to succeed
   but getxattr returns ``ENODATA``). shirudo cannot operate
   safely on such a kernel — the filesystem-sealing LSM authorises
   by reading inode-bound labels, and pin files that silently
   reject labels become unprotected. Recovery: upgrade the
   kernel to a current upstream release that includes bpffs
   xattr support (see ``kernel/bpf/inode.c::bpf_inode_xattr_*``
   in the kernel tree). This is a hard failure; ``--no-tpm``
   does not bypass it because filesystem sealing is independent
   of TPM measurement.

``shirudo init`` reports ``failed_checks: [tpm_index_conflict]`` or
``[tpm_index_auth_mismatch]``
   The configured ``SHIRUDO_NV_INDEX`` (default ``0x01818E00``)
   is already defined on this TPM, but either with different
   attributes (``tpm_index_conflict`` — another tool is using
   the index) or with an auth_value that does not match
   shirudo's derived value (``tpm_index_auth_mismatch`` — a
   previous shirudo with a different cert defined it, or a
   foreign tool used the same index name with a different
   secret). Recovery: out-of-band ``tpm2 nvundefine`` under
   owner auth (lossy — the chain restarts from zero, all
   cached operator expectations become stale) **or** pick a
   different ``SHIRUDO_NV_INDEX`` at build time and rebuild
   shirudo. Never silently overwrite — the conflict-detection
   is intentional.

``shirudo upatch load`` returns ``category: eventlog_full``
   The on-disk eventlog at ``/var/lib/shirudo/eventlog`` has
   reached ``eventlog.max_bytes`` from
   ``/etc/shirudo/shirudo.conf``. shirudo refused the operation
   entirely — no BPF was loaded, no chain extension, no log
   append — because a chain extension without a matching
   eventlog entry would defeat replay verification. Recovery:
   rotate the eventlog out of band (``cp eventlog
   eventlog.$(date +%s)`` then truncate the live file under
   the same xattr-sealed permissions) and retry. Future:
   ``shirudo eventlog rotate`` subcommand is in the open
   questions.

``shirudo rollback`` returns ``category: payload_mismatch``
   The pin under ``/var/lib/shirudo/bpffs/upatches/<name>/link``
   exists, but the loaded upatch's ``payload_sha256`` (looked
   up in the in-kernel ``upatches_registry`` map) does not
   match the digest embedded in the unload directive. Either
   (a) an attacker substituted a different upatch under the
   same name (security incident; investigate), or (b) the
   operator's rollback artifact is stale (re-derive the
   ``--payload-sha256`` from the currently-loaded upatch on
   the target via ``shirudo upatch list`` or
   ``shirudo upatch info``). shirudo refuses to detach
   without confirmation; this protection is intentional.

``shirudo rollback`` returns ``category: detach_failed``
   The unload directive ran and verified, but the kernel
   returned an error on ``BPF_LINK_DETACH`` or
   ``BPF_OBJ_UNPIN``. Unusual — surface to a human with the
   reported errno. Could indicate a kernel BPF subsystem
   issue, an extension of the LSM hook policy that's now
   stricter than expected, or a state corruption.

shirudo refuses to start with ``category: binary_tampered``
   ``util/self_check.c`` read the shirudo binary's bytes on
   disk, hashed them with the embedded hash region zeroed,
   and got a different value from the build-time stamped
   expected hash. **Refuse to operate.** The binary has been
   modified since the build host's stamping pass. This
   catches in-place patches; it does NOT catch a sophisticated
   attacker who also re-stamped the patched binary (the
   stamping tool is not a secret). Real defence is
   distribution-layer integrity (signed packages, IMA
   appraisal, dm-verity, measured boot — see
   ``threat-model.rst`` §"Binary integrity"). Recovery:
   re-install shirudo from a trusted distribution source.
