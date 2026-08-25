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

``make help`` prints an overview of every target (build, test,
the three install variants, and the tunable variables).

Install with:

.. code-block:: sh

    sudo make install              # places shirudo in /usr/local/bin

Cross-compile for an embedded target by setting ``CROSS_COMPILE`` and
``ARCH`` as you would for any kernel-style build. See PLAN.md
"Build system" for details.

Live integration tests in a vTPM VM
-----------------------------------

The live ``t11xx`` tests need a throwaway kernel with BPF LSM support
and a TPM.  Build the repository's pinned bpf-next kernel first, then
run the suite in a disposable QEMU/KVM guest backed by swtpm::

    make bpf-next
    make test-vm

``make bpf-next`` writes both kernel DEBs and a directly bootable
``artifacts/bpf-next-kernel-debs/bzImage``.  It uses
``third_party/bpf-next`` and applies patches under ``kernel/``.
``make test-vm`` verifies that image, boots an Ubuntu 26.04 cloud-image
overlay with a fresh vTPM, runs measured ``shirudo init``, and then runs
``SHIRUDO_INTEGRATION=1 make check``.  The host checkout is mounted
read-only and all guest build writes stay in the disposable overlay.

The VM target requires an x86_64 host with accessible ``/dev/kvm``,
``qemu-system-x86_64``, ``qemu-img``, ``swtpm``, and
``cloud-localds``.  It does not install host packages.  To use a kernel
published elsewhere instead of the local artifact::

    make test-vm \
        TEST_VM_KERNEL_URL=https://example.invalid/bzImage \
        TEST_VM_KERNEL_SHA256=<64-hex-digit-sha256>

A local raw kernel can be selected with
``TEST_VM_KERNEL=/path/to/bzImage``.  CPU count, memory, disk size, and
timeout are configurable with ``TEST_VM_CPUS``, ``TEST_VM_MEMORY``,
``TEST_VM_DISK_SIZE``, and ``TEST_VM_TIMEOUT``.  Failure logs are kept
under ``build/test-vm/logs``; ``TEST_VM_KEEP=1`` also preserves the
guest disk and TPM state, which contain the ephemeral signing key.

4. Generate the signing key (operator machine, one time)
=========================================================

The operator machine is the only place the private key ever exists.
Generate the key pair and self-signed cert:

.. code-block:: sh

    sudo shirudo genkey

By default this writes the root-owned production key directory under
``/var/lib/shirudo/keys``. For a user-owned operator key directory,
export ``SHIRUDO_KEYS_DIR`` once in your tooling environment, or pass
``--keys-dir`` on individual commands:

.. code-block:: sh

    export SHIRUDO_KEYS_DIR=~/.local/share/shirudo/keys
    shirudo genkey
    shirudo build fix.bpf.c -o fix.upatch

``--keys-dir`` takes precedence over ``SHIRUDO_KEYS_DIR`` when both
are set.

The default command produces:

- ``/var/lib/shirudo/keys/signing_key.pem`` (mode 0600, root-owned)
- ``/var/lib/shirudo/keys/cert.der``

With ``--keys-dir``, the same filenames are written under that
directory instead. With ``SHIRUDO_KEYS_DIR`` set, they are written
under the exported directory.

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

``shirudo rollout`` and ``shirudo nodes``
**only accept registered remote names** — literal
``user@host:port`` is refused with a "register first" error. So
the operator's first interaction with each target is to register
it:

.. code-block:: sh

    shirudo remote add prod-a root@target-a.prod.example.com:22 \
        --label shirudo.nodes.type=production \
        --label shirudo.nodes.location=us-east-1 \
        --label shirudo.nodes.role=database

``--label key=value`` is repeatable and attaches plain key=value
labels for selector-based fleet operations (see step 9). Common
conventions: namespace your keys (``shirudo.nodes.type``,
``team.foo``, …); keep values simple
(``production``/``staging``/…); add as many as helps.

The entry lives at ``~/.config/shirudo/remotes.d/prod-a.conf`` (or
``/etc/shirudo/remotes.d/prod-a.conf`` with ``--system``). It's
plain text — ``host = ...``, ``user = ...``, ``port = ...``, one
``label.<key> = <value>`` line per label — and contains no
secrets. Authentication still flows through ssh-agent and
``~/.ssh/known_hosts``.

To mutate labels after registration, use the dedicated
``shirudo remote label`` sub-router (strict key→value semantics —
re-adding an existing key overwrites; ``rm`` of a missing key is
a warning, not an error):

.. code-block:: sh

    # add or update labels (idempotent; overwrite on collision)
    shirudo remote label add prod-a region=us-east-1 tier=primary

    # remove specific labels
    shirudo remote label rm prod-a tier

    # nuke all labels (endpoint and timestamp preserved)
    shirudo remote label clear prod-a

    # fleet form: --filter (registry-name glob) and/or
    # --selector (label expression) instead of a positional name
    shirudo remote label add --filter='prod-*' tier=canary
    shirudo remote label rm  --selector='env=staging' env

Editing the conf text by hand still works — the file format is
the canonical one — but the subcommands rewrite atomically
(``<conf>.tmp`` + ``rename(2)``) so concurrent reads always see
a consistent file.

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

11. Observing what an upatch is doing
======================================

A typical defensive upatch carries a small map -- a counter, a
table of per-comm hits, an LRU of offending PIDs -- so an operator
can answer "is the mitigation firing?". shirudo auto-pins every
map the loader created under
``/var/lib/shirudo/bpffs/upatches/<name>/maps/<map_name>`` and
exposes them read-only via two routes: target-local
``shirudo upatch map`` for detailed inspection, and operator-side
``shirudo nodes show --include-maps`` for the fleet-wide summary.

The example program ``examples/cve-2026-31431-counter.bpf.c``
extends the AF_ALG-blocker with a per-CPU counter::

    struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, __u64);
    } blocked_af_alg SEC(".maps");

    SEC("lsm/socket_create")
    int BPF_PROG(block_af_alg, int family, int type, int protocol, int kern)
    {
        __u32 zero = 0;
        __u64 *count;

        if (family != AF_ALG)
            return 0;
        count = bpf_map_lookup_elem(&blocked_af_alg, &zero);
        if (count)
            (*count)++;        /* per-CPU; no atomic needed */
        return -EPERM;
    }

Build, sign and roll out exactly like the original example:

.. code-block:: sh

    # operator machine
    shirudo build examples/cve-2026-31431-counter.bpf.c
    shirudo rollout examples/cve-2026-31431-counter.bpf.upatch prod-a

Inspect on the target (SSH in once):

.. code-block:: sh

    # on prod-a
    shirudo upatch map
    # UPATCH                       MAP             TYPE         ENTRIES
    # cve-2026-31431-counter       blocked_af_alg  percpu_array max=1  (per-cpu)

    shirudo upatch map cve-2026-31431-counter blocked_af_alg
    # upatch:             cve-2026-31431-counter
    # Map:                blocked_af_alg
    # Type:               percpu_array (16 CPUs)
    # Entries:            1 of 1
    # Key type:           __u32 (4 B)
    # Value type:         __u64 (8 B per CPU)
    #
    # Contents:
    #   key=0: sum=42
    #     cpu0=3   cpu1=5   cpu2=0   cpu3=2
    #     cpu4=1   cpu5=0   cpu6=4   cpu7=2
    #     cpu8=6   cpu9=3   cpu10=1  cpu11=0
    #     cpu12=4  cpu13=8  cpu14=1  cpu15=2

Inspect from the operator, no SSH hop needed (the target's status
JSON ships under the same one round-trip ``nodes show`` already
makes):

.. code-block:: sh

    # operator
    shirudo nodes show --include-maps prod-a
    #   ... (Conditions, System Info, upatches loaded ...)
    # upatches loaded (1):
    #   NAME                          PAYLOAD-SHA256     APPLIED
    #   cve-2026-31431-counter        4513ab88..         23m
    #     Maps:
    #       blocked_af_alg          percpu_array   1/1 entries   sum=42

The summary inline form is the default; for per-CPU detail or for
hashes with many entries, run ``shirudo upatch map`` on the target.

For tooling, ``--json`` carries the structure (here trimmed):

.. code-block:: sh

    shirudo nodes show --include-maps --json prod-a | jq '
      .nodes[0].report.upatch_maps[].maps[] | {name, type, n_entries, first_sum}'
    # { "name": "blocked_af_alg", "type": "percpu_array",
    #   "n_entries": 1, "first_sum": "42" }

Per-map truncation kicks in at 256 entries by default (HASH walk
order is BPF-defined); the JSON ``truncated: true`` and
``n_truncated_at: 256`` carry that fact so consumers can render
"256 of N (use --show-full)". The same ``--show-full`` flag that
expands the loaded-modules dependency tree also lifts the per-map
cap.

A few map types -- ``ringbuf``, ``perf_event_array``,
``stack_trace``, ``prog_array`` -- are listed but not dumped
inline; they need dedicated readers (future work). They appear
with a ``skipped: "use shirudo upatch <verb> (future work)"``
marker so they remain discoverable.

To persist snapshots locally, give ``upatch map`` an explicit NDJSON file:

.. code-block:: sh

    shirudo upatch map cve-2026-31431-counter blocked_af_alg \
      --json=/var/log/shirudo/maps.ndjson

Each invocation appends one schema-1 record.  The zero- and one-positional
forms append a map-list record; the detailed two-positional form appends the
map data.  ``--json`` without a path is rejected.  On the detailed form,
``--json=<path>`` can be combined with ``--otel``: Shirudo reads the map once,
attempts both outputs, and exits nonzero if either fails without rolling back
the output that succeeded.

To export every pinned map in one pass, use ``--all``. Unlike the existing
zero-positional inventory form, this reads each map and emits one detailed
record per map::

    shirudo upatch map --all --json=/var/log/shirudo/maps.ndjson

With no explicit output options, ``--all`` reads the ``map_export.*`` keys
shown by ``shirudo config``. An empty ``map_export.json_path`` together with
``map_export.otel_mode = off`` is a successful no-op. JSON and OTEL may be
enabled together; each map is read once and sent to both destinations.
Batch export continues after a per-map failure and exits nonzero if any map
or destination failed. Metric names remain derived from each upatch and map,
so ``--metric-name`` is rejected with ``--all``. In automatic OTEL mode,
metric settings apply only to maps classified as metrics; log maps ignore
those settings.

Decoding serialized maps with Lua
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An upatch can carry a Lua decoder for a serializer-backed map. Declare the
decoder in the BPF source and keep its Lua file beside the source tree:

.. code-block:: c

    #include "shirudo_decoder.h"

    const struct shirudo_decoder_manifest events_decoder SEC(".rodata") = {
        .magic = SHIRUDO_DECODER_MANIFEST_MAGIC,
        .version = SHIRUDO_UPATCH_DECODER_VERSION,
        .language = SHIRUDO_UPATCH_DECODER_LANG_LUA,
        .api_version = 1,
        .input_format = SHIRUDO_UPATCH_DECODER_INPUT_SERIAL_V2,
        .upatch = "my-patch",
        .map = "events",
        .source = "decoders/events.lua",
        .entrypoint = "decode",
    };

``shirudo build`` resolves the relative source path, embeds the Lua bytes in
the upatch's signed data, and rejects a manifest whose upatch or map does not
match the package. ``shirudo upatch info`` reports the embedded decoder.

The entrypoint receives a table containing the upatch and map identity plus
the serializer-v2 pages. ``shirudo.fixed_records(input.data.pages,
slot_size)`` turns fixed-width page data into slots with ``u8``, ``u16``,
``u32``, ``u64``, and ``cstring`` accessors. The decoder returns a Lua value
made from tables, strings, finite numbers, booleans, and nil.

For ``--json=<path>``, the returned value is appended as the NDJSON record.
For ``--otel`` or ``--otel=log``, it becomes the log body: Lua objects map to
OTLP ``kvlistValue``, arrays to ``arrayValue``, and scalars retain their OTLP
types. The OTLP resource, event name, map identity attributes, endpoint,
credentials, and transport remain controlled by Shirudo. ``--otel=metric``
does not infer metrics from decoder output; it continues to require a
structurally numeric map. ``--otel=s3`` retains the raw serializer snapshot
for archival fidelity.

The LuaJIT host removes filesystem, network, package-loading, FFI, debug, and
dynamic-code globals. Native JIT traces are disabled so the instruction hook
can enforce its budget. The host also enforces memory, nesting, and
output-size limits. LuaJIT is an optional build dependency; without it the
signed manifest remains inspectable and serialized maps fall back to their raw
page representation.

Exporting map snapshots to OpenTelemetry
-----------------------------------------

The detailed map form can export a snapshot over OTLP/HTTP JSON.  ``--otel``
chooses a cumulative metric for an unsigned scalar per-CPU map and a
structured log for every other map shape.  The explicit values override that
choice:

.. code-block:: sh

    # blocked_af_alg is a PERCPU_ARRAY<u32,u64>, so this selects metrics.
    shirudo upatch map cve-2026-31431-counter blocked_af_alg --otel

    # Preserve any map shape as one structured OTLP log record.
    shirudo upatch map my-patch events --otel=log

    # Force gauge semantics and select an OTLP base URL.
    shirudo upatch map my-patch active \
      --otel=metric --otel-endpoint=https://collector.example \
      --metric-kind=gauge --metric-unit=1

``--otel-endpoint`` is always a base URL; Shirudo appends ``v1/logs`` or
``v1/metrics`` for the selected signal.  Without that option, the standard
``OTEL_EXPORTER_OTLP_LOGS_*``, ``OTEL_EXPORTER_OTLP_METRICS_*``, and generic
``OTEL_EXPORTER_OTLP_*`` environment variables configure the endpoint,
headers, CA, mTLS client certificate/key, timeout, and gzip compression.  The
default is the local Collector at ``http://localhost:4318``.

HTTPS verifies both the certificate chain and host name.
``--otel-insecure`` is required for remote cleartext HTTP; on HTTPS it
disables both checks.  Either use prints a prominent warning.  Authentication
tokens belong in
``OTEL_EXPORTER_OTLP_LOGS_HEADERS`` or
``OTEL_EXPORTER_OTLP_METRICS_HEADERS`` rather than the command line, for
example ``Authorization=Bearer%20TOKEN``.  Shirudo never prints configured
header values.

Metric export produces one point per map key and sums per-CPU replicas.
It defaults to a monotonic cumulative counter; use ``--metric-kind=gauge`` for
instantaneous values.  Compound values, maps without numeric BTF, and map
types with dedicated serializers should use ``--otel=log``.  A truncated metric
view is rejected instead of silently omitting time series; add
``--show-full`` when exporting a map with more than 256 entries.  Delivery is
synchronous and defaults to three retries; ``--otel-retries=0`` disables
retries.

Storing large snapshots in S3
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For maps whose serialized form is too large for a useful log record,
``--otel=s3`` writes the complete schema-1 JSON snapshot to S3 and emits only a
small OTLP log reference:

.. code-block:: sh

    export AWS_ACCESS_KEY_ID=...
    export AWS_SECRET_ACCESS_KEY=...
    export AWS_SESSION_TOKEN=...       # optional temporary credentials
    export AWS_REGION=us-west-2

    shirudo upatch map dns dns_arena \
      --otel=s3 --s3-uri=s3://security-telemetry/shirudo/maps

``--s3-uri`` must be ``s3://<bucket>[/<prefix>]``.  S3 mode automatically
lifts the normal 256-entry display cap; ``--show-full`` is accepted but
unnecessary.  Unsupported map types without a pinned serializer and any
unexpectedly truncated view fail without uploading an object.
``AWS_DEFAULT_REGION`` is used when ``AWS_REGION`` is unset; the final
fallback is ``us-east-1``.

The object key is content-addressed and partitioned for browsing::

    <prefix>/<host>/<upatch>/<map>/<sha256>.json.gz

The uploaded bytes are deterministic gzip with ``Content-Type:
application/json``, ``Content-Encoding: gzip``, an S3 SHA-256 checksum, and
``Cache-Control: immutable``.  A conditional PUT makes a retry of identical
content idempotent.  The decompressed document has exactly the same top-level
``schema``, ``upatch``, ``map``, and ``data`` shape written by
``--json=<path>``.

After the PUT succeeds, shirudo sends an OTLP log event named
``shirudo.bpf.map.snapshot.reference``.  Its body contains a short description
and durable ``s3://`` URI; attributes contain map identity, entry counts,
format, compressed and uncompressed sizes, and the object's SHA-256.  Map
entries are never copied into this log event.  If upload fails, no event is
sent.  If OTLP delivery fails, the immutable object is retained and the
command exits nonzero.

``AWS_ENDPOINT_URL_S3`` selects a path-style S3-compatible endpoint such as
MinIO; ``AWS_CA_BUNDLE`` supplies its CA.  AWS itself uses virtual-hosted URLs
(or path style for dotted bucket names).  HTTPS verification is on by default.
Loopback HTTP is allowed for development; any other cleartext endpoint, or
disabling HTTPS verification, requires ``--otel-insecure`` and prints a
warning.  S3 credentials and OTLP authorization headers are read only from the
environment and are never printed.  Retention, encryption at rest, and read
access remain bucket-policy concerns; shirudo neither creates public ACLs nor
puts presigned GET URLs into telemetry.

When the upatch is later unloaded (next section), shirudo
descends into the ``maps/`` subdir and unpins every map before
unlinking the link pin -- no orphan map refs left behind.

12. Roll back
==============

To remove an upatch:

.. code-block:: sh

    # On the operator machine:
    shirudo build --unload myhook -o myhook.unload.upatch
    shirudo rollout myhook.unload.upatch prod-a

The unload artifact is itself a signed `.upatch` — there is no
out-of-band "destroy" path. The target verifies the signature,
verifies that the named upatch is currently loaded with the
expected ``payload_sha256``, detaches the link, removes the pin,
and extends the TPM chain with a ``"shirudo-unload\0"`` event.
For an upatch with maps the cleanup descends into the ``maps/``
subdir first (every map pin is unlinked, refcount drop releases
each map; then ``maps/`` is rmdir'd, then the link pin, then the
parent dir) so the unload teardown is symmetric with the load.

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
       shirudo rollout cve-2026-31431.unload.upatch \\
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
    shirudo rollout workaround.unload.upatch \
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

A target reboot drops the bpffs mount (and with it every ``.upatch``
link and its ``security.bpf.shirudo.payload`` xattr), the kernel
keyring, and the LSM attachment — only the TPM NV chain survives, by
design. So ``shirudo init`` must run once per boot to re-establish
enforcement. shirudo ships a unit for this:

::

    # On the target (target-only -- the operator never runs init):
    make install-target          # drops /usr/lib/systemd/system/shirudo.service
    systemctl enable shirudo.service

``shirudo.service`` is ``Type=oneshot`` and runs as early as a
filesystem-dependent service can: ``DefaultDependencies=no``,
``After=local-fs.target``, ``Before=sysinit.target`` — ahead of
networking, container runtimes, and any other BPF loader, so the
``bpf()`` lockdown and filesystem seal are enforcing before anything
unsigned can act. It uses ``KeyringMode=inherit`` so the cert add into
the user keyring isn't blocked by systemd's private-keyring isolation.

On a target without a TPM, point the unit at degraded mode without
editing it:

::

    echo 'SHIRUDO_INIT_ARGS=--no-tpm' > /etc/shirudo/init.env

A reboot still leaves a brief unenforced window between boot and the
unit running; an even-earlier initramfs-stage init (future work) would
close it. ``shirudo nodes`` shows a target that has not yet re-init'd
as ``UNREACHABLE`` or with the LSM detached.

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
   - **owner-hierarchy authorization failed** (log line
     ``tpm: NV_DefineSpace(...): owner-hierarchy authorization
     failed (rc=0x9a2)``) — the TPM's owner (storage) hierarchy
     has an auth value set, so shirudo cannot create its
     NV-extend index. Common on cloud vTPMs and any TPM a prior
     tool has taken ownership of. Supply the owner auth via
     ``tpm.owner_auth`` in ``/etc/shirudo/shirudo.conf`` (a
     passphrase, or ``hex:<even-hex>`` for a binary value), or
     the ``SHIRUDO_TPM_OWNER_AUTH`` env var, or clear the TPM
     owner auth out of band. Until then init still completes but
     the chain is unmeasured (degraded), exactly as ``--no-tpm``.

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

``shirudo upatch load`` logs ``cannot record payload xattr``
   The target's bpffs rejected ``setxattr`` on the pin directory —
   almost always a kernel below shirudo's minimum bar, which requires
   bpffs extended-attribute support (``kernel/bpf/inode.c``, upstream
   in bpf-next as ``9722955b5430 "bpf: Add simple xattr support to
   bpffs"``). The load itself already succeeded and is enforcing, but
   the per-upatch ``security.bpf.shirudo.payload`` value the unload
   check reads was never recorded, so ``shirudo upatch unload`` for
   that name will refuse. Recovery: run a kernel that includes the
   bpffs xattr support; the value is re-recorded on the next load of
   that upatch, including ``init`` boot-restore.

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

``shirudo upatch unload`` returns ``category: payload_mismatch``
   The pin under ``/var/lib/shirudo/bpffs/upatches/<name>/link``
   exists, but the loaded upatch's ``payload_sha256`` — read from
   the ``security.bpf.shirudo.payload`` xattr on the pin directory
   (set at load, kept unforgeable by bpf2's ``inode_setxattr``
   guard) — does not match the digest the unload directive expects.
   Either (a) an attacker substituted a different upatch under the
   same name (security incident; investigate), (b) the operator's
   unload directive is stale (re-derive the ``--payload-sha256``
   from the currently-loaded upatch on the target via ``shirudo
   upatch info``), or (c) the xattr could not be read at all — the
   check is fail-closed, so an unreadable payload refuses the
   unload rather than proceeding unverified (see the ``cannot
   record payload xattr`` entry above). shirudo refuses to detach
   without confirmation; this protection is intentional. (Pushed
   from the operator, this is a ``shirudo rollout`` of an UNLOAD
   directive — there is no separate ``rollback`` command.)

``shirudo upatch unload`` returns ``category: detach_failed``
   The unload directive verified, but the userspace VFS-unlink of
   the pin failed (dropping the link refcount is how shirudo
   detaches; ``bpf_sys_bpf`` cannot detach in-kernel — TODO.kernel
   item 6). Unusual — surface to a human with the reported errno.
   Could indicate a kernel BPF subsystem issue or state corruption.

shirudo does **not** self-check its own binary
   There is no ``binary_tampered`` category and no build-time hash
   stamping — by design, on-disk binary integrity is **not** an
   in-shirudo defense. It belongs to the distribution layer: signed
   packages, IMA appraisal, dm-verity, measured boot (see
   ``threat-model.rst`` §"Binary integrity"). A substituted shirudo
   binary can lie about anything, including its ``SHIRUDO_VERSION_ID``;
   nothing shirudo runs at startup would catch that, so it does not
   pretend to.

Developer setup: one box as operator and target
================================================

For hacking on shirudo it is convenient to play **both** roles on a
single machine. This works because shirudo is one binary whose role is
decided by which artifacts are present locally, not by a build flag: put
the signing key on the box and it is an operator; put the cert in the
keyring and run ``init`` and it is a target. On a dev box both sets of
artifacts co-locate under ``/var/lib/shirudo/`` and ``shirudo keys``
shows both halves.

This is a development convenience only. A real deployment keeps the
private key on the operator and never on a target; see
``threat-model.rst`` for why.

Prerequisites: root, a current upstream kernel with the BPF LSM enabled
(``lsm=...,bpf`` on the kernel command line) and bpffs xattr support,
and ``clang`` for ``shirudo build``. ``shirudo init --check-only``
reports the readiness picture without touching kernel state.

1. Build and install both roles
--------------------------------

.. code-block:: sh

    make
    # Installs the core binary + completion + systemd unit (target),
    # the shirudo-build dispatch + BPF headers (operator):
    sudo make install-target install-operator

2. Generate the signing key and cert (operator half)
----------------------------------------------------

.. code-block:: sh

    sudo shirudo genkey
    # → /var/lib/shirudo/keys/{signing_key.pem,cert.der}
    #   On a both-roles box the cert is already where the target reads it.

3. Bring up enforcement (target half)
-------------------------------------

.. code-block:: sh

    sudo shirudo init --no-tpm     # simplest dev path; drop --no-tpm to measure
    sudo shirudo status            # LSM attached, keyring serial, assets, ...

``--no-tpm`` keeps the LSM enforcing while skipping chain measurement —
the least-friction choice for a dev loop. To exercise the TPM path, see
"TPM in development" below.

4. Build and load an upatch (the round trip)
--------------------------------------------

.. code-block:: sh

    # Operator half: compile + sign a BPF program into a .upatch.
    shirudo build path/to/your.bpf.c -o /tmp/your.upatch
    shirudo upatch info /tmp/your.upatch          # inspect (works either side)

    # Target half: load it. --no-precheck skips the operator-supplied
    # --expect-chain gate, which a local one-shot load has no need for.
    sudo shirudo upatch load /tmp/your.upatch --no-precheck

    sudo shirudo upatch list      # persisted vs loaded, with orphan detection
    sudo shirudo status           # upatch now shows under "upatches loaded"

To exercise the **full operator path** (SFTP + ssh-exec over libssh)
against your own box, register loopback as a remote and roll out — this
needs ``sshd`` running locally and key-based auth to ``127.0.0.1``
(ssh-agent or ``authorized_keys``):

.. code-block:: sh

    shirudo remote add local root@127.0.0.1 --label env=dev
    shirudo remote list
    shirudo rollout /tmp/your.upatch local

Unload is signed BPF too — there is no separate rollback verb:

.. code-block:: sh

    shirudo build --unload your-name --payload-sha256 <hex> -o /tmp/unload.upatch
    sudo shirudo upatch unload /tmp/unload.upatch --no-precheck

5. The rebuild/reinstall loop (important)
-----------------------------------------

Once ``init`` has run, the filesystem-sealing LSM (``bpf/seal.c``)
protects the installed binary and the whole ``/var/lib/shirudo/`` tree:
a plain ``make install`` then fails with ``Operation not permitted``,
because the seal only lets shirudo's own (matching-xattr) executable
write those inodes. Unmounting the private bpffs drops every shirudo
pin, which detaches the LSM and the seal in one step, after which the
binary is writable again:

.. code-block:: sh

    sudo umount /var/lib/shirudo/bpffs     # detaches LSM + seal + all pins
    sudo make install-target install-operator
    sudo shirudo init --no-tpm             # re-attach; boot-restores the upatch set

If ``umount`` reports the mount busy, retry it a couple of times (a pin
fd may still be closing). This umount/install/init cycle is the standard
inner loop while iterating on shirudo itself.

TPM in development
------------------

Three options, easiest first:

- ``--no-tpm`` — LSM enforces, chain is not measured. Fine for most work.
- **swtpm** — a software TPM 2.0 emulator, recommended for any dev
  or CI environment without real hardware. Point shirudo at it via
  ``SHIRUDO_TPM_TCTI`` and the same NV-extend chain that drives a
  real TPM works against the emulator:

  .. code-block:: sh

      # 1) install (Debian/Ubuntu; equivalents exist on RHEL/Fedora)
      sudo apt install swtpm swtpm-tools

      # 2) one-time state dir (persists across restarts of swtpm; nuke
      #    it to wipe TPM state and start over)
      STATE=/tmp/swtpm-dev
      mkdir -p "$STATE"
      chmod 0700 "$STATE"
      swtpm_setup --tpm2 --tpm-state "$STATE" \
          --create-ek-cert --create-platform-cert --overwrite

      # 3) start swtpm in the background; TCP socket TCTI is the
      #    simplest path and needs no kernel module
      swtpm socket --tpm2 --tpmstate dir="$STATE",mode=0700 \
          --server type=tcp,port=2321 \
          --ctrl   type=tcp,port=2322,terminate \
          --flags startup-clear \
          --log file=/tmp/swtpm-dev.log,level=20 \
          --daemon

      # 4) point shirudo at it. Two equivalent ways -- pick whichever
      #    fits the workflow:
      #
      #    a) per-shell, via env (good for one-shot dev runs):
      #
      export SHIRUDO_TPM_TCTI='swtpm:host=127.0.0.1,port=2321'
      sudo -E shirudo init                  # defines NV index, extends chain
      sudo -E shirudo status --include-tpm  # shows NV chain + eventlog
      #
      #    b) persistent, via the global config (good for CI runners or
      #       a dev host that always uses swtpm). The shirudo.conf key
      #       is `tpm.tcti`; verify with `shirudo config`:
      #
      sudo mkdir -p /etc/shirudo
      printf 'tpm.tcti = swtpm:host=127.0.0.1,port=2321\n' | \
          sudo tee /etc/shirudo/shirudo.conf
      shirudo config | grep tpm.tcti
      sudo shirudo init                     # no -E needed; config wins
      sudo shirudo status --include-tpm

      # The pre-flight check honors either source automatically -- no
      # --no-tpm needed. SHIRUDO_TPM_TCTI takes precedence when both
      # the env var and the config file set the key, so you can
      # temporarily redirect a host with a configured swtpm to a
      # second instance for one ad-hoc run.

  Teardown is the inverse:

  .. code-block:: sh

      # stop swtpm (the --ctrl ... terminate above makes a TPM2 shutdown
      # propagate to swtpm's exit; otherwise pkill is the hammer)
      pkill -f 'swtpm socket' || true

      # forget the state (wipes the NV index, the chain, the EK)
      rm -rf "$STATE"
      unset SHIRUDO_TPM_TCTI

  Notes on the recipe:

  * The override is **dev-only** -- when SHIRUDO_TPM_TCTI is set the
    pre-flight skips the ``/dev/tpmrm0`` access check. The
    operator-side chain expectation still rejects any value a fake
    TPM produces, so a malicious target swapping in a controlled
    swtpm cannot manufacture a "matches" verdict against a real
    operator-pinned ``--expect-chain``.
  * swtpm's owner hierarchy auth is empty by default; if you later
    want to test the ``tpm.owner_auth`` path, take ownership with
    ``tpm2_changeauth -c o '<new-auth>'`` first and set
    ``SHIRUDO_TPM_OWNER_AUTH`` (or the ``tpm.owner_auth`` config
    key) before running ``shirudo init``.
  * The recipe works identically for CI -- pin the ``$STATE`` dir
    in the runner's workspace and the chain survives across the
    ``init`` / ``upatch load`` / ``upatch unload`` cycle in one job.

- **A real/virtual hardware TPM** at ``/dev/tpmrm0`` (the default). If
  its owner hierarchy auth is set (common on cloud vTPMs), ``init``
  cannot define the NV index and degrades with ``tpm: ...
  owner-hierarchy authorization failed``; supply the auth via
  ``tpm.owner_auth`` in ``/etc/shirudo/shirudo.conf`` or
  ``SHIRUDO_TPM_OWNER_AUTH`` (see Troubleshooting).

6. Tear it all down
-------------------

.. code-block:: sh

    sudo umount /var/lib/shirudo/bpffs     # LSM off, all pins gone
    sudo rm -rf /var/lib/shirudo/*         # keys, cert, upatches, eventlog, pins

A reboot also clears the in-kernel state (keyring and bpffs are
per-boot); the installed systemd unit re-runs ``init`` early on the next
boot to restore enforcement. The **only** state that survives a reboot
is the TPM NV measurement chain — if you defined it and want a clean
slate, undefine the index out of band (under the TPM owner auth) or pick
a different ``tpm.nv_index``.
