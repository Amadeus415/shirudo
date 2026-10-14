..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

Getting started
===============

This guide takes one operator host and one target from a source
checkout to a loaded, measured upatch, and then to packages pulled from
a registry.  Commands shown with ``sudo`` run on the target as root;
the others run on the operator as the user who owns the signing key.
`requirements <requirements.rst>`__ lists what each host needs; read it
first if the target kernel is older than Linux v7.4 or not built with
the BPF LSM, BTF and ML-DSA enabled.  For local development one host
can play both roles.


1) Build
--------

From the checkout::

    make                  # the operator-profile shirudo binary
    make shirudo-build    # the operator-only build and publish helper
    make target           # the target binary, shirudo-target
    make test-op          # host-side TAP suite; no root, LSM or TPM
    make SANITIZE=address,undefined test-op
                          # the same suite under ASan and UBSan

``make`` probes the toolchain and libraries and refuses an OpenSSL
older than 3.5.  ``make target`` first runs ``make target-deps``, which
builds a static OpenSSL, libcurl and tpm2-tss from source; the build
host must also provide static ``libelf``, ``zlib``, ``zstd``,
``jitterentropy`` and LuaJIT archives, with
``SHIRUDO_TARGET_STATIC_LIBDIR`` naming their directory when it is not
the system one.  ``make help`` lists every target.

Installable packages::

    make bintar-pkg       # tarballs with an install.sh
    make bindeb-pkg       # shirudo-target and shirudo-operator .deb
    make binrpm-pkg       # the same two packages as RPMs

``PKG_ROLES=target`` or ``PKG_ROLES=operator`` builds one of them; the
operator package links the host's shared libcurl and must be built on
the distribution it is installed on, while the target package is
self-contained.  ``make install-target`` and ``make install-operator``
install one role straight from the tree.  The target package carries
the ``shirudo`` binary, the systemd units and timers, and the default
configuration; the operator package adds ``shirudo-build`` and needs
clang on the host.  Neither ``shirudo-build`` nor clang ever ships to
a target.

When working from a checkout instead of an installed package, put the
checkout root first on ``$PATH`` so ``shirudo build`` finds the helper,
or point ``SHIRUDO_BUILD`` at it.


2) Create a signing key
-----------------------

On the operator::

    sudo shirudo genkey
    sudo shirudo keys

``genkey`` writes an ML-DSA-87 (FIPS 204) private key to
``/var/lib/shirudo/keys/signing_key.pem`` (mode 0600) and a self-signed
certificate to ``cert.der`` beside it; ``--keys-dir <dir>`` chooses
another directory and ``--force`` overwrites an existing pair.  There
is no other key type.  ``keys`` prints the algorithm and fingerprints
of the material on disk and, on a target, the state of the kernel
keyring.

Copy ``cert.der`` to the target through the organisation's normal
provisioning path, into ``/var/lib/shirudo/keys/cert.der``.  Never
copy ``signing_key.pem`` to a target; nothing on the target can use
it, and the threat model assumes it is not there.


3) Build a signed upatch
------------------------

From BPF source, or from an already compiled object::

    shirudo build fix.bpf.c
    shirudo build fix.bpf.o -o fix.upatch

The default output is the input name with ``.c`` or ``.o`` replaced by
``.upatch``, next to the input.  ``shirudo build`` dispatches to
``shirudo-build``, which compiles with ``clang -target bpf -O2 -g``,
generates the signed loader, signs it and writes the container.
Useful options: ``--name <name>`` to override the upatch name,
``--keys-dir <dir>`` (or ``--key`` and ``--cert``) when the key is not
in the default location, ``--vmlinux <vmlinux.h>`` when the default
``vendor/linux/vmlinux.h`` is not the target kernel's,
``--extra-cflags``, and ``--emit-artifacts`` to keep the compiled
``.bpf.o``.  Build against BTF from the target kernel generation:
CO-RE relocations make the artifact portable across builds of the same
kernel, not across kernels that renamed a field.

Review before shipping::

    shirudo upatch info fix.upatch
    shirudo upatch info --json fix.upatch

``info`` prints the header, the sections, the attach metadata and the
signed decoders.  It is an offline view of the file; the program as
the kernel actually loaded it is shown by ``upatch get`` after the
load.


4) Initialise a target
----------------------

Install the target package, place ``cert.der``, then::

    sudo shirudo init --check-only
    sudo shirudo init
    sudo shirudo status --include-tpm

``--check-only`` runs the pre-flight and reports every missing
prerequisite at once without touching the kernel: root, BPF LSM active,
bpffs mountable, the signed-loader kernel ABI, the certificate present
and ML-DSA-87, the kernel able to parse it, the keyring usable, the
embedded enforcement programs present, a TPM 2.0 reachable.  All of
them are hard; there is no unmeasured mode.  A machine without a TPM
can use a software one for development::

    contrib/swtpm.sh start      # prints the SHIRUDO_TPM_TCTI line
    contrib/swtpm.sh env

Either export that variable or set ``tpm.tcti`` in
``/etc/shirudo/shirudo.conf``.  A TPM whose owner hierarchy has a
password needs ``tpm.owner_auth`` (or ``SHIRUDO_TPM_OWNER_AUTH``) for
the one-time NV index definition.

``init`` mounts the private bpffs, installs the certificate into the
``shirudo`` keyring and seals it, labels ``/var/lib/shirudo`` with the
sealing xattr, attaches the enforcement programs, re-applies any
installed upatches and extends the TPM chain.  It is idempotent and
safe to re-run.  ``shirudo.service`` runs it on every boot before
``sysinit.target``; extra arguments go in ``/etc/shirudo/init.env`` as
``SHIRUDO_INIT_ARGS``.  Enable the unit and the timers you want::

    sudo systemctl enable --now shirudo.service
    sudo systemctl enable --now shirudo-bpm-repo-update.timer
    sudo systemctl enable --now shirudo-keepalive.timer shirudo-map-export.timer

``status`` shows the roles, the four conditions, the keyring serial
against its pin, the chain against the eventlog replay and the assets
on disk; ``--json`` emits the same as a document.


5) Load and unload a local artifact
-----------------------------------

Copy the ``.upatch`` to the target by any means and load it::

    sudo shirudo upatch load fix.upatch
    sudo shirudo upatch list
    sudo shirudo upatch get fix

A stricter load binds the operation to the state the caller expects::

    chain=$(sudo shirudo status --json | jq -r .tpm.chain)
    sudo shirudo upatch load --expect-chain=$chain \
        --report=/tmp/fix.json fix.upatch

The load refuses with ``tampered`` if the chain moved since the status
was taken, whether by an attacker or by another operator; take a fresh
status and decide again rather than retrying.  ``--report`` writes a
JSON document with the phase reached, the failure category, the
verifier log and the chain after the operation.

Unloading needs a signed directive, built on the operator and bound to
the payload it may remove::

    shirudo build --unload fix --payload-sha256 <hex from upatch info>
    sudo shirudo upatch unload fix.unload.upatch

Without ``--payload-sha256`` the builder reads the digest from
``/var/lib/shirudo/upatches/fix.upatch`` when that archive exists
locally, and otherwise emits an all-zero digest that makes the target
skip the payload check.  The target loads the directive through the
same signature check as a load, compares the live pin's payload against
the directive, detaches, removes the persisted artifact and extends the
chain.  Unloading something that is not loaded is ``already_unloaded``
and extends nothing.


6) Packages and registries
--------------------------

A package is a directory with a ``Beefile`` next to the BPF sources::

    [package]
    name = "bpf-observability"
    description = "shirudo observability BPF upatches"
    license = "GPL-2.0 OR BSD-2-Clause"
    authors = ["Example Org"]

    [[files]]
    source = "decoders/exec.lua"

    [[upatches]]
    source = "linux-observability.bpf.c"

``[[files]]`` entries are copied into the package (headers, decoders,
reproducers); each ``[[upatches]]`` entry is built and signed, with its
unload directive, through ``shirudo-build``.  On the operator::

    shirudo bpm build ./pkg --version 1.0.0 --keys-dir /var/lib/shirudo/keys
    shirudo bpm info ./bpf-observability-1.0.0.bee
    shirudo bpm push ./bpf-observability-1.0.0.bee \
        oci://quay.io/example/bpf-observability --keys-dir /var/lib/shirudo/keys

``push`` uploads the package and its certificate and, given the signing
material, adds the version to the registry's signed index at
``shirudo/bpm-index:stable``.  Registry credentials come from
``BPM_OCI_USERNAME`` and ``BPM_OCI_PASSWORD``, ``REGISTRY_AUTH_FILE``
or ``DOCKER_CONFIG``; ``BPM_OCI_CA_FILE`` adds a CA and
``BPM_OCI_SCHEME=http`` allows a cleartext local registry.

On the target, register the repository once with the operator's
certificate, then install by hand or let the timer refresh and
upgrade::

    sudo shirudo bpm config register add example oci://quay.io \
        --key-file cert.der
    sudo shirudo bpm repo update
    sudo shirudo bpm install example/bpf-observability
    sudo shirudo bpm list
    sudo shirudo bpm upgrade
    sudo shirudo bpm uninstall bpf-observability

``shirudo bpm install oci://quay.io/example/bpf-observability:1.0.0``
installs a reference directly.  ``bpm info`` prints a package's README
before installing it, from a local ``.bee`` or a reference.  ``bpm
uninstall`` loads the unload directives the package shipped.

Packages whose ``Beefile`` entries carry an ``[upatches.tree]`` table
can also be appended to a signed, append-only upatch tree with
selectors, so a fleet of mixed kernels pulls only what applies::

    shirudo bpm tree append ./bpf-observability-1.0.0.bee \
        oci://quay.io/example/tree --keys-dir /var/lib/shirudo/keys
    shirudo bpm tree append ./bpf-observability-1.0.0.bee \
        oci://quay.io/example/tree --keys-dir /var/lib/shirudo/keys --op delete

A target follows a tree when ``/etc/shirudo/bpm/upatch-tree.conf``
names it (``endpoint=`` and ``reference=``); ``shirudo bpm tree sync
[--dry-run]`` applies the matching operations, and
``shirudo-bpm-tree-sync.timer`` runs it every minute.  Node labels for
selectors live in ``/etc/shirudo/node.labels``.


7) Export telemetry
-------------------

Loaded upatches expose their maps, and shirudo exports them as OTLP
logs and metrics::

    sudo shirudo upatch map --all
    sudo shirudo upatch map --all --otel \
        --otel-endpoint=https://collector.example:4318
    sudo shirudo status --otel --include-tpm --include-system

Set ``map_export.otel_endpoint`` in ``/etc/shirudo/shirudo.conf`` and
enable ``shirudo-map-export.timer`` and ``shirudo-keepalive.timer`` to
push map snapshots and a status keepalive every five seconds.
`telemetry <telemetry.rst>`__ describes the records, the decoders and
how to land them in ClickHouse, Splunk or a collector of your own.


8) Inspect
----------

::

    sudo shirudo status --include-tpm --include-eventlog
    sudo shirudo status --json
    sudo shirudo upatch list
    sudo shirudo upatch get fix
    sudo shirudo upatch map fix counters
    sudo shirudo config
    journalctl -t shirudo

``config`` prints the effective configuration with every key explained.
Every command logs to syslog under the ``shirudo`` tag.


9) Troubleshooting
------------------

``init_prereqs_missing``
    One or more pre-flight checks failed; the message names each one.
    ``shirudo init --check-only`` reproduces the report.

``cert_kernel_support`` (pre-flight), ``signature_unsupported`` (load)
    The kernel cannot verify ML-DSA.  Enable ``CONFIG_CRYPTO_MLDSA`` and
    ``CONFIG_CRYPTO_SHA512``.

``cert_algorithm`` (pre-flight)
    The provisioned ``cert.der`` is not ML-DSA-87.  Re-key with
    ``shirudo genkey`` on the operator.

``kernel_abi_unsupported``
    The kernel lacks the signed-loader ABI.  Upgrade to a current
    upstream kernel.

``signature_rejected``, ``keyring_missing``
    The target was initialised with a different certificate, or not at
    all.  Compare ``shirudo keys`` on both sides.

``tpm2_reachable`` (pre-flight), ``tpm_error``
    No TPM 2.0, or the NV index cannot be defined.  Check
    ``/dev/tpmrm0``, ``tpm.tcti`` for a software TPM, and
    ``tpm.owner_auth`` on a TPM with an owner password.

``verifier_rejected``
    Read the verifier log in the ``--report`` document and rebuild
    against the target kernel's BTF.

``btf_mismatch``
    Regenerate ``vmlinux.h`` from the target kernel and rebuild.

``tampered``
    The chain, the keyring serial or the pins are not what the
    operation expected.  Inspect ``shirudo status`` and the eventlog;
    retry only after the state is understood.

``eventlog_full``
    ``eventlog.max_bytes`` would be exceeded; nothing was loaded or
    extended.  Raise the cap or archive the eventlog.

``version_mismatch``
    ``--expect-version-id`` named a different build of shirudo.

Registry fetch failures
    Check the ``oci://`` endpoint, the ``BPM_OCI_*`` environment, the
    certificate registered under ``/etc/shirudo/bpm``, and that the
    registry offers TLS 1.3 with a hybrid ML-KEM group; shirudo never
    falls back to classical TLS.
