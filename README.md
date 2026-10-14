<picture>
  <source media="(prefers-color-scheme: dark)" srcset="Documentation/logos/shirudo-horizontal-for-dark-back.png">
  <img src="Documentation/logos/shirudo-horizontal-for-light-back.png" width="350" alt="shirudo">
</picture>

\
[![Build packages](https://github.com/shirudo-dev/shirudo/actions/workflows/deb.yml/badge.svg?branch=main)](https://github.com/shirudo-dev/shirudo/actions/workflows/deb.yml)
[![Documentation](https://github.com/shirudo-dev/shirudo/actions/workflows/docs.yml/badge.svg?branch=main)](https://github.com/shirudo-dev/shirudo/actions/workflows/docs.yml)
[![Sanitizers](https://github.com/shirudo-dev/shirudo/actions/workflows/sanitizers.yml/badge.svg?branch=main)](https://github.com/shirudo-dev/shirudo/actions/workflows/sanitizers.yml)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg)](LICENSE)

shirudo ("shields", Japanese) is a BPF security platform for the agentic
era. It ships BPF live patches, called upatches, to Linux targets
without a reboot, and it makes sure a target runs only the BPF its
operator signed. upatches can harden or patch the kernel itself or
userspace applications; the goal is on-the-fly security patching and
attack-surface hardening in the age of Mythos/Glasswing, for production
systems whose patch and reboot cycles are longer than an attacker's.

The kernel's CVE stream runs at dozens of fixes a day, exploitation now
regularly precedes the patch, and a fleet reboot cycle takes weeks.
shirudo exists for the window in between: an agent or an engineer
derives a BPF shield from the fix, the operator signs it, and the fleet
pulls it within the hour, measured and revocable. There is deliberately
no configuration DSL, since agents work a lot better with code.

What it does:

* **Signed BPF only.** Once `shirudo init` has run, the kernel accepts
  BPF from userspace only inside a signed loader program whose CMS
  signature verifies against the certificate in a sealed kernel keyring,
  before the verifier runs. The payload is hash-locked to the loader.
* **Root is not enough.** BPF LSM programs lock down the `bpf()` syscall
  so that even `CAP_SYS_ADMIN` cannot load, replace or detach BPF
  without the signing key; pins live in a private bpffs that cannot be
  unlinked, unmounted or mounted over.
* **Sealed state.** Every file shirudo owns carries an xattr label
  that only the shirudo binary itself may write, rename or remove;
  shirudo processes cannot be ptraced or profiled by root.
* **Measured.** Every init, load and unload extends a non-resettable
  TPM 2.0 NV index and appends to an eventlog; an operator checks a
  target from one 32-byte value, and a chain that moved refuses every
  further operation as `tampered`.
* **Agentless.** One plain-C binary with git-like subcommands, no
  daemon, no listening socket. Everything on the target is a one-shot
  command, run by hand or by systemd timers, which keeps it light
  enough for embedded devices.
* **Pull-based delivery.** The operator publishes signed packages to an
  OCI registry; targets pull, verify and install them on a timer, or
  follow a signed, append-only upatch tree whose selectors match kernel
  release, build ID, Kconfig and node labels.
* **Telemetry out, nothing in.** Map snapshots and status keepalives
  are pushed as OTLP logs and metrics to the OpenTelemetry Collector,
  ClickHouse, Splunk or any collector that accepts OTLP/HTTP JSON, with
  decoders that ship signed inside the upatch.
* **Post-quantum by default.** ML-DSA-87 is the only signing algorithm;
  every TLS client speaks TLS 1.3 with hybrid ML-KEM key exchange only.
* **Built for agents.** Every command has structured JSON input and
  output, named failure categories and verifier logs captured in full,
  so an agent can build, test and ship a mitigation and read back
  exactly what happened.

Two roles, one binary: the *operator* holds the private signing key and
builds, signs and publishes; the *target* holds only the public
certificate, verifies every load and reports its state. For local
development both roles can live on the same node.

## Getting Started

* [Getting started](Documentation/getting-started.rst): build, sign,
  initialise a target, load and unload, publish and install packages.
* [Requirements](Documentation/requirements.rst): kernel options,
  operator toolchain, target runtime.
* [Architecture](Documentation/architecture.rst): why shirudo exists,
  its design properties and how the pieces fit.
* [Threat model](Documentation/threat-model.rst): trust boundaries,
  the threats addressed and the residual risks.
* [Telemetry](Documentation/telemetry.rst): the OTLP export and how to
  integrate it with collectors.
* [The .upatch format](Documentation/upatch-spec.rst): the signed
  artifact, byte by byte.
* [Contributing](Documentation/contributing.rst) and the
  [Code of Conduct](CODE_OF_CONDUCT.md).

The full index is in [Documentation/index.rst](Documentation/index.rst).

## License

shirudo is licensed under the [BSD-2-Clause License](LICENSE). BPF
programs are dual-licensed `Dual BSD/GPL`. Each source file holds a
SPDX license identifier.
