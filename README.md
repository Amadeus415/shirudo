<picture>
  <source media="(prefers-color-scheme: dark)" srcset="Documentation/logos/shirudo-horizontal-for-dark-back.png">
  <img src="Documentation/logos/shirudo-horizontal-for-light-back.png" width="350" alt="shirudo">
</picture>

\
[![Build packages](https://github.com/shirudo-dev/shirudo/actions/workflows/deb.yml/badge.svg?branch=main)](https://github.com/shirudo-dev/shirudo/actions/workflows/deb.yml)
[![Documentation](https://github.com/shirudo-dev/shirudo/actions/workflows/docs.yml/badge.svg?branch=main)](https://github.com/shirudo-dev/shirudo/actions/workflows/docs.yml)
[![Sanitizers](https://github.com/shirudo-dev/shirudo/actions/workflows/sanitizers.yml/badge.svg?branch=main)](https://github.com/shirudo-dev/shirudo/actions/workflows/sanitizers.yml)
[![CodeQL](https://github.com/shirudo-dev/shirudo/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/shirudo-dev/shirudo/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg)](LICENSE)

shirudo ("shields", JP) is a BPF security platform for the agentic era.
It ships BPF live patches, called upatches, to Linux targets without a
reboot, and it makes sure a target runs only the BPF its operator signed.
upatches can harden or patch the kernel itself or userspace applications;
the goal is on-the-fly security visibility, patching and attack-surface
hardening in the age of LLMs, for production systems whose patch and
reboot cycles often span multiple days if not weeks.

For example, the Linux kernel's CVE stream runs at dozens of fixes a day,
exploitation now regularly precedes the patch, and a fleet reboot cycle
might takes weeks. shirudo exists for the window in between: an agent,
engineer or hybrid workflow derives a BPF mitigation from the fix, the
operator signs it, and the fleet pulls it within the hour, measured and
revocable. There is deliberately no configuration DSL, since agents work
better with plain code. shirudo is not limited to just mitigations, it
serves as a platform and can deploy any BPF programs into the fleet.

What it does:

* **Signed BPF only:** Once shirudo is brought up during early boot, the
  kernel accepts BPF from userspace only inside a signed loader program
  whose CMS signature verifies against the certificate in a sealed BPF
  kernel keyring before the verifier runs.
* **Root is not enough:** shiurdo's BPF programs lock down the bpf(2)
  syscall so that even CAP\_SYS\_ADMIN cannot load, replace or detach
  BPF without the signing key; pins live in a private bpffs that cannot
  be unlinked, unmounted or mounted over.
* **Sealed state:** Every file shirudo owns carries an xattr security
  label that only the shirudo binary itself can access and modify.
* **Measured:** Every init, load and unload extends a per-boot TPM
  measurement register built like a systemd NvPCR, bound from the
  initrd and anchored in PCR 9; `shirudo attest` has the TPM quote the
  boot PCRs and certify the
  register, and the operator verifies that evidence offline against the
  value predicted from the signed artifacts.
* **Agentless:** shirudo is a plain-C binary, no daemon, no listening
  socket. Everything on the target is a one-shot command, run by hand
  or by systemd timers, which keeps it generally light enough to deploy
  also on embedded devices.
* **Pull-based delivery:** The operator publishes signed packages to an
  OCI registry; target nodes pull, verify and install them on a timer, or
  follow a signed, append-only upatch tree whose selectors match kernel
  release, build ID, Kconfig and node labels.
* **Telemetry out, nothing in:** Map snapshots and status keepalives
  are pushed as OTLP logs and metrics to the OpenTelemetry Collector,
  ClickHouse, Splunk or any collector that accepts OTLP/HTTP JSON, with
  decoders that ship signed inside the upatch.
* **PQC by default:** ML-DSA-87 is used as signing algorithm; every TLS
  client speaks TLS 1.3 with hybrid ML-KEM key exchange.

Two roles, one binary: the *operator* holds the private signing key and
builds, signs and publishes; the *target* holds only the public
certificate, verifies every load and reports its state. For local
development both roles can live on the same node.

## Getting Started

* [Getting started](Documentation/getting-started.rst): build, sign,
  initialise a target, load and unload, publish and install packages.
* [Upatches](Documentation/upatch.rst): writing the BPF side, building
  and signing, packaging, publishing to a registry and the signed tree.
* [Key lifecycle](Documentation/key-lifecycle.rst): the signing key and
  certificate, distribution, rotation, revocation and custody.
* [Operations](Documentation/operations.rst): watching a target,
  upgrades, decommissioning, backup, recovery and the failure
  categories.
* [Requirements](Documentation/requirements.rst): kernel options,
  operator toolchain, target runtime.
* [Architecture](Documentation/architecture.rst): why shirudo exists,
  its design properties and how the pieces fit.
* [Threat model](Documentation/threat-model.rst): trust boundaries,
  the threats addressed and the residual risks.
* [The TPM](Documentation/tpm.rst): the per-boot measurement
  register, the signed evidence and its verification.
* [The initrd](Documentation/initrd.rst): the production configuration,
  with `init` run from the initrd, and the generator and installer that
  set it up.
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
