# shirudo

shirudo ("shields", Japanese) is a BPF LSM-based security platform written
in plain C. Once active, shirudo locks down the `bpf()` syscall so only
**signed in-kernel BPF loader programs** can install BPF code, create maps,
or attach links — even for `CAP_SYS_ADMIN` callers.

The userspace tool is agentless: a single `shirudo` binary with git-like
subcommands, fronted by the system's `sshd`. There is no shirudo daemon,
no shirudo-owned listening socket, and no long-lived process on the target.

## Status

**Planning phase.** This repository currently contains the design (in
`PLAN.md`), the threat model and contributor docs (in `Documentation/`),
and one worked example (in `examples/`). No source has been committed
yet — implementation order is documented in `PLAN.md` § "First
implementation order".

The design has been reviewed and is considered ready for phase 0 of
implementation. Open questions and deferred items are tracked in
`PLAN.md` § "Open questions / future work".

## Build/target split

| Side | Holds | Produces | Talks to |
|---|---|---|---|
| Operator | Private signing key | Signed `.upatch` artifacts | Targets via SSH (libssh) |
| Target   | Public X.509 cert in a kernel keyring | Nothing — applies upatches | Kernel via `bpf()` |

This mirrors `git push`: artifacts flow outward from the
credential-holder. The build/sign step lives in a separate
`shirudo-build` binary that is **only** installed on the operator
machine — it is the single subprocess exception in shirudo, and physically
isolating it as a separate binary keeps the target attack surface
minimal.

## Documentation

| File | For |
|---|---|
| `PLAN.md` | Implementation plan / source of truth design |
| `CLAUDE.md` | Project guidance for AI-driven contribution |
| `Documentation/architecture.rst` | Contributor-facing conceptual model |
| `Documentation/threat-model.rst` | Adversary classes, target/operator threats, residual risks |
| `Documentation/getting-started.rst` | Operator quickstart, troubleshooting, CVE response |
| `Documentation/index.rst` | Doc tree index |
| `examples/` | Worked `.upatch` examples (CVE mitigation) |

## License

BSD-2-Clause for userspace; the BPF programs in `bpf/` declare
`Dual BSD/GPL` for the kernel's LSM-hook framework. See `LICENSE` for
the full text and `PLAN.md` § "Source file headers" for the per-file
SPDX matrix.

## Reporting issues

shirudo is pre-implementation. Design-level issues, threat-model gaps,
and questions about the plan are welcome — file them where the project
host directs you.
