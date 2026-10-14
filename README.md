# shirudo

shirudo ("shields", Japanese) is a BPF-based security platform for
the agentic era. It is targeted to operate in a close loop with
agents developing and deploying BPF live patches to target systems
(data center fleet, Kubernetes clusters, embedded devices,
air-gapped systems, etc). There is deliberately no config DSL since agents
work a lot better with code.

BPF live patches (aka BPF upatches) can target the Linux kernel
itself or user space applications. The goal is to enable on-the-fly
security patching as well as system attack surface hardening in the
age of Mythos/Glasswing for production systems which have longer
patch/reboot cycles.

Once active, shirudo locks down the `bpf()` syscall on the target
systems so only **signed in-kernel BPF loader programs** can install
BPF code, create maps, or attach links - even for `CAP_SYS_ADMIN`
callers in order to protect against unauthorized tampering.

The userspace tool is agentless: a single `shirudo` binary with git-
like subcommands. There is no shirudo daemon, no shirudo-owned
listening socket, and no long-lived process on the target in order to
be scalable as well as lightweight to fit embedded devices. Targets
pull signed packages from OCI registries on systemd timers and export
status over OTLP.

There are two roles: operator and target. The operator can be
integrated with agents to develop BPF upatches and to deploy them
into the fleet of target machines.

Note: for local development, operator and target roles can both
reside on the same node as well.

*Start here:* Documentation/getting-started.rst
