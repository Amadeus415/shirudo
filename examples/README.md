# shirudo example upatches

This directory contains reference BPF upatches that operators can
build, sign, and roll out as-is, or use as templates for their own.
Each example is a single `.bpf.c` source file plus this README; the
build is the standard `clang -target bpf -O2 -g -c` against the
shared `bpf/lib/` headers and the build-time-generated
`bpf/vmlinux.h`.

See `../PLAN.md` for the implementation plan and
`../Documentation/architecture.rst` for the conceptual model.

## Building

On an operator machine where the `shirudo-build` package is
installed, one command produces a signed `.upatch` from BPF
source:

```sh
shirudo build examples/cve-2026-31431.bpf.c -o cve-2026-31431.upatch
```

`shirudo build` holds the **single subprocess exception** in
shirudo (PLAN.md §"Goals & non-goals"): the core `shirudo`
binary dispatches via `execv` to a separate `shirudo-build`
binary at `$(libexecdir)/shirudo/shirudo-build`, which `execv`s
`clang -target bpf -O2 -g -Wall -Wextra …` and then runs libbpf
gen_loader + CMS signing in-process to package the `.upatch`.
Both `shirudo-build` and `clang` ship only with the operator
package — they do not exist on targets. On a target where the
dispatcher isn't installed, `shirudo build` returns exit 127
with a clear "operator-only subcommand" message.

For the **bundled examples in this directory**, there's also a
convenience Makefile that calls `clang` directly to produce
`.bpf.o` files (no `.upatch`), useful when developing shirudo
itself or when separating compile and sign across machines:

```sh
make examples                       # compile all examples to .bpf.o
make examples/cve-2026-31431.bpf.o  # compile one
```

You can then hand the resulting `.bpf.o` to `shirudo build`
(which skips the compile step for `.bpf.o` inputs and goes
straight to gen_loader + sign + package):

```sh
shirudo build examples/cve-2026-31431.bpf.o -o cve-2026-31431.upatch
```

For **operator-authored upatches outside this tree** that
don't want to use `shirudo build` (e.g., a CI build farm with a
custom toolchain), invoke `clang` directly and hand the result
to `shirudo build` for signing:

```sh
# Generate vmlinux.h for the target kernel (one time):
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Compile:
clang -target bpf -O2 -g -Wall -Wextra \
      -I . -I /usr/include/bpf \
      -c my-upatch.bpf.c -o my-upatch.bpf.o

# Sign and package on the operator (signing key is here):
shirudo build my-upatch.bpf.o -o my-upatch.upatch
```

## Signing and rolling out

On the operator machine (which holds the signing key):

```sh
shirudo build examples/cve-2026-31431.bpf.c -o cve-2026-31431.upatch
shirudo rollout cve-2026-31431.upatch prod-fleet-a prod-fleet-b ...
```

`shirudo build` compiles, runs gen_loader, signs, and packages
the `.upatch` in one step. There is no separate `sign` subcommand
— the entire artifact-producing pipeline lives in the
operator-only `shirudo-build` binary.

To roll back when the upstream kernel fix has landed:

```sh
shirudo build --unload cve-2026-31431 -o cve-2026-31431.unload.upatch
shirudo rollback cve-2026-31431.unload.upatch prod-fleet-a prod-fleet-b ...
```

## Index

| File | Purpose |
|---|---|
| [`cve-2026-31431.bpf.c`](cve-2026-31431.bpf.c) | Mitigates CVE-2026-31431 by refusing every userspace `socket(AF_ALG, …)` call. Hooks the BPF LSM `socket_create` hook; returns `-EPERM` when `family == AF_ALG`; allows everything else. Carries the dual `(GPL-2.0 OR BSD-2-Clause)` SPDX header required for BPF LSM programs. |

## Conventions for new examples

- One self-contained `.bpf.c` per example, named after the threat
  it mitigates (`cve-YYYY-NNNNN.bpf.c`) or the behaviour it adds
  (`audit-foo.bpf.c`). The basename without `.bpf.c` becomes the
  `upatch_name` shirudo records on the target.
- First-line SPDX `// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)`
  (matches the BPF LSM dual-license requirement) followed by
  `Copyright (c) 2026 Authors of shirudo`. See PLAN.md
  §"Source file headers".
- Include `"vmlinux.h"` (build-time-generated) plus the libbpf
  helper headers from `bpf/lib/` (`bpf_helpers.h`,
  `bpf_tracing.h`). Do not pull in `<linux/...>` headers
  directly; `vmlinux.h` provides everything.
- Keep each example small. The goal is "an operator can read the
  source in 30 seconds and understand the change", not "a
  general-purpose framework". Composability is handled at the
  upatch level (deploy several small upatches, not one big one).
- A comment at the top of the file should name the threat being
  mitigated, the upstream fix (if any) that the mitigation is
  bridging to, and the conditions under which the upatch should
  be rolled back.
