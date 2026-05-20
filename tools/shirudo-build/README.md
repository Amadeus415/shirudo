# shirudo-build

`shirudo-build` is the **operator-only** artifact-producing dispatcher
for shirudo. It compiles BPF source, runs libbpf's `gen_loader`, CMS-
signs the resulting loader bytes with the operator's private key, and
serialises the result as a `.upatch` container ready for
`shirudo rollout`.

## Why a separate binary

shirudo's invariant is "no subprocesses at runtime, ever — with one
named exception." That exception is the `execv` of `clang -target bpf`
needed to compile `.bpf.c` sources. By physically isolating that
exception in a separate binary that ships only with the operator
package, the no-subprocess invariant remains absolute on every
target-side code path.

The core `shirudo` binary's `builtin-build.c` is a five-line `execv`
wrapper to `$(libexecdir)/shirudo/shirudo-build`; the libexec path is
hardcoded at build time, not `$PATH`-resolved.

See `PLAN.md` § "Operator-only binaries and dual install targets" for
the full rationale.

## Modes

| Input | Action |
|---|---|
| `<source.bpf.c>` | compile (execv clang) → gen_loader → sign → package |
| `<file.bpf.o>` | gen_loader → sign → package (skip compile) |
| `--unload <name>` | emit signed UNLOAD directive `.upatch` |

## Install location

`$(libexecdir)/shirudo/shirudo-build`, typically
`/usr/local/libexec/shirudo/shirudo-build`.

Distribution packagers should put this in a separate `shirudo-build`
package that depends on `shirudo`, `clang`, and `llvm`.
