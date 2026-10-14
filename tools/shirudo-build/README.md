# shirudo-build

`shirudo-build` is the **operator-only** artifact-producing dispatcher
for shirudo. It compiles BPF source, runs libbpf's `gen_loader`, CMS-
signs the resulting loader bytes with the operator's private key, and
serialises the result as a `.upatch` container ready for
direct target-side loading.

## Why a separate binary

shirudo's invariant is "no subprocesses at runtime, ever — with one
named exception." That exception is the `execv` of `clang -target bpf`
needed to compile `.bpf.c` sources. By physically isolating that
exception in a separate binary that ships only with the operator
package, the no-subprocess invariant remains absolute on every
target-side code path. The same binary hosts every operator-only BPM
command: `shirudo bpm build` (Beefile to signed `.bee`), `shirudo bpm
push` (package plus signed repository index) and `shirudo bpm tree
append` (signed upatch tree). They are compiled only into
`shirudo-build`, so the `shirudo` binary shipped to targets carries
none of that code, and they sign in-process with the CMS signer that
is linked only here.

The core `shirudo` binary's `builtin-build.c` dispatches to the helper
using this resolution order: the `SHIRUDO_BUILD` environment override,
the compiled-in `$(libexecdir)/shirudo/shirudo-build` path, then
`shirudo-build` found on `$PATH`. The last case supports using a
checkout's locally built binaries without installing them. `shirudo
bpm build|push|tree append` hand their full argument vector to
`shirudo-build bpm ...` the same way.

See `PLAN.md` § "Operator-only binaries and dual install targets" for
the full rationale.

## Modes

| Input | Action |
|---|---|
| `<source.bpf.c>` | compile (execv clang) → gen_loader → sign → package |
| `<file.bpf.o>` | gen_loader → sign → package (skip compile) |
| `--unload <name>` | emit signed UNLOAD directive `.upatch` |
| `bpm build [context] --version <v>` | compile, sign and package every Beefile upatch into a `.bee` |
| `bpm push <pkg.bee> oci://...` | publish the package, its cert referrer and the signed index entry |
| `bpm tree append <pkg.bee> oci://...` | publish the next generation of a signed upatch tree |

## Install location

`$(libexecdir)/shirudo/shirudo-build`, typically
`/usr/local/libexec/shirudo/shirudo-build`.

Distribution packagers should put this in a separate `shirudo-build`
package that depends on `shirudo`, `clang`, and `llvm`.

For checkout/developer use, build both binaries and put their directories
first on `PATH`:

```sh
PATH="$PWD/tools/shirudo-build:$PWD:$PATH" \
  shirudo bpm build --version 1.0.0 --keys-dir "$HOME/.config/bpm"
```

## Uprobe multi attach points

One upatch BPF program can attach to multiple entry points in one user-space
ELF with:

```c
SEC("uprobe.multi//absolute/path/to/program:*Func")
int probe(struct pt_regs *ctx)
{
	return 0;
}
```

The portion after the colon is a standard libbpf glob: `*` matches any
sequence and `?` matches one character. Thus `*Func` can match unrelated
functions such as `fooFunc` and `barFunc`. Comma/`|` alternation is not
supported; use a single glob that covers the desired names. Each section
targets one absolute ELF path, entry probes only.

`shirudo-build` resolves matching `STT_FUNC` symbols to sorted, unique ELF
file offsets and records the ELF's GNU build ID in UPGM v2 metadata. The build
fails if the path is not absolute, the glob is empty or longer than 127 bytes,
no function matches, the ELF lacks a GNU build ID, or more than 1,048,576
offsets match. The target verifies the build ID before loading any BPF state.
