# vendor/libbpf

Vendored copy of libbpf and the BPF UAPI headers shirudo builds against.
Normal builds use only this directory; no kernel tree or submodule is
needed. Refresh it on demand with

    make bpf-deps                       # clones bpf-next
    make bpf-deps KERNEL_SRC=/path/to/linux

which overwrites the copied files from `tools/lib/bpf/` and
`tools/include/uapi/linux/` of that tree, regenerates
`bpf/bpf_helper_defs.h` with the tree's `scripts/bpf_doc.py`, records the
source commit in `COMMIT`, and rebuilds `libbpf.a` as a check.

| Path | Origin | License |
|---|---|---|
| `bpf/*.c`, `bpf/*.h` | `tools/lib/bpf/` (verbatim) | `LGPL-2.1 OR BSD-2-Clause`; shirudo consumes the BSD branch |
| `bpf/bpf_helper_defs.h` | generated from `bpf.h` by `scripts/bpf_doc.py` | as libbpf |
| `include/uapi/linux/*.h` | `tools/include/uapi/linux/` (verbatim) | `GPL-2.0 WITH Linux-syscall-note`: the syscall note permits user programs to include them |
| `include/linux/*.h`, `include/asm/*.h` | shirudo-owned shims replacing the kernel's `tools/include` internals | BSD-2-Clause |
| `Makefile`, `README.md` | shirudo-owned | BSD-2-Clause |

The shims are the reason this copy builds outside the kernel tree: libbpf
reaches for a handful of `tools/include/linux` helpers (`ARRAY_SIZE`,
error pointers, byte-order conversion, the eBPF instruction constructors,
acquire/release ring-buffer accessors), all GPL-2.0-only in the kernel, so
shirudo provides its own definitions of exactly that surface. When an
update makes libbpf need a new helper, the `libbpf.a` rebuild at the end
of `bpf-deps` fails on the missing symbol; extend the shim.
