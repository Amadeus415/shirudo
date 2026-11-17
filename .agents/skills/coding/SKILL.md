---
name: coding
description: Write or change shirudo's C code, userspace or BPF, and the Rust that replaces its C modules, in the tree's style. Covers the kernel coding style it follows, where a comment belongs and where it is clutter, the helpers in util/ and include/shirudo/ to use instead of libc or open code, moving code two places need into util/, memory, secrets, JSON and logging, porting a C module to rust/, and the checks a change passes. Use whenever writing, changing or reviewing C or Rust in shirudo.
---

# Coding

`Documentation/contribute/code/coding-style.rst` is the kernel's coding
style, and the tree follows it in userspace as well as in BPF: tabs
eight wide, 80 columns where it reads well and never past 100, K&R
braces, short functions that do one thing. AGENTS.md lists the
project's conventions in short; this skill gives them with their
reasons. Read the code around a change first and write like it.

## Write code that explains itself

Write self-documenting code: a reader gets what it does and why from
the names and the shape of the code, without a comment.

- Name a function for what it does and a variable for what it holds:
  `payload_len`, not `n2`; `upatch_name_valid()`, not `check()`; a
  boolean for what is true, `whole`, `found`. A bare number becomes a
  named constant or a `sizeof`.
- A step that would need a comment becomes a small function whose name
  says it, and a condition that needs reading twice becomes a helper or
  a well-named local.
- One function does one job and fits on a screen; errors return early
  instead of nesting the rest.
- The plain construct beats the clever one. Where the clever one is
  needed for correctness or speed, that need is the why worth a comment.
- A comment that restates the code means the code should change: rename
  or split until the comment says nothing new, then drop it.

Instead of

```c
/* Leave out the per-CPU maps. */
if (type == 5 || type == 6 || type == 10)
	continue;
```

write

```c
if (upatch_map_is_percpu(type))
	continue;
```

## Comments

Code says what it does; a comment is for what it cannot say.

- A `.c` file starts with `// SPDX-License-Identifier: BSD-2-Clause`, a
  header with `/* SPDX-License-Identifier: BSD-2-Clause */`, followed by
  the copyright, `Copyright (c) 2026 Authors of shirudo`, and at most
  five lines on what the file holds. Nothing more at the top.
- In a function, almost never. Write one only for the why a reader
  cannot get from the code: an invariant kept elsewhere, a kernel or
  library quirk ("zlib 1.3.2 reads past the end of a member"), the
  reason the obvious way is wrong here. One or two sentences, before the
  code it explains.
- Never what the code does, what a name already says, or what a message
  prints; never history ("added for", "was", "used by"), which goes in
  the commit message; never code commented out.
- A function's contract goes above its declaration in the header, and
  only when the prototype does not tell it: what it returns on which
  failure, what it owns or frees, what it refuses.
- Block comments open with `/*` and close with `*/` on lines of their
  own, every line between starting with ` *`; `//` is for SPDX alone.

Clutter, to leave out:

```c
/* Check the length. */
if (len > max)
	return -E2BIG;
```

Worth writing:

```c
/*
 * The header is not signed: .rodata is where the signed loader takes
 * it from, and a header naming another offset would aim the rewrite at
 * other bytes.
 */
```

## Use util/, and grow it

Never write the same logic twice. Before writing a parser, a check, a
path, a copy loop or a record format, look for one that already does it,
in `util/`, `include/shirudo/` and the builtins alike: `git grep -n
'<word>'`. A variant that differs only in a length check, a bound or a
message is still a copy: make one helper, with a parameter or with the
extra check left to the caller, and move one found in a builtin into
`util/` for both. The basics:

| Need | Use |
|---|---|
| Parse a number | `parse_u64()`, `parse_s64()`, `parse_x64()`, `digits()` (`<shirudo/string.h>`) |
| Copy a string | `strscpy()`, and check `-E2BIG` |
| An upatch's pin directory or a pin in it | `upatch_pin_path()` (`util/paths.h`) |
| A file name's extension | `name_has_suffix()` (`<shirudo/string.h>`), `upatch_select()` for a scandir of upatches |
| Text from outside on a terminal | `text_sanitize()`; UTF-8 with `utf8_width()` |
| Sizes and lengths | `check_add_overflow()` and kin, `size_add()`, `size_mul()`, `struct_size()` (`<shirudo/overflow.h>`) |
| Smaller or larger | `min()`, `max()` (`<shirudo/misc.h>`) |
| Memory | `xmalloc()`, `xcalloc()`, `xreallocarray()`, `xstrndup()`, `xfree(p, size)` (`util/malloc.h`) |
| Secrets | `memzero_explicit()`, `memneq_explicit()` |
| Files | `read_file()`, `read_fd()`, `write_complete()`, `append_line()`, `lines_len()`, `open_beneath()`, `lock_exclusive()` (`util/io.h`) |
| Sealed state and paths root names | `seal_open()`, `seal_lock()`, `seal_append_line()`, `seal_write_file()`; `seal_output_create()` and `seal_output_commit()` for a report or export (`util/seal.h`) |
| Bytes on the wire | `get_le32()`, `put_be32()`, `le32_to_cpu()` and kin (`<shirudo/byteorder.h>`), `hex_encode()`, `hex_decode()`, `hex_decode_max()`, `sha256_digest_decode()` (`util/hex.h`) |
| JSON | `util/json.h`: `json_parse()` with a schema, `json_walk()`, `struct json_emit` |
| Messages | `log::err()`, `warn()`, `info()`, `audit()`, and `log_c!` for a C format (`rust/src/log.rs`) |

Code that a second place needs moves into `util/<m>.c`, declared in
`util/<m>.h`, or in `include/shirudo/` for the project's basics, with
cases in `testing/unit/<m>.c`, and the copies it replaces go in the same
commit. Two static copies of one helper in two builtins are a bug in
waiting: one gets fixed and the other does not. A util function takes a
length rather than trusting a terminator in outside data, returns 0 or
a negative errno, and leaves the message to its caller. Operator-only
code, signing and the package builder, stays out of the core binary.

## Conventions

- Plain C; zero-initialise with `= {}`.
- Integers are `__u8` to `__u64` and `__s8` to `__s64`; `__u64` prints
  with `%llu`, and `ptr_to_u64()` gives the `__u64` the bpf() ABI takes.
  A library interface that takes another type keeps it, and BPF spells
  hook arguments as the kernel's prototypes do. `check-style.sh` refuses
  `uint32_t` and its kin, and in userspace `unsigned int`, `long` and
  the like. System headers that use `uint8_t` and kin go above the first
  shirudo header, which poisons them.
- `strtoul()`, `atoi()`, `strcpy()`, `sprintf()`, `snprintf()`, the libc
  allocators and `explicit_bzero()` are poisoned; the table above has
  what replaces each, and a missing one is wrapped in `util/`, never
  given an exception.
- A `strsprintf()` that does not fit leaves the buffer empty: a path or
  value is refused, a helper formatting display text returns the error,
  and status shows `"?"`. Constant text is copied, not formatted.
- `xstrdup()` measures with `strlen()`, so outside input gets
  `xstrndup(s, bound)`. `xfree(p, size)` and `xstrfree()` scrub before
  they free.
- `min_t()` and `max_t()` cast and can cut a value, so they are for
  only what `min()` and `max()` refuse; a constant compared with an
  unsigned value takes a `U` suffix.
- `ret` holds a return code, `err` an errno kept beside the value a
  function returns. No `(void)` casts: a result that must be checked
  comes from a `__must_check` function, and every call checks it.
- Internal names carry no `shirudo_` prefix; it stays only where a name
  leaves the code: include guards, BPF object and pin names, environment
  variables, a clash with libc.
- Locals in reverse-Christmas-tree order, longest line first, except
  where an initializer needs an earlier local.
- Never two blank lines in a row. Removing code often brings the blank
  lines around it together: drop one of them. checkpatch checks only
  the lines a patch adds, so it does not see a pair a deletion makes.
- A frame past 128 KiB fails the build: tables go on the heap, and a
  helper with a big buffer is `noinline_for_stack`.
- Scrub a key, a seed, a credential or a buffer that held one with
  `memzero_explicit()` on every path out, error paths included, and
  compare it with `memneq_explicit()`. Mark a struct member that holds
  one `__sensitive`: a check then wants every local of that struct
  scrubbed the same way, member filled by a parser and all.
- All JSON goes through `util/json.h`; text from outside is written
  with its lossy writers. All logging goes through `rust/src/log.rs` to syslog;
  shirudo writes no log file of its own.
- Fields of a little- or big-endian format are read and written with
  `le32_to_cpu()`, `get_le32()` and their kin; sparse refuses the rest.
- Userspace is BSD-2-Clause. Every file a BPF object compiles, and each
  Lua decoder, is `GPL-2.0 OR BSD-2-Clause`, with
  `char _license[] SEC("license") = "Dual BSD/GPL";`. No emojis.
- BPF code is CO-RE, built for `-mcpu=v4`; upatch code follows the
  `upatch` and `bpf-concurrency` skills.

## Rust

The Rust library under `rust/` replaces C modules, re-implemented
rather than translated line by line, and a module's C interface stays
its contract while any C caller uses it.

- The port of `util/<m>.c` is `rust/src/util/<m>.rs`, or the directory
  `rust/src/util/<m>/` for one that takes more than a file: safe code
  over slices and Rust types, and a `capi` submodule whose
  `#[unsafe(no_mangle)] pub unsafe extern "C"` functions keep the names,
  types and behavior `util/<m>.h` declares, down to what one returns for
  an empty buffer. The header stays and names the Rust file. The C file
  goes in the same commit, and every link in `Makefile.shirudo` that
  took its object takes `$(RUST_LIB)` after the objects and
  `$(RUST_LDLIBS)` after the libraries, `$(RUST_TEST_LDLIBS)` in a
  helper, unit or fuzz link and in shirudo-build's, which take a few
  util objects, as it lets the link drop the Rust it does not reach and
  the C that Rust calls. A helper that links few libraries also names
  one the archive calls that it would find only behind another, zlib
  behind libcrypto: ld refuses such a symbol before `--gc-sections`
  drops the call. A test or fuzz target that included the C file to
  reach a static function calls an export of the port instead, which the
  header declares as one for it, and a test that wrapped a call the port
  now makes inside Rust drives the same case through the interface or a
  path or environment override.
- `rust/src/ffi.rs` turns what C hands over into Rust views: `c_str()`
  for a C string, `slice()` for an array that may be NULL when empty,
  `bytes_mut()` for a C buffer to write into as it is,
  `zeroed_slice_mut()` for room C has not initialised, and
  `rust/src/text.rs` gives Rust code the string rules of
  `include/shirudo/string.h` and the C library, `strscpy()` to
  `parse_u64()`, over byte slices. Every `unsafe` block says in a
  `// SAFETY:` comment what part of the C contract makes it sound.
- What the Rust code calls in C that std does not cover, the `*at()`
  calls and ioctls, libcurl, zlib, OpenSSL past `util/crypto.h` and the
  `util/` modules not ported yet, is declared in `rust/src/sys/`, one
  module for each header, which goes when the C it declares does. A
  message goes through `rust/src/log.rs` and reads as the C's did.
- Before the C file goes, compare the two: build the old file from git
  with its functions renamed, link it beside the archive and run both on
  the same random and corpus inputs until they agree on every result and
  every byte written; the calls each makes on the way may differ. The
  tests then hold the port to the rest.
- std, and a crate only where it replaces a large binding layer and
  AGENTS.md's dependency rules admit it, vendored and pinned in
  `rust/Cargo.lock` so that cargo builds offline. Rust allocations go through the allocator of
  `rust/src/heap.rs`, which zeroes and scrubs as its `xmalloc()` family
  for C does; a buffer C frees with `xfree()` comes from that family. A panic reports through `log::err()`
  and aborts: the crate unwinds only so that a Lua error can cross a
  `"C-unwind"` callback. Overflow checks and LTO hold in every release
  build, and arithmetic that input can overflow is checked.
- `rustfmt` sets the layout. Comments follow the rules above with `//`
  and `///`, and `//!` holds the lines of purpose under the SPDX line
  and the copyright.

## Check

A warning fails the build, so fix it rather than silence it. Build with
GCC and with clang 23 (`make -B` when switching), run the unit suite of
every `util/` file the change touches, adapt and run the proofs under
`testing/proofs/` that reach the code (the `proofs` skill), and run the
`pre-submit` skill's checks before handing the change over: checkpatch
in strict mode, Coccinelle, sparse and both sanitizers find what review
misses, and `cargo fmt --check` and `cargo clippy` keep `rust/` to its
style and its `// SAFETY:` comments.
