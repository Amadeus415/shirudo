..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

============================
The .upatch container format
============================

This document specifies the on-disk ``.upatch`` container: the portable,
signed unit shirudo's operator side produces (``shirudo build``) and the
target side consumes (``shirudo upatch load`` / ``unload``, ``rollout``).
It is the authoritative byte-level reference; the structures live in
``include/shirudo/upatch.h``, the writer in
``tools/shirudo-build/package.c``, and the reader in ``util/upatch.c``.

A ``.upatch`` carries everything a *signed* ``BPF_PROG_LOAD`` needs to
install a BPF program on a machine other than the one that built it: the
gen_loader "light skeleton" instructions, the data those instructions
reference, a detached CMS signature, and a small amount of metadata.
There is exactly one container shape for both **LOAD** artifacts and
**UNLOAD** directives; a flag bit distinguishes them.


Conventions
===========

- **Little-endian** for every multi-byte integer, on every supported
  architecture (operator and target may differ in arch; the wire format
  does not).
- The file begins with a **fixed 352-byte header** of naturally aligned
  fields (no padding). All other content is referenced by ``*_off`` /
  ``*_len`` pairs in the header, as byte offsets from the start of the
  file. Sections do not overlap the header and must lie within the file.
- Sizes are bounded: a reader rejects a file larger than 16 MiB
  (``util/upatch.c``); ``.upatch`` artifacts are small in practice.


File layout
===========

::

    offset 0    +-------------------------------------------+
                | header (352 bytes, fixed)                 |
    352         +-------------------------------------------+
                | loader_insns   (signature-covered)        |
                +-------------------------------------------+
                | signature      (CMS/PKCS#7, detached)     |
                +-------------------------------------------+
                | data           (gen_loader_opts.data)     |  optional
                +-------------------------------------------+
                | metadata                                  |  optional
                +-------------------------------------------+
                | extras         (embedded C source)        |  optional
                +-------------------------------------------+

The writer emits the sections in the order above, but a reader must rely
only on the header offsets, not on adjacency. ``loader_insns`` begins at
offset 352 (immediately after the header). ``data``, ``metadata`` and
``extras`` are optional: an absent section has its ``*_off`` (and, for
extras, ``extra_off``) set to 0.


Header
======

``struct shirudo_upatch_header`` -- 352 bytes, little-endian, no padding:

==========  ====  ======  =====================  ===========================================
offset      size  type    field                  meaning
==========  ====  ======  =====================  ===========================================
0           8     u64     magic                  ``0x53485244554E4150`` (see Magic)
8           4     u32     version                ``1``
12          4     u32     flags                  bit 0 = ``DIRECTIVE_UNLOAD``; bits 1-31 zero
16          256   char[]  name                   upatch name; NUL-padded, not guaranteed
                                                  NUL-terminated on disk
272         32    u8[]    payload_sha256          SHA-256; meaning depends on flags
304         4     u32     loader_insns_off        file offset of the loader instructions
308         4     u32     loader_insns_len        length in bytes (multiple of 8)
312         4     u32     signature_off           file offset of the CMS signature
316         4     u32     signature_len           length in bytes
320         4     u32     metadata_off            file offset of metadata, or 0
324         4     u32     metadata_len            length in bytes, or 0
328         4     u32     data_off               file offset of the loader data, or 0
332         4     u32     data_len               length in bytes, or 0
336         4     u32     log_buf_sz             verifier-log buffer size to allocate at load
340         4     u32     nr_maps                gen_loader bpf_map_desc count
344         4     u32     nr_progs               gen_loader bpf_prog_desc count
348         4     u32     extra_off              file offset of the extras blob, or 0
==========  ====  ======  =====================  ===========================================

Magic
-----

``magic`` is the u64 ``0x53485244554E4150`` stored little-endian (its
bytes spell ``SHRDUNAP`` when read most-significant-first). A reader that
sees any other value rejects the file.

log_buf_sz
----------

There is no log-buffer *section* in the file. ``log_buf_sz`` (typically
1 MiB) records the size of the verifier-log buffer the target allocates
in memory at load so a verifier rejection can be captured in full and
surfaced in the failure report. Only the size travels in the artifact.

nr_maps / nr_progs
------------------

After the signed loader runs under ``BPF_PROG_TEST_RUN``, it writes the
created map and program fds into descriptor arrays trailing its context,
in libbpf's object-iteration order. The target has only the ``.upatch``,
not the original object, so these counts tell it where to find the
resulting ``prog_fd`` to pin. They mirror gen_loader's own iteration.


Sections
========

loader_insns
------------

The bytes of ``gen_loader_opts.insns`` after ``bpf_object__gen_loader()``
+ ``bpf_object__load()`` on the operator. This is a
``BPF_PROG_TYPE_SYSCALL`` "light skeleton" loader program: run via
``BPF_PROG_TEST_RUN`` on the target, it issues the ``bpf()`` syscalls
(``BPF_BTF_LOAD``, ``BPF_MAP_CREATE``, ``BPF_PROG_LOAD``, ...) that
install the payload. **This is the only section the signature covers.**

For an **UNLOAD directive** (``flags & DIRECTIVE_UNLOAD``), the loader is
not a gen_loader output but the compiled bytes of the small hand-written
``bpf/unload.c`` template, parameterized via its ``.rodata`` with the
target name and expected ``payload_sha256``.

signature
---------

A detached CMS / PKCS#7 signature over the **loader_insns bytes only**,
produced by the vendored ``util/sign.c`` (operator side). On the target,
the kernel's ``bpf_prog_verify_signature()`` checks it against the cert
in the sealed ``shirudo`` keyring (the keyring's serial is passed as
``attr.keyring_id``) **before** the verifier and the LSM hooks run.

data
----

The bytes of ``gen_loader_opts.data`` -- the blob the loader
instructions reference (the program BTF, ``.rodata``/map initial values,
relocation inputs, ...). The loader is parameterized by this data, so it
must travel with the instructions. Absent (``data_off == 0``) only for
artifacts with no such data. **Not signature-covered** (see Integrity).

metadata
--------

Optional, opaque-to-the-format auxiliary bytes (e.g. an UNLOAD
directive's expected ``payload_sha256``, so the target can compute the
unload chain event without parsing the loader data). **Not
signature-covered.**

For LOAD upatches produced by ``shirudo build``, metadata may carry
attach metadata:

==========  ====  =====================  ====================================
offset      size  field                  meaning
==========  ====  =====================  ====================================
+0          4     magic                  ``0x4D475055`` (``"UPGM"`` LE)
+4          4     version                ``1``
+8          4     nr_progs               number of program entries
+12         4     reserved               zero
+16         ...   progs                  one entry per program
==========  ====  =====================  ====================================

Each program entry is 160 bytes:

==========  ====  =====================  ====================================
offset      size  field                  meaning
==========  ====  =====================  ====================================
+0          4     role                   ``0`` attach program, ``1`` serializer
+4          4     kind                   ``0`` raw tracepoint, ``1`` kprobe,
                                         ``2`` kretprobe,
                                         ``3`` cgroup_skb ingress,
                                         ``4`` cgroup_skb egress,
                                         ``5`` fmod_ret
+8          8     offset                 kprobe offset, zero for kretprobe
+16         128   target                 NUL-terminated kprobe symbol name
+144        16    map                    NUL-terminated serializer target map
==========  ====  =====================  ====================================

Attach metadata is advisory in the container integrity model because
metadata is not CMS-signed in v1. The loaded program bytes remain
hash-locked by the signed loader; the target validates this blob before
creating links. ``cgroup_skb`` support is limited to
``cgroup_skb/ingress`` and ``cgroup_skb/egress`` sections, attached to
the cgroup v2 root through a pinned ``bpf_link``. ``sk_skb`` and socket
filter sections are rejected by ``shirudo build``. ``fmod_ret/<symbol>``
and ``fmod_ret.s/<symbol>`` sections attach as ``BPF_MODIFY_RETURN`` so
return-value override programs can reject a call before the hooked
function body runs. Kprobe return override uses a normal
``kprobe/<symbol>`` section plus the program's ``bpf_override_return()``
helper call; the attach metadata remains ``kprobe``.

extras (embedded C source)
--------------------------

Optional, additive, **not signature-covered**. Present (``extra_off !=
0``) when ``shirudo build`` was given a ``.bpf.c`` input: the top-level
source file is embedded verbatim so ``shirudo upatch info`` can print the
**full** source offline. A pre-compiled ``.bpf.o`` input has no source to
embed, so it produces no extras.

The blob begins with ``struct shirudo_upatch_extras`` (16 bytes,
little-endian), then the source path string, then the source bytes:

==========  ====  =====================  ====================================
offset      size  field                  meaning
==========  ====  =====================  ====================================
+0          4     magic                  ``0x52545853`` (``"SXTR"`` LE)
+4          4     format                 ``1`` (``SHIRUDO_UPATCH_EXTRAS_SOURCE``)
+8          4     name_len               source path length in bytes (no NUL)
+12         4     source_len             source text length in bytes (no NUL)
+16         ...   <source path>          ``name_len`` bytes, the input file path
...         ...   <source text>          ``source_len`` bytes, the verbatim ``.c``
==========  ====  =====================  ====================================

Neither string is NUL-terminated on disk; both are length-prefixed. The
path is the operator-side input path passed to ``shirudo build`` (e.g.
``examples/cve-2026-31431.bpf.c``); it is informational only.

Embedding the source (rather than BTF + ``line_info``) lets ``shirudo
upatch info`` show the **complete** program -- comments, blank lines,
every statement -- not just the sparse instruction-tagged lines that
``clang -O2`` ``line_info`` records. Because it is unsigned, this view is
advisory. The authoritative view of what is *actually loaded* is the
kernel's, via ``shirudo upatch get``, which reads the loaded program's
``line_info`` + BTF from the kernel (the BTF the signed loader installed
alongside the hash-verified program); ``get`` therefore renders
instruction-tagged ``line_info`` lines, not the embedded ``.c``.


flags
=====

``flags`` bit 0 is ``SHIRUDO_DIRECTIVE_UNLOAD``. When clear, the artifact
is a **LOAD** (install a program); when set, it is a signed **UNLOAD
directive** (authorize removing a named, previously-loaded upatch). Bits
1-31 are reserved and must be zero. The flag changes the meaning of
``loader_insns`` and ``payload_sha256`` but nothing about the container
layout, the signature path, or kernel verification: both kinds load
through the same ``BPF_PROG_LOAD`` + signature + ``keyring_id`` check.


payload_sha256
==============

- **LOAD**: SHA-256 of the payload program, equal to the
  ``excl_prog_hash`` baked into the signed loader instructions. At load,
  shirudo records it as the ``security.bpf.shirudo.payload`` xattr on the
  pin directory.
- **UNLOAD directive**: the *expected* ``payload_sha256`` of the
  currently-loaded upatch the directive intends to remove. The target
  refuses (``category: payload_mismatch``) if the loaded upatch under
  that name has a different digest.

It also lets ``shirudo upatch list`` / ``status`` identify an artifact
without parsing the instruction stream.


Integrity: what is signed
==========================

The CMS signature covers **loader_insns only**. ``data``, ``metadata``
and ``extras`` are **not** signed. The integrity model is therefore:

- The **loader instructions** are signature-verified by the kernel
  before anything runs.
- The **payload program** is hash-locked: ``payload_sha256`` (=
  ``excl_prog_hash``) is embedded in the signed loader instructions, and
  the kernel checks the loaded program against it at ``BPF_PROG_LOAD``.
  Tampering with ``data`` cannot substitute different program *code* --
  the hash check fails.
- ``metadata`` and ``extras`` are advisory. Tampering with extras only
  mis-renders the offline ``upatch info`` source dump; the loaded
  program and the kernel-resident ``line_info`` (what ``upatch get``
  reads) are unaffected. Tampering with an UNLOAD directive's metadata
  can only produce a chain value the operator's expectation rejects, or a
  ``payload_mismatch``.

Whether a tampered (unsigned) BTF inside ``data`` could perturb CO-RE
relocation before the ``excl_prog_hash`` check is a property of the
upstream gen_loader signing model, not something this format guarantees.


Versioning and compatibility
============================

``version`` is ``1``. The format is designed to grow **additively**
without a version bump:

- ``extra_off`` reuses the slot that was a ``reserved`` u32 in the
  original layout. A reader that predates the extras blob sees
  ``extra_off == 0`` (older writers zeroed ``reserved``) and ignores the
  trailing bytes; a current reader parses the extras only when
  ``extra_off != 0``. The extras follow every signature-covered section,
  so adding them changes neither the signed bytes nor the layout a prior
  reader depends on.

A reader **must** reject a file whose ``magic`` or ``version`` does not
match, before trusting any offset.


Reader validation rules
========================

``util/upatch.c`` enforces, in order:

1. File is a regular file, non-empty, and at most 16 MiB.
2. ``magic`` and ``version`` match.
3. Each section ``(off, len)`` lies within the file, and any non-empty
   section starts at or after the 352-byte header (``section_inside``).
4. ``loader_insns_len`` and ``signature_len`` are non-zero (mandatory);
   ``data`` may be empty.
5. Extras are parsed only if ``extra_off != 0``, the extras header fits,
   its ``magic`` and ``format`` match, and ``name_len`` + ``source_len``
   stay within the file. **Extras are advisory**: a malformed extras blob
   is treated as "no source", never a hard failure -- the signed sections
   are validated independently.


Production and consumption
==========================

- **Produced by** ``shirudo build`` (which dispatches to the operator-only
  ``shirudo-build``): compile ``.bpf.c`` with ``clang -target bpf -O2
  -g`` (or accept a ``.bpf.o``), run ``bpf_object__gen_loader()`` +
  ``bpf_object__load()``, CMS-sign the loader bytes, embed the ``.bpf.c``
  source (extras), and serialize the container. ``--unload <name>`` emits
  an UNLOAD directive instead.
- **Inspected by** ``shirudo upatch info <file>`` (offline; header,
  sections, and the advisory embedded source) and ``shirudo upatch
  list``.
- **Consumed by** ``shirudo upatch load`` / ``unload`` on the target
  (signature-gated ``BPF_PROG_LOAD`` via the sealed keyring serial), and
  pushed by ``shirudo rollout`` over libssh.
- **Introspected after load** by ``shirudo upatch get <name>``, which
  reads the loaded program's line_info + BTF from the kernel (the
  authoritative view of what is loaded).

See ``PLAN.md`` (subcommands, "``.upatch`` artifact format") and
``Documentation/threat-model.rst`` for the surrounding design and the
trust boundaries.
