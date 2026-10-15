..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

Features: what a upatch can attach to
=====================================

A upatch is a signed loader that installs one or more BPF programs and
attaches each one where its section name says.  This document lists
every attachment kind shirudo supports, what the kernel does at that
point, how the loader attaches there, what the author writes and what
the target needs, and then the two program roles that attach nowhere.
The `upatch <upatch.rst>`__ guide covers writing, building and
shipping; the `requirements <requirements.rst>`__ list the kernel
options behind each kind.

Two rules hold for every kind.  The attach point is fixed at build
time: the builder reads the section name from the object, records the
kind and the target in the signed metadata, and the signed loader
resolves the BTF target when it loads, so the artifact attaches where
its author said and nowhere else.  And every attachment is a BPF link
pinned in shirudo's private bpffs (``link`` for a single program,
``link_0``, ``link_1`` and so on for several): the pin is what keeps
the program attached once the one-shot command has exited, the
enforcement programs stop anyone but shirudo from removing it, and an
unload is a signed directive that removes the pins.  Section names
whose attachment cannot be a pinnable link are refused by the builder,
which is why plain ``socket`` filters and ``sk_skb`` programs are not
in the list.


1) Kernel functions: fentry, fexit, fmod_ret
--------------------------------------------

``SEC("fentry/<function>")`` runs the program when the kernel enters
the function, with the function's arguments; ``SEC("fexit/<function>")``
runs it on return, with the arguments and the return value;
``SEC("fmod_ret/<function>")`` runs it on entry and, when the program
returns non-zero, skips the function body and returns that value to
the caller.  All three go through the BPF trampoline the kernel
generates for the function from its BTF, and all three need the
function to be visible in BTF: ``fentry`` and ``fexit`` work on any
such function the kernel allows tracing programs to attach to, while
``fmod_ret`` is restricted to the ``security_*`` LSM hooks and to
functions marked ``ALLOW_ERROR_INJECTION``, which needs
``CONFIG_FUNCTION_ERROR_INJECTION`` and ``CONFIG_BPF_KPROBE_OVERRIDE``
beyond the hooks.

The loader records the function's BTF id as the program's attach
target at load, so the kernel checks the program's signature of
arguments against the function's.  shirudo attaches with
``BPF_LINK_CREATE`` of the trampoline kind and falls back to
``BPF_RAW_TRACEPOINT_OPEN`` on a kernel that does not create links for
it; either way the result is pinned.  ``fmod_ret`` is the shape of a
shield that rejects a call before the vulnerable code runs: return
``-EPERM`` or ``-EINVAL`` from the program and the caller sees the
error.  ``fmod_ret.s/<function>`` declares the sleepable variant.  The
builder refuses a bare ``fmod_ret`` without a function.


2) LSM hooks: lsm
-----------------

``SEC("lsm/<hook>")`` and ``SEC("lsm.s/<hook>")`` (sleepable) attach a
program to a hook of the Linux Security Module framework, named after
the ``security_<hook>`` function: ``lsm/file_open``,
``lsm/bprm_check_security``, ``lsm/socket_connect``.  The kernel calls
the program where it would call an LSM module, with the hook's
arguments and the verdict of the modules before it, and a non-zero
return denies the operation.  This is how shirudo's own enforcement
programs work (``bpf/bpf2.c`` and ``bpf/seal.c`` are LSM programs on
``bpf``, ``bpf_prog_load``, ``inode_unlink``, ``key_permission``,
``file_open`` and the mount hooks), and a upatch may use the same
hooks for policy of its own: refuse an ``ioctl``, a mount option or a
path before the vulnerable code sees it.

Attachment is ``BPF_LINK_CREATE`` with ``BPF_LSM_MAC`` on the hook's
BTF, pinned like every other link.  The target needs
``CONFIG_BPF_LSM`` and ``bpf`` in the active LSM list, which the base
requirements already demand for shirudo itself, so every target that
runs shirudo accepts LSM upatches.  The program's return value matters
only on hooks that return an ``int``; on ``void`` hooks it observes.


3) Tracepoints: tp_btf
----------------------

``SEC("tp_btf/<tracepoint>")`` attaches a program to a kernel
tracepoint with its arguments typed from BTF, for example
``tp_btf/sched_process_exec`` or ``tp_btf/inet_sock_set_state``.  The
program runs when the tracepoint fires and sees the raw arguments, not
the formatted trace record.  Tracepoints are stable observation points
the kernel maintains deliberately, which makes them the first choice
for a detection shield that watches for the pattern of an exploit
without changing the code path.

Attachment is a raw-tracepoint link on the BTF target, pinned.  Nothing
beyond the base requirements is needed; the tracepoint must exist in
the target kernel, which CO-RE checks at load and reports as
``btf_mismatch`` when it does not.


4) Probes on kernel functions: kprobe, kretprobe
------------------------------------------------

``SEC("kprobe/<symbol>")`` and ``SEC("kretprobe/<symbol>")`` attach to
the entry or the return of any kernel function the kprobe subsystem
can instrument, whether or not it is in BTF or allowed as a trampoline
target.  ``kprobe/<symbol>+<offset>`` probes an instruction inside the
function.  The program receives the registers as ``struct pt_regs``,
so it reads its arguments through the ``PT_REGS_PARM*`` macros, and a
kprobe may call ``bpf_override_return()`` on functions marked for error
injection, the kprobe route to rejecting a call.

The loader opens a perf event of the ``kprobe`` type for the symbol
and offset, with the retprobe bit set for ``kretprobe``, and attaches
the program to it with ``BPF_LINK_CREATE`` of the perf-event kind; the
link is pinned and the perf event lives as long as the link.  The
target needs ``CONFIG_KPROBES`` and ``CONFIG_KPROBE_EVENTS``.  The
builder requires the symbol in the section name, refuses
``kprobe.multi`` and ``kretprobe.multi``, and refuses an offset on a
``kretprobe``.  A kprobe on a function the target kernel does not
export fails at load with the kernel's error in the report; when the
function is in a module that is not loaded, the report says so and
``bpm`` treats the package as installed but not attached.


5) Probes on userspace binaries: uprobe.multi
---------------------------------------------

``SEC("uprobe.multi//absolute/path:<glob>")`` attaches a program to
the entry of every function in the named binary whose symbol matches
the glob, for example ``uprobe.multi//usr/bin/example:*Func``.  The
program runs in the context of the process executing the function,
sees its registers, and is the way a shield reaches a userspace
library or daemon: a check at the entry of the vulnerable function, a
counter of its callers.

This kind is resolved at build time.  The builder opens the binary on
the operator, matches the glob against its symbol table, records every
matching function's file offset and the binary's GNU build ID in the
signed metadata, and refuses a pattern that matches nothing or a binary
without a build ID.  On the target the loader opens the path, checks
that it is a regular file whose build ID equals the recorded one and
whose size covers every offset, and attaches with ``BPF_LINK_CREATE``
of the ``uprobe_multi`` kind by file descriptor, so the probes land in
the inode that was checked and not in whatever the path names a moment
later; a kernel without the descriptor form gets the path, after the
same inode check.  A binary that differs from the one the operator
built against is refused as stale, never probed at the wrong offsets.
The target needs ``CONFIG_UPROBE_EVENTS``.  Return probes, the
single-function ``uprobe/`` form and ``,`` or ``|`` alternation in the
glob are refused by the builder; one ``*`` or ``?`` glob per section.


6) Packets at the cgroup: cgroup_skb
------------------------------------

``SEC("cgroup_skb/ingress")`` and ``SEC("cgroup_skb/egress")`` attach a
program to the cgroup v2 root, so it sees every IP packet received by
or sent from any socket on the host, as a ``struct __sk_buff``.  The
program returns 1 to let the packet through and 0 to drop it; it can
read the headers and the socket's cgroup, which makes it a host-wide
filter that a shield uses to stop a malformed packet or a known bad
peer before the vulnerable protocol code parses it.

Attachment is ``BPF_LINK_CREATE`` on a descriptor of ``/sys/fs/cgroup``
with ``BPF_CGROUP_INET_INGRESS`` or ``BPF_CGROUP_INET_EGRESS``, pinned.
The target needs ``CONFIG_CGROUP_BPF`` and the unified cgroup
hierarchy mounted at ``/sys/fs/cgroup``, which is systemd's default.
The builder accepts only the two directions spelled out; ``cgroup/skb``
and a bare ``cgroup_skb`` are refused.  Several ``cgroup_skb`` programs
on the host coexist; the kernel runs all of them and drops the packet
if any says so.


7) Packets at netfilter: netfilter
----------------------------------

``SEC("netfilter")`` attaches a program as a netfilter hook at IPv6
pre-routing, the point where a packet has arrived on an interface and
no routing decision has been made.  The program receives a
``struct bpf_nf_ctx`` with the packet and the hook state and returns a
netfilter verdict, ``NF_ACCEPT`` or ``NF_DROP``; it runs before
connection tracking and before defragmentation (priority
``NF_IP6_PRI_RAW_BEFORE_DEFRAG``), so it sees fragments as they arrive,
which is where shields against malformed-fragment and extension-header
bugs belong.

Attachment is ``BPF_LINK_CREATE`` with ``BPF_NETFILTER`` for
``NFPROTO_IPV6`` at ``NF_INET_PRE_ROUTING``, pinned.  The target needs
``CONFIG_NETFILTER`` and ``CONFIG_NETFILTER_BPF_LINK``.  This is the
one kind whose hook, family and priority are fixed by shirudo rather
than by the section name; a shield that needs another family or hook
is written as a ``cgroup_skb`` or an ``lsm`` program instead.


8) Programs that attach nowhere
-------------------------------

Two roles are recognised by the program's name and must be in
``SEC("syscall")``, the program type the loader can run on request
with ``BPF_PROG_TEST_RUN``.  Neither is attached; both are pinned
under the upatch's directory.

Serializers
    ``shirudo_serialize__<map>`` renders ``<map>`` into the upatch's
    ``shirudo_ser`` output map as a stream of ``struct
    shirudo_serial_chunk`` records, which is how a map of structs or a
    per-CPU map becomes a flat record the exporter can ship.  ``shirudo
    upatch map`` and the map-export timer run it on the target instead
    of reading the map directly.  The builder refuses a serializer
    without the output map, one for a reserved or missing map, and two
    for the same map.

Test-run programs
    ``shirudo_test__<id>`` is run once by the loader right after the
    attachments, with a zero context, which is how a upatch initialises
    an arena it shares with its programs; a negative return fails the
    load.  It is then pinned for the author's own checks.  One per
    upatch.

Both roles ride inside the signed loader with the attached programs,
so a serializer is as much the operator's code as the shield beside
it, and neither can introduce anything the signature does not cover.


9) Maps and decoders
--------------------

Whatever a program attaches to, its maps are declared in
``SEC(".maps")`` as usual.  Every map the upatch creates is pinned
under ``upatches/<name>/maps/`` in the private bpffs, readable with
``shirudo upatch map <name> <map>`` and exportable to a collector
through a Lua decoder signed inside the upatch; a map whose name starts
with ``obs_i_`` is private to the upatch and neither pinned for the
operator nor exported.  The metadata the loader needs rides in frozen
array maps the builder creates.  The `telemetry <telemetry.rst>`__
document describes the export and the decoder API.


10) At a glance
---------------

.. list-table::
   :header-rows: 1
   :widths: 24 30 46

   * - Section
     - Attaches through
     - Needs beyond the base kernel
   * - ``fentry/<fn>``, ``fexit/<fn>``
     - trampoline link on the BTF target
     - nothing
   * - ``fmod_ret/<fn>``, ``fmod_ret.s/<fn>``
     - trampoline link, ``BPF_MODIFY_RETURN``
     - error injection for functions outside the ``security_*`` hooks
   * - ``lsm/<hook>``, ``lsm.s/<hook>``
     - link with ``BPF_LSM_MAC``
     - nothing
   * - ``tp_btf/<tracepoint>``
     - raw-tracepoint link on the BTF target
     - nothing
   * - ``kprobe/<sym>[+off]``, ``kretprobe/<sym>``
     - perf event of the kprobe type, perf-event link
     - ``CONFIG_KPROBES``, ``CONFIG_KPROBE_EVENTS``
   * - ``uprobe.multi//path:<glob>``
     - ``uprobe_multi`` link by file descriptor, build ID checked
     - ``CONFIG_UPROBE_EVENTS``
   * - ``cgroup_skb/ingress``, ``cgroup_skb/egress``
     - link on the cgroup v2 root
     - ``CONFIG_CGROUP_BPF``
   * - ``netfilter``
     - ``BPF_NETFILTER`` link, IPv6 pre-routing
     - ``CONFIG_NETFILTER``, ``CONFIG_NETFILTER_BPF_LINK``
   * - ``syscall`` (serializer, test-run)
     - not attached; run on request
     - nothing

Everything else, including ``socket``, ``sk_skb``, ``uprobe``,
``uretprobe``, ``kprobe.multi``, ``cgroup/skb`` and ``xdp``, is refused
by ``shirudo build`` with a message naming the supported form.
