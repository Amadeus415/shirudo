..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

shirudo pwru
============

Sign the ``pwru`` upatch, which records the packets a pcap filter matches
as they pass the kernel's network stack, without clang.

Runs on: operator host, through the ``shirudo-build`` helper. Requires:
the signing key and certificate, and libpcap, as ``libpcap.so.1`` or
``libpcap.so.0.8``, when a filter is given. Changes measured state: no.

Usage
-----

.. code-block:: none

   shirudo pwru [-o <output.upatch> | --output=<output.upatch>]
                [--keys-dir <dir> | --keys-dir=<dir>] [<pcap-filter>...]

Description
-----------

#. ``pwru`` reads ``signing_key.pem`` and ``cert.der`` from
   ``--keys-dir``, else ``$SHIRUDO_KEYS_DIR``, else
   ``/var/lib/shirudo/keys``.
#. It joins its arguments with spaces into one filter in the syntax of
   ``pcap-filter(7)``, as ``tcpdump`` and pwru take one. Without
   arguments it adds no filter, and the upatch records every packet.
#. The host's libpcap, opened at run time, compiles the filter twice,
   optimized: for Ethernet frames, ``DLT_EN10MB``, and for IP packets
   without a link-layer header, ``DLT_RAW``. A filter with a term that
   only an Ethernet header can satisfy, such as ``arp`` or
   ``ether host``, does not compile for IP packets, even where ``or``
   joins it to a term an IP packet can satisfy, as in
   ``ether host 00:11:22:33:44:55 or tcp port 443``: ``pwru`` then
   refuses every IP packet that has no link-layer header and says so.
#. It translates each classic BPF filter into eBPF that reads the packet
   with ``bpf_probe_read_kernel()`` after checking the read against the
   packet's length, and refuses what the kernel's classic BPF checker
   refuses.
#. It opens the object it carries, :src:`upatches/pwru/pwru.bpf.c` as
   it was compiled with the helper, and replaces the filter stub at the
   end of each probe with the two filters. It does so as libbpf loads
   the first of the object's ``syscall`` programs, which come before
   every probe, once libbpf has relocated them all; the probes keep
   libbpf's own ``fentry`` and ``tp_btf`` handling, so the loader looks
   up each target on the target. It runs no compiler.
#. It signs the upatch as :doc:`build` does, with the decoder
   :src:`upatches/pwru/decoders/pwru.lua`, and writes it to ``--output``,
   else ``pwru.upatch`` in the current directory. The upatch is always
   named ``pwru``.

The upatch
----------

.. list-table::
   :header-rows: 1
   :widths: 22 78

   * - Part
     - Content
   * - Probes
     - One program on each function or tracepoint
       :src:`upatches/pwru/pwru_funcs.h` lists, 14 of them, one where a
       packet enters each layer in each direction rather than every
       function that takes an ``sk_buff``.
       On the way in, ``__netif_receive_skb_core``, which every driver,
       GRO and the backlog hand a frame to, then ``ip_rcv_core`` or
       ``ip6_rcv_core``, then ``ip_forward`` or ``ip6_forward`` for a
       packet the host routes and ``ip_protocol_deliver_rcu`` or
       ``ip6_input_finish`` for one it receives; ``ip6_input_finish``
       calls ``ip6_protocol_deliver_rcu``, which has no BTF in a kernel
       built with clang. On the way out,
       ``ip_output`` or ``ip6_output``, then ``__dev_queue_xmit`` and,
       past the queueing discipline, ``dev_hard_start_xmit``. In both
       directions, ``nf_hook_slow`` for each netfilter hook with a rule,
       and where the packet ends, the ``kfree_skb`` tracepoint, with the
       drop reason, and the ``consume_skb`` one. Each is an ``fentry``
       program but three ``tp_btf`` programs. The first is on the
       ``netif_receive_skb`` tracepoint that
       ``__netif_receive_skb_core()`` fires for every frame: the compiler
       may clone that function, as ``__netif_receive_skb_core.constprop.0``
       on the test kernel, and ``fentry`` cannot attach to a clone by the
       function's name. The last two fire once the last reference to the
       ``sk_buff`` is gone, where ``sk_skb_reason_drop()`` and
       ``consume_skb()`` also see references that are not the last, and
       on paths that call neither, through ``kfree_skb_list_reason()``,
       ``napi_consume_skb()`` and ``net_tx_action()``. The load fails on
       a target whose kernel lacks one of the others, or traces it under
       another name.
   * - Filter
     - A packet whose ``mac_header`` is set apart from its
       ``network_header`` is matched from its Ethernet header, an IPv4 or
       IPv6 packet without one from its IP header. An ``sk_buff`` that is
       neither, such as a netlink message, is not recorded. The filter
       reads the linear part of the ``sk_buff`` only, so ``len``,
       ``less`` and ``greater`` compare that part's length.
   * - ``events``
     - The log of what the probes record, in an arena, with its
       serializer. It holds 1024 records an export interval, some 700 KiB
       as the body of an OTLP log record, within the default 1 MiB of
       ``map_export.log_record_max_bytes``. It counts the records it had
       no room for as ``overflow`` and those an interrupted drain left as
       ``lost``.
   * - Record
     - ``time_unix_nano``, ``skb``, ``func``, ``cpu``, ``pid``, ``comm``,
       ``netns``, ``mark``, ``ifindex``, ``len``, ``protocol``, ``tuple``
       as pwru prints it, ``tcp_flags`` for TCP and the drop ``reason``
       for ``kfree_skb``. The tuple has the addresses where the IP header
       is in the linear part of the ``sk_buff``, and the ports, and
       ``tcp_flags``, where the TCP or UDP header is too, but not for an
       IPv4 fragment after the first.

The probes read their arguments through their context, not from
registers, and the arena takes the same address on every
architecture, so the object is the same for x86-64, arm64 and riscv64
targets, whichever architecture the helper runs on. The tests load it on
x86-64.

What the probes do not see:

- A packet that leaves through ``ip_mc_output()``, multicast or
  broadcast, shows from ``__dev_queue_xmit`` on.
- A packet that a socket's reader has taken, which TCP and UDP free
  through ``skb_attempt_defer_free()``, ends at the last function it
  passed, without a record of its end, when the CPU that frees it is
  the one that allocated it: no tracepoint fires there. A drop always
  has one, at the ``kfree_skb`` tracepoint.
- ``dev_hard_start_xmit()`` takes a list of packets, of which it records
  the first.

Options
-------

.. list-table::
   :header-rows: 1
   :widths: 22 22 26 30

   * - Option
     - Argument
     - Default
     - Description
   * - ``--output``, ``-o``
     - ``<output.upatch>``, as the next argument or after ``=``
     - ``pwru.upatch``
     - Where to write the upatch.
   * - ``--keys-dir``
     - ``<dir>``, as the next argument or after ``=``
     - ``$SHIRUDO_KEYS_DIR``, else ``/var/lib/shirudo/keys``
     - Directory of ``signing_key.pem`` and ``cert.der``.

Exit status
-----------

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Status
     - Meaning
   * - 0
     - The upatch was written.
   * - 1
     - The key or certificate cannot be read, libpcap is missing, libpcap
       refuses the filter or it cannot be translated, or signing or
       writing failed.
   * - 2
     - A usage error, or a keys directory whose paths are too long.
   * - 127
     - The ``shirudo-build`` helper cannot be run.

Examples
--------

Sign the upatch for the TLS traffic of one host:

.. code-block:: console

   operator$ shirudo pwru --keys-dir ~/shirudo-keys -o pwru.upatch host 10.0.0.1 and tcp port 443

Load it on the target, and read what it recorded without draining it:

.. code-block:: console

   target# shirudo upatch load pwru.upatch
   target# shirudo upatch map pwru events --json --peek

Sign the directive that unloads it:

.. code-block:: console

   operator$ shirudo build --unload pwru --payload-sha256 "$(shirudo upatch info --json pwru.upatch | jq -r .payload_sha256)" -o pwru.unload.upatch --keys-dir ~/shirudo-keys

Related
-------

- :doc:`build`
- :doc:`upatch-load`
- :doc:`upatch-map`
- :doc:`/upatches/write/decoders`
- :doc:`/operate/run/telemetry`
