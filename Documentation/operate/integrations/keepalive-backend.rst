..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: Operators, SecOps

Keepalive backend
=================

The other pages of this section store what targets send and alert on
it. The keepalive backend goes further: it checks every keepalive's TPM
quote and compares what each target reports with the upatch tree it
follows. It lives in a repository of its own,
`shirudo-dev/backend <https://github.com/shirudo-dev/backend>`_, whose
README is its documentation.

This is a do-it-yourself example, not an integration shirudo
maintains. shirudo holds no fleet state: a target only sends its
keepalive to the collector it is configured with, and nothing on the
target depends on the backend. Start from it and adapt retention,
access control and sizing to your deployment.

What it does
------------

- An OpenTelemetry Collector configuration that writes every keepalive
  to ClickHouse, where a materialized view checks its quote with
  ``shirudo-quote-check``, installed as the ClickHouse function
  ``tpm_quote_check``, and keeps the record or the reason it was
  refused. A node is known by the name of its attestation key, never by
  the host name it claims, and its records are ordered by the quote's
  clock.
- A tree ingest job that loads every publication of an upatch tree
  through ``shirudo bpm tree show``, which verifies it as a target does,
  and the ``fixes`` its operations carry.
- A table, ``node_status``, refreshed every minute, that says for every
  node whether it is healthy, unhealthy or stale, with one line per
  check: the record is fresh, the target reports no problem, its mask
  and roots match the tree, it is at the head of the tree or still
  within the time a rollout may take, the upatches it has loaded are
  those the tree leaves, and its outcomes are the most common among
  nodes in the same place in the tree.
- A table, ``node_vulns``, refreshed every five minutes, that says
  which advisories affect each node's image and kernel and whether a
  published upatch shields it.

``shirudo-quote-check`` and ``shirudo bpm tree show`` come with the
operator package, :doc:`/reference/cli/quote-check` and
:doc:`/reference/cli/bpm` describe them. A pass of the quote check says
that the body is what one key signed, not that the key lives in a
genuine TPM, so every node reads ``untrusted``.

A silent node
-------------

A node turns stale when its newest keepalive is older than the
backend's ``stale_seconds``, 10 minutes by default. A keepalive cannot
run while a ``bpm tree sync`` holds the config operation lock, so a sync
of several minutes leaves a gap of that length, as
:doc:`/operate/run/telemetry` explains; the alerts for a silent target on
the other pages of this section use the same 10 minutes. Tune the value
to the longest sync your fleet runs.

The end-to-end test ``t9107`` runs the backend against the example
keepalives of :src:`testing/fixtures/keepalive/` and their recorded
quotes, through its collector, its quote check and its tree ingest job.
