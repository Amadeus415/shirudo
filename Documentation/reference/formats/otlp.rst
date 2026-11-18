..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

OTLP documents
==============

shirudo sends OpenTelemetry data as OTLP/HTTP JSON. Each document is
one ``POST`` from a one-shot command:

.. list-table::
   :header-rows: 1
   :widths: 34 26 40

   * - Document
     - Sent by
     - Signal
   * - Status keepalive
     - ``shirudo status --otel``
     - One log record
   * - Map snapshot
     - ``shirudo upatch map --otel``, ``shirudo upatch map --all``
     - One log record or the decoder's metrics, per map
   * - Map snapshot reference
     - The same, when a snapshot goes to S3
     - One log record

The timers ``shirudo-keepalive.timer`` and ``shirudo-map-export.timer``
run these commands, see :doc:`/reference/systemd-units`. Setting up an
export is in :doc:`/operate/run/telemetry`. Decoders are in
:doc:`/upatches/write/decoders`.

Transport
---------

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Property
     - Value
   * - Protocol
     - OTLP/HTTP with JSON bodies. ``OTEL_EXPORTER_OTLP_PROTOCOL`` may
       only be ``http/json``.
   * - Paths
     - ``v1/logs`` for logs, ``v1/metrics`` for metrics, appended to a
       base URL.
   * - Headers
     - ``Content-Type: application/json``,
       ``Content-Encoding: gzip`` when compression is on,
       ``User-Agent: shirudo OTel-OTLP-Exporter-C/1``, the configured
       headers and ``X-Tenant-ID``.
   * - Compression
     - ``none`` (default) or ``gzip``.
   * - TLS
     - TLS 1.3 only, hybrid ML-KEM key exchange
       (``X25519MLKEM768``, ``SecP256r1MLKEM768``). A host listed in
       ``tls.classical_hosts`` may also use ``X25519`` and
       ``secp256r1``, see :doc:`configuration`.
   * - Cleartext
     - ``http://`` only to ``localhost``, ``127.0.0.1`` or ``[::1]``,
       unless insecure mode is on. Other schemes are refused.
   * - Insecure mode
     - ``--otel-insecure`` or ``map_export.otel_insecure = true``
       allows ``http://`` to any host and turns off certificate and
       host name verification for ``https://``. shirudo prints a
       warning for each export.
   * - Credentials in the URL
     - Refused.
   * - Timeout
     - Per attempt, ``OTEL_EXPORTER_OTLP_TIMEOUT`` in milliseconds, 1
       to 120000, default 10000.
   * - Success
     - HTTP ``200`` only, unless the response reports
       ``partialSuccess`` with ``rejectedLogRecords`` or
       ``rejectedDataPoints`` above zero.
   * - Retries
     - ``map_export.otel_retries`` or ``--otel-retries``, 0 to 10,
       default 3, after the first attempt. Retried: HTTP ``429``,
       ``502``, ``503``, ``504``, and failures to resolve, connect,
       send or receive, and timeouts. Any other response fails at
       once.
   * - Backoff
     - The response's ``Retry-After``, at most 30 seconds, else a
       random delay up to 250 ms doubled per retry, at most 4 s.
   * - Response size
     - A response body over 65535 bytes fails the export.
   * - Request size
     - ``map_export.otlp_max_bytes``, default 4194304, at most
       8388608, before compression. A larger document fails with
       ``E2BIG``.

Endpoint
--------

shirudo picks the first that is set:

.. list-table::
   :header-rows: 1
   :widths: 46 54

   * - Source
     - URL used
   * - ``--otel-endpoint=<url>`` (``upatch map`` only)
     - ``<url>`` plus the signal path
   * - ``map_export.otel_endpoint`` (``status --otel`` and
       ``upatch map --all``)
     - The value plus the signal path
   * - ``OTEL_EXPORTER_OTLP_LOGS_ENDPOINT``,
       ``OTEL_EXPORTER_OTLP_METRICS_ENDPOINT``
     - The value as given
   * - ``OTEL_EXPORTER_OTLP_ENDPOINT``
     - The value plus the signal path
   * - None (``upatch map`` only)
     - ``http://localhost:4318`` plus the signal path

The signal path goes before any ``?`` or ``#`` and gets a ``/`` when
the base does not end in one. An empty variable counts as unset.
``status --otel`` sends no keepalive without one of the first four
sources. ``upatch map`` reads the ``map_export.*`` settings only with
``--all``. While a config activation is pending or cannot be verified,
the config image's ``map_export.*`` settings are not in effect and only
the environment can name the endpoint.

Environment
-----------

For each ``OTEL_EXPORTER_OTLP_<setting>`` below, the signal variable
``OTEL_EXPORTER_OTLP_LOGS_<setting>`` or
``OTEL_EXPORTER_OTLP_METRICS_<setting>`` takes precedence. The systemd
services read them from ``/etc/shirudo/map-export.env``.

.. list-table::
   :header-rows: 1
   :widths: 44 56

   * - Variable
     - Value
   * - ``OTEL_EXPORTER_OTLP_ENDPOINT``
     - Base URL, see `Endpoint`_.
   * - ``OTEL_EXPORTER_OTLP_PROTOCOL``
     - ``http/json``
   * - ``OTEL_EXPORTER_OTLP_COMPRESSION``
     - ``none`` or ``gzip``
   * - ``OTEL_EXPORTER_OTLP_HEADERS``
     - ``<name>=<value>[,<name>=<value>...]``, at most 16384 bytes.
       Blanks around names and values are dropped and values are
       percent-decoded. Refused: a name that is not an HTTP token (RFC
       9110), a value that holds a control character other than tab
       before or after decoding, ``%00`` included, and the names
       ``Content-Type``, ``Content-Encoding``, ``Content-Length``,
       ``Host`` and ``User-Agent``. One ``X-Tenant-ID`` is allowed and
       must be a valid tenant id. A tenant id from the command line or
       the config replaces it.
   * - ``OTEL_EXPORTER_OTLP_CERTIFICATE``
     - CA bundle for the collector's certificate.
   * - ``OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE``,
       ``OTEL_EXPORTER_OTLP_CLIENT_KEY``
     - Client certificate and key for mutual TLS. Both or neither.
   * - ``OTEL_EXPORTER_OTLP_TIMEOUT``
     - Milliseconds, 1 to 120000.

A tenant id, from ``--tenant-id=<id>`` or ``map_export.tenant_id``, is 1
to 128 characters from ``A-Z``, ``a-z``, ``0-9``, ``.``, ``_`` and
``-``. shirudo sends it as ``X-Tenant-ID``.

Resource and scope
------------------

Every document has one resource and one scope.

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Field
     - Value
   * - Resource attribute ``service.name``
     - ``shirudo``
   * - Resource attribute ``service.version``
     - The version string without the extra version and release name
       that ``shirudo version`` adds, for example ``58d3fa7`` where
       ``shirudo version`` prints ``shirudo (58d3fa7-rc0, ...)``.
   * - Resource attribute ``host.name``
     - The host name, or ``unknown``.
   * - Scope ``name``
     - ``shirudo.keepalive`` for the keepalive,
       ``shirudo.upatch.maps`` for map documents.
   * - Scope ``version``
     - Same as ``service.version``.

Attribute values follow the OTLP JSON encoding: ``stringValue``,
``intValue`` as a decimal string, ``boolValue``.

Status keepalive
----------------

One log record in ``resourceLogs[0].scopeLogs[0].logRecords``:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Field
     - Value
   * - ``timeUnixNano``, ``observedTimeUnixNano``
     - Wall clock when shirudo builds the document, nanoseconds since
       the epoch, decimal string.
   * - ``severityNumber``, ``severityText``
     - ``9`` ``INFO`` for ``ok``. ``13`` ``WARN`` for ``degraded``,
       ``init-pending`` and ``reboot-pending``. ``17`` ``ERROR`` for
       every other verdict, ``tampered`` and ``lsm-off`` included.
   * - ``eventName``
     - ``shirudo.keepalive``
   * - ``body``
     - ``{"stringValue": <body>}``: the keepalive body that ``status
       --keepalive`` prints (:doc:`/reference/cli/status`), the compact
       JSON object as one string, never a ``kvlistValue``. A collector
       may re-encode a structure, and the quote covers these exact
       bytes.
   * - Attribute ``shirudo.quote``
     - The one attribute, a string: the TPM quote of the body, below.

``timeUnixNano`` and the resource attributes are for display only. They
identify nothing and order nothing; the quote does both.

``shirudo.quote`` has three fields in this order, separated by ``;``
with no blanks, each in standard base64 with padding:

.. code-block:: none

   attest=<TPMS_ATTEST>;sig=<TPMT_SIGNATURE>;ak=<TPMT_PUBLIC>

.. list-table::
   :header-rows: 1
   :widths: 14 86

   * - Field
     - Value
   * - ``attest``
     - The ``TPMS_ATTEST`` the TPM signed, without the ``TPM2B`` size: a
       ``TPM2_Quote`` whose qualifying data is the SHA-256 of the body
       bytes and whose PCR selection is one SHA-256 bank with no PCR set.
       Its clock information, ``resetCount`` and ``clock``, orders the
       keepalives of one node.
   * - ``sig``
     - The marshalled ``TPMT_SIGNATURE`` over ``attest``: ECDSA with
       SHA-256.
   * - ``ak``
     - The marshalled ``TPMT_PUBLIC`` of the attestation key, without
       the ``TPM2B`` size: the fixed-template P-256 ECDSA primary under
       the endorsement hierarchy that :doc:`/reference/cli/attest` uses.
       ``000b`` and the SHA-256 of these bytes is the key's name, which
       identifies the node. The quote's signer is the key's qualified
       name under the endorsement hierarchy.

:doc:`/reference/cli/quote-check` checks a quote against its body without
a TPM. An attestation quote always selects a PCR, so it cannot pass as
a keepalive quote. A quote that checks proves that the body is
unchanged since the key signed it, not that the key lives in a TPM.

When no TPM answers or the quote fails, ``status --otel`` sends nothing.
A body that JSON cannot carry unchanged, one with a NUL byte or
malformed UTF-8, is not sent either; the body ``status`` builds is never
one.

The keepalive uses ``map_export.otel_endpoint``,
``map_export.tenant_id``, ``map_export.otel_insecure``,
``map_export.otel_retries`` and ``map_export.otlp_max_bytes``.
``status --otel`` exits ``1`` when the export fails and ``2`` when the
``map_export.*`` settings are invalid.

Map snapshot log
----------------

One log record per map:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Field
     - Value
   * - ``timeUnixNano``, ``observedTimeUnixNano``
     - Wall clock when shirudo builds the document, nanoseconds since
       the epoch, decimal string.
   * - ``severityNumber``, ``severityText``
     - ``9``, ``INFO``
   * - ``eventName``
     - ``shirudo.bpf.map.snapshot``
   * - ``body``
     - The value the map's decoder returns, as an OTLP value. Without a
       decoder, a ``kvlistValue`` of the map's contents, see
       `Undecoded body`_.
   * - Attribute ``shirudo.upatch.name``
     - The upatch name.
   * - Attribute ``shirudo.upatch.location``
     - The upatch's attach point.
   * - Attribute ``shirudo.map.name``
     - The map name.
   * - Attribute ``shirudo.map.type``
     - The map type name.
   * - Attribute ``shirudo.map.max_entries``
     - Integer.
   * - Attribute ``shirudo.map.n_entries``
     - Integer, entries read.
   * - Attribute ``shirudo.map.n_cpus``
     - Integer.
   * - Attribute ``shirudo.map.serialized``
     - Boolean, the map was read through its serializer.
   * - Attribute ``shirudo.map.truncated``
     - Boolean, the read stopped before the last entry.

A decoded body larger than ``map_export.log_record_max_bytes`` (default
1048576, at most ``map_export.otlp_max_bytes``) fails with ``E2BIG``.

Undecoded body
~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Key
     - Value
   * - ``name``, ``type``, ``max_entries``, ``n_entries``
     - The map.
   * - ``n_cpus``
     - Per-CPU maps only.
   * - ``serialized``
     - Boolean.
   * - ``serialized_pages``, ``serialized_bytes``, ``pages``
     - Serializer-backed maps. Each page has ``page_index``,
       ``cursor``, ``next_cursor``, ``done``, ``flags``, ``chunks``,
       ``bytes`` and ``data_hex``.
   * - ``skipped``
     - The reason, for a map type shirudo cannot read generically.
   * - ``truncated``, ``n_truncated_at``
     - Other maps. ``n_truncated_at`` only when truncated.
   * - ``btf``
     - ``key_type``, ``value_type``, and ``key_type_def`` and
       ``value_type_def`` when known.
   * - ``entries``
     - Each with ``key`` and ``value``, or for per-CPU maps ``key``,
       ``values_per_cpu`` and ``sum``, formatted from BTF.

Map metrics
-----------

A decoder that declares the metric signal returns a list of OTLP
``Metric`` objects. shirudo sends them as
``resourceMetrics[0].scopeMetrics[0].metrics`` under the resource and
scope above and adds no attributes.

Signal selection
~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Map
     - Export
   * - Has a decoder
     - The signal the decoder declares, log or metric.
   * - No decoder, unsigned per-CPU integer value
     - Classified as a metric. Metrics come only from decoders, so the
       export fails with ``ENODATA``.
   * - No decoder, any other map
     - Log record with the undecoded body.

For an undecoded map ``upatch map`` prints the choice on standard
error as ``otel: selected <signal> for <type> map <name>: <reason>``.

S3 snapshots
------------

When a decoded map's document fails with ``E2BIG`` and an S3 URI is
set (``--s3-uri=<uri>`` or ``map_export.s3_uri``), shirudo uploads the
snapshot to S3 and sends a reference log record instead. Undecoded,
skipped and truncated maps are not uploaded.
``map_export.s3_uri`` requires ``map_export.otel_endpoint``.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Property
     - Value
   * - URI
     - ``s3://<bucket>[/<prefix>]``. Bucket: 3 to 63 characters from
       ``a-z``, ``0-9``, ``.`` and ``-``, starting and ending with a
       letter or digit. Prefix: at most 512 bytes, no control
       characters, ``?``, ``#``, ``.`` or ``..`` segments.
   * - Object
     - The decoder's JSON output, gzip-compressed, at most 64 MiB
       before compression.
   * - Key
     - ``[<prefix>/]<host>/<upatch>/<map>/<sha256>.json.gz``.
       ``<host>`` is the host name with every character other than
       ``A-Z``, ``a-z``, ``0-9``, ``-``, ``_`` and ``.`` replaced by
       ``_``. ``<sha256>`` is the digest of the compressed object.
   * - URL
     - With ``AWS_ENDPOINT_URL_S3``: ``<endpoint>/<bucket>/<key>``.
       Else ``https://<bucket>.s3.<region>.amazonaws.com/<key>``, or
       ``https://s3.<region>.amazonaws.com/<bucket>/<key>`` for a
       bucket name with a dot.
   * - Request
     - ``PUT`` signed with AWS SigV4, with ``If-None-Match: *``,
       ``Cache-Control: immutable``, ``x-amz-content-sha256``,
       ``x-amz-checksum-sha256``, ``x-amz-meta-shirudo-schema: 1``,
       ``x-amz-meta-shirudo-upatch`` and ``x-amz-meta-shirudo-map``.
       ``412`` counts as already uploaded.
   * - Timeout and retries
     - 10 seconds per attempt. Retries as for OTLP, also on ``408``,
       ``409`` and ``500``.
   * - Cleartext
     - As for OTLP, for ``AWS_ENDPOINT_URL_S3``. Insecure mode also
       turns off certificate verification for the AWS endpoints.

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Variable
     - Value
   * - ``AWS_ACCESS_KEY_ID``, ``AWS_SECRET_ACCESS_KEY``
     - Required. Missing credentials fail with ``EACCES``.
   * - ``AWS_SESSION_TOKEN``
     - Sent as ``x-amz-security-token``.
   * - ``AWS_REGION``, ``AWS_DEFAULT_REGION``
     - Region, in this order, default ``us-east-1``.
   * - ``AWS_ENDPOINT_URL_S3``
     - S3-compatible endpoint, path-style.
   * - ``AWS_CA_BUNDLE``
     - CA bundle for the S3 endpoint.

The reference log record goes to the logs endpoint, whatever signal
the decoder declares, and is not subject to
``map_export.otlp_max_bytes``:

.. list-table::
   :header-rows: 1
   :widths: 44 56

   * - Field
     - Value
   * - ``eventName``
     - ``shirudo.bpf.map.snapshot.reference``
   * - ``severityNumber``, ``severityText``
     - ``9``, ``INFO``
   * - ``body``
     - ``stringValue``: ``BPF map snapshot stored in S3: <uri>``
   * - Attributes
     - The map snapshot attributes above, and
       ``shirudo.map.snapshot.uri``,
       ``shirudo.map.snapshot.format`` (``shirudo.map.v1+json``),
       ``shirudo.map.snapshot.content_type`` (``application/json``),
       ``shirudo.map.snapshot.content_encoding`` (``gzip``),
       ``shirudo.map.snapshot.size_bytes``,
       ``shirudo.map.snapshot.uncompressed_size_bytes`` and
       ``shirudo.map.snapshot.sha256``.

JSON lines
----------

``map_export.json_path`` or ``upatch map --json=<path>`` appends one line
per map to a file, instead of OTLP or besides it. The line is the JSON
value the map's decoder returns, not an OTLP document. A map without a
decoder fails with ``ENODATA``. ``map_export.json_path`` must be an
absolute path. A file or directory that carries shirudo's seal label is
refused. A new file gets mode ``0644``.

Keepalive structure
-------------------

The keepalive of a target with verdict ``ok``, as the code builds it.
Angle brackets mark values that vary, and the body string is shortened
to its first keys:

.. code-block:: json

   {
     "resourceLogs": [
       {
         "resource": {
           "attributes": [
             {"key": "service.name", "value": {"stringValue": "shirudo"}},
             {"key": "service.version", "value": {"stringValue": "<version>"}},
             {"key": "host.name", "value": {"stringValue": "<host>"}}
           ]
         },
         "scopeLogs": [
           {
             "scope": {"name": "shirudo.keepalive", "version": "<version>"},
             "logRecords": [
               {
                 "timeUnixNano": "<ns>",
                 "observedTimeUnixNano": "<ns>",
                 "severityNumber": 9,
                 "severityText": "INFO",
                 "eventName": "shirudo.keepalive",
                 "body": {
                   "stringValue": "{\"schema\":\"shirudo.keepalive/1\",\"boot_id\":\"<boot-id>\",\"version_id\":\"<version-id>\",...}"
                 },
                 "attributes": [
                   {"key": "shirudo.quote", "value": {"stringValue": "attest=<base64>;sig=<base64>;ak=<base64>"}}
                 ]
               }
             ]
           }
         ]
       }
     ]
   }

Related
-------

- :doc:`/operate/run/telemetry`
- :doc:`/reference/cli/status`
- :doc:`/reference/cli/quote-check`
- :doc:`/reference/cli/upatch-map`
- :doc:`/upatches/write/decoders`
- :doc:`status-json`
- :doc:`configuration`
