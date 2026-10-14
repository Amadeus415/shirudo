#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
"""OTLP/HTTP sink for the exporter tests.

usage: otel-mock.py <success|retry|partial> <port-file> <body-file>
                    <meta-file> [<cert.pem> <key.pem>]

Listens on an ephemeral loopback port (written to <port-file> once
bound), serves until the exchange the mode describes is complete, then
exits 0 so a test can `wait` for it:

  success  the first request is accepted with 200 {}
  retry    the first two requests fail with 503, the third succeeds
  partial  the first request gets 200 with a partialSuccess body, which
           the exporter must treat as a non-retryable failure

The last request body (gzip-decoded when announced) is written as JSON
to <body-file>; <meta-file> records the attempt count, the request path
and, when sent, the Authorization and Content-Encoding headers. With a
certificate and key the sink speaks HTTPS.
"""

import gzip
import http.server
import json
import pathlib
import ssl
import sys


mode, port_file, body_file, meta_file = sys.argv[1:5]
tls = sys.argv[5:7]
attempts = 0
meta = {}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def reply(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        global attempts, meta
        attempts += 1
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.headers.get("Content-Encoding", "").lower() == "gzip":
            raw = gzip.decompress(raw)
        meta = {"attempts": attempts, "path": self.path}
        if self.headers.get("Authorization"):
            meta["authorization"] = self.headers["Authorization"]
        if self.headers.get("Content-Encoding"):
            meta["content_encoding"] = self.headers["Content-Encoding"]
        try:
            document = json.loads(raw)
        except ValueError:
            document = {"invalid": raw.decode(errors="replace")}
        pathlib.Path(body_file).write_text(json.dumps(document, indent=1))
        pathlib.Path(meta_file).write_text(json.dumps(meta))

        if mode == "retry" and attempts < 3:
            self.reply(503, {"message": "try again"})
            return
        if mode == "partial":
            self.reply(200, {"partialSuccess": {"rejectedLogRecords": 1,
                                                 "errorMessage": "rejected by mock"}})
        else:
            self.reply(200, {})
        self.server.done = True


server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
server.done = False
if tls:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(tls[0], tls[1])
    server.socket = context.wrap_socket(server.socket, server_side=True)
pathlib.Path(port_file).write_text(f"{server.server_address[1]}\n")
while not server.done:
    server.handle_request()
server.server_close()
