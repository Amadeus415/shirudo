#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

import argparse
import http.server
import pathlib
import ssl


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header(
                "Location", f"https://localhost:{self.server.server_port}/ok"
            )
            body = b""
        elif self.path == "/auth" and not self.headers.get("Authorization"):
            self.send_response(401)
            self.send_header(
                "WWW-Authenticate",
                f'Bearer realm="https://localhost:{self.server.server_port}/token", '
                'service="test", scope="repository:test:pull"',
            )
            body = b""
        else:
            self.send_response(200)
            body = b'{"token":"test-token"}' if self.path.startswith("/token") else b"ok"
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


parser = argparse.ArgumentParser()
parser.add_argument("--cert", required=True)
parser.add_argument("--key", required=True)
parser.add_argument("--ready-file", required=True)
parser.add_argument("--tls12", action="store_true")
args = parser.parse_args()

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
version = ssl.TLSVersion.TLSv1_2 if args.tls12 else ssl.TLSVersion.TLSv1_3
ctx.minimum_version = version
ctx.maximum_version = version
ctx.set_ecdh_curve("X25519")
ctx.load_cert_chain(args.cert, args.key)
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
server.socket = ctx.wrap_socket(server.socket, server_side=True)
pathlib.Path(args.ready_file).write_text(str(server.server_port), encoding="ascii")
server.serve_forever()
