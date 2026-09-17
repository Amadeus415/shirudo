#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
"""Small read-only OCI Registry HTTP fixture for target-side tests.

The fixture deliberately implements only the OCI distribution GET surface
needed by Shirudo tree synchronization.  Files are laid out as:

  ROOT/<repository>/manifests/<reference>
  ROOT/<repository>/blobs/<digest>

Every request is recorded as ``METHOD<TAB>PATH<TAB>STATUS`` when --log is
provided, so tests can assert that selectors caused only the expected
artifact requests.
"""

import argparse
import http.server
import pathlib
import sys
import urllib.parse


class RegistryHandler(http.server.BaseHTTPRequestHandler):
    server_version = "shirudo-test-oci/1"

    def log_message(self, _format, *_args):
        pass

    def _record(self, status):
        log = self.server.request_log
        if log is not None:
            with log.open("a", encoding="utf-8") as stream:
                stream.write(f"{self.command}\t{self.path}\t{status}\n")

    def _reply(self, status, body=b"", content_type="text/plain"):
        self._record(status)
        self.send_response(status)
        if body:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _file_for_request(self):
        path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        parts = path.split("/")
        if len(parts) < 5 or parts[1] != "v2":
            return None
        try:
            marker = next(i for i in range(2, len(parts))
                          if parts[i] in ("manifests", "blobs"))
        except StopIteration:
            return None
        repository = "/".join(parts[2:marker])
        reference = "/".join(parts[marker + 1:])
        if not repository or not reference:
            return None
        relative = pathlib.Path(repository) / parts[marker] / reference
        root = self.server.registry_root.resolve()
        candidate = (root / relative).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            return None
        return candidate, parts[marker]

    def do_HEAD(self):
        self._serve()

    def do_GET(self):
        self._serve()

    def _serve(self):
        path = urllib.parse.urlsplit(self.path).path
        if path in ("/v2", "/v2/"):
            self._reply(200, b"", "application/json")
            return
        result = self._file_for_request()
        if result is None:
            self._reply(404)
            return
        candidate, kind = result
        if not candidate.is_file():
            self._reply(404)
            return
        body = candidate.read_bytes()
        content_type = (
            "application/vnd.oci.image.manifest.v1+json"
            if kind == "manifests" else "application/octet-stream"
        )
        self._reply(200, body, content_type)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=pathlib.Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--log", type=pathlib.Path)
    parser.add_argument("--ready-file", type=pathlib.Path)
    args = parser.parse_args()

    args.root.mkdir(parents=True, exist_ok=True)
    if args.log is not None:
        args.log.parent.mkdir(parents=True, exist_ok=True)
        args.log.write_text("", encoding="utf-8")
    if args.ready_file is not None:
        args.ready_file.unlink(missing_ok=True)

    server = http.server.ThreadingHTTPServer((args.host, args.port),
                                               RegistryHandler)
    server.registry_root = args.root
    server.request_log = args.log
    if args.ready_file is not None:
        args.ready_file.touch()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
