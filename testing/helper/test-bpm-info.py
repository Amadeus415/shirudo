#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest


SHIRUDO = str(Path(sys.argv.pop(1)).resolve())
README = b"# Example package\n\nPackage documentation without a final newline."


def package_bytes(entries):
    body = io.BytesIO()
    with tarfile.open(fileobj=body, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        for name, content in entries:
            header = tarfile.TarInfo(name)
            header.size = len(content)
            archive.addfile(header, io.BytesIO(content))
    return body.getvalue()


def package(readme=README):
    entries = [("example-1.0/Beefile", b'[package]\nname = "example"\n')]
    if readme is not None:
        entries.append(("example-1.0/README.md", readme))
    return package_bytes(entries)


class InfoTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="shirudo-bpm-info-test-")
        self.root = Path(self.work.name)
        self.addCleanup(self.work.cleanup)

    def run_bpm(self, *args):
        env = {**os.environ, "BPM_OCI_SCHEME": "http",
               "REGISTRY_AUTH_FILE": str(self.root / "absent-auth.json"),
               "NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}
        env.pop("BPM_OCI_CA_FILE", None)
        env.pop("BPM_OCI_USERNAME", None)
        env.pop("BPM_OCI_PASSWORD", None)
        return subprocess.run([SHIRUDO, "bpm", *args], cwd=self.root,
                              capture_output=True, env=env)

    def run_info(self, *args):
        return self.run_bpm("info", *args)

    def local(self, body):
        path = self.root / "package.bee"
        path.write_bytes(body)
        return self.run_info(str(path))

    def test_local_readme_is_exact(self):
        result = self.local(package())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, README)
        self.assertEqual(list(self.root.iterdir()), [self.root / "package.bee"])

    def test_empty_readme(self):
        result = self.local(package(b""))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_missing_readme(self):
        result = self.local(package(None))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"README.md", result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_missing_beefile(self):
        result = self.local(package_bytes([("example-1.0/README.md", README)]))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"Beefile", result.stderr)

    def test_readme_belongs_to_beefile_directory(self):
        result = self.local(package_bytes([
            ("other-1.0/README.md", b"wrong README"),
            ("example-1.0/Beefile", b'[package]\nname = "example"\n'),
            ("example-1.0/README.md", README),
        ]))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, README)

    def test_unrelated_readme_is_not_used(self):
        result = self.local(package_bytes([
            ("example-1.0/Beefile", b'[package]\nname = "example"\n'),
            ("other-1.0/README.md", README),
        ]))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_non_regular_readme_is_rejected(self):
        body = io.BytesIO()
        with tarfile.open(fileobj=body, mode="w:gz") as archive:
            header = tarfile.TarInfo("example-1.0/Beefile")
            archive.addfile(header, io.BytesIO())
            header = tarfile.TarInfo("example-1.0/README.md")
            header.type = tarfile.SYMTYPE
            header.linkname = "/etc/passwd"
            archive.addfile(header)
        result = self.local(body.getvalue())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_invalid_and_truncated_archives(self):
        for body in (b"not a package", package()[:30]):
            with self.subTest(body=body):
                result = self.local(body)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")

    def test_oversized_readme(self):
        result = self.local(package(b"x" * (4 * 1024 * 1024 + 1)))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_usage_and_help(self):
        self.assertEqual(self.run_info().returncode, 2)
        self.assertEqual(self.run_info("one", "two").returncode, 2)
        result = self.run_info("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"package-file|package-reference", result.stderr)

    def test_invalid_oci_reference(self):
        result = self.run_info("oci://registry.example/package")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_oci_readme_and_integrity(self):
        blob = package()
        digest = "sha256:" + hashlib.sha256(blob).hexdigest()
        for expected_digest, size, success in (
            (digest, len(blob), True),
            ("sha256:" + "0" * 64, len(blob), False),
            (digest, len(blob) + 1, False),
        ):
            with self.subTest(digest=expected_digest, size=size):
                manifest = json.dumps({
                    "schemaVersion": 2,
                    "layers": [{
                        "mediaType": "application/vnd.shirudo.bpm.package.v1+gzip",
                        "digest": expected_digest, "size": size,
                    }],
                }).encode()
                requests = []

                class Handler(http.server.BaseHTTPRequestHandler):
                    def log_message(self, *_args):
                        pass

                    def do_GET(self):
                        requests.append(self.path)
                        if self.path == "/v2/test/example/manifests/1.0":
                            payload = manifest
                        elif self.path == "/v2/test/example/blobs/" + expected_digest:
                            payload = blob
                        else:
                            self.send_error(404)
                            return
                        self.send_response(200)
                        self.send_header("Content-Length", str(len(payload)))
                        self.end_headers()
                        self.wfile.write(payload)

                server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    reference = f"oci://127.0.0.1:{server.server_port}/test/example:1.0"
                    result = self.run_info(reference)
                    self.assertEqual(list(self.root.iterdir()), [])
                    if success:
                        pulled = self.run_bpm("pull", reference)
                        self.assertEqual(pulled.returncode, 0, pulled.stderr)
                        path = self.root / "example-1.0.bee"
                        self.assertEqual(path.read_bytes(), blob)
                        path.unlink()
                finally:
                    server.shutdown()
                    thread.join()
                    server.server_close()
                self.assertEqual(result.returncode == 0, success, result.stderr)
                self.assertEqual(result.stdout, README if success else b"")
                self.assertEqual(len(requests), 4 if success else 2)
                self.assertEqual(list(self.root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
