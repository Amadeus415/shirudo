#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
"""What t9109 recomputes from a node's records and the backend's rows, each
from the format's own definition, so that neither side is taken on trust."""

import base64
import hashlib
import json
import sys

ZERO = bytes(32)
HISTORY_TAG = b"shirudo-tree-history\0"


def hexdigest(value):
    return value.removeprefix("sha256:")


def lines(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def roots(digests):
    """projection_root with every operation applied, and history_root."""
    projection = history = ZERO
    for digest in digests:
        raw = bytes.fromhex(hexdigest(digest))
        projection = hashlib.sha256(projection + raw).digest()
        history = hashlib.sha256(HISTORY_TAG + history + raw).digest()
    return projection.hex(), history.hex()


def mask(outcomes, head_seq):
    """The keepalive mask of a node whose window starts at seq 1."""
    codes = {line["seq"]: line["outcome"] for line in outcomes}
    pairs = [codes.get(seq, 0) for seq in range(1, head_seq + 1)]
    raw = bytearray((len(pairs) + 3) // 4)
    for i, code in enumerate(pairs):
        raw[i // 4] |= code << (6 - 2 * (i % 4))
    return base64.b64encode(bytes(raw)).decode()


def loaded_set(upatch_list):
    """set_sha256 over the loaded upatches of `upatch list --json`."""
    with open(upatch_list, encoding="utf-8") as f:
        upatches = json.load(f)["upatches"]
    loaded = sorted((u["name"], u["payload_sha256"]) for u in upatches
                    if u["loaded"] and u.get("type") == "load")
    text = "".join(f"{payload} {name}\n" for name, payload in loaded)
    return hashlib.sha256(text.encode()).hexdigest()


def quote_extra(quote):
    """The qualifying data of the TPMS_ATTEST in a shirudo.quote value."""
    fields = dict(part.split("=", 1) for part in quote.split(";"))
    attest = base64.b64decode(fields["attest"])
    offset = 6
    signer = int.from_bytes(attest[offset:offset + 2], "big")
    offset += 2 + signer
    size = int.from_bytes(attest[offset:offset + 2], "big")
    return attest[offset + 2:offset + 2 + size].hex()


def node(state_path, outcomes_path, eventlog_path):
    """A node's view: its roots, its mask, and the digests it chained."""
    with open(state_path, encoding="utf-8") as f:
        state = json.load(f)
    outcomes = lines(outcomes_path)
    seqs = [line["seq"] for line in outcomes]
    assert seqs == list(range(1, state["last_seq"] + 1)), seqs
    return {
        "last_seq": state["last_seq"],
        "generation": state["generation"],
        "projection_root": hexdigest(state["projection_root"]),
        "outcomes": [line["outcome"] for line in outcomes],
        "history_root": hexdigest(outcomes[-1]["history_root"]),
        "outcome_root": hexdigest(outcomes[-1]["projection_root"]),
        "mask": mask(outcomes, state["head_seq"]),
        "chained": [hexdigest(line["digest"]) for line in lines(eventlog_path)],
    }


def main():
    command, args = sys.argv[1], sys.argv[2:]
    if command == "roots":
        print(*roots(args))
    elif command == "node":
        print(json.dumps(node(*args), sort_keys=True))
    elif command == "set":
        print(loaded_set(args[0]))
    elif command == "quotes":
        # Every stored record: its body's SHA-256 is what the TPM quoted.
        for record in lines(args[0]):
            body = hashlib.sha256(record["body"].encode()).hexdigest()
            assert quote_extra(record["quote"]) == body, record["clock"]
            print(record["ak_name"], record["clock"])
    elif command == "replay":
        # The newest stored record of a node with one byte of its body
        # changed: its quote in $2, the body in $3.
        record = max(lines(args[0]), key=lambda r: r["clock"])
        body = bytearray(record["body"].encode())
        at = body.index(b'"boot_id":"') + len(b'"boot_id":"')
        body[at] = ord("0") if body[at] != ord("0") else ord("1")
        with open(args[1], "w", encoding="ascii") as f:
            f.write(record["quote"])
        with open(args[2], "wb") as f:
            f.write(body)
    else:
        raise SystemExit(f"pipeline_checks.py: no command {command}")


if __name__ == "__main__":
    main()
