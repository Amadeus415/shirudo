#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
"""What t9109 and t9110 recompute from a node's records, the publications
and the backend's rows, each from the format's own definition, so that
neither side is taken on trust."""

import base64
import hashlib
import json
import ssl
import sys
import urllib.request

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


def mask(outcomes, head_seq, base_seq=0):
    """The keepalive mask of a node over the window past base_seq."""
    codes = {line["seq"]: line["outcome"] for line in outcomes}
    pairs = [codes.get(seq, 0) for seq in range(base_seq + 1, head_seq + 1)]
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


def node(state_path, outcomes_path, eventlog_path, window=None):
    """A node's view: its roots, the window of its keepalive, which starts
    at seq 1 without a window size, and the digests it chained."""
    with open(state_path, encoding="utf-8") as f:
        state = json.load(f)
    outcomes = lines(outcomes_path)
    seqs = [line["seq"] for line in outcomes]
    assert seqs == list(range(1, state["last_seq"] + 1)), seqs
    base = max(0, state["head_seq"] - int(window)) if window else 0
    base_root = ZERO.hex()
    if base:
        base_root = hexdigest(outcomes[base - 1]["projection_root"])
    return {
        "last_seq": state["last_seq"],
        "head_seq": state["head_seq"],
        "segment_base_seq": state["segment_base_seq"],
        "generation": state["generation"],
        "projection_root": hexdigest(state["projection_root"]),
        "outcomes": [line["outcome"] for line in outcomes],
        "history_root": hexdigest(outcomes[-1]["history_root"]),
        "outcome_root": hexdigest(outcomes[-1]["projection_root"]),
        "base_seq": base,
        "base_root": base_root,
        "mask": mask(outcomes, state["head_seq"], base),
        "chained": [hexdigest(line["digest"]) for line in lines(eventlog_path)],
    }


def history(outcomes_path, gap):
    """The rows of node_ops for a node's outcomes: from seq 1 with gap 0,
    else from a gap row at seq gap that holds the root there."""
    outcomes = lines(outcomes_path)
    rows = []
    if gap:
        rows.append((gap, 0, outcomes[gap - 1]["projection_root"]))
    rows += [(line["seq"], line["outcome"], line["projection_root"])
             for line in outcomes if line["seq"] > gap]
    return [f"{seq}\t{code}\t{hexdigest(root)}" for seq, code, root in rows]


def walk(path):
    """The objects `bpm tree show --walk` printed, each a JSON value that
    may span lines."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    decoder, at, objects = json.JSONDecoder(), 0, []
    while True:
        while at < len(text) and text[at].isspace():
            at += 1
        if at == len(text):
            return objects
        value, at = decoder.raw_decode(text, at)
        objects.append(value)


def segments(path):
    """One line per segment of a walk, oldest first: base, head,
    generation, manifest digest, the sealed segment it names (- for none)
    and its history_root. Each segment continues the one before it, and
    its history_root is the fold of every earlier operation."""
    history_root = ZERO
    previous, head, out = None, 0, []
    for segment in walk(path):
        document = segment["document"]
        base = document["base"]
        assert base["seq"] == head, (base, head)
        if previous is None:
            assert set(base) == {"seq"}, base
        else:
            assert hexdigest(base["segment_manifest_digest"]) == previous, base
            assert base["history_root"] == history_root.hex(), base
        for op in document["operations"]:
            raw = bytes.fromhex(hexdigest(op["operation_digest"]))
            history_root = hashlib.sha256(HISTORY_TAG + history_root + raw).digest()
        head = document["head"]["seq"]
        assert document["operations"][-1]["seq"] == head, document
        manifest = hexdigest(segment["manifest_digest"])
        sealed = hexdigest(base.get("segment_manifest_digest", "-"))
        root = base.get("history_root", ZERO.hex())
        out.append(f"{base['seq']}\t{head}\t{document['generation']}\t"
                   f"{manifest}\t{sealed}\t{root}")
        previous = manifest
    return out


def operations(path):
    """Every operation of a walk: seq, op, id and digest."""
    return [f"{op['seq']}\t{op['op']}\t{op['id']}\t"
            f"{hexdigest(op['operation_digest'])}"
            for segment in walk(path)
            for op in segment["document"]["operations"]]


def tags(registry, ca, repository, count):
    """The manifest digests of the tags segment-1 to segment-<count>."""
    ctx = ssl.create_default_context(cafile=ca)
    out = []
    for k in range(1, count + 1):
        request = urllib.request.Request(
            f"https://{registry}/v2/{repository}/manifests/segment-{k}",
            headers={"Accept": "application/vnd.oci.image.manifest.v1+json"})
        with urllib.request.urlopen(request, context=ctx) as response:
            out.append(hashlib.sha256(response.read()).hexdigest())
    return out


def main():
    command, args = sys.argv[1], sys.argv[2:]
    if command == "roots":
        print(*roots(args))
    elif command == "node":
        print(json.dumps(node(*args), sort_keys=True))
    elif command == "history":
        print(*history(args[0], int(args[1])), sep="\n")
    elif command == "segments":
        print(*segments(args[0]), sep="\n")
    elif command == "operations":
        print(*operations(args[0]), sep="\n")
    elif command == "tags":
        print(*tags(args[0], args[1], args[2], int(args[3])), sep="\n")
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
