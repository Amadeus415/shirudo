#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

"""Prepare dependency-free crates from unchanged production Rust items."""

import argparse
import hashlib
import json
from pathlib import Path
import re


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
HEADER = "// SPDX-License-Identifier: BSD-2-Clause\n// Copyright (c) 2026 Authors of shirudo\n"
CONFIG = "rust/src/util/config_update.rs"
TAR = "rust/src/util/bpm_package/tar.rs"
SELECTIONS = {
    "config_predicates": [
        (CONFIG, "const", "PREFIX_MAX"),
        ("rust/src/errno.rs", "const", "EUCLEAN"),
        ("rust/src/util/config_measure.rs", "const", "EVENT_BOOT"),
        ("rust/src/util/config_measure.rs", "const", "EVENT_UPDATE"),
        (CONFIG, "struct", "ConfigUpdateTarget"),
        (CONFIG, "struct", "ConfigUpdateRecord"),
        (CONFIG, "struct", "BootIdentity"),
        (CONFIG, "method", "boot"),
        (CONFIG, "fn", "same_boot"),
        (CONFIG, "fn", "same_event"),
        (CONFIG, "fn", "event_follows"),
    ],
    "archive_path": [
        (TAR, "fn", "archive_rel_ok"),
        (TAR, "fn", "package_member_name_ok"),
    ],
    "pin_codec": [
        ("rust/src/util/upatch.rs", "fn", "pin_name"),
        ("rust/src/util/upatch.rs", "fn", "name_from_pin"),
    ],
    "pin_encode": [("rust/src/util/upatch.rs", "fn", "pin_name")],
}


def select(path, kind, name):
    source = (ROOT / path).read_text()
    lines = source.splitlines(keepends=True)
    if kind == "method":
        pattern = (rf"^    fn {name}\(&self\) -> BootIdentity \{{\n"
                   r"[\s\S]*?^    \}\n")
        matches = list(re.finditer(pattern, source, re.M))
        if len(matches) != 1:
            raise ValueError(f"{path}: expected exactly one BootIdentity method {name}")
        match = matches[0]
        item = match.group()
        return "impl ConfigUpdateRecord {\n" + item + "}\n", {
            "path": path, "item": name,
            "first_line": source[:match.start()].count("\n") + 1,
            "last_line": source[:match.end()].count("\n"),
            "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "item_sha256": hashlib.sha256(item.encode()).hexdigest(),
        }
    pattern = rf"^(?:pub(?:\([^)]*\))? )?{kind} {name}\b"
    starts = [i for i, line in enumerate(lines) if re.match(pattern, line)]
    if len(starts) != 1:
        raise ValueError(f"{path}: expected exactly one {kind} {name}")
    start = starts[0]
    end = start + 1
    if kind == "const":
        if not lines[start].rstrip().endswith(";"):
            raise ValueError(f"{path}: {name} is no longer a one-line constant")
    else:
        # rustfmt puts only the item's closing brace at column zero.
        while end < len(lines) and lines[end] != "}\n":
            if lines[end].strip() and not lines[end][0].isspace():
                raise ValueError(f"{path}: unexpected item boundary in {name}")
            end += 1
        if end == len(lines):
            raise ValueError(f"{path}: missing closing brace for {name}")
        end += 1
    while start and (lines[start - 1].startswith("#[") or
                     lines[start - 1].startswith("///")):
        start -= 1
    item = "".join(lines[start:end])
    return item, {
        "path": path, "item": name, "first_line": start + 1, "last_line": end,
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "item_sha256": hashlib.sha256(item.encode()).hexdigest(),
    }


def prepare(output):
    provenance = {}
    for crate, selections in SELECTIONS.items():
        items, records = [], []
        for selection in selections:
            item, record = select(*selection)
            items.append(item)
            records.append(record)
        directory = output / crate
        directory.mkdir(parents=True, exist_ok=True)
        imports = "use core::ffi::c_int;\n\n" if crate == "config_predicates" else ""
        subject = HEADER + "\n" + imports + "\n".join(items)
        (directory / "subject.rs").write_text(subject)
        (directory / "lib.rs").write_text(
            HEADER + '\nmod subject {\n    include!("subject.rs");\n}\n')
        (directory / "Cargo.toml").write_text(
            '# SPDX-License-Identifier: BSD-2-Clause\n'
            '# Copyright (c) 2026 Authors of shirudo\n\n'
            f'[package]\nname = "{crate}"\nversion = "0.0.0"\n'
            'edition = "2024"\nlicense = "BSD-2-Clause"\npublish = false\n\n'
            '[lib]\npath = "lib.rs"\n\n[workspace]\n\n'
            '[profile.dev]\noverflow-checks = true\n\n'
            '[profile.release]\noverflow-checks = true\n')
        provenance[crate] = records
    lean = output / "lean"
    (lean / "Shirudo").mkdir(parents=True, exist_ok=True)
    for name in ("ArchivePath", "ConfigActivation", "Chain", "PinName"):
        path = ROOT / f"testing/proofs/lean4/Shirudo/{name}.lean"
        (lean / "Shirudo" / path.name).write_bytes(path.read_bytes())
    (lean / "Contracts.lean").write_bytes((HERE / "Contracts.lean").read_bytes())
    codec = HERE / "PinCodec.lean"
    if codec.exists():
        (lean / codec.name).write_bytes(codec.read_bytes())
    refinement = HERE / "ConfigRefinement.lean"
    if refinement.exists():
        (lean / refinement.name).write_bytes(refinement.read_bytes())
    for name in ("ArchiveModels", "ArchiveList", "ArchiveSlice", "ArchiveRefinement", "PinDecode"):
        proof = HERE / f"{name}.lean"
        if proof.exists() and not (lean / proof.name).is_symlink():
            (lean / proof.name).write_bytes(proof.read_bytes())
    pins = json.loads((HERE / "toolchain.json").read_text())
    (lean / "lean-toolchain").write_text(pins["lean"] + "\n")
    (output / "sources.json").write_text(json.dumps(provenance, indent=2) + "\n")
    print(f"Prepared production source slices in {output}; no extraction or proof run.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/aeneas")
    args = parser.parse_args()
    prepare(args.output.resolve())
