#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

"""Check a prepared pilot inside the pinned Aeneas backend's `lake env`."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from prepare import HERE, ROOT
from extract import check_checkout


def check(output, candidate, refinement_only):
    lean = output / "lean"
    candidates = ["pin_encode", candidate] if candidate == "pin_codec" else [candidate]
    pins = json.loads((HERE / "toolchain.json").read_text())
    extractions = {}
    for name in candidates:
        extraction_path = output / name / "extraction.json"
        extraction = json.loads(extraction_path.read_text())
        checkout = Path(extraction["aeneas_checkout"])
        check_checkout(checkout, pins["aeneas"], pins.get("local_sources"))
        check_checkout(checkout / "charon", pins["charon"])
        executables = {
            "aeneas": extraction["commands"][1][0],
            "charon": extraction["commands"][0][3],
        }
        for tool, expected in extraction["binaries"].items():
            if hashlib.sha256(Path(executables[tool]).read_bytes()).hexdigest() != expected:
                raise ValueError(f"{tool} binary changed after extraction")
        extractions[name] = hashlib.sha256(extraction_path.read_bytes()).hexdigest()
        if extraction["status"] != "extracted; refinement obligations remain unproved":
            raise ValueError("checking requires a completed production extraction")
        if extraction["pins"] != pins:
            raise ValueError("extraction tool pins differ from the current pilot")
        for source in extraction["sources"]:
            current = hashlib.sha256((ROOT / source["path"]).read_bytes()).hexdigest()
            if current != source["source_sha256"]:
                raise ValueError(f"production source changed after extraction: {source['path']}")
        for path, expected in extraction["generated_lean_sha256"].items():
            if hashlib.sha256((lean / path).read_bytes()).hexdigest() != expected:
                raise ValueError(f"generated source changed after extraction: {path}")
        subject = output / name / "subject.rs"
        if hashlib.sha256(subject.read_bytes()).hexdigest() != extraction["subject_sha256"]:
            raise ValueError("Rust candidate changed after extraction")
    inherited = [str(Path(path).resolve()) for path in
                 os.environ.get("LEAN_PATH", "").split(os.pathsep) if path]
    roots = [lean, *(lean / "generated").glob("*")]
    env = dict(os.environ, LEAN_PATH=os.pathsep.join(map(str, roots)) +
               os.pathsep + os.pathsep.join(inherited))
    files = [lean / "Shirudo" / f"{name}.lean" for name in
             ("Chain", "ConfigActivation", "ArchivePath", "PinName")]
    files.append(lean / "Contracts.lean")
    modules = {
        "config_predicates": ("ConfigPredicates", "ConfigRefinement"),
        "pin_encode": ("PinEncodeGenerated", "PinCodec"),
        "pin_codec": ("PinCodecGenerated", "PinDecode"),
        "archive_path": ("ArchivePath", "ArchiveRefinement"),
    }
    for name in candidates:
        module, refinement = modules[name]
        directory = lean / "generated" / name / module
        files.append(directory / "Types.lean")
        if name == "archive_path":
            model = directory / "FunsExternal.lean"
            if model.read_bytes() != (HERE / "ArchiveModels.lean").read_bytes():
                raise ValueError("prepared archive standard-library models differ")
            files.append(model)
        files.append(directory / "Funs.lean")
        if name == "archive_path":
            files.extend(lean / f"{helper}.lean" for helper in ("ArchiveList", "ArchiveSlice"))
        files.append(lean / f"{refinement}.lean")
    for path in files:
        relative = path.relative_to(lean)
        if relative.parts[0] == "Shirudo":
            original = ROOT / "testing/proofs/lean4" / relative
        elif path.parent == lean:
            original = HERE / path.name
        else:
            continue
        if path.read_bytes() != original.read_bytes():
            raise ValueError(f"prepared Lean source differs from repository: {relative}")
    report = output / candidate / "check.json"
    record = {
        "status": "checking refinement only" if refinement_only else "checking",
        "lean_version": subprocess.check_output(["lean", "--version"], text=True).strip(),
        "sources": {str(path.relative_to(lean)): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in files},
        "commands": [],
        "extraction_sha256": extractions,
        "lean_search_path": env["LEAN_PATH"],
        "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    lean_version = pins["lean"].split(":v", 1)[1]
    if f"version {lean_version}," not in record["lean_version"]:
        raise ValueError("Lean version differs from the pilot pin")
    report.write_text(json.dumps(record, indent=2) + "\n")
    if refinement_only:
        files = files[-1:]
    for path in files:
        command = ["lean", "-j1", "-DwarningAsError=true", "-o", str(path.with_suffix(".olean")),
                   str(path)]
        print(" ".join(command), flush=True)
        record["commands"].append(command)
        result = subprocess.run(command, cwd=lean, env=env, capture_output=True, text=True)
        print(result.stdout, end="", flush=True)
        print(result.stderr, end="", flush=True)
        if result.returncode:
            record["status"] = "failed"
            record["failed_output"] = result.stdout + result.stderr
            report.write_text(json.dumps(record, indent=2) + "\n")
            result.check_returncode()
        if path == files[-1]:
            record["refinement_output"] = result.stdout
            axioms = re.findall(r"depends on axioms: \[([^]]*)\]", result.stdout)
            expected_count = {"config_predicates": 3, "pin_encode": 4,
                              "pin_codec": 1, "archive_path": 2}[candidate]
            allowed = {"propext", "Classical.choice", "Quot.sound"}
            if len(axioms) != expected_count or any(
                    set(filter(None, map(str.strip, names.split(",")))) - allowed
                    for names in axioms):
                record["status"] = "unexpected axiom report"
                report.write_text(json.dumps(record, indent=2) + "\n")
                raise ValueError("refinement axiom report is missing or contains extra axioms")
    record["status"] = "refinement checked" if refinement_only else "checked"
    report.write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--candidate", choices=("config_predicates", "pin_encode",
                                                    "pin_codec", "archive_path"), required=True)
    parser.add_argument("--refinement-only", action="store_true")
    args = parser.parse_args()
    check(args.output.resolve(), args.candidate, args.refinement_only)
