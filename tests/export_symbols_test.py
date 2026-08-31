#!/usr/bin/env python3
"""Compare api.o global definitions with the reviewed public API allowlist."""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent
ALLOWLIST = ROOT / "tests" / "public_symbols.txt"


def defined_symbols(object_path: Path) -> set[str]:
    nm = shlex.split(os.environ.get("NM", "nm"))
    if not nm:
        raise AssertionError("NM resolves to an empty command")
    output = subprocess.run(
        [*nm, "-g", str(object_path)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout
    symbols: set[str] = set()
    for line in output.splitlines():
        columns = line.split()
        if len(columns) < 2:
            continue
        symbol_type = columns[-2]
        if len(symbol_type) != 1 or not symbol_type.isupper() or symbol_type == "U":
            continue
        name = columns[-1]
        if name.startswith("_mc"):
            name = name[1:]
        symbols.add(name)
    return symbols


def main() -> None:
    expected = {
        line.strip()
        for line in ALLOWLIST.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }
    compiler = shlex.split(os.environ.get("CC", "cc"))
    if not compiler:
        raise AssertionError("CC resolves to an empty command")
    with tempfile.TemporaryDirectory(prefix="mcprotocol-exports-") as directory:
        object_path = Path(directory) / "api.o"
        subprocess.run(
            [
                *compiler,
                "-std=c11",
                "-O2",
                "-DNDEBUG",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Wconversion",
                "-Wshadow",
                "-Werror",
                "-c",
                str(ROOT / "api.c"),
                "-o",
                str(object_path),
            ],
            cwd=ROOT,
            check=True,
        )
        actual = defined_symbols(object_path)

    unexpected = sorted(actual - expected)
    missing = sorted(expected - actual)
    if unexpected or missing:
        if unexpected:
            print("unexpected global definitions:", *unexpected, sep="\n  ", file=sys.stderr)
        if missing:
            print("allowlisted symbols not defined:", *missing, sep="\n  ", file=sys.stderr)
        raise SystemExit(1)
    print(f"PASS public export allowlist ({len(expected)} symbols)")


if __name__ == "__main__":
    main()
