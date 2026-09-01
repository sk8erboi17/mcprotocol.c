#!/usr/bin/env python3
"""Build and run the public API tests under the requested sanitizers."""

from __future__ import annotations

import os
from pathlib import Path
import platform
import shlex
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent
TESTS = (
    "api_test",
    "codec_test",
    "stream_test",
    "typed_packet_test",
    "envelope_test",
    "canonical_test",
    "replay_test",
    "property_test",
    "generated_test",
)


def main() -> None:
    sanitizers = os.environ.get("SANITIZERS", "address,undefined")
    compiler = shlex.split(os.environ.get("CC", "cc"))
    if not compiler:
        raise AssertionError("CC resolves to an empty command")
    flags = [
        "-std=c11",
        "-O1",
        "-g",
        "-fno-omit-frame-pointer",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Wconversion",
        "-Wshadow",
        "-Werror",
        "-UNDEBUG",
        f"-fsanitize={sanitizers}",
        f"-I{ROOT}",
    ]
    environment = os.environ.copy()
    leak_detection = "0" if platform.system() == "Darwin" else "1"
    environment.setdefault(
        "ASAN_OPTIONS", f"detect_leaks={leak_detection}:halt_on_error=1"
    )
    environment.setdefault("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1")
    with tempfile.TemporaryDirectory(prefix="mcprotocol-sanitize-") as directory:
        build = Path(directory)
        for name in TESTS:
            executable = build / name
            subprocess.run(
                [
                    *compiler,
                    *flags,
                    str(ROOT / "tests" / f"{name}.c"),
                    str(ROOT / "api.c"),
                    "-lz",
                    "-o",
                    str(executable),
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run([str(executable)], env=environment, check=True)
    print(f"PASS sanitizer suite ({sanitizers})")


if __name__ == "__main__":
    main()
