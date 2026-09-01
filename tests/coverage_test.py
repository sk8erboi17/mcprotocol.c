#!/usr/bin/env python3
"""Run the C suite with LLVM source coverage instrumentation."""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import shutil
import subprocess


ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build" / "coverage"
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


def resolve_tool(name: str, environment: str) -> str:
    requested = shlex.split(os.environ.get(environment, name))
    if len(requested) != 1:
        raise SystemExit(f"{environment} must resolve to exactly one executable")
    value = shutil.which(requested[0])
    if value is None:
        raise SystemExit(
            f"{requested[0]} is required for make coverage "
            f"(override with {environment})"
        )
    return value


def main() -> None:
    compiler = shlex.split(os.environ.get("COVERAGE_CC", "clang"))
    if not compiler:
        raise SystemExit("COVERAGE_CC resolves to an empty command")
    profdata = resolve_tool("llvm-profdata", "LLVM_PROFDATA")
    cov = resolve_tool("llvm-cov", "LLVM_COV")
    BUILD.mkdir(parents=True, exist_ok=True)
    raw_profiles: list[Path] = []
    executables: list[Path] = []
    flags = [
        "-std=c11", "-O0", "-g", "-fprofile-instr-generate",
        "-fcoverage-mapping", "-Wall", "-Wextra", "-Wpedantic",
        "-Wconversion", "-Wshadow", "-Werror", "-UNDEBUG", f"-I{ROOT}",
    ]
    for name in TESTS:
        executable = BUILD / name
        subprocess.run(
            [*compiler, *flags, str(ROOT / "tests" / f"{name}.c"),
             str(ROOT / "api.c"), "-lz", "-o", str(executable)],
            cwd=ROOT,
            check=True,
        )
        profile = BUILD / f"{name}.profraw"
        environment = os.environ.copy()
        environment["LLVM_PROFILE_FILE"] = str(profile)
        subprocess.run([str(executable)], cwd=ROOT, env=environment, check=True)
        raw_profiles.append(profile)
        executables.append(executable)
    merged = BUILD / "coverage.profdata"
    subprocess.run(
        [profdata, "merge", "-sparse", *map(str, raw_profiles), "-o", str(merged)],
        check=True,
        cwd=ROOT,
    )
    object_arguments: list[str] = []
    for executable in executables[1:]:
        object_arguments.extend(["-object", str(executable)])
    common = [str(executables[0]), *object_arguments,
              f"-instr-profile={merged}", str(ROOT / "api.c")]
    report = subprocess.check_output([cov, "report", *common], cwd=ROOT, text=True)
    (BUILD / "coverage.txt").write_text(report, encoding="utf-8")
    lcov = subprocess.check_output(
        [cov, "export", "-format=lcov", *common], cwd=ROOT, text=True
    )
    (BUILD / "coverage.lcov").write_text(lcov, encoding="utf-8")
    print(report.rstrip())
    print("PASS LLVM coverage report (build/coverage/coverage.txt)")


if __name__ == "__main__":
    main()
