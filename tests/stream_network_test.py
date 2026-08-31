#!/usr/bin/env python3
"""Regression test for draining decoder-buffered frames before socket wait."""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent


def run_case(server: Path, client: Path, mode: str,
             clients: int, messages: int) -> None:
    process = subprocess.Popen(
        [str(server), mode, str(clients), str(messages)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    port = process.stdout.readline().strip()
    if not port.isdecimal():
        _, server_error = process.communicate(timeout=5)
        raise AssertionError(f"mock server did not publish a port: {server_error}")
    try:
        completed = subprocess.run(
            [
                str(client), mode, "127.0.0.1", port,
                str(clients), str(messages),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
        _, server_error = process.communicate(timeout=10)
    except BaseException:
        process.kill()
        process.wait()
        raise
    if completed.returncode != 0:
        raise AssertionError(f"client failed: {completed.stderr.strip()}")
    if process.returncode != 0:
        raise AssertionError(f"server rejected stream: {server_error.strip()}")


def main() -> None:
    compiler = shlex.split(os.environ.get("CC", "cc"))
    if not compiler:
        raise AssertionError("CC resolves to an empty command")
    common = [
        *compiler,
        "-O2",
        "-DNDEBUG",
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Wconversion",
        "-Wshadow",
        "-Werror",
        "-pthread",
    ]
    with tempfile.TemporaryDirectory(prefix="mcprotocol-network-stream-") as directory:
        build = Path(directory)
        server = build / "mock_server"
        client = build / "c_client"
        subprocess.run(
            [*common, str(ROOT / "benchmark" / "mock_server.c"),
             "-o", str(server)],
            cwd=ROOT,
            check=True,
        )
        subprocess.run(
            [
                *common,
                str(ROOT / "benchmark" / "c_client.c"),
                str(ROOT / "api.c"),
                "-lz",
                "-o",
                str(client),
            ],
            cwd=ROOT,
            check=True,
        )
        run_case(server, client, "stream", 1, 512)
        run_case(server, client, "concurrent", 8, 64)
    print("PASS socket stream drains buffered and concurrent frames")


if __name__ == "__main__":
    main()
