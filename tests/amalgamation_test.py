#!/usr/bin/env python3
"""Prove that the production library is distributable as api.c + api.h."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    source = (ROOT / "api.c").read_text(encoding="utf-8")
    local_includes = re.findall(r'^\s*#include\s+"([^"]+)"', source, re.MULTILINE)
    if local_includes != ["api.h"]:
        raise AssertionError(
            "api.c must include exactly one local production header (api.h), "
            f"found: {local_includes}"
        )

    compiler = shlex.split(os.environ.get("CC", "cc"))
    if not compiler:
        raise AssertionError("CC resolves to an empty command")
    with tempfile.TemporaryDirectory(prefix="mcprotocol-two-file-") as directory:
        isolated = Path(directory)
        shutil.copy2(ROOT / "api.c", isolated / "api.c")
        shutil.copy2(ROOT / "api.h", isolated / "api.h")
        consumer = isolated / "smoke_consumer.c"
        consumer.write_text(
            """#include "api.h"

#include <stddef.h>

int main(void)
{
    size_t count = 0U;
    const int *protocols = mc_supported_protocols(&count);
    return protocols != NULL && count != 0U && mc_protocol_supported(47) ? 0 : 1;
}
""",
            encoding="utf-8",
        )
        subprocess.run(
            [
                *compiler,
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Wconversion",
                "-Wshadow",
                "-Werror",
                str(consumer),
                str(isolated / "api.c"),
                "-lz",
                "-o",
                str(isolated / "smoke_consumer"),
            ],
            cwd=isolated,
            check=True,
        )
        subprocess.run([str(isolated / "smoke_consumer")], check=True)
    print("PASS api.c + api.h + zlib isolated distribution")


if __name__ == "__main__":
    main()
