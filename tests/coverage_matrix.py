#!/usr/bin/env python3
"""Generate a protocol/family coverage matrix from the public C API."""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "build" / "coverage-matrix.md"

PROBE = r'''#include "api.h"
#include <stdio.h>

static const char *status(int protocol, McPacketDirection direction,
    const char *first, const char *second)
{
    int32_t id = mc_packet_id(protocol, MC_STATE_PLAY, direction, first);
    if (id < 0 && second != NULL) {
        id = mc_packet_id(protocol, MC_STATE_PLAY, direction, second);
    }
    if (id < 0) return "N/A";
    const McPacketFamily family = mc_packet_family(protocol, MC_STATE_PLAY,
        direction, id);
    return family != MC_FAMILY_UNKNOWN && mc_packet_decoded_size(family) != 0U
        ? "PASS" : "BLOCKED";
}

int main(void)
{
    puts("| Protocol | Release | Movement | Input | Attack | Dig | Place | Velocity | Entity move | Block change | Inventory | Chunk envelope |");
    puts("|---:|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|");
    size_t count = 0U;
    const int *protocols = mc_supported_protocols(&count);
    for (size_t index = 0U; index < count; ++index) {
        const int protocol = protocols[index];
        const char *release = mc_protocol_name(protocol);
        printf("| %d | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
            protocol, release != NULL ? release : "unknown",
            status(protocol, MC_PACKET_SERVERBOUND, "position_look", NULL),
            status(protocol, MC_PACKET_SERVERBOUND, "player_input", NULL),
            status(protocol, MC_PACKET_SERVERBOUND, "attack", "use_entity"),
            status(protocol, MC_PACKET_SERVERBOUND, "block_dig", NULL),
            status(protocol, MC_PACKET_SERVERBOUND, "block_place", NULL),
            status(protocol, MC_PACKET_CLIENTBOUND, "entity_velocity", NULL),
            status(protocol, MC_PACKET_CLIENTBOUND, "entity_move_look", NULL),
            status(protocol, MC_PACKET_CLIENTBOUND, "block_change", NULL),
            status(protocol, MC_PACKET_CLIENTBOUND, "window_items", NULL),
            mc_packet_id(protocol, MC_STATE_PLAY, MC_PACKET_CLIENTBOUND,
                "map_chunk") >= 0 ? "PARTIAL" : "N/A");
    }
    return 0;
}
'''


def main() -> None:
    compiler = shlex.split(os.environ.get("CC", "cc"))
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mcprotocol-matrix-") as directory:
        temporary = Path(directory)
        source = temporary / "matrix.c"
        executable = temporary / "matrix"
        source.write_text(PROBE, encoding="utf-8")
        subprocess.run(
            [
                *compiler,
                "-std=c11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Wconversion",
                "-Wshadow",
                "-Werror",
                f"-I{ROOT}",
                str(source),
                str(ROOT / "api.c"),
                "-lz",
                "-o",
                str(executable),
            ],
            check=True,
            cwd=ROOT,
        )
        matrix = subprocess.check_output([str(executable)], text=True, cwd=ROOT)
    preamble = (
        "# Protocol coverage matrix\n\n"
        "Generated from the immutable public catalog and typed-dispatch API. "
        "`PARTIAL` for chunk means the packet envelope is fully bounded and "
        "exact-consumed, while legacy section palette access is not yet "
        "materialized; modern protocols additionally expose borrowed section "
        "iteration.\n\n"
    )
    OUTPUT.write_text(preamble + matrix, encoding="utf-8")
    print(f"PASS coverage matrix ({OUTPUT.relative_to(ROOT)})")


if __name__ == "__main__":
    main()
