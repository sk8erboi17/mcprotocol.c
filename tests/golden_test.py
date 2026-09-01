#!/usr/bin/env python3
"""Compile packet-driven golden fixtures against the public two-file API."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from golden_fixture import load_cases


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "tier_a_golden.json"


def c_bytes(raw_hex: str) -> str:
    data = bytes.fromhex(raw_hex)
    return ", ".join(f"UINT8_C(0x{value:02x})" for value in data)


def check_expression(case: dict[str, object]) -> str:
    expected = case["expected"]
    assert isinstance(expected, dict)
    kind = expected["kind"]
    if kind == "movement":
        return (
            f"((McPlayerMovementPacket *)(void *)decoded)->x == {expected['x']} && "
            f"((McPlayerMovementPacket *)(void *)decoded)->y == {expected['y']} && "
            f"((McPlayerMovementPacket *)(void *)decoded)->z == {expected['z']} && "
            f"((McPlayerMovementPacket *)(void *)decoded)->yaw == {expected['yaw']}F && "
            f"((McPlayerMovementPacket *)(void *)decoded)->pitch == {expected['pitch']}F && "
            f"((McPlayerMovementPacket *)(void *)decoded)->on_ground == "
            f"{'true' if expected['on_ground'] else 'false'}"
        )
    if kind == "player_input":
        return (
            f"((McPlayerInputPacket *)(void *)decoded)->flags == {expected['flags']}U && "
            f"((McPlayerInputPacket *)(void *)decoded)->bitset == "
            f"{'true' if expected['bitset'] else 'false'}"
        )
    if kind == "steer_vehicle":
        return (
            f"((McPlayerInputPacket *)(void *)decoded)->sideways == {expected['sideways']}F && "
            f"((McPlayerInputPacket *)(void *)decoded)->forward == {expected['forward']}F && "
            f"((McPlayerInputPacket *)(void *)decoded)->flags == {expected['flags']}U"
        )
    if kind == "vehicle_move":
        return (
            f"((McVehicleMovePacket *)(void *)decoded)->x == {expected['x']} && "
            f"((McVehicleMovePacket *)(void *)decoded)->y == {expected['y']} && "
            f"((McVehicleMovePacket *)(void *)decoded)->z == {expected['z']} && "
            f"((McVehicleMovePacket *)(void *)decoded)->yaw == {expected['yaw']}F && "
            f"((McVehicleMovePacket *)(void *)decoded)->pitch == {expected['pitch']}F && "
            f"((McVehicleMovePacket *)(void *)decoded)->on_ground == "
            f"{'true' if expected['on_ground'] else 'false'}"
        )
    if kind == "arm_animation":
        return (
            f"((McArmAnimationPacket *)(void *)decoded)->entity_id == "
            f"{expected['entity_id']} && "
            f"((McArmAnimationPacket *)(void *)decoded)->hand == {expected['hand']}"
        )
    if kind == "client_command":
        return (
            f"((McClientCommandPacket *)(void *)decoded)->action == "
            f"{expected['action']}"
        )
    if kind == "close_window":
        return (
            f"((McCloseWindowPacket *)(void *)decoded)->window_id == "
            f"{expected['window_id']}"
        )
    if kind == "attack":
        return (
            f"((McUseEntityPacket *)(void *)decoded)->entity_id == {expected['entity_id']} && "
            f"((McUseEntityPacket *)(void *)decoded)->action == {expected['action']}"
        )
    if kind == "slot":
        return f"((McHeldItemSlotPacket *)(void *)decoded)->slot == {expected['slot']}"
    if kind == "teleport":
        return (
            "((McTeleportConfirmPacket *)(void *)decoded)->teleport_id == "
            f"{expected['teleport_id']}"
        )
    if kind == "entity_action":
        return (
            f"((McEntityAction *)(void *)decoded)->entity_id == {expected['entity_id']} && "
            f"((McEntityAction *)(void *)decoded)->action == {expected['action']} && "
            f"((McEntityAction *)(void *)decoded)->jump_boost == {expected['jump_boost']}"
        )
    if kind == "abilities":
        return (
            f"((McPlayerAbilities *)(void *)decoded)->flags == {expected['flags']}U"
        )
    if kind == "block_dig":
        return (
            f"((McBlockDig *)(void *)decoded)->status == {expected['status']} && "
            f"((McBlockDig *)(void *)decoded)->location.x == {expected['x']} && "
            f"((McBlockDig *)(void *)decoded)->location.y == {expected['y']} && "
            f"((McBlockDig *)(void *)decoded)->location.z == {expected['z']} && "
            f"((McBlockDig *)(void *)decoded)->face == {expected['face']} && "
            f"((McBlockDig *)(void *)decoded)->sequence == {expected['sequence']}"
        )
    if kind == "block_place":
        return (
            f"((McBlockPlace *)(void *)decoded)->location.x == {expected['x']} && "
            f"((McBlockPlace *)(void *)decoded)->location.y == {expected['y']} && "
            f"((McBlockPlace *)(void *)decoded)->location.z == {expected['z']} && "
            f"((McBlockPlace *)(void *)decoded)->direction == {expected['direction']} && "
            f"((McBlockPlace *)(void *)decoded)->hand == {expected['hand']} && "
            f"((McBlockPlace *)(void *)decoded)->sequence == {expected['sequence']}"
        )
    if kind == "use_item":
        return (
            f"((McUseItem *)(void *)decoded)->hand == {expected['hand']} && "
            f"((McUseItem *)(void *)decoded)->sequence == {expected['sequence']} && "
            f"((McUseItem *)(void *)decoded)->yaw == {expected['yaw']}F && "
            f"((McUseItem *)(void *)decoded)->pitch == {expected['pitch']}F"
        )
    if kind == "server_position":
        return (
            f"((McClientboundPlayerPosition *)(void *)decoded)->position.x == {expected['x']} && "
            f"((McClientboundPlayerPosition *)(void *)decoded)->position.y == {expected['y']} && "
            f"((McClientboundPlayerPosition *)(void *)decoded)->position.z == {expected['z']} && "
            f"((McClientboundPlayerPosition *)(void *)decoded)->teleport_id == "
            f"{expected['teleport_id']}"
        )
    if kind == "velocity":
        return (
            f"((McEntityVelocityPacket *)(void *)decoded)->entity_id == {expected['entity_id']} && "
            f"((McEntityVelocityPacket *)(void *)decoded)->velocity_x == {expected['x']} && "
            f"((McEntityVelocityPacket *)(void *)decoded)->velocity_y == {expected['y']} && "
            f"((McEntityVelocityPacket *)(void *)decoded)->velocity_z == {expected['z']}"
        )
    if kind == "block_change":
        return (
            f"((McBlockChangePacket *)(void *)decoded)->position.x == {expected['x']} && "
            f"((McBlockChangePacket *)(void *)decoded)->position.y == {expected['y']} && "
            f"((McBlockChangePacket *)(void *)decoded)->position.z == {expected['z']} && "
            f"((McBlockChangePacket *)(void *)decoded)->state_id == {expected['state_id']}"
        )
    if kind == "entity_move":
        return (
            f"((McEntityMovePacket *)(void *)decoded)->entity_id == {expected['entity_id']} && "
            f"((McEntityMovePacket *)(void *)decoded)->delta_x_raw == {expected['dx_raw']} && "
            f"((McEntityMovePacket *)(void *)decoded)->delta_y_raw == {expected['dy_raw']} && "
            f"((McEntityMovePacket *)(void *)decoded)->delta_z_raw == {expected['dz_raw']} && "
            f"((McEntityMovePacket *)(void *)decoded)->yaw_raw == {expected['yaw_raw']}U && "
            f"((McEntityMovePacket *)(void *)decoded)->pitch_raw == {expected['pitch_raw']}U && "
            f"((McEntityMovePacket *)(void *)decoded)->on_ground == "
            f"{'true' if expected['on_ground'] else 'false'}"
        )
    if kind == "entity_teleport":
        return (
            f"((McEntityTeleportPacket *)(void *)decoded)->entity_id == {expected['entity_id']} && "
            f"((McEntityTeleportPacket *)(void *)decoded)->x == {expected['x']} && "
            f"((McEntityTeleportPacket *)(void *)decoded)->y == {expected['y']} && "
            f"((McEntityTeleportPacket *)(void *)decoded)->z == {expected['z']} && "
            f"((McEntityTeleportPacket *)(void *)decoded)->yaw_raw == {expected['yaw_raw']}U && "
            f"((McEntityTeleportPacket *)(void *)decoded)->pitch_raw == {expected['pitch_raw']}U && "
            f"((McEntityTeleportPacket *)(void *)decoded)->on_ground == "
            f"{'true' if expected['on_ground'] else 'false'}"
        )
    if kind == "head_rotation":
        return (
            f"((McEntityHeadRotationPacket *)(void *)decoded)->entity_id == "
            f"{expected['entity_id']} && "
            f"((McEntityHeadRotationPacket *)(void *)decoded)->yaw_raw == "
            f"{expected['yaw_raw']}U"
        )
    if kind == "multi_block_change":
        return (
            f"((McMultiBlockChangePacket *)(void *)decoded)->chunk_x == {expected['chunk_x']} && "
            f"((McMultiBlockChangePacket *)(void *)decoded)->chunk_z == {expected['chunk_z']} && "
            f"((McMultiBlockChangePacket *)(void *)decoded)->section_y == {expected['section_y']} && "
            f"((McMultiBlockChangePacket *)(void *)decoded)->record_count == "
            f"{expected['record_count']}U"
        )
    if kind == "set_slot":
        return (
            f"((McSetSlotPacket *)(void *)decoded)->window_id == {expected['window_id']} && "
            f"((McSetSlotPacket *)(void *)decoded)->state_id == {expected['state_id']} && "
            f"((McSetSlotPacket *)(void *)decoded)->slot == {expected['slot']} && "
            f"((McSetSlotPacket *)(void *)decoded)->item.item_id == {expected['item_id']} && "
            f"((McSetSlotPacket *)(void *)decoded)->item.count == {expected['count']} && "
            f"((McSetSlotPacket *)(void *)decoded)->item.added_component_count == "
            f"{expected['added']}U"
        )
    if kind == "set_slot_empty":
        return (
            f"((McSetSlotPacket *)(void *)decoded)->window_id == {expected['window_id']} && "
            f"((McSetSlotPacket *)(void *)decoded)->state_id == {expected['state_id']} && "
            f"((McSetSlotPacket *)(void *)decoded)->slot == {expected['slot']} && "
            "!((McSetSlotPacket *)(void *)decoded)->item.present"
        )
    if kind == "window_items":
        return (
            f"((McWindowItemsPacket *)(void *)decoded)->window_id == {expected['window_id']} && "
            f"((McWindowItemsPacket *)(void *)decoded)->state_id == {expected['state_id']} && "
            f"((McWindowItemsPacket *)(void *)decoded)->item_count == {expected['item_count']}U && "
            f"((McWindowItemsPacket *)(void *)decoded)->items.size != 0U"
        )
    if kind == "window_click":
        return (
            f"((McWindowClickPacket *)(void *)decoded)->window_id == {expected['window_id']} && "
            f"((McWindowClickPacket *)(void *)decoded)->state_id == {expected['state_id']} && "
            f"((McWindowClickPacket *)(void *)decoded)->slot == {expected['slot']} && "
            f"((McWindowClickPacket *)(void *)decoded)->action_number == "
            f"{expected['action_number']} && "
            f"((McWindowClickPacket *)(void *)decoded)->changed_slot_count == 0U && "
            f"!((McWindowClickPacket *)(void *)decoded)->carried_item.present"
        )
    if kind == "creative_slot":
        return (
            f"((McSetCreativeSlotPacket *)(void *)decoded)->slot == {expected['slot']} && "
            "!((McSetCreativeSlotPacket *)(void *)decoded)->item.present"
        )
    raise ValueError(f"unknown expected kind: {kind}")


def generated_source(cases: list[dict[str, object]]) -> str:
    arrays = []
    rows = []
    for index, case in enumerate(cases):
        raw_hex = str(case["raw_hex"])
        raw_size = len(bytes.fromhex(raw_hex))
        initializer = c_bytes(raw_hex) if raw_size != 0 else "UINT8_C(0)"
        arrays.append(
            f"static const unsigned char raw_{index}[] = {{{initializer}}};"
        )
        rows.append(
            "    {"
            f"{case['protocol']}, "
            f"{'MC_PACKET_SERVERBOUND' if case['direction'] == 'serverbound' else 'MC_PACKET_CLIENTBOUND'}, "
            f"{case['packet_id']}, \"{case['packet_name']}\", "
            f"\"{case['family']}\", raw_{index}, {raw_size}U, "
            f"{str(case['strict']).lower()}, {str(case['compat']).lower()}, {index}U"
            "},"
        )
    checks = "\n".join(
        f"        case {index}U: assert({check_expression(case)}); break;"
        for index, case in enumerate(cases)
    )
    return f'''#include "api.h"
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

{chr(10).join(arrays)}

typedef struct {{
    int protocol;
    McPacketDirection direction;
    int32_t packet_id;
    const char *packet_name;
    const char *family_name;
    const unsigned char *raw;
    size_t raw_size;
    bool strict;
    bool compat;
    size_t check;
}} GoldenCase;

static const GoldenCase cases[] = {{
{chr(10).join(rows)}
}};

static void verify_decode(const GoldenCase *test, McDecodeMode mode) {{
    max_align_t decoded_words[64];
    unsigned char *decoded = (unsigned char *)(void *)decoded_words;
    McPacketFamily family = MC_FAMILY_UNKNOWN;
    McError error;
    memset(decoded, 0, sizeof(decoded_words));
    const int result = mc_decode_packet(test->protocol, MC_STATE_PLAY,
        test->direction, test->packet_id, test->raw, test->raw_size,
        mode, decoded, sizeof(decoded_words), &family, &error);
    if (result != 0) {{
        fprintf(stderr, "golden decode failed: protocol=%d packet=%s mode=%d error=%s offset=%zu\\n",
            test->protocol, test->packet_name, (int)mode,
            mc_error_name(error.code), error.offset);
    }}
    assert(result == 0);
    assert(error.code == MC_ERROR_NONE);
    assert(strcmp(mc_packet_family_name(family), test->family_name) == 0);
    switch (test->check) {{
{checks}
        default: assert(false);
    }}
}}

int main(void) {{
    for (size_t index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {{
        const GoldenCase *test = &cases[index];
        assert(strcmp(mc_packet_name(test->protocol, MC_STATE_PLAY,
            test->direction, test->packet_id), test->packet_name) == 0);
        if (test->strict) verify_decode(test, MC_DECODE_STRICT);
        if (test->compat) verify_decode(test, MC_DECODE_VANILLA_COMPAT);
        if (test->strict) {{
            for (size_t prefix = 0U; prefix < test->raw_size; ++prefix) {{
                max_align_t output[64];
                McPacketFamily family = MC_FAMILY_UNKNOWN;
                McError error;
                assert(mc_decode_packet(test->protocol, MC_STATE_PLAY,
                    test->direction, test->packet_id, test->raw, prefix,
                    MC_DECODE_STRICT, output, sizeof(output), &family,
                    &error) != 0);
            }}
            static const unsigned char suffixes[] = {{
                UINT8_C(0x00), UINT8_C(0xff), UINT8_C(0x5a)
            }};
            for (size_t suffix = 0U;
                    suffix < sizeof(suffixes) / sizeof(suffixes[0]); ++suffix) {{
                unsigned char trailing[128];
                assert(test->raw_size + 1U <= sizeof(trailing));
                memcpy(trailing, test->raw, test->raw_size);
                trailing[test->raw_size] = suffixes[suffix];
                max_align_t output[64];
                McPacketFamily family = MC_FAMILY_UNKNOWN;
                McError error;
                assert(mc_decode_packet(test->protocol, MC_STATE_PLAY,
                    test->direction, test->packet_id, trailing,
                    test->raw_size + 1U, MC_DECODE_STRICT, output,
                    sizeof(output), &family, &error) != 0);
            }}
        }}
    }}
    puts("PASS packet-driven Tier A golden fixtures");
    return 0;
}}
'''


def main() -> int:
    cases = load_cases(FIXTURE)
    with tempfile.TemporaryDirectory(prefix="mcprotocol-golden-") as directory:
        temporary = Path(directory)
        source = temporary / "golden_generated.c"
        executable = temporary / "golden_test"
        source.write_text(generated_source(cases), encoding="utf-8")
        compiler = os.environ.get("CC", "cc")
        subprocess.run([
            compiler, "-O2", "-std=c11", "-Wall", "-Wextra", "-Wpedantic",
            "-Wconversion", "-Wshadow", "-Werror", "-Wcast-align",
            "-Wstrict-prototypes", "-Wmissing-prototypes", "-Wformat=2",
            "-Wundef", "-Wdouble-promotion", "-Wnull-dereference",
            "-I", str(ROOT),
            str(source), str(ROOT / "api.c"), "-lz", "-o", str(executable),
        ], check=True)
        subprocess.run([str(executable)], check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
