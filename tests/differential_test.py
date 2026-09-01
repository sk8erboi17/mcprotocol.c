#!/usr/bin/env python3
"""Compare Tier-A golden packets with node-minecraft-protocol.

The C side is exercised by test-golden before this script is invoked. This
script independently decodes and re-encodes the same packet bytes with the
Node oracle, then compares a normalized semantic projection.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

from golden_fixture import load_cases


ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "tier_a_golden.json"
NODE_MODULE = ROOT / "benchmark" / "node_modules" / "minecraft-protocol"

NODE_PROGRAM = r"""
const path = require('path')
const mc = require(path.resolve(process.env.MC_NODE_MODULE))
const cases = JSON.parse(process.env.MC_CASES_JSON)
const versions = {
  47: '1.8.8', 340: '1.12.2', 754: '1.16.5',
  763: '1.20', 768: '1.21.3', 776: '26.1'
}

function varint (value) {
  const bytes = []
  let remaining = value >>> 0
  do {
    let byte = remaining & 0x7f
    remaining >>>= 7
    if (remaining !== 0) byte |= 0x80
    bytes.push(byte)
  } while (remaining !== 0)
  return Buffer.from(bytes)
}

function project (entry, params) {
  switch (entry.expected.kind) {
    case 'movement':
      return {
        kind: 'movement', x: params.x ?? 0, y: params.y ?? 0,
        z: params.z ?? 0, yaw: params.yaw ?? 0, pitch: params.pitch ?? 0,
        on_ground: params.onGround ?? params.flags?.onGround
      }
    case 'player_input': {
      const inputs = params.inputs
      const flags = typeof inputs === 'number' ? inputs
        : (inputs.forward ? 1 : 0) | (inputs.backward ? 2 : 0)
          | (inputs.left ? 4 : 0) | (inputs.right ? 8 : 0)
          | (inputs.jump ? 16 : 0) | (inputs.shift ? 32 : 0)
          | (inputs.sprint ? 64 : 0)
      return { kind: 'player_input', flags, bitset: true }
    }
    case 'steer_vehicle':
      return {
        kind: 'steer_vehicle', sideways: params.sideways,
        forward: params.forward,
        flags: (params.jump ? 1 : 0) | (params.unmount ? 2 : 0)
      }
    case 'vehicle_move':
      return {
        kind: 'vehicle_move', x: params.x, y: params.y, z: params.z,
        yaw: params.yaw, pitch: params.pitch,
        on_ground: params.onGround ?? false
      }
    case 'arm_animation':
      return {
        kind: 'arm_animation', entity_id: params.entityId ?? 0,
        hand: params.hand ?? 0
      }
    case 'client_command': {
      const actions = { perform_respawn: 0, request_stats: 1,
        request_gamerule_values: 2 }
      const action = params.actionId ?? params.payload
      return { kind: 'client_command', action: typeof action === 'string'
        ? actions[action] : action }
    }
    case 'close_window':
      return { kind: 'close_window', window_id: params.windowId }
    case 'attack':
      return {
        kind: 'attack', entity_id: params.target ?? params.entityId,
        action: params.mouse ?? 1
      }
    case 'slot':
      return { kind: 'slot', slot: params.slotId }
    case 'teleport':
      return { kind: 'teleport', teleport_id: params.teleportId }
    case 'entity_action': {
      const actions = {
        start_sneaking: 0, stop_sneaking: 1, leave_bed: 2,
        start_sprinting: 3, stop_sprinting: 4, start_horse_jump: 5,
        stop_horse_jump: 6, open_horse_inventory: 7,
        start_fall_flying: 8
      }
      return {
        kind: 'entity_action', entity_id: params.entityId,
        action: typeof params.actionId === 'string'
          ? actions[params.actionId] : params.actionId,
        jump_boost: params.jumpBoost
      }
    }
    case 'abilities':
      return { kind: 'abilities', flags: params.flags }
    case 'block_dig': {
      const statuses = {
        started_digging: 0, cancelled_digging: 1, finished_digging: 2,
        drop_item_stack: 3, drop_item: 4, shoot_arrow_or_finish_eating: 5,
        swap_item_in_hand: 6
      }
      return {
        kind: 'block_dig',
        status: typeof params.status === 'string' ? statuses[params.status] : params.status,
        x: params.location.x, y: params.location.y, z: params.location.z,
        face: params.face, sequence: params.sequence ?? 0
      }
    }
    case 'block_place':
      return {
        kind: 'block_place', x: params.location.x, y: params.location.y,
        z: params.location.z, direction: params.direction,
        hand: params.hand ?? 0, sequence: params.sequence ?? 0
      }
    case 'use_item':
      return {
        kind: 'use_item', hand: params.hand, sequence: params.sequence ?? 0,
        yaw: params.rotation?.x ?? 0, pitch: params.rotation?.y ?? 0
      }
    case 'server_position':
      return {
        kind: 'server_position', x: params.x, y: params.y, z: params.z,
        teleport_id: params.teleportId ?? 0
      }
    case 'velocity':
      return {
        kind: 'velocity', entity_id: params.entityId,
        x: (params.velocity.x === 0 ? 0 : params.velocity.x),
        y: (params.velocity.y === 0 ? 0 : params.velocity.y),
        z: (params.velocity.z === 0 ? 0 : params.velocity.z)
      }
    case 'block_change':
      return {
        kind: 'block_change', x: params.location.x, y: params.location.y,
        z: params.location.z, state_id: params.type
      }
    case 'entity_move':
      return {
        kind: 'entity_move', entity_id: params.entityId,
        dx_raw: params.dX, dy_raw: params.dY, dz_raw: params.dZ,
        yaw_raw: params.yaw ?? 0, pitch_raw: params.pitch ?? 0,
        on_ground: params.onGround ?? false
      }
    case 'entity_teleport':
      return {
        kind: 'entity_teleport', entity_id: params.entityId,
        x: entry.protocol <= 47 ? params.x / 32 : params.x,
        y: entry.protocol <= 47 ? params.y / 32 : params.y,
        z: entry.protocol <= 47 ? params.z / 32 : params.z,
        yaw_raw: params.yaw, pitch_raw: params.pitch,
        on_ground: params.onGround ?? false
      }
    case 'head_rotation':
      return { kind: 'head_rotation', entity_id: params.entityId,
        yaw_raw: params.headYaw }
    case 'multi_block_change':
      return {
        kind: 'multi_block_change',
        chunk_x: params.chunkX ?? params.chunkCoordinates.x,
        chunk_z: params.chunkZ ?? params.chunkCoordinates.z,
        section_y: params.chunkCoordinates?.y ?? 0,
        record_count: params.records.length
      }
    case 'set_slot':
      return {
        kind: 'set_slot', window_id: params.windowId,
        state_id: params.stateId, slot: params.slot,
        item_id: params.item.itemId, count: params.item.itemCount,
        added: params.item.addedComponentCount
      }
    case 'set_slot_empty':
      return {
        kind: 'set_slot_empty', window_id: params.windowId,
        state_id: params.stateId ?? 0, slot: params.slot, present: false
      }
    case 'window_items':
      return {
        kind: 'window_items', window_id: params.windowId,
        state_id: params.stateId ?? 0, item_count: params.items.length
      }
    case 'window_click':
      return {
        kind: 'window_click', window_id: params.windowId,
        state_id: params.stateId ?? 0, slot: params.slot,
        action_number: params.action ?? 0,
        changed_slot_count: params.changedSlots?.length ?? 0,
        carried_present: false
      }
    case 'creative_slot':
      return { kind: 'creative_slot', slot: params.slot, present: false }
    default:
      throw new Error(`unknown projection ${entry.expected.kind}`)
  }
}

const results = []
for (const entry of cases) {
  const version = versions[entry.protocol]
  if (version === undefined) throw new Error(`no Node version for ${entry.protocol}`)
  const serverbound = entry.direction === 'serverbound'
  const packet = Buffer.concat([
    varint(entry.packet_id), Buffer.from(entry.raw_hex, 'hex')
  ])
  const deserializer = mc.createDeserializer({
    state: mc.states.PLAY,
    version,
    isServer: serverbound,
    noErrorLogging: true
  })
  const decoded = deserializer.parsePacketBuffer(packet).data
  if (decoded.name !== entry.packet_name) {
    throw new Error(`${entry.protocol}: expected ${entry.packet_name}, got ${decoded.name}`)
  }
  const serializer = mc.createSerializer({
    state: mc.states.PLAY, version, isServer: !serverbound
  })
  const encoded = serializer.createPacketBuffer(decoded)
  if (!encoded.equals(packet)) {
    throw new Error(`${entry.protocol}:${entry.packet_name} byte round-trip mismatch`)
  }
  results.push(project(entry, decoded.params))
}
process.stdout.write(JSON.stringify(results))
"""


def main() -> None:
    if not NODE_MODULE.is_dir():
        raise SystemExit(
            "minecraft-protocol is unavailable; run: npm ci --prefix benchmark"
        )
    cases = load_cases(FIXTURE)
    completed = subprocess.run(
        ["node", "-"],
        cwd=ROOT,
        input=NODE_PROGRAM,
        text=True,
        capture_output=True,
        env={
            **__import__("os").environ,
            "MC_NODE_MODULE": str(NODE_MODULE),
            "MC_CASES_JSON": json.dumps(cases, separators=(",", ":")),
        },
        check=False,
    )
    if completed.returncode != 0:
        sys.stderr.write(completed.stderr)
        raise SystemExit(completed.returncode)
    projections = json.loads(completed.stdout)
    expected = [entry["expected"] for entry in cases]
    if projections != expected:
        for index, (actual, wanted) in enumerate(zip(projections, expected)):
            if actual != wanted:
                raise AssertionError(
                    f"differential mismatch at case {index}: {actual!r} != {wanted!r}"
                )
        raise AssertionError("differential result count mismatch")
    print(
        f"PASS differential oracle ({len(expected)} packet fixtures, "
        "Node decode/encode and C golden projection)"
    )


if __name__ == "__main__":
    main()
