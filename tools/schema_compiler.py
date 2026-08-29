#!/usr/bin/env python3
"""Compile selected minecraft-data packet schemas into allocation-free C11 codecs.

The compiler deliberately fails on an unsupported schema node. Generated code
must never guess a field layout or silently expose an opaque remainder.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


PRIMITIVES = {
    "bool": ("bool", "bool"),
    "i8": ("int8_t", "i8"),
    "u8": ("uint8_t", "u8"),
    "i16": ("int16_t", "i16"),
    "u16": ("uint16_t", "u16"),
    "i32": ("int32_t", "i32"),
    "u32": ("uint32_t", "u32"),
    "i64": ("int64_t", "i64"),
    "u64": ("uint64_t", "u64"),
    "f32": ("float", "float"),
    "f64": ("double", "double"),
    "varint": ("int32_t", "varint"),
    "varlong": ("int64_t", "varlong"),
    "string": ("McBytes", "string"),
    "UUID": ("McUuid", "uuid"),
    "uuid": ("McUuid", "uuid"),
}

STATE_ORDER = ("handshaking", "status", "login", "configuration", "play")
DIRECTIONS = {"serverbound": "toServer", "clientbound": "toClient"}
STATE_CONSTANTS = {
    "login": "MC_STATE_LOGIN",
    "configuration": "MC_STATE_CONFIGURATION",
    "play": "MC_STATE_PLAY",
}
DIRECTION_CONSTANTS = {
    "serverbound": "MC_PACKET_SERVERBOUND",
    "clientbound": "MC_PACKET_CLIENTBOUND",
}


def c_name(value: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    value = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").lower()
    if not value or value[0].isdigit():
        value = "field_" + value
    return value


def title_name(value: str) -> str:
    return "".join(part.capitalize() for part in c_name(value).split("_"))


class Compiler:
    def __init__(self, document: dict[str, Any], protocol: int, overlay: dict[str, Any]):
        self.document = document
        self.protocol = protocol
        self.overlay = overlay

    def direction_types(self, state: str, direction: str) -> dict[str, Any]:
        return self.document[state][DIRECTIONS[direction]]["types"]

    def resolve(self, schema: Any, types: dict[str, Any]) -> Any:
        seen: set[str] = set()
        while isinstance(schema, str) and schema not in PRIMITIVES and schema != "position":
            if schema in seen:
                raise ValueError(f"recursive schema alias: {schema}")
            seen.add(schema)
            if schema in types:
                schema = types[schema]
            elif schema in self.document["types"]:
                schema = self.document["types"][schema]
            else:
                raise ValueError(f"unknown schema type: {schema}")
        return schema

    def packet_table(self, state: str, direction: str) -> tuple[dict[str, int], dict[str, Any]]:
        types = self.direction_types(state, direction)
        packet = self.resolve(types["packet"], types)
        if not isinstance(packet, list) or packet[0] != "container":
            raise ValueError(f"{state}/{direction}: packet root is not a container")
        fields = packet[1]
        mapper = next(field["type"] for field in fields if field["name"] == "name")
        switch = next(field["type"] for field in fields if field["name"] == "params")
        if mapper[0] != "mapper" or switch[0] != "switch":
            raise ValueError(f"{state}/{direction}: unexpected packet mapper shape")
        ids = {name: int(raw_id, 0) for raw_id, name in mapper[1]["mappings"].items()}
        schemas = dict(switch[1]["fields"])
        prefix = f"{state}:{direction}:"
        for selector, replacement in self.overlay.get("packet_renames", {}).items():
            if not selector.startswith(prefix):
                continue
            original = selector[len(prefix):]
            if original not in ids or original not in schemas or replacement in ids:
                raise ValueError(f"invalid packet rename: {selector} -> {replacement}")
            ids[replacement] = ids.pop(original)
            schemas[replacement] = schemas.pop(original)
        return ids, schemas

    def declaration(self, schema: Any, name: str, types: dict[str, Any], indent: str) -> list[str]:
        if schema == "position":
            return [f"{indent}McPosition {name};"]
        schema = self.resolve(schema, types)
        if isinstance(schema, str):
            if schema not in PRIMITIVES:
                raise ValueError(f"unsupported scalar type: {schema}")
            return [f"{indent}{PRIMITIVES[schema][0]} {name};"]
        if not isinstance(schema, list) or not schema:
            raise ValueError(f"invalid schema node for {name}: {schema!r}")
        if schema[0] != "container":
            raise ValueError(f"unsupported schema node {schema[0]} for {name}")
        lines = [f"{indent}struct {{"]
        for field in schema[1]:
            lines.extend(self.declaration(field["type"], c_name(field["name"]), types, indent + "    "))
        lines.append(f"{indent}}} {name};")
        return lines

    def codec(self, schema: Any, expression: str, types: dict[str, Any], encode: bool) -> list[str]:
        if schema == "position":
            if encode:
                return [f"    if (!mc_packet_position(packet, {self.protocol}, value->{expression})) return false;"]
            return [f"    if (!mc_reader_position(reader, {self.protocol}, &value->{expression})) return false;"]
        schema = self.resolve(schema, types)
        if isinstance(schema, str):
            if schema not in PRIMITIVES:
                raise ValueError(f"unsupported scalar type: {schema}")
            _, suffix = PRIMITIVES[schema]
            if encode:
                if suffix == "string":
                    return [f"    if (!mc_packet_string_n(packet, (const char *)value->{expression}.data, value->{expression}.size)) return false;"]
                if suffix == "uuid":
                    return [f"    if (!mc_packet_uuid(packet, &value->{expression})) return false;"]
                return [f"    if (!mc_packet_{suffix}(packet, value->{expression})) return false;"]
            return [f"    if (!mc_reader_{suffix}(reader, &value->{expression})) return false;"]
        if not isinstance(schema, list) or not schema or schema[0] != "container":
            kind = schema[0] if isinstance(schema, list) and schema else repr(schema)
            raise ValueError(f"unsupported schema node {kind} for {expression}")
        lines: list[str] = []
        for field in schema[1]:
            lines.extend(self.codec(field["type"], f"{expression}.{c_name(field['name'])}", types, encode))
        return lines

    def all_packet_constants(self) -> list[tuple[str, str, str, int]]:
        constants: list[tuple[str, str, str, int]] = []
        for state in STATE_ORDER:
            if state not in self.document:
                continue
            for direction in ("serverbound", "clientbound"):
                ids, _ = self.packet_table(state, direction)
                for packet_name, packet_id in sorted(ids.items(), key=lambda item: item[1]):
                    constants.append((state, direction, packet_name, packet_id))
        return constants

    def selected_packet(self, selector: str) -> tuple[str, str, str, int, Any, dict[str, Any]]:
        parts = selector.split(":")
        if len(parts) != 3 or parts[0] not in STATE_ORDER or parts[1] not in DIRECTIONS:
            raise ValueError(f"invalid packet selector: {selector}")
        state, direction, packet_name = parts
        ids, schemas = self.packet_table(state, direction)
        if packet_name not in ids or packet_name not in schemas:
            raise ValueError(f"packet not found: {selector}")
        types = self.direction_types(state, direction)
        schema = self.resolve(schemas[packet_name], types)
        if not isinstance(schema, list) or schema[0] != "container":
            raise ValueError(f"packet is not a container: {selector}")
        return state, direction, packet_name, ids[packet_name], schema, types


def generate(document: dict[str, Any], protocol: int, selectors: list[str], source_sha: str,
             overlay: dict[str, Any], overlay_sha: str | None) -> tuple[str, str, dict[str, Any]]:
    compiler = Compiler(document, protocol, overlay)
    guard = f"MC_PROTOCOL_GENERATED_{protocol}_H"
    header = [
        "/* Generated from minecraft-data; do not edit. */",
        f"#ifndef {guard}",
        f"#define {guard}",
        "",
        '#include "api.h"',
        "",
    ]
    constants = compiler.all_packet_constants()
    for state, direction, packet_name, packet_id in constants:
        constant = f"MC{protocol}_{state}_{direction}_{packet_name}".upper()
        header.append(f"#define {constant} {packet_id}")
    catalog_constants = [entry for entry in constants if entry[0] in STATE_CONSTANTS]
    header.extend([
        "",
        f"extern const McPacketInfo mc{protocol}_generated_packet_ids[];",
        f"extern const size_t mc{protocol}_generated_packet_id_count;",
        "",
    ])
    source = [
        "/* Generated from minecraft-data; do not edit. */",
        f'#include "mc_protocol_{protocol}.h"',
        "",
    ]
    source.append(f"const McPacketInfo mc{protocol}_generated_packet_ids[] = {{")
    for state, direction, packet_name, packet_id in catalog_constants:
        source.append(
            f'    {{{STATE_CONSTANTS[state]}, {DIRECTION_CONSTANTS[direction]}, '
            f'{packet_id}, "{packet_name}"}},')
    source.extend([
        "};",
        f"const size_t mc{protocol}_generated_packet_id_count =",
        f"    sizeof(mc{protocol}_generated_packet_ids) / sizeof(mc{protocol}_generated_packet_ids[0]);",
        "",
    ])
    manifest_packets: list[dict[str, Any]] = []
    for selector in selectors:
        state, direction, packet_name, packet_id, schema, types = compiler.selected_packet(selector)
        type_name = f"Mc{protocol}{title_name(state)}{title_name(direction)}{title_name(packet_name)}"
        function = f"mc{protocol}_{c_name(state)}_{c_name(direction)}_{c_name(packet_name)}"
        header.append(f"typedef struct {type_name} {{")
        for field in schema[1]:
            header.extend(compiler.declaration(field["type"], c_name(field["name"]), types, "    "))
        header.extend([
            f"}} {type_name};",
            "",
            f"bool {function}_encode(McPacket *packet, const {type_name} *value);",
            f"bool {function}_decode(McReader *reader, {type_name} *value);",
            "",
        ])
        source.extend([
            f"bool {function}_encode(McPacket *packet, const {type_name} *value)",
            "{",
            "    if (packet == NULL || value == NULL) return false;",
        ])
        for field in schema[1]:
            source.extend(compiler.codec(field["type"], c_name(field["name"]), types, True))
        source.extend(["    return !packet->failed;", "}", ""])
        source.extend([
            f"bool {function}_decode(McReader *reader, {type_name} *value)",
            "{",
            "    if (reader == NULL || value == NULL) return false;",
        ])
        for field in schema[1]:
            source.extend(compiler.codec(field["type"], c_name(field["name"]), types, False))
        source.extend(["    return mc_reader_remaining(reader) == 0U;", "}", ""])
        manifest_packets.append({"selector": selector, "packet_id": packet_id, "type": type_name})
    header.extend([f"#endif /* {guard} */", ""])
    manifest = {
        "generator_version": 1,
        "protocol": protocol,
        "source_sha256": source_sha,
        "overlay_sha256": overlay_sha,
        "packet_id_count": len(constants),
        "catalog_validation_count": len(catalog_constants),
        "generated_packets": manifest_packets,
    }
    return "\n".join(header), "\n".join(source), manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol-json", required=True, type=Path)
    parser.add_argument("--protocol-number", required=True, type=int)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--overlay", type=Path)
    parser.add_argument("--packet", action="append", default=[])
    args = parser.parse_args()
    raw = args.protocol_json.read_bytes()
    overlay_raw = args.overlay.read_bytes() if args.overlay is not None else None
    overlay = json.loads(overlay_raw) if overlay_raw is not None else {}
    header, source, manifest = generate(
        json.loads(raw),
        args.protocol_number,
        args.packet,
        hashlib.sha256(raw).hexdigest(),
        overlay,
        hashlib.sha256(overlay_raw).hexdigest() if overlay_raw is not None else None)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"mc_protocol_{args.protocol_number}"
    (args.out_dir / f"{stem}.h").write_text(header, encoding="utf-8")
    (args.out_dir / f"{stem}.c").write_text(source, encoding="utf-8")
    (args.out_dir / f"{stem}.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
