#include "api.h"

#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

static McCanonicalHeader header_for(int protocol,
    McPacketDirection direction, const char *name, const McPacket *body)
{
    const int32_t packet_id = mc_packet_id(protocol, MC_STATE_PLAY,
        direction, name);
    assert(packet_id >= 0);
    McCanonicalHeader header;
    McError error;
    assert(mc_canonical_header_init(&header, protocol, MC_STATE_PLAY,
        direction, packet_id, body->data, body->length, &error));
    assert(error.code == MC_ERROR_NONE);
    assert(header.raw_payload.data == body->data);
    assert(header.raw_payload.size == body->length);
    return header;
}

static void test_cross_version_movement(void)
{
    static const int protocols[] = {47, 340, 754, 763, 768, 776};
    McCanonicalMovement reference = {0};
    for (size_t index = 0U;
            index < sizeof(protocols) / sizeof(protocols[0]); ++index) {
        unsigned char storage[256];
        McPacket body;
        mc_packet_init(&body, storage, sizeof(storage));
        const McPlayerPosition input = {
            .x = 12.25,
            .y = 64.5,
            .z = -7.75,
            .yaw = 91.0F,
            .pitch = -22.5F,
            .on_ground = true,
        };
        assert(mc_packet_player_position(&body, protocols[index], &input));
        const McCanonicalHeader header = header_for(protocols[index],
            MC_PACKET_SERVERBOUND, "position_look", &body);
        McCanonicalMovement movement;
        McError error;
        assert(mc_decode_canonical_movement(&header, &movement,
            MC_DECODE_STRICT, &error));
        assert(error.code == MC_ERROR_NONE);
        assert(movement.protocol == protocols[index]);
        assert(movement.packet_id == header.packet_id);
        assert(movement.family == MC_FAMILY_PLAYER_MOVEMENT);
        assert(movement.x == input.x && movement.y == input.y
            && movement.z == input.z);
        assert(movement.yaw == input.yaw && movement.pitch == input.pitch);
        assert(movement.on_ground);
        assert((movement.presence & (MC_MOVE_HAS_POSITION
            | MC_MOVE_HAS_ROTATION | MC_MOVE_HAS_ON_GROUND))
            == (MC_MOVE_HAS_POSITION | MC_MOVE_HAS_ROTATION
                | MC_MOVE_HAS_ON_GROUND));
        if (index == 0U) reference = movement;
        else {
            assert(movement.x == reference.x);
            assert(movement.y == reference.y);
            assert(movement.z == reference.z);
            assert(movement.yaw == reference.yaw);
            assert(movement.pitch == reference.pitch);
        }
    }
}

static void test_lossless_legacy_stance(void)
{
    unsigned char storage[128];
    McPacket body;
    mc_packet_init(&body, storage, sizeof(storage));
    const McPlayerPosition input = {
        .x = 1.0, .y = 70.0, .z = -2.0,
        .yaw = 10.0F, .pitch = 5.0F, .on_ground = false,
    };
    assert(mc_packet_player_position(&body, 5, &input));
    const McCanonicalHeader header = header_for(5, MC_PACKET_SERVERBOUND,
        "position_look", &body);
    McCanonicalMovement movement;
    McError error;
    assert(mc_decode_canonical_movement(&header, &movement,
        MC_DECODE_STRICT, &error));
    assert(movement.wire_y_is_stance);
    assert((movement.presence & MC_MOVE_HAS_STANCE_Y) != 0U);
    assert(fabs(movement.wire_y - (input.y + 1.6200000047683716)) < 0.000001);
}

static void test_canonical_action(void)
{
    static const int protocols[] = {5, 47, 340, 754, 763, 768, 776};
    for (size_t index = 0U;
            index < sizeof(protocols) / sizeof(protocols[0]); ++index) {
        unsigned char storage[64];
        McPacket body;
        mc_packet_init(&body, storage, sizeof(storage));
        const McEntityAction action = {
            .entity_id = 9,
            .action = MC_ENTITY_ACTION_START_SPRINTING,
        };
        assert(mc_packet_entity_action(&body, protocols[index], &action));
        const McCanonicalHeader header = header_for(protocols[index],
            MC_PACKET_SERVERBOUND, "entity_action", &body);
        McCanonicalAction decoded;
        McError error;
        assert(mc_decode_canonical_action(&header, &decoded,
            MC_DECODE_STRICT, &error));
        assert(decoded.entity_id == 9);
        assert(decoded.action == (int32_t)MC_ENTITY_ACTION_START_SPRINTING);
        assert((decoded.presence & (MC_ACTION_HAS_ENTITY
            | MC_ACTION_HAS_ACTION))
            == (MC_ACTION_HAS_ENTITY | MC_ACTION_HAS_ACTION));
    }
}

static void test_canonical_inventory(void)
{
    unsigned char storage[128];
    McPacket body;
    mc_packet_init(&body, storage, sizeof(storage));
    assert(mc_packet_set_creative_slot(&body, 776, 36, 5, 3));
    const McCanonicalHeader header = header_for(776, MC_PACKET_SERVERBOUND,
        "set_creative_slot", &body);
    McCanonicalInventory inventory;
    McError error;
    assert(mc_decode_canonical_inventory(&header, &inventory,
        MC_DECODE_STRICT, &error));
    assert(inventory.slot == 36);
    assert(inventory.item.present);
    assert(inventory.item.item_id == 5);
    assert(inventory.item.count == 3);
    assert(inventory.item.encoded.data >= header.raw_payload.data);
}

static void encode_block_change(McPacket *body, int protocol)
{
    if (protocol <= 5) {
        assert(mc_packet_i32(body, 4));
        assert(mc_packet_u8(body, 64U));
        assert(mc_packet_i32(body, -2));
        assert(mc_packet_varint(body, 5));
        assert(mc_packet_u8(body, 3U));
    } else {
        assert(mc_packet_position(body, protocol,
            (McPosition){.x = 4, .y = 64, .z = -2}));
        assert(mc_packet_varint(body, 83));
    }
}

static void test_canonical_block_change(void)
{
    static const int protocols[] = {5, 47, 340, 754, 763, 768, 776};
    for (size_t index = 0U;
            index < sizeof(protocols) / sizeof(protocols[0]); ++index) {
        unsigned char storage[128];
        McPacket body;
        mc_packet_init(&body, storage, sizeof(storage));
        encode_block_change(&body, protocols[index]);
        const McCanonicalHeader header = header_for(protocols[index],
            MC_PACKET_CLIENTBOUND, "block_change", &body);
        McCanonicalBlockChange block;
        McError error;
        assert(mc_decode_canonical_block_change(&header, &block,
            MC_DECODE_STRICT, &error));
        assert(block.position.x == 4 && block.position.y == 64
            && block.position.z == -2);
        assert(block.state_id == 83);
        assert(block.record_count == 1U);
    }
}

static void test_wrong_projection_rejected(void)
{
    unsigned char storage[32];
    McPacket body;
    mc_packet_init(&body, storage, sizeof(storage));
    assert(mc_packet_held_item_slot(&body, 776, 2));
    const McCanonicalHeader header = header_for(776, MC_PACKET_SERVERBOUND,
        "held_item_slot", &body);
    McCanonicalMovement movement;
    McError error;
    memset(&movement, 0xa5, sizeof(movement));
    const McCanonicalMovement before = movement;
    assert(!mc_decode_canonical_movement(&header, &movement,
        MC_DECODE_STRICT, &error));
    assert(error.code == MC_ERROR_INVALID_PACKET_BODY);
    assert(memcmp(&movement, &before, sizeof(movement)) == 0);
}

static void test_header_errors(void)
{
    McCanonicalHeader header;
    McError error;
    assert(!mc_canonical_header_init(&header, 9999, MC_STATE_PLAY,
        MC_PACKET_SERVERBOUND, 0, NULL, 0U, &error));
    assert(error.code == MC_ERROR_UNSUPPORTED_PROTOCOL);
    assert(!mc_canonical_header_init(&header, 776, MC_STATE_UNKNOWN,
        MC_PACKET_SERVERBOUND, 0, NULL, 0U, &error));
    assert(error.code == MC_ERROR_INVALID_STATE);
    assert(!mc_canonical_header_init(&header, 776, MC_STATE_PLAY,
        MC_PACKET_DIRECTION_UNKNOWN, 0, NULL, 0U, &error));
    assert(error.code == MC_ERROR_INVALID_DIRECTION);
}

static void test_catalog_only_raw_header(void)
{
    const int protocol = 776;
    const size_t count = mc_packet_count(protocol);
    McPacketInfo catalog_only = {0};
    bool found = false;
    for (size_t index = 0U; index < count; ++index) {
        McPacketInfo candidate;
        assert(mc_packet_at(protocol, index, &candidate));
        if (mc_packet_family(protocol, candidate.state, candidate.direction,
                candidate.id) == MC_FAMILY_UNKNOWN) {
            catalog_only = candidate;
            found = true;
            break;
        }
    }
    assert(found);
    const unsigned char payload[] = {0xaaU, 0x55U};
    McCanonicalHeader header;
    McError error;
    assert(mc_canonical_header_init(&header, protocol, catalog_only.state,
        catalog_only.direction, catalog_only.id, payload, sizeof(payload),
        &error));
    assert(error.code == MC_ERROR_NONE);
    assert(header.family == MC_FAMILY_UNKNOWN);
    assert(header.raw_payload.data == payload);
    assert(header.raw_payload.size == sizeof(payload));

    McCanonicalMovement movement;
    assert(!mc_decode_canonical_movement(&header, &movement,
        MC_DECODE_STRICT, &error));
    assert(error.code == MC_ERROR_UNKNOWN_PACKET);
}

int main(void)
{
    test_cross_version_movement();
    test_lossless_legacy_stance();
    test_canonical_action();
    test_canonical_inventory();
    test_canonical_block_change();
    test_wrong_projection_rejected();
    test_header_errors();
    test_catalog_only_raw_header();
    puts("PASS lossless canonical packet projections");
    return 0;
}
