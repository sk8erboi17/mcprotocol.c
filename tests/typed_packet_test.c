#include "api.h"

#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

typedef union {
    McPlayerMovementPacket movement;
    McPlayerInputPacket input;
    McEntityAction action;
    McPlayerAbilities abilities;
    McVehicleMovePacket vehicle;
    McUseEntityPacket use_entity;
    McArmAnimationPacket arm;
    McBlockDig dig;
    McBlockPlace place;
    McUseItem use_item;
    McHeldItemSlotPacket held;
    McTeleportConfirmPacket teleport;
    McClientCommandPacket command;
    McCloseWindowPacket close_window;
    McClientboundPlayerPosition server_position;
    McEntityVelocityPacket velocity;
    McEntityMovePacket move;
    McEntityTeleportPacket entity_teleport;
    McEntityHeadRotationPacket head;
    McBlockChangePacket block;
    McWindowClickPacket window_click;
    McSetCreativeSlotPacket creative_slot;
    McSetSlotPacket set_slot;
    McWindowItemsPacket window_items;
    McMultiBlockChangePacket multi_block;
} TestDecoded;

static int32_t packet_id(int protocol, McPacketDirection direction,
    const char *name)
{
    return mc_packet_id(protocol, MC_STATE_PLAY, direction, name);
}

static McPacketFamily decode(int protocol, McPacketDirection direction,
    const char *name, const unsigned char *payload, size_t payload_size,
    TestDecoded *decoded)
{
    const int32_t id = packet_id(protocol, direction, name);
    assert(id >= 0);
    McPacketFamily family = MC_FAMILY_UNKNOWN;
    McError error;
    memset(decoded, 0, sizeof(*decoded));
    assert(mc_decode_packet(protocol, MC_STATE_PLAY, direction, id,
        payload, payload_size, MC_DECODE_STRICT, decoded, sizeof(*decoded),
        &family, &error) == 0);
    assert(error.code == MC_ERROR_NONE);
    return family;
}

static void assert_exact_rejections(int protocol,
    McPacketDirection direction, const char *name,
    const unsigned char *payload, size_t payload_size)
{
    const int32_t id = packet_id(protocol, direction, name);
    assert(id >= 0);
    for (size_t prefix = 0U; prefix < payload_size; ++prefix) {
        TestDecoded decoded;
        TestDecoded before;
        memset(&decoded, 0xa5, sizeof(decoded));
        before = decoded;
        McPacketFamily family = MC_FAMILY_UNKNOWN;
        McError error;
        assert(mc_decode_packet(protocol, MC_STATE_PLAY, direction, id,
            payload, prefix, MC_DECODE_STRICT, &decoded, sizeof(decoded),
            &family, &error) != 0);
        assert(error.code != MC_ERROR_NONE);
        assert(memcmp(&decoded, &before, sizeof(decoded)) == 0);
    }
    static const unsigned char suffixes[] = {0U, UINT8_MAX, 0x5aU};
    for (size_t suffix = 0U;
            suffix < sizeof(suffixes) / sizeof(suffixes[0]); ++suffix) {
        unsigned char with_trailing[1024];
        assert(payload_size + 1U <= sizeof(with_trailing));
        memcpy(with_trailing, payload, payload_size);
        with_trailing[payload_size] = suffixes[suffix];
        TestDecoded decoded;
        McPacketFamily family = MC_FAMILY_UNKNOWN;
        McError error;
        assert(mc_decode_packet(protocol, MC_STATE_PLAY, direction, id,
            with_trailing, payload_size + 1U, MC_DECODE_STRICT,
            &decoded, sizeof(decoded), &family, &error) != 0);
        assert(error.code == MC_ERROR_TRAILING_BYTES
            || error.code == MC_ERROR_INVALID_PACKET_BODY);
    }
}

static void test_family_catalog(void)
{
    size_t protocol_count = 0U;
    const int *protocols = mc_supported_protocols(&protocol_count);
    assert(protocol_count == 51U);
    for (size_t protocol_index = 0U; protocol_index < protocol_count;
            ++protocol_index) {
        const int protocol = protocols[protocol_index];
        const size_t count = mc_packet_count(protocol);
        assert(count != 0U);
        for (size_t index = 0U; index < count; ++index) {
            McPacketInfo info;
            assert(mc_packet_at(protocol, index, &info));
            const McPacketFamily first = mc_packet_family(protocol,
                info.state, info.direction, info.id);
            const McPacketFamily second = mc_packet_family(protocol,
                info.state, info.direction, info.id);
            assert(first == second);
            assert(mc_packet_family_name(first) != NULL);
        }
        assert(mc_packet_family(protocol, MC_STATE_PLAY,
            MC_PACKET_SERVERBOUND, INT32_MAX) == MC_FAMILY_UNKNOWN);
        const int32_t bulk = packet_id(protocol, MC_PACKET_CLIENTBOUND,
            "map_chunk_bulk");
        if (bulk >= 0) {
            assert(mc_packet_family(protocol, MC_STATE_PLAY,
                MC_PACKET_CLIENTBOUND, bulk) == MC_FAMILY_UNKNOWN);
        }
    }
}

static void test_serverbound_tier_a(void)
{
    size_t protocol_count = 0U;
    const int *protocols = mc_supported_protocols(&protocol_count);
    for (size_t index = 0U; index < protocol_count; ++index) {
        const int protocol = protocols[index];
        unsigned char storage[512];
        McPacket body;
        TestDecoded decoded;

        mc_packet_init(&body, storage, sizeof(storage));
        const McPlayerPosition movement = {
            .x = 12.25,
            .y = 64.5,
            .z = -7.75,
            .yaw = 91.0F,
            .pitch = -22.5F,
            .on_ground = true,
        };
        assert(mc_packet_player_position(&body, protocol, &movement));
        assert(decode(protocol, MC_PACKET_SERVERBOUND, "position_look",
            body.data, body.length, &decoded) == MC_FAMILY_PLAYER_MOVEMENT);
        assert(decoded.movement.x == movement.x);
        assert(decoded.movement.y == movement.y);
        assert(decoded.movement.z == movement.z);
        assert(decoded.movement.yaw == movement.yaw);
        assert(decoded.movement.pitch == movement.pitch);
        assert(decoded.movement.on_ground);
        assert((decoded.movement.presence & (MC_MOVE_HAS_POSITION
            | MC_MOVE_HAS_ROTATION | MC_MOVE_HAS_ON_GROUND))
            == (MC_MOVE_HAS_POSITION | MC_MOVE_HAS_ROTATION
                | MC_MOVE_HAS_ON_GROUND));
        assert_exact_rejections(protocol, MC_PACKET_SERVERBOUND,
            "position_look", body.data, body.length);

        mc_packet_init(&body, storage, sizeof(storage));
        if (protocol >= 768) assert(mc_packet_u8(&body, 1U));
        else assert(mc_packet_bool(&body, true));
        assert(decode(protocol, MC_PACKET_SERVERBOUND, "flying",
            body.data, body.length, &decoded) == MC_FAMILY_PLAYER_MOVEMENT);
        assert(decoded.movement.on_ground);
        assert(decoded.movement.presence == MC_MOVE_HAS_ON_GROUND
            || decoded.movement.presence == (MC_MOVE_HAS_ON_GROUND
                | MC_MOVE_HAS_HORIZONTAL_COLLISION));
        assert_exact_rejections(protocol, MC_PACKET_SERVERBOUND,
            "flying", body.data, body.length);

        mc_packet_init(&body, storage, sizeof(storage));
        assert(mc_packet_double(&body, 12.25));
        assert(mc_packet_double(&body, 64.5));
        if (protocol <= 5) assert(mc_packet_double(&body, 66.12));
        assert(mc_packet_double(&body, -7.75));
        if (protocol >= 768) assert(mc_packet_u8(&body, 1U));
        else assert(mc_packet_bool(&body, true));
        assert(decode(protocol, MC_PACKET_SERVERBOUND, "position",
            body.data, body.length, &decoded) == MC_FAMILY_PLAYER_MOVEMENT);
        assert(decoded.movement.x == 12.25);
        assert((decoded.movement.presence & MC_MOVE_HAS_POSITION) != 0U);
        assert_exact_rejections(protocol, MC_PACKET_SERVERBOUND,
            "position", body.data, body.length);

        mc_packet_init(&body, storage, sizeof(storage));
        assert(mc_packet_float(&body, 91.0F));
        assert(mc_packet_float(&body, -22.5F));
        if (protocol >= 768) assert(mc_packet_u8(&body, 1U));
        else assert(mc_packet_bool(&body, true));
        assert(decode(protocol, MC_PACKET_SERVERBOUND, "look",
            body.data, body.length, &decoded) == MC_FAMILY_PLAYER_MOVEMENT);
        assert(decoded.movement.yaw == 91.0F);
        assert((decoded.movement.presence & MC_MOVE_HAS_ROTATION) != 0U);
        assert_exact_rejections(protocol, MC_PACKET_SERVERBOUND,
            "look", body.data, body.length);

        mc_packet_init(&body, storage, sizeof(storage));
        const McEntityAction action = {
            .entity_id = 7,
            .action = MC_ENTITY_ACTION_START_SPRINTING,
            .jump_boost = 0,
        };
        assert(mc_packet_entity_action(&body, protocol, &action));
        assert(decode(protocol, MC_PACKET_SERVERBOUND, "entity_action",
            body.data, body.length, &decoded) == MC_FAMILY_ENTITY_ACTION);
        assert(decoded.action.entity_id == action.entity_id);
        assert(decoded.action.action == action.action);
        assert_exact_rejections(protocol, MC_PACKET_SERVERBOUND,
            "entity_action", body.data, body.length);

        mc_packet_init(&body, storage, sizeof(storage));
        const McPlayerAbilities abilities = {
            .flags = 2U,
            .flying_speed = 0.05F,
            .walking_speed = 0.1F,
        };
        assert(mc_packet_player_abilities(&body, protocol, &abilities));
        assert(decode(protocol, MC_PACKET_SERVERBOUND, "abilities",
            body.data, body.length, &decoded) == MC_FAMILY_ABILITIES);
        assert(decoded.abilities.flags == abilities.flags);
        assert_exact_rejections(protocol, MC_PACKET_SERVERBOUND,
            "abilities", body.data, body.length);

        mc_packet_init(&body, storage, sizeof(storage));
        assert(mc_packet_attack_entity(&body, protocol, 17));
        const char *attack_name = protocol >= 775 ? "attack" : "use_entity";
        const McPacketFamily attack_family = protocol >= 775
            ? MC_FAMILY_ATTACK : MC_FAMILY_USE_ENTITY;
        assert(decode(protocol, MC_PACKET_SERVERBOUND, attack_name,
            body.data, body.length, &decoded) == attack_family);
        assert(decoded.use_entity.entity_id == 17);
        assert(decoded.use_entity.action == 1);
        assert_exact_rejections(protocol, MC_PACKET_SERVERBOUND,
            attack_name, body.data, body.length);

        mc_packet_init(&body, storage, sizeof(storage));
        const McBlockDig dig = {
            .status = 0,
            .location = {.x = -12, .y = 64, .z = 33},
            .face = 1,
            .sequence = 9,
        };
        assert(mc_packet_block_dig(&body, protocol, &dig));
        assert(decode(protocol, MC_PACKET_SERVERBOUND, "block_dig",
            body.data, body.length, &decoded) == MC_FAMILY_BLOCK_DIG);
        assert(decoded.dig.status == dig.status);
        assert(decoded.dig.location.x == dig.location.x);
        assert(decoded.dig.location.y == dig.location.y);
        assert(decoded.dig.location.z == dig.location.z);
        assert_exact_rejections(protocol, MC_PACKET_SERVERBOUND,
            "block_dig", body.data, body.length);

        mc_packet_init(&body, storage, sizeof(storage));
        const McBlockPlace place = {
            .location = {.x = 1, .y = 65, .z = -2},
            .direction = 1,
            .hand = 0,
            .cursor_x = 0.5F,
            .cursor_y = 0.5F,
            .cursor_z = 0.5F,
            .inside_block = false,
            .world_border_hit = false,
            .sequence = 11,
        };
        assert(mc_packet_block_place(&body, protocol, &place));
        assert(decode(protocol, MC_PACKET_SERVERBOUND, "block_place",
            body.data, body.length, &decoded) == MC_FAMILY_BLOCK_PLACE);
        assert(decoded.place.location.x == place.location.x);
        assert(decoded.place.location.y == place.location.y);
        assert(decoded.place.location.z == place.location.z);
        assert(decoded.place.direction == place.direction);
        assert_exact_rejections(protocol, MC_PACKET_SERVERBOUND,
            "block_place", body.data, body.length);

        mc_packet_init(&body, storage, sizeof(storage));
        const McUseItem use_item = {
            .hand = 0,
            .sequence = 5,
            .yaw = 12.0F,
            .pitch = -4.0F,
        };
        assert(mc_packet_use_item(&body, protocol, &use_item));
        const char *use_name = protocol <= 47 ? "block_place" : "use_item";
        const McPacketFamily use_family = protocol <= 47
            ? MC_FAMILY_BLOCK_PLACE : MC_FAMILY_USE_ITEM;
        assert(decode(protocol, MC_PACKET_SERVERBOUND, use_name,
            body.data, body.length, &decoded) == use_family);
        if (protocol <= 47) {
            assert(decoded.place.direction == -1);
        } else {
            assert(decoded.use_item.hand == use_item.hand);
        }
        assert_exact_rejections(protocol, MC_PACKET_SERVERBOUND,
            use_name, body.data, body.length);

        mc_packet_init(&body, storage, sizeof(storage));
        assert(mc_packet_held_item_slot(&body, protocol, 4));
        assert(decode(protocol, MC_PACKET_SERVERBOUND, "held_item_slot",
            body.data, body.length, &decoded) == MC_FAMILY_HELD_ITEM_SLOT);
        assert(decoded.held.slot == 4);
        assert_exact_rejections(protocol, MC_PACKET_SERVERBOUND,
            "held_item_slot", body.data, body.length);

        if (packet_id(protocol, MC_PACKET_SERVERBOUND, "steer_vehicle") >= 0) {
            mc_packet_init(&body, storage, sizeof(storage));
            assert(mc_packet_float(&body, 0.25F));
            assert(mc_packet_float(&body, -0.5F));
            if (protocol <= 5) {
                assert(mc_packet_bool(&body, true));
                assert(mc_packet_bool(&body, false));
            } else {
                assert(mc_packet_u8(&body, 1U));
            }
            assert(decode(protocol, MC_PACKET_SERVERBOUND, "steer_vehicle",
                body.data, body.length, &decoded) == MC_FAMILY_STEER_VEHICLE);
            assert(decoded.input.sideways == 0.25F);
            assert(decoded.input.forward == -0.5F);
            assert(decoded.input.flags == 1U);
            assert_exact_rejections(protocol, MC_PACKET_SERVERBOUND,
                "steer_vehicle", body.data, body.length);
        }

        if (packet_id(protocol, MC_PACKET_SERVERBOUND, "player_input") >= 0) {
            mc_packet_init(&body, storage, sizeof(storage));
            assert(mc_packet_player_input(&body, protocol,
                MC_PLAYER_INPUT_FORWARD | MC_PLAYER_INPUT_JUMP));
            assert(decode(protocol, MC_PACKET_SERVERBOUND, "player_input",
                body.data, body.length, &decoded) == MC_FAMILY_PLAYER_INPUT);
            assert(decoded.input.bitset);
            assert(decoded.input.flags
                == (MC_PLAYER_INPUT_FORWARD | MC_PLAYER_INPUT_JUMP));
            assert_exact_rejections(protocol, MC_PACKET_SERVERBOUND,
                "player_input", body.data, body.length);
        }

        if (packet_id(protocol, MC_PACKET_SERVERBOUND, "vehicle_move") >= 0) {
            mc_packet_init(&body, storage, sizeof(storage));
            assert(mc_packet_double(&body, 4.0));
            assert(mc_packet_double(&body, 65.0));
            assert(mc_packet_double(&body, -8.0));
            assert(mc_packet_float(&body, 30.0F));
            assert(mc_packet_float(&body, 5.0F));
            if (protocol >= 770) assert(mc_packet_bool(&body, true));
            assert(decode(protocol, MC_PACKET_SERVERBOUND, "vehicle_move",
                body.data, body.length, &decoded) == MC_FAMILY_VEHICLE_MOVE);
            assert(decoded.vehicle.x == 4.0);
            assert(decoded.vehicle.pitch == 5.0F);
            assert_exact_rejections(protocol, MC_PACKET_SERVERBOUND,
                "vehicle_move", body.data, body.length);
        }

        mc_packet_init(&body, storage, sizeof(storage));
        assert(mc_packet_arm_animation(&body, protocol, 7, 0));
        assert(decode(protocol, MC_PACKET_SERVERBOUND, "arm_animation",
            body.data, body.length, &decoded) == MC_FAMILY_ARM_ANIMATION);
        assert_exact_rejections(protocol, MC_PACKET_SERVERBOUND,
            "arm_animation", body.data, body.length);

        if (packet_id(protocol, MC_PACKET_SERVERBOUND, "teleport_confirm") >= 0) {
            mc_packet_init(&body, storage, sizeof(storage));
            assert(mc_packet_varint(&body, 44));
            assert(decode(protocol, MC_PACKET_SERVERBOUND, "teleport_confirm",
                body.data, body.length, &decoded) == MC_FAMILY_TELEPORT_CONFIRM);
            assert(decoded.teleport.teleport_id == 44);
            assert_exact_rejections(protocol, MC_PACKET_SERVERBOUND,
                "teleport_confirm", body.data, body.length);
        }

        mc_packet_init(&body, storage, sizeof(storage));
        assert(mc_packet_respawn_request(&body, protocol));
        assert(decode(protocol, MC_PACKET_SERVERBOUND, "client_command",
            body.data, body.length, &decoded) == MC_FAMILY_CLIENT_COMMAND);
        assert(decoded.command.action == 0);
        assert_exact_rejections(protocol, MC_PACKET_SERVERBOUND,
            "client_command", body.data, body.length);

        mc_packet_init(&body, storage, sizeof(storage));
        assert(mc_packet_close_window(&body, protocol, 2));
        assert(decode(protocol, MC_PACKET_SERVERBOUND, "close_window",
            body.data, body.length, &decoded) == MC_FAMILY_CLOSE_WINDOW);
        assert(decoded.close_window.window_id == 2);
        assert_exact_rejections(protocol, MC_PACKET_SERVERBOUND,
            "close_window", body.data, body.length);
    }
}

static void encode_server_position(McPacket *body, int protocol)
{
    if (protocol >= 768) {
        assert(mc_packet_varint(body, 42));
        assert(mc_packet_double(body, 10.0));
        assert(mc_packet_double(body, 65.0));
        assert(mc_packet_double(body, -3.0));
        assert(mc_packet_double(body, 0.25));
        assert(mc_packet_double(body, -0.5));
        assert(mc_packet_double(body, 0.75));
        assert(mc_packet_float(body, 45.0F));
        assert(mc_packet_float(body, -10.0F));
        assert(mc_packet_i32(body, 0x101));
        return;
    }
    assert(mc_packet_double(body, 10.0));
    assert(mc_packet_double(body, protocol <= 5 ? 66.62 : 65.0));
    assert(mc_packet_double(body, -3.0));
    assert(mc_packet_float(body, 45.0F));
    assert(mc_packet_float(body, -10.0F));
    assert(mc_packet_u8(body, 1U));
    if (protocol >= 107) assert(mc_packet_varint(body, 42));
    if (protocol >= 755 && protocol <= 762) assert(mc_packet_bool(body, false));
}

static void encode_entity_move(McPacket *body, int protocol, bool rotation)
{
    if (protocol <= 5) assert(mc_packet_i32(body, 9));
    else assert(mc_packet_varint(body, 9));
    if (protocol <= 47) {
        assert(mc_packet_i8(body, 3));
        assert(mc_packet_i8(body, -2));
        assert(mc_packet_i8(body, 1));
    } else {
        assert(mc_packet_i16(body, 300));
        assert(mc_packet_i16(body, -200));
        assert(mc_packet_i16(body, 100));
    }
    if (rotation) {
        assert(mc_packet_u8(body, 64U));
        assert(mc_packet_u8(body, 32U));
    }
    if (protocol > 5) assert(mc_packet_bool(body, true));
}

static void encode_entity_teleport(McPacket *body, int protocol)
{
    if (protocol <= 5) assert(mc_packet_i32(body, 9));
    else assert(mc_packet_varint(body, 9));
    if (protocol <= 47) {
        assert(mc_packet_i32(body, 320));
        assert(mc_packet_i32(body, 2080));
        assert(mc_packet_i32(body, -96));
    } else {
        assert(mc_packet_double(body, 10.0));
        assert(mc_packet_double(body, 65.0));
        assert(mc_packet_double(body, -3.0));
    }
    assert(mc_packet_u8(body, 64U));
    assert(mc_packet_u8(body, 32U));
    if (protocol > 5) assert(mc_packet_bool(body, true));
}

static void test_clientbound_tier_a(void)
{
    size_t protocol_count = 0U;
    const int *protocols = mc_supported_protocols(&protocol_count);
    for (size_t index = 0U; index < protocol_count; ++index) {
        const int protocol = protocols[index];
        unsigned char storage[512];
        McPacket body;
        TestDecoded decoded;

        mc_packet_init(&body, storage, sizeof(storage));
        encode_server_position(&body, protocol);
        assert(decode(protocol, MC_PACKET_CLIENTBOUND, "position",
            body.data, body.length, &decoded) == MC_FAMILY_SERVER_POSITION);
        assert(fabs(decoded.server_position.position.x - 10.0) < 0.0001);
        assert(fabs(decoded.server_position.position.y - 65.0) < 0.0001);
        assert_exact_rejections(protocol, MC_PACKET_CLIENTBOUND,
            "position", body.data, body.length);

        mc_packet_init(&body, storage, sizeof(storage));
        if (protocol <= 5) assert(mc_packet_i32(&body, 9));
        else assert(mc_packet_varint(&body, 9));
        if (protocol >= 773) {
            assert(mc_packet_u8(&body, 0U));
        } else {
            assert(mc_packet_i16(&body, 800));
            assert(mc_packet_i16(&body, -400));
            assert(mc_packet_i16(&body, 200));
        }
        assert(decode(protocol, MC_PACKET_CLIENTBOUND, "entity_velocity",
            body.data, body.length, &decoded) == MC_FAMILY_ENTITY_VELOCITY);
        assert(decoded.velocity.entity_id == 9);
        assert(decoded.velocity.velocity_x == (protocol >= 773 ? 0.0 : 0.1));
        assert(decoded.velocity.low_precision_encoding == (protocol >= 773));
        assert_exact_rejections(protocol, MC_PACKET_CLIENTBOUND,
            "entity_velocity", body.data, body.length);

        mc_packet_init(&body, storage, sizeof(storage));
        encode_entity_move(&body, protocol, false);
        assert(decode(protocol, MC_PACKET_CLIENTBOUND, "rel_entity_move",
            body.data, body.length, &decoded) == MC_FAMILY_RELATIVE_ENTITY_MOVE);
        assert(decoded.move.entity_id == 9);
        assert_exact_rejections(protocol, MC_PACKET_CLIENTBOUND,
            "rel_entity_move", body.data, body.length);

        mc_packet_init(&body, storage, sizeof(storage));
        encode_entity_move(&body, protocol, true);
        assert(decode(protocol, MC_PACKET_CLIENTBOUND, "entity_move_look",
            body.data, body.length, &decoded) == MC_FAMILY_ENTITY_MOVE_LOOK);
        assert((decoded.move.presence & MC_MOVE_HAS_ROTATION) != 0U);
        assert_exact_rejections(protocol, MC_PACKET_CLIENTBOUND,
            "entity_move_look", body.data, body.length);

        mc_packet_init(&body, storage, sizeof(storage));
        encode_entity_teleport(&body, protocol);
        assert(decode(protocol, MC_PACKET_CLIENTBOUND, "entity_teleport",
            body.data, body.length, &decoded) == MC_FAMILY_ENTITY_TELEPORT);
        assert(fabs(decoded.entity_teleport.x - 10.0) < 0.0001);
        assert_exact_rejections(protocol, MC_PACKET_CLIENTBOUND,
            "entity_teleport", body.data, body.length);

        if (packet_id(protocol, MC_PACKET_CLIENTBOUND,
                "sync_entity_position") >= 0) {
            mc_packet_init(&body, storage, sizeof(storage));
            assert(mc_packet_varint(&body, 9));
            assert(mc_packet_double(&body, 10.0));
            assert(mc_packet_double(&body, 65.0));
            assert(mc_packet_double(&body, -3.0));
            assert(mc_packet_double(&body, 0.25));
            assert(mc_packet_double(&body, -0.5));
            assert(mc_packet_double(&body, 0.75));
            assert(mc_packet_float(&body, 30.0F));
            assert(mc_packet_float(&body, 5.0F));
            assert(mc_packet_bool(&body, true));
            assert(decode(protocol, MC_PACKET_CLIENTBOUND,
                "sync_entity_position", body.data, body.length, &decoded)
                == MC_FAMILY_ENTITY_TELEPORT);
            assert(decoded.entity_teleport.entity_id == 9);
            assert(decoded.entity_teleport.delta_x == 0.25);
            assert((decoded.entity_teleport.presence & MC_MOVE_HAS_DELTA) != 0U);
            assert_exact_rejections(protocol, MC_PACKET_CLIENTBOUND,
                "sync_entity_position", body.data, body.length);
        }

        mc_packet_init(&body, storage, sizeof(storage));
        if (protocol <= 5) assert(mc_packet_i32(&body, 9));
        else assert(mc_packet_varint(&body, 9));
        assert(mc_packet_u8(&body, 64U));
        assert(decode(protocol, MC_PACKET_CLIENTBOUND, "entity_head_rotation",
            body.data, body.length, &decoded) == MC_FAMILY_ENTITY_HEAD_ROTATION);
        assert(decoded.head.yaw == 90.0F);
        assert_exact_rejections(protocol, MC_PACKET_CLIENTBOUND,
            "entity_head_rotation", body.data, body.length);

        mc_packet_init(&body, storage, sizeof(storage));
        if (protocol <= 5) {
            assert(mc_packet_i32(&body, 4));
            assert(mc_packet_u8(&body, 64U));
            assert(mc_packet_i32(&body, -2));
            assert(mc_packet_varint(&body, 5));
            assert(mc_packet_u8(&body, 3U));
        } else {
            assert(mc_packet_position(&body, protocol,
                (McPosition){.x = 4, .y = 64, .z = -2}));
            assert(mc_packet_varint(&body, 83));
        }
        assert(decode(protocol, MC_PACKET_CLIENTBOUND, "block_change",
            body.data, body.length, &decoded) == MC_FAMILY_BLOCK_CHANGE);
        assert(decoded.block.position.x == 4);
        assert(decoded.block.position.y == 64);
        assert(decoded.block.position.z == -2);
        assert(decoded.block.state_id == (protocol <= 5 ? 83 : 83));
        assert_exact_rejections(protocol, MC_PACKET_CLIENTBOUND,
            "block_change", body.data, body.length);

        mc_packet_init(&body, storage, sizeof(storage));
        assert(mc_packet_u8(&body, 2U));
        assert(mc_packet_float(&body, 0.05F));
        assert(mc_packet_float(&body, 0.1F));
        assert(decode(protocol, MC_PACKET_CLIENTBOUND, "abilities",
            body.data, body.length, &decoded) == MC_FAMILY_ABILITIES);
        assert(decoded.abilities.flags == 2U);
        assert(decoded.abilities.flying_speed == 0.05F);
        assert_exact_rejections(protocol, MC_PACKET_CLIENTBOUND,
            "abilities", body.data, body.length);

        mc_packet_init(&body, storage, sizeof(storage));
        if (protocol >= 770) assert(mc_packet_varint(&body, 4));
        else assert(mc_packet_i8(&body, 4));
        assert(decode(protocol, MC_PACKET_CLIENTBOUND, "held_item_slot",
            body.data, body.length, &decoded) == MC_FAMILY_HELD_ITEM_SLOT);
        assert(decoded.held.slot == 4);
        assert_exact_rejections(protocol, MC_PACKET_CLIENTBOUND,
            "held_item_slot", body.data, body.length);
    }
}

static void encode_set_slot(McPacket *body, int protocol, int32_t window_id,
    int32_t state_id, int16_t slot, int32_t item_id, int32_t count)
{
    if (protocol >= 768) assert(mc_packet_varint(body, window_id));
    else assert(mc_packet_i8(body, (int8_t)window_id));
    if (protocol >= 756) assert(mc_packet_varint(body, state_id));
    assert(mc_packet_i16(body, slot));
    assert(mc_packet_plain_item(body, protocol, item_id, count));
}

static void encode_window_items(McPacket *body, int protocol)
{
    if (protocol >= 768) assert(mc_packet_varint(body, 2));
    else assert(mc_packet_u8(body, 2U));
    if (protocol >= 756) assert(mc_packet_varint(body, 7));
    if (protocol >= 756) assert(mc_packet_varint(body, 2));
    else assert(mc_packet_u16(body, 2U));
    assert(mc_packet_plain_item(body, protocol, 0, 0));
    assert(mc_packet_plain_item(body, protocol, 5, 3));
    if (protocol >= 755) {
        assert(mc_packet_plain_item(body, protocol, 0, 0));
    }
}

static uint64_t packed_section(int32_t x, int32_t y, int32_t z)
{
    return (((uint64_t)(uint32_t)x & UINT64_C(0x3fffff)) << 42U)
        | (((uint64_t)(uint32_t)z & UINT64_C(0x3fffff)) << 20U)
        | ((uint64_t)(uint32_t)y & UINT64_C(0xfffff));
}

static void encode_multi_block_change(McPacket *body, int protocol)
{
    if (protocol <= 5) {
        assert(mc_packet_i32(body, -2));
        assert(mc_packet_i32(body, 3));
        assert(mc_packet_u16(body, 1U));
        assert(mc_packet_i32(body, 4));
        assert(mc_packet_u8(body, UINT8_C(0x12)));
        assert(mc_packet_u8(body, 64U));
        assert(mc_packet_u16(body, 83U));
        return;
    }
    if (protocol < 751) {
        assert(mc_packet_i32(body, -2));
        assert(mc_packet_i32(body, 3));
        assert(mc_packet_varint(body, 1));
        assert(mc_packet_u8(body, UINT8_C(0x12)));
        assert(mc_packet_u8(body, 64U));
        assert(mc_packet_varint(body, 83));
        return;
    }
    assert(mc_packet_u64(body, packed_section(-2, 4, 3)));
    if (protocol <= 762) assert(mc_packet_bool(body, false));
    assert(mc_packet_varint(body, 1));
    const int64_t packed = ((int64_t)83 << 12) | (1 << 8) | (2 << 4) | 3;
    if (protocol <= 758) assert(mc_packet_varlong(body, packed));
    else assert(mc_packet_varint(body, (int32_t)packed));
}

static void test_inventory_and_multi_block(void)
{
    size_t protocol_count = 0U;
    const int *protocols = mc_supported_protocols(&protocol_count);
    for (size_t index = 0U; index < protocol_count; ++index) {
        const int protocol = protocols[index];
        unsigned char storage[2048];
        McPacket body;
        TestDecoded decoded;

        mc_packet_init(&body, storage, sizeof(storage));
        const McWindowClick click = {
            .window_id = 2,
            .state_id = 7,
            .slot = 4,
            .mouse_button = 0,
            .action_number = 11,
            .mode = 0,
        };
        assert(mc_packet_window_click(&body, protocol, &click));
        assert(decode(protocol, MC_PACKET_SERVERBOUND, "window_click",
            body.data, body.length, &decoded) == MC_FAMILY_WINDOW_CLICK);
        assert(decoded.window_click.window_id == 2);
        assert(decoded.window_click.slot == 4);
        assert(decoded.window_click.changed_slot_count == 0U);
        assert(!decoded.window_click.carried_item.present);
        assert_exact_rejections(protocol, MC_PACKET_SERVERBOUND,
            "window_click", body.data, body.length);

        mc_packet_init(&body, storage, sizeof(storage));
        assert(mc_packet_set_creative_slot(&body, protocol, 36, 5, 3));
        assert(decode(protocol, MC_PACKET_SERVERBOUND, "set_creative_slot",
            body.data, body.length, &decoded) == MC_FAMILY_SET_CREATIVE_SLOT);
        assert(decoded.creative_slot.slot == 36);
        assert(decoded.creative_slot.item.present);
        assert(decoded.creative_slot.item.item_id == 5);
        assert(decoded.creative_slot.item.count == 3);
        assert_exact_rejections(protocol, MC_PACKET_SERVERBOUND,
            "set_creative_slot", body.data, body.length);

        mc_packet_init(&body, storage, sizeof(storage));
        encode_set_slot(&body, protocol, -1, 7, 4, 5, 3);
        assert(decode(protocol, MC_PACKET_CLIENTBOUND, "set_slot",
            body.data, body.length, &decoded) == MC_FAMILY_SET_SLOT);
        assert(decoded.set_slot.window_id == -1);
        assert(decoded.set_slot.slot == 4);
        assert(decoded.set_slot.item.item_id == 5);
        assert_exact_rejections(protocol, MC_PACKET_CLIENTBOUND,
            "set_slot", body.data, body.length);

        mc_packet_init(&body, storage, sizeof(storage));
        encode_window_items(&body, protocol);
        assert(decode(protocol, MC_PACKET_CLIENTBOUND, "window_items",
            body.data, body.length, &decoded) == MC_FAMILY_WINDOW_ITEMS);
        assert(decoded.window_items.item_count == 2U);
        McItemIterator items;
        McItemStackView item;
        assert(mc_window_items_iterator(&decoded.window_items, protocol, &items));
        assert(mc_item_iterator_next(&items, &item));
        assert(!item.present);
        assert(mc_item_iterator_next(&items, &item));
        assert(item.item_id == 5 && item.count == 3);
        assert(!mc_item_iterator_next(&items, &item));
        assert_exact_rejections(protocol, MC_PACKET_CLIENTBOUND,
            "window_items", body.data, body.length);

        mc_packet_init(&body, storage, sizeof(storage));
        encode_multi_block_change(&body, protocol);
        assert(decode(protocol, MC_PACKET_CLIENTBOUND, "multi_block_change",
            body.data, body.length, &decoded) == MC_FAMILY_MULTI_BLOCK_CHANGE);
        assert(decoded.multi_block.record_count == 1U);
        McBlockChangeIterator changes;
        McBlockChangeRecord change;
        assert(mc_multi_block_change_iterator(&decoded.multi_block, &changes));
        assert(mc_block_change_iterator_next(&changes, &change));
        assert(change.state_id == 83);
        if (protocol < 751) {
            assert(change.position.x == -31);
            assert(change.position.y == 64);
            assert(change.position.z == 50);
        } else {
            assert(change.position.x == -31);
            assert(change.position.y == 67);
            assert(change.position.z == 50);
        }
        assert(!mc_block_change_iterator_next(&changes, &change));
        assert_exact_rejections(protocol, MC_PACKET_CLIENTBOUND,
            "multi_block_change", body.data, body.length);
    }
}

static void test_dispatch_errors(void)
{
    TestDecoded decoded;
    McPacketFamily family = MC_FAMILY_UNKNOWN;
    McError error;
    assert(mc_decode_packet(9999, MC_STATE_PLAY, MC_PACKET_SERVERBOUND,
        0, NULL, 0U, MC_DECODE_STRICT, &decoded, sizeof(decoded),
        &family, &error) != 0);
    assert(error.code == MC_ERROR_UNSUPPORTED_PROTOCOL);
    assert(error.protocol == 9999);
    assert(mc_decode_packet(776, MC_STATE_PLAY, MC_PACKET_SERVERBOUND,
        INT32_MAX, NULL, 0U, MC_DECODE_STRICT, &decoded, sizeof(decoded),
        &family, &error) != 0);
    assert(error.code == MC_ERROR_UNKNOWN_PACKET);
}

int main(void)
{
    test_family_catalog();
    test_serverbound_tier_a();
    test_clientbound_tier_a();
    test_inventory_and_multi_block();
    test_dispatch_errors();
    puts("PASS typed packet families, exact decoding and cross-version Tier A core");
    return 0;
}
