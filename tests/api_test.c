#include "api.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void expect_string(McReader *reader, const char *expected)
{
    McBytes value;
    assert(mc_reader_string(reader, &value));
    assert(value.size == strlen(expected));
    assert(memcmp(value.data, expected, value.size) == 0);
}

static void nbt_writer_validates_complete_values(void)
{
    static const unsigned char compound[] = {10U, 0U};
    static const unsigned char named_compound[] = {10U, 0U, 0U, 0U};
    static const unsigned char truncated[] = {10U};
    unsigned char storage[8];
    McPacket packet;
    const McBytes valid = {compound, sizeof(compound)};
    const McBytes invalid = {truncated, sizeof(truncated)};

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_nbt(&packet, false, &valid));
    assert(packet.length == sizeof(compound));
    assert(memcmp(packet.data, compound, sizeof(compound)) == 0);

    const McBytes named = {named_compound, sizeof(named_compound)};
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_nbt(&packet, true, &named));
    assert(packet.length == sizeof(named_compound));

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_nbt(&packet, false, &named));
    assert(packet.failed);
    assert(packet.length == 0U);

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_nbt(&packet, false, &invalid));
    assert(packet.failed);
    assert(packet.length == 0U);
}

static void length_prefixed_buffers_round_trip(void)
{
    static const unsigned char bytes[] = {0x00U, 0x7fU, 0x80U, 0xffU};
    unsigned char storage[32];
    const McBytes expected = {bytes, sizeof(bytes)};
    McPacket packet;
    McReader reader;
    McBytes decoded = {0};

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_buffer_i32(&packet, &expected));
    mc_reader_init(&reader, packet.data, packet.length);
    assert(mc_reader_buffer_i32(&reader, &decoded));
    assert(mc_reader_remaining(&reader) == 0U);
    assert(decoded.size == expected.size);
    assert(memcmp(decoded.data, expected.data, expected.size) == 0);

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_buffer_varint(&packet, &expected));
    mc_reader_init(&reader, packet.data, packet.length);
    assert(mc_reader_buffer_varint(&reader, &decoded));
    assert(mc_reader_remaining(&reader) == 0U);
    assert(decoded.size == expected.size);
    assert(memcmp(decoded.data, expected.data, expected.size) == 0);

    static const unsigned char negative_i32[] = {0xffU, 0xffU, 0xffU, 0xffU};
    mc_reader_init(&reader, negative_i32, sizeof(negative_i32));
    assert(!mc_reader_buffer_i32(&reader, &decoded));
    assert(reader.failed);

    static const unsigned char truncated_varint[] = {3U, 1U, 2U};
    mc_reader_init(&reader, truncated_varint, sizeof(truncated_varint));
    assert(!mc_reader_buffer_varint(&reader, &decoded));
    assert(reader.failed);
}

static void expect_command(int protocol)
{
    unsigned char storage[384];
    McPacket packet;
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_command(&packet, protocol, "/tps",
        INT64_C(1234567890), INT64_C(987654321)));

    McReader reader;
    mc_reader_init(&reader, packet.data, packet.length);
    expect_string(&reader, protocol <= 758 ? "/tps" : "tps");
    if (protocol >= 759 && protocol <= 765) {
        int64_t timestamp = 0;
        int64_t salt = 0;
        int32_t signatures = -1;
        assert(mc_reader_i64(&reader, &timestamp));
        assert(mc_reader_i64(&reader, &salt));
        assert(mc_reader_varint(&reader, &signatures));
        assert(timestamp == INT64_C(1234567890));
        assert(salt == INT64_C(987654321));
        assert(signatures == 0);
        if (protocol == 759) {
            bool signed_preview = true;
            assert(mc_reader_bool(&reader, &signed_preview));
            assert(!signed_preview);
        } else if (protocol == 760) {
            bool signed_preview = true;
            int32_t previous_messages = -1;
            bool has_last_rejected = true;
            assert(mc_reader_bool(&reader, &signed_preview));
            assert(mc_reader_varint(&reader, &previous_messages));
            assert(mc_reader_bool(&reader, &has_last_rejected));
            assert(!signed_preview);
            assert(previous_messages == 0);
            assert(!has_last_rejected);
        } else {
            int32_t message_count = -1;
            McBytes acknowledged;
            assert(mc_reader_varint(&reader, &message_count));
            assert(mc_reader_bytes(&reader, 3U, &acknowledged));
            assert(message_count == 0);
            assert(acknowledged.data[0] == 0U);
            assert(acknowledged.data[1] == 0U);
            assert(acknowledged.data[2] == 0U);
        }
    }
    assert(mc_reader_remaining(&reader) == 0U);
    const char *packet_name = protocol <= 758 ? "chat" : "chat_command";
    assert(mc_packet_id(protocol, MC_STATE_PLAY,
        MC_PACKET_SERVERBOUND, packet_name) >= 0);
}

static void invalid_commands_fail_sticky(void)
{
    unsigned char storage[512];
    char too_long[258];
    memset(too_long, 'a', sizeof(too_long));
    too_long[sizeof(too_long) - 1U] = '\0';

    McPacket packet;
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_command(&packet, 776, "", 0, 0));
    assert(packet.failed);

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_command(&packet, 776, "/", 0, 0));
    assert(packet.failed);

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_command(&packet, 776, too_long, 0, 0));
    assert(packet.failed);

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_command(&packet, 6, "tps", 0, 0));
    assert(packet.failed);
}

static void expect_player_abilities(int protocol)
{
    const McPlayerAbilities expected = {
        .flags = 0x0dU,
        .flying_speed = 0.05F,
        .walking_speed = 0.1F,
    };
    unsigned char storage[9];
    McPacket packet;
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_player_abilities(&packet, protocol, &expected));
    assert(packet.length == (protocol < 735 ? sizeof(storage) : 1U));

    McReader reader;
    uint8_t flags = 0U;
    float flying_speed = 0.0F;
    float walking_speed = 0.0F;
    mc_reader_init(&reader, packet.data, packet.length);
    assert(mc_reader_u8(&reader, &flags));
    if (protocol < 735) {
        assert(mc_reader_float(&reader, &flying_speed));
        assert(mc_reader_float(&reader, &walking_speed));
    }
    assert(mc_reader_remaining(&reader) == 0U);
    assert(flags == expected.flags);
    if (protocol < 735) {
        assert(flying_speed == expected.flying_speed);
        assert(walking_speed == expected.walking_speed);
    }

    unsigned char short_storage[8];
    mc_packet_init(&packet, short_storage, sizeof(short_storage));
    assert(mc_packet_player_abilities(&packet, protocol, &expected) == (protocol >= 735));
    assert(packet.failed == (protocol < 735));
    if (protocol < 735) {
        assert(!mc_packet_player_abilities(&packet, protocol, &expected));
    }

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_player_abilities(&packet, protocol, NULL));
    assert(packet.failed);

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_player_abilities(&packet, 6, &expected));
    assert(packet.failed);
}

static void attack_and_respawn_bodies_are_versioned(void)
{
    static const struct {
        int protocol;
        unsigned char bytes[5];
        size_t size;
    } attacks[] = {
        {5, {0x00U, 0x00U, 0x01U, 0x2cU, 0x01U}, 5U},
        {47, {0xacU, 0x02U, 0x01U}, 3U},
        {578, {0xacU, 0x02U, 0x01U}, 3U},
        {735, {0xacU, 0x02U, 0x01U, 0x00U}, 4U},
        {774, {0xacU, 0x02U, 0x01U, 0x00U}, 4U},
        {775, {0xacU, 0x02U}, 2U},
        {776, {0xacU, 0x02U}, 2U},
    };
    unsigned char storage[16];
    McPacket packet;
    for (size_t index = 0U; index < sizeof(attacks) / sizeof(attacks[0]); ++index) {
        mc_packet_init(&packet, storage, sizeof(storage));
        assert(mc_packet_attack_entity(&packet, attacks[index].protocol, 300));
        assert(packet.length == attacks[index].size);
        assert(memcmp(packet.data, attacks[index].bytes, packet.length) == 0);

        mc_packet_init(&packet, storage, sizeof(storage));
        assert(mc_packet_respawn_request(&packet, attacks[index].protocol));
        assert(packet.length == 1U && packet.data[0] == 0U);
    }

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_attack_entity(&packet, 776, 0));
    assert(packet.failed);
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_attack_entity(&packet, 6, 1));
    assert(packet.failed);
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_respawn_request(&packet, 6));
    assert(packet.failed);
    assert(!mc_packet_attack_entity(NULL, 776, 1));
    assert(!mc_packet_respawn_request(NULL, 776));
}

static void block_dig_bodies_are_versioned(void)
{
    static const struct {
        int protocol;
        McBlockDig dig;
        unsigned char bytes[11];
        size_t size;
    } cases[] = {
        {5, {0, {-9, 64, 11}, 1, 7},
            {0x00U,0xffU,0xffU,0xffU,0xf7U,0x40U,0x00U,0x00U,0x00U,0x0bU,0x01U}, 11U},
        {47, {0, {-9, 64, 11}, 1, 7},
            {0x00U,0xffU,0xffU,0xfdU,0xc1U,0x00U,0x00U,0x00U,0x0bU,0x01U}, 10U},
        {758, {0, {-9, -60, 11}, 1, 7},
            {0x00U,0xffU,0xffU,0xfdU,0xc0U,0x00U,0x00U,0xbfU,0xc4U,0x01U}, 10U},
        {759, {0, {-9, -60, 11}, 1, 7},
            {0x00U,0xffU,0xffU,0xfdU,0xc0U,0x00U,0x00U,0xbfU,0xc4U,0x01U,0x07U}, 11U},
        {776, {4, {0, 0, 0}, 0, 0},
            {0x04U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U}, 11U},
    };
    unsigned char storage[16];
    McPacket packet;
    for (size_t index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        mc_packet_init(&packet, storage, sizeof(storage));
        assert(mc_packet_block_dig(
            &packet, cases[index].protocol, &cases[index].dig));
        assert(packet.length == cases[index].size);
        assert(memcmp(packet.data, cases[index].bytes, packet.length) == 0);
    }

    const McBlockDig invalid_status = {7, {0, 0, 0}, 0, 0};
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_block_dig(&packet, 776, &invalid_status));
    assert(packet.failed);
    const McBlockDig invalid_legacy_y = {0, {0, -1, 0}, 1, 0};
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_block_dig(&packet, 5, &invalid_legacy_y));
    assert(packet.failed);
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_block_dig(&packet, 6, &cases[0].dig));
    assert(packet.failed);
    assert(!mc_packet_block_dig(NULL, 776, &cases[4].dig));
}

static void block_place_bodies_are_versioned(void)
{
    static const unsigned char body_5[] = {
        0xffU,0xffU,0xffU,0xf7U,0x3fU,0x00U,0x00U,0x00U,0x0bU,0x01U,
        0x00U,0x01U,0x40U,0x00U,0x00U,0xffU,0xffU,0x08U,0x10U,0x08U};
    static const unsigned char body_47[] = {
        0xffU,0xffU,0xfdU,0xc0U,0xfcU,0x00U,0x00U,0x0bU,0x01U,0x00U,
        0x01U,0x40U,0x00U,0x00U,0x00U,0x08U,0x10U,0x08U};
    static const unsigned char body_107[] = {
        0xffU,0xffU,0xfdU,0xc0U,0xfcU,0x00U,0x00U,0x0bU,0x01U,0x00U,
        0x08U,0x10U,0x08U};
    static const unsigned char body_315[] = {
        0xffU,0xffU,0xfdU,0xc0U,0xfcU,0x00U,0x00U,0x0bU,0x01U,0x00U,
        0x3fU,0x00U,0x00U,0x00U,0x3fU,0x80U,0x00U,0x00U,0x3fU,0x00U,
        0x00U,0x00U};
    static const unsigned char body_477[] = {
        0x00U,0xffU,0xffU,0xfdU,0xc0U,0x00U,0x00U,0xb0U,0x3fU,0x01U,
        0x3fU,0x00U,0x00U,0x00U,0x3fU,0x80U,0x00U,0x00U,0x3fU,0x00U,
        0x00U,0x00U,0x00U};
    static const unsigned char body_758[] = {
        0x00U,0xffU,0xffU,0xfdU,0xc0U,0x00U,0x00U,0xbfU,0xc3U,0x01U,
        0x3fU,0x00U,0x00U,0x00U,0x3fU,0x80U,0x00U,0x00U,0x3fU,0x00U,
        0x00U,0x00U,0x00U};
    static const unsigned char body_759[] = {
        0x00U,0xffU,0xffU,0xfdU,0xc0U,0x00U,0x00U,0xbfU,0xc3U,0x01U,
        0x3fU,0x00U,0x00U,0x00U,0x3fU,0x80U,0x00U,0x00U,0x3fU,0x00U,
        0x00U,0x00U,0x00U,0x01U};
    static const unsigned char body_768[] = {
        0x00U,0xffU,0xffU,0xfdU,0xc0U,0x00U,0x00U,0xbfU,0xc3U,0x01U,
        0x3fU,0x00U,0x00U,0x00U,0x3fU,0x80U,0x00U,0x00U,0x3fU,0x00U,
        0x00U,0x00U,0x00U,0x00U,0x01U};
    static const struct {
        int protocol;
        const unsigned char *bytes;
        size_t size;
    } cases[] = {
        {5, body_5, sizeof(body_5)},
        {47, body_47, sizeof(body_47)},
        {107, body_107, sizeof(body_107)},
        {315, body_315, sizeof(body_315)},
        {477, body_477, sizeof(body_477)},
        {758, body_758, sizeof(body_758)},
        {759, body_759, sizeof(body_759)},
        {768, body_768, sizeof(body_768)},
        {775, body_768, sizeof(body_768)},
        {776, body_768, sizeof(body_768)},
    };
    unsigned char storage[32];
    McPacket packet;
    for (size_t index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const int protocol = cases[index].protocol;
        const McBlockPlace place = {
            .location = {-9, protocol <= 756 ? 63 : -61, 11},
            .direction = 1,
            .hand = 0,
            .held_item_id = 1,
            .held_item_count = 64,
            .cursor_x = 0.5F,
            .cursor_y = 1.0F,
            .cursor_z = 0.5F,
            .inside_block = false,
            .world_border_hit = false,
            .sequence = 1,
        };
        mc_packet_init(&packet, storage, sizeof(storage));
        assert(mc_packet_block_place(&packet, protocol, &place));
        assert(packet.length == cases[index].size);
        assert(memcmp(packet.data, cases[index].bytes, packet.length) == 0);
    }

    McBlockPlace invalid = {
        .location = {0, 0, 0}, .direction = 6, .cursor_x = 0.5F,
        .cursor_y = 1.0F, .cursor_z = 0.5F,
    };
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_block_place(&packet, 776, &invalid));
    assert(packet.failed);
    invalid.direction = 1;
    invalid.cursor_x = 0.3F;
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_block_place(&packet, 47, &invalid));
    assert(packet.failed);
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_block_place(&packet, 6, &invalid));
    assert(packet.failed);
    assert(!mc_packet_block_place(NULL, 776, &invalid));
}

static void untrusted_component_items_match_node(void)
{
    static const unsigned char enchantment_data[] = {0x01U, 0x21U, 0x05U};
    const McItemComponentPatch enchantment = {
        .type_id = 13,
        .data = {enchantment_data, sizeof(enchantment_data)},
    };
    static const unsigned char expected[] = {
        0x01U,0xa9U,0x07U,0x01U,0x00U,0x0dU,0x03U,0x01U,0x21U,0x05U,
    };
    unsigned char storage[32];
    McPacket packet;
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_untrusted_component_item(
        &packet, 776, 937, 1, &enchantment, 1U, NULL, 0U));
    assert(packet.length == sizeof(expected));
    assert(memcmp(packet.data, expected, sizeof(expected)) == 0);

    static const int32_t removed[] = {42};
    static const unsigned char removed_expected[] = {
        0x01U,0xddU,0x09U,0x00U,0x01U,0x2aU,
    };
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_untrusted_component_item(
        &packet, 776, 1245, 1, NULL, 0U, removed, 1U));
    assert(packet.length == sizeof(removed_expected));
    assert(memcmp(packet.data, removed_expected, sizeof(removed_expected)) == 0);

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_untrusted_component_item(
        &packet, 776, 0, 0, NULL, 0U, NULL, 0U));
    assert(packet.length == 1U && packet.data[0] == 0U);
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_untrusted_component_item(
        &packet, 765, 937, 1, &enchantment, 1U, NULL, 0U));
    assert(packet.failed);
    const McItemComponentPatch invalid = {.type_id = -1, .data = {NULL, 0U}};
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_untrusted_component_item(
        &packet, 776, 937, 1, &invalid, 1U, NULL, 0U));
    assert(packet.failed);
    assert(!mc_packet_untrusted_component_item(
        NULL, 776, 937, 1, &enchantment, 1U, NULL, 0U));
}

static void dump_command(int protocol)
{
    unsigned char storage[384];
    McPacket packet;
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_command(&packet, protocol, "/tps",
        INT64_C(1234567890), INT64_C(987654321)));
    printf("%d:", protocol);
    for (size_t index = 0U; index < packet.length; ++index) {
        printf("%02x", packet.data[index]);
    }
    putchar('\n');
}

static void dump_player_abilities(int protocol)
{
    unsigned char storage[9];
    const McPlayerAbilities abilities = {
        .flags = 0x0dU,
        .flying_speed = 0.05F,
        .walking_speed = 0.1F,
    };
    McPacket packet;
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_player_abilities(&packet, protocol, &abilities));
    printf("%d:", protocol);
    for (size_t index = 0U; index < packet.length; ++index) {
        printf("%02x", packet.data[index]);
    }
    putchar('\n');
}

int main(int argc, char **argv)
{
    const int boundary_protocols[] = {4, 578, 735, 758, 759, 760, 761, 765, 766, 776};
    if (argc == 2 && strcmp(argv[1], "--dump-commands") == 0) {
        for (size_t index = 0U;
                index < sizeof(boundary_protocols) / sizeof(boundary_protocols[0]); ++index) {
            dump_command(boundary_protocols[index]);
        }
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--dump-abilities") == 0) {
        for (size_t index = 0U;
                index < sizeof(boundary_protocols) / sizeof(boundary_protocols[0]); ++index) {
            dump_player_abilities(boundary_protocols[index]);
        }
        return 0;
    }
    for (size_t index = 0U;
            index < sizeof(boundary_protocols) / sizeof(boundary_protocols[0]); ++index) {
        expect_command(boundary_protocols[index]);
    }
    invalid_commands_fail_sticky();
    nbt_writer_validates_complete_values();
    length_prefixed_buffers_round_trip();
    expect_player_abilities(4);
    expect_player_abilities(578);
    expect_player_abilities(735);
    expect_player_abilities(776);
    attack_and_respawn_bodies_are_versioned();
    block_dig_bodies_are_versioned();
    block_place_bodies_are_versioned();
    untrusted_component_items_match_node();
    puts("PASS command, abilities, block actions, component items, combat, respawn, NBT and buffer codecs");
    return 0;
}
