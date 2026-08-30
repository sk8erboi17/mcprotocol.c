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
    puts("PASS command, abilities, NBT and length-prefixed buffer codecs");
    return 0;
}
