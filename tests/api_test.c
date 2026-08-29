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

int main(int argc, char **argv)
{
    const int boundary_protocols[] = {4, 758, 759, 760, 761, 765, 766, 776};
    if (argc == 2 && strcmp(argv[1], "--dump-commands") == 0) {
        for (size_t index = 0U;
                index < sizeof(boundary_protocols) / sizeof(boundary_protocols[0]); ++index) {
            dump_command(boundary_protocols[index]);
        }
        return 0;
    }
    for (size_t index = 0U;
            index < sizeof(boundary_protocols) / sizeof(boundary_protocols[0]); ++index) {
        expect_command(boundary_protocols[index]);
    }
    invalid_commands_fail_sticky();
    puts("PASS command codec boundaries 4/758/759/760/761/765/766/776");
    return 0;
}
