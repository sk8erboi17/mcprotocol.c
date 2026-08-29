#include "generated/mc_protocol_776.h"

#include <assert.h>
#include <stdio.h>

static void test_complete_packet_catalog(void)
{
    assert(mc776_generated_packet_id_count != 0U);
    for (size_t index = 0U; index < mc776_generated_packet_id_count; ++index) {
        const McPacketInfo expected = mc776_generated_packet_ids[index];
        const int32_t actual =
            mc_packet_id(776, expected.state, expected.direction, expected.name);
        if (actual != expected.id) {
            fprintf(stderr,
                "catalog mismatch: state=%d direction=%d name=%s generated=%d api=%d\n",
                expected.state, expected.direction, expected.name, expected.id, actual);
        }
        assert(actual == expected.id);
        assert(mc_packet_name(776, expected.state, expected.direction, expected.id) != NULL);
    }
}

static void test_use_item(void)
{
    unsigned char storage[32];
    McPacket packet;
    mc_packet_init(&packet, storage, sizeof(storage));
    const Mc776PlayServerboundUseItem expected = {
        .hand = 1,
        .sequence = 42,
        .rotation = {.x = 12.5F, .y = -33.25F},
    };
    assert(mc776_play_serverbound_use_item_encode(&packet, &expected));
    assert(MC776_PLAY_SERVERBOUND_USE_ITEM ==
        mc_packet_id(776, MC_STATE_PLAY, MC_PACKET_SERVERBOUND, "use_item"));

    McReader reader;
    Mc776PlayServerboundUseItem decoded = {0};
    mc_reader_init(&reader, packet.data, packet.length);
    assert(mc776_play_serverbound_use_item_decode(&reader, &decoded));
    assert(decoded.hand == expected.hand);
    assert(decoded.sequence == expected.sequence);
    assert(decoded.rotation.x == expected.rotation.x);
    assert(decoded.rotation.y == expected.rotation.y);
}

static void test_block_dig(void)
{
    unsigned char storage[32];
    McPacket packet;
    mc_packet_init(&packet, storage, sizeof(storage));
    const Mc776PlayServerboundBlockDig expected = {
        .status = 6,
        .location = {.x = -12, .y = 64, .z = 33},
        .face = 1,
        .sequence = 7,
    };
    assert(mc776_play_serverbound_block_dig_encode(&packet, &expected));
    assert(MC776_PLAY_SERVERBOUND_BLOCK_DIG ==
        mc_packet_id(776, MC_STATE_PLAY, MC_PACKET_SERVERBOUND, "block_dig"));

    McReader reader;
    Mc776PlayServerboundBlockDig decoded = {0};
    mc_reader_init(&reader, packet.data, packet.length);
    assert(mc776_play_serverbound_block_dig_decode(&reader, &decoded));
    assert(decoded.status == expected.status);
    assert(decoded.location.x == expected.location.x);
    assert(decoded.location.y == expected.location.y);
    assert(decoded.location.z == expected.location.z);
    assert(decoded.face == expected.face);
    assert(decoded.sequence == expected.sequence);
}

int main(void)
{
    test_complete_packet_catalog();
    test_use_item();
    test_block_dig();
    puts("PASS minecraft-data generated packet IDs, structs and codecs");
    return 0;
}
