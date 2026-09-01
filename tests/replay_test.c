#include "api.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    McPacketFamily family;
    int32_t packet_id;
    uint64_t delta_time_ns;
    double x;
    int32_t slot;
} ReplayObservation;

static void append_record(McPacket *trace, McPacketDirection direction,
    McState state, uint64_t delta_time_ns, int32_t packet_id,
    const McPacket *body)
{
    assert(body->length <= UINT32_MAX);
    assert(mc_packet_u8(trace, (uint8_t)direction));
    assert(mc_packet_u8(trace, (uint8_t)state));
    assert(mc_packet_u64(trace, delta_time_ns));
    assert(mc_packet_i32(trace, packet_id));
    assert(mc_packet_u32(trace, (uint32_t)body->length));
    assert(mc_packet_bytes(trace, body->data, body->length));
}

static size_t build_trace(unsigned char *storage, size_t capacity)
{
    McPacket trace;
    mc_packet_init(&trace, storage, capacity);
    assert(mc_packet_bytes(&trace, "MCTR", MC_REPLAY_MAGIC_SIZE));
    assert(mc_packet_u16(&trace, MC_REPLAY_FORMAT_VERSION));
    assert(mc_packet_u16(&trace, 0U));
    assert(mc_packet_i32(&trace, 776));
    assert(mc_packet_u32(&trace, 2U));

    unsigned char body_storage[128];
    McPacket body;
    mc_packet_init(&body, body_storage, sizeof(body_storage));
    const McPlayerPosition movement = {
        .x = 12.25, .y = 64.5, .z = -7.75,
        .yaw = 91.0F, .pitch = -22.5F, .on_ground = true,
    };
    assert(mc_packet_player_position(&body, 776, &movement));
    append_record(&trace, MC_PACKET_SERVERBOUND, MC_STATE_PLAY, 0U,
        mc_packet_id(776, MC_STATE_PLAY, MC_PACKET_SERVERBOUND,
            "position_look"), &body);

    mc_packet_init(&body, body_storage, sizeof(body_storage));
    assert(mc_packet_held_item_slot(&body, 776, 4));
    append_record(&trace, MC_PACKET_SERVERBOUND, MC_STATE_PLAY, 50000000U,
        mc_packet_id(776, MC_STATE_PLAY, MC_PACKET_SERVERBOUND,
            "held_item_slot"), &body);
    assert(!trace.failed);
    return trace.length;
}

static size_t observe(const unsigned char *trace, size_t trace_size,
    ReplayObservation *observations, size_t capacity)
{
    McReplayReader replay;
    McError error;
    assert(mc_replay_reader_init(&replay, trace, trace_size, &error));
    assert(replay.protocol == 776);
    size_t count = 0U;
    McReplayRecord record;
    while (mc_replay_reader_next(&replay, &record)) {
        assert(count < capacity);
        ReplayObservation observation = {
            .packet_id = record.packet_id,
            .delta_time_ns = record.delta_time_ns,
        };
        unsigned char decoded[512];
        memset(decoded, 0, sizeof(decoded));
        assert(mc_decode_packet(replay.protocol, record.state,
            record.direction, record.packet_id, record.payload.data,
            record.payload.size, MC_DECODE_STRICT, decoded, sizeof(decoded),
            &observation.family, &error) == 0);
        if (observation.family == MC_FAMILY_PLAYER_MOVEMENT) {
            const McPlayerMovementPacket *movement =
                (const McPlayerMovementPacket *)(const void *)decoded;
            observation.x = movement->x;
        } else if (observation.family == MC_FAMILY_HELD_ITEM_SLOT) {
            const McHeldItemSlotPacket *held =
                (const McHeldItemSlotPacket *)(const void *)decoded;
            observation.slot = held->slot;
        } else {
            assert(false);
        }
        observations[count++] = observation;
    }
    assert(replay.record_index == replay.record_count);
    assert(mc_replay_reader_finish(&replay));
    assert(error.code == MC_ERROR_NONE);
    return count;
}

static void test_deterministic_replay(void)
{
    unsigned char trace[1024];
    const size_t trace_size = build_trace(trace, sizeof(trace));
    ReplayObservation first[2];
    ReplayObservation second[2];
    assert(observe(trace, trace_size, first, 2U) == 2U);
    assert(observe(trace, trace_size, second, 2U) == 2U);
    assert(memcmp(first, second, sizeof(first)) == 0);
    assert(first[0].family == MC_FAMILY_PLAYER_MOVEMENT);
    assert(first[0].x == 12.25);
    assert(first[1].family == MC_FAMILY_HELD_ITEM_SLOT);
    assert(first[1].slot == 4);
    assert(first[1].delta_time_ns == 50000000U);
}

static bool complete_prefix(const unsigned char *trace, size_t size)
{
    McReplayReader replay;
    McError error;
    if (!mc_replay_reader_init(&replay, trace, size, &error)) return false;
    McReplayRecord record;
    while (mc_replay_reader_next(&replay, &record)) {
    }
    return mc_replay_reader_finish(&replay);
}

static void test_exact_truncation(void)
{
    unsigned char trace[1024];
    const size_t trace_size = build_trace(trace, sizeof(trace));
    for (size_t prefix = 0U; prefix < trace_size; ++prefix) {
        assert(!complete_prefix(trace, prefix));
    }
    assert(complete_prefix(trace, trace_size));
    trace[trace_size] = 0U;
    assert(!complete_prefix(trace, trace_size + 1U));
}

static void test_invalid_headers(void)
{
    unsigned char trace[1024];
    const size_t trace_size = build_trace(trace, sizeof(trace));
    McReplayReader replay;
    McError error;
    trace[0] = (unsigned char)'X';
    assert(!mc_replay_reader_init(&replay, trace, trace_size, &error));
    assert(error.code == MC_ERROR_INVALID_PACKET_BODY);
    (void)build_trace(trace, sizeof(trace));
    trace[5] = 2U;
    assert(!mc_replay_reader_init(&replay, trace, trace_size, &error));
    assert(error.code == MC_ERROR_INVALID_PACKET_BODY);
}

int main(void)
{
    test_deterministic_replay();
    test_exact_truncation();
    test_invalid_headers();
    puts("PASS bounded deterministic packet replay");
    return 0;
}
