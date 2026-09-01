#define _POSIX_C_SOURCE 200809L
#if defined(__APPLE__) && defined(__MACH__)
#define _DARWIN_C_SOURCE
#endif

#include "../api.h"
#include "alloc_hooks.h"

#include <inttypes.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <zlib.h>

#define BENCH_CHECK(expression) do { \
    if (!(expression)) abort(); \
} while (0)

typedef union {
    max_align_t alignment;
    unsigned char bytes[4096];
    McPlayerMovementPacket movement;
    McUseEntityPacket attack;
} BenchOutput;

typedef struct {
    const char *name;
    uint64_t elapsed_ns;
    uint64_t operations;
    uint64_t bytes;
    double allocations_per_operation;
    size_t peak_retained_bytes;
} BenchResult;

static volatile uint64_t bench_sink;
static uint64_t benchmark_allocation_count;

void *mc_benchmark_malloc(size_t size)
{
    ++benchmark_allocation_count;
    return malloc(size);
}

void *mc_benchmark_calloc(size_t count, size_t size)
{
    ++benchmark_allocation_count;
    return calloc(count, size);
}

void *mc_benchmark_realloc(void *pointer, size_t size)
{
    ++benchmark_allocation_count;
    return realloc(pointer, size);
}

void mc_benchmark_free(void *pointer)
{
    free(pointer);
}

static double allocations_since(uint64_t initial, uint64_t operations)
{
    return (double)(benchmark_allocation_count - initial) / (double)operations;
}

static uint64_t peak_resident_bytes(void)
{
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) != 0 || usage.ru_maxrss <= 0L) return 0U;
    const uint64_t resident = (uint64_t)usage.ru_maxrss;
#if defined(__APPLE__) && defined(__MACH__)
    return resident;
#else
    return resident <= UINT64_MAX / UINT64_C(1024)
        ? resident * UINT64_C(1024) : UINT64_MAX;
#endif
}

static uint64_t monotonic_ns(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0U;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000)
        + (uint64_t)now.tv_nsec;
}

static size_t write_varint(unsigned char *output, uint32_t value)
{
    size_t size = 0U;
    do {
        uint8_t byte = (uint8_t)(value & UINT32_C(0x7f));
        value >>= 7U;
        if (value != 0U) byte |= UINT8_C(0x80);
        output[size++] = byte;
    } while (value != 0U);
    return size;
}

static BenchResult benchmark_varint(uint64_t iterations)
{
    const unsigned char encoded[] = {0xffU, 0xffU, 0xffU, 0xffU, 0x07U};
    const uint64_t initial_allocations = benchmark_allocation_count;
    uint64_t started = monotonic_ns();
    for (uint64_t index = 0U; index < iterations; ++index) {
        McReader reader;
        int32_t value = 0;
        mc_reader_init(&reader, encoded, sizeof(encoded));
        BENCH_CHECK(mc_reader_varint(&reader, &value));
        bench_sink += (uint32_t)value;
    }
    return (BenchResult){"varint_decode", monotonic_ns() - started,
        iterations, iterations * sizeof(encoded),
        allocations_since(initial_allocations, iterations), 0U};
}

static void make_movement(McPacket *packet, unsigned char *storage,
    size_t capacity)
{
    const McPlayerPosition movement = {
        .x = 12.25, .y = 64.5, .z = -7.75,
        .yaw = 91.0F, .pitch = -22.5F, .on_ground = true,
    };
    mc_packet_init(packet, storage, capacity);
    BENCH_CHECK(mc_packet_player_position(packet, 768, &movement));
}

static BenchResult benchmark_packet(uint64_t iterations, bool movement)
{
    unsigned char storage[128];
    McPacket body;
    const char *name = movement ? "position_look" : "use_entity";
    if (movement) {
        make_movement(&body, storage, sizeof(storage));
    } else {
        mc_packet_init(&body, storage, sizeof(storage));
        BENCH_CHECK(mc_packet_attack_entity(&body, 768, 17));
    }
    const int32_t packet_id = mc_packet_id(768, MC_STATE_PLAY,
        MC_PACKET_SERVERBOUND, name);
    BENCH_CHECK(packet_id >= 0);
    const uint64_t initial_allocations = benchmark_allocation_count;
    uint64_t started = monotonic_ns();
    for (uint64_t index = 0U; index < iterations; ++index) {
        BenchOutput output;
        McPacketFamily family = MC_FAMILY_UNKNOWN;
        McError error;
        BENCH_CHECK(mc_decode_packet(768, MC_STATE_PLAY, MC_PACKET_SERVERBOUND,
            packet_id, body.data, body.length, MC_DECODE_STRICT, &output,
            sizeof(output), &family, &error) == 0);
        bench_sink += movement ? (uint64_t)output.movement.presence
                               : (uint64_t)output.attack.entity_id;
    }
    return (BenchResult){movement ? "position_look_decode" : "attack_decode",
        monotonic_ns() - started, iterations, iterations * body.length,
        allocations_since(initial_allocations, iterations), 0U};
}

static BenchResult benchmark_movement_base(uint64_t iterations)
{
    const unsigned char body[] = {1U};
    const int32_t packet_id = mc_packet_id(768, MC_STATE_PLAY,
        MC_PACKET_SERVERBOUND, "flying");
    BENCH_CHECK(packet_id >= 0);
    const uint64_t initial_allocations = benchmark_allocation_count;
    uint64_t started = monotonic_ns();
    for (uint64_t index = 0U; index < iterations; ++index) {
        BenchOutput output;
        McPacketFamily family = MC_FAMILY_UNKNOWN;
        McError error;
        BENCH_CHECK(mc_decode_packet(768, MC_STATE_PLAY,
            MC_PACKET_SERVERBOUND, packet_id, body, sizeof(body),
            MC_DECODE_STRICT, &output, sizeof(output), &family, &error) == 0);
        bench_sink += output.movement.raw_flags;
    }
    return (BenchResult){"movement_decode", monotonic_ns() - started,
        iterations, iterations * sizeof(body),
        allocations_since(initial_allocations, iterations), 0U};
}

static BenchResult benchmark_nbt(uint64_t iterations)
{
    static const unsigned char nbt[] = {10U, 0U, 0U, 0U};
    const uint64_t initial_allocations = benchmark_allocation_count;
    uint64_t started = monotonic_ns();
    for (uint64_t index = 0U; index < iterations; ++index) {
        McReader reader;
        mc_reader_init(&reader, nbt, sizeof(nbt));
        BENCH_CHECK(mc_reader_nbt(&reader, true, NULL));
        bench_sink += reader.offset;
    }
    return (BenchResult){"nbt_validate", monotonic_ns() - started,
        iterations, iterations * sizeof(nbt),
        allocations_since(initial_allocations, iterations), 0U};
}

static BenchResult benchmark_canonical(uint64_t iterations)
{
    unsigned char storage[128];
    McPacket body;
    make_movement(&body, storage, sizeof(storage));
    const int32_t packet_id = mc_packet_id(768, MC_STATE_PLAY,
        MC_PACKET_SERVERBOUND, "position_look");
    McCanonicalHeader header;
    McError error;
    BENCH_CHECK(mc_canonical_header_init(&header, 768, MC_STATE_PLAY,
        MC_PACKET_SERVERBOUND, packet_id, body.data, body.length, &error));
    const uint64_t initial_allocations = benchmark_allocation_count;
    uint64_t started = monotonic_ns();
    for (uint64_t index = 0U; index < iterations; ++index) {
        McCanonicalMovement output;
        BENCH_CHECK(mc_decode_canonical_movement(&header, &output,
            MC_DECODE_STRICT, &error));
        bench_sink += output.presence;
    }
    return (BenchResult){"canonical_movement", monotonic_ns() - started,
        iterations, iterations * body.length,
        allocations_since(initial_allocations, iterations), 0U};
}

static size_t make_plain_frame(unsigned char *frame, size_t payload_size)
{
    unsigned char packet[512];
    BENCH_CHECK(payload_size + 1U <= sizeof(packet));
    packet[0] = 0U;
    memset(packet + 1U, 0x5a, payload_size);
    const size_t packet_size = payload_size + 1U;
    const size_t header = write_varint(frame, (uint32_t)packet_size);
    memcpy(frame + header, packet, packet_size);
    return header + packet_size;
}

static size_t make_compressed_frame(unsigned char *frame, size_t capacity,
    size_t payload_size)
{
    unsigned char packet[512];
    unsigned char compressed[1024];
    BENCH_CHECK(payload_size + 1U <= sizeof(packet));
    packet[0] = 0U;
    memset(packet + 1U, 0x5a, payload_size);
    const uLong packet_size = (uLong)(payload_size + 1U);
    uLongf compressed_size = (uLongf)sizeof(compressed);
    BENCH_CHECK(compress2(compressed, &compressed_size, packet, packet_size,
        Z_BEST_SPEED) == Z_OK);
    unsigned char envelope[1100];
    const size_t declared_size = write_varint(envelope, (uint32_t)packet_size);
    BENCH_CHECK((size_t)compressed_size <= sizeof(envelope) - declared_size);
    memcpy(envelope + declared_size, compressed, (size_t)compressed_size);
    const size_t envelope_size = declared_size + (size_t)compressed_size;
    const size_t frame_header = write_varint(frame, (uint32_t)envelope_size);
    BENCH_CHECK(envelope_size <= capacity - frame_header);
    memcpy(frame + frame_header, envelope, envelope_size);
    return frame_header + envelope_size;
}

static McStreamDecoder *make_decoder(void)
{
    McStreamDecoderConfig config;
    mc_stream_decoder_config_init(&config);
    config.max_frame_size = 64U * 1024U;
    config.max_decompressed_size = 64U * 1024U;
    config.max_buffered_size = 128U * 1024U;
    config.max_output_size = 128U * 1024U;
    config.mode = MC_DECODE_STRICT;
    McError error;
    McStreamDecoder *decoder = mc_stream_decoder_create(&config, &error);
    BENCH_CHECK(decoder != NULL);
    return decoder;
}

static BenchResult benchmark_frame(uint64_t iterations, bool compressed)
{
    unsigned char frame[2048];
    const size_t frame_size = compressed
        ? make_compressed_frame(frame, sizeof(frame), 128U)
        : make_plain_frame(frame, 16U);
    McStreamDecoder *decoder = make_decoder();
    size_t peak = 0U;
    const uint64_t initial_allocations = benchmark_allocation_count;
    uint64_t started = monotonic_ns();
    for (uint64_t index = 0U; index < iterations; ++index) {
        mc_stream_decoder_reset(decoder);
        McError error;
        if (compressed) {
            BENCH_CHECK(mc_stream_decoder_set_compression(decoder, 1, &error) == 0);
        }
        McDecodedFrame output;
        size_t count = 0U;
        BENCH_CHECK(mc_stream_decoder_feed(decoder, frame, frame_size, &output, 1U,
            &count, &error) == 0 && count == 1U);
        const size_t retained = mc_stream_decoder_retained_size(decoder);
        if (retained > peak) peak = retained;
        bench_sink += output.payload.size;
    }
    mc_stream_decoder_destroy(decoder);
    return (BenchResult){compressed ? "compressed_frame_extract"
                                    : "frame_extract",
        monotonic_ns() - started, iterations, iterations * frame_size,
        allocations_since(initial_allocations, iterations), peak};
}

static BenchResult benchmark_streams(uint64_t requested, size_t stream_count)
{
    unsigned char frame[64];
    const size_t frame_size = make_plain_frame(frame, 8U);
    McStreamDecoder **decoders = calloc(stream_count, sizeof(*decoders));
    BENCH_CHECK(decoders != NULL);
    for (size_t index = 0U; index < stream_count; ++index) {
        decoders[index] = make_decoder();
    }
    uint64_t rounds = requested / stream_count;
    if (rounds == 0U) rounds = 1U;
    size_t peak = 0U;
    const uint64_t initial_allocations = benchmark_allocation_count;
    uint64_t started = monotonic_ns();
    for (uint64_t round = 0U; round < rounds; ++round) {
        for (size_t index = 0U; index < stream_count; ++index) {
            mc_stream_decoder_reset(decoders[index]);
            McDecodedFrame output;
            size_t count = 0U;
            McError error;
            BENCH_CHECK(mc_stream_decoder_feed(decoders[index], frame, frame_size,
                &output, 1U, &count, &error) == 0 && count == 1U);
            const size_t retained = mc_stream_decoder_retained_size(
                decoders[index]);
            if (retained > peak) peak = retained;
            bench_sink += output.payload.size;
        }
    }
    for (size_t index = 0U; index < stream_count; ++index) {
        mc_stream_decoder_destroy(decoders[index]);
    }
    free(decoders);
    static char names[3][32];
    const size_t slot = stream_count == 1U ? 0U : stream_count == 32U ? 1U : 2U;
    (void)snprintf(names[slot], sizeof(names[slot]), "streams_%zu", stream_count);
    const uint64_t operations = rounds * stream_count;
    return (BenchResult){names[slot], monotonic_ns() - started, operations,
        operations * frame_size,
        allocations_since(initial_allocations, operations), peak * stream_count};
}

static BenchResult benchmark_burst(uint64_t requested)
{
    unsigned char frame[64];
    const size_t one_size = make_plain_frame(frame, 1U);
    unsigned char burst[4096];
    const size_t per_burst = 64U;
    for (size_t index = 0U; index < per_burst; ++index) {
        memcpy(burst + index * one_size, frame, one_size);
    }
    McStreamDecoder *decoder = make_decoder();
    uint64_t rounds = requested / per_burst;
    if (rounds == 0U) rounds = 1U;
    size_t peak = 0U;
    const uint64_t initial_allocations = benchmark_allocation_count;
    uint64_t started = monotonic_ns();
    for (uint64_t round = 0U; round < rounds; ++round) {
        mc_stream_decoder_reset(decoder);
        McDecodedFrame frames[64];
        size_t count = 0U;
        McError error;
        BENCH_CHECK(mc_stream_decoder_feed(decoder, burst, one_size * per_burst,
            frames, per_burst, &count, &error) == 0 && count == per_burst);
        const size_t retained = mc_stream_decoder_retained_size(decoder);
        if (retained > peak) peak = retained;
        bench_sink += count;
    }
    mc_stream_decoder_destroy(decoder);
    const uint64_t operations = rounds * per_burst;
    return (BenchResult){"small_packet_burst", monotonic_ns() - started,
        operations, operations * one_size,
        allocations_since(initial_allocations, operations), peak};
}

static BenchResult benchmark_mixed_corpus(uint64_t requested)
{
    static const size_t payload_sizes[] = {1U, 8U, 32U, 128U};
    unsigned char corpus[1024];
    size_t corpus_size = 0U;
    for (size_t index = 0U;
            index < sizeof(payload_sizes) / sizeof(payload_sizes[0]); ++index) {
        corpus_size += make_plain_frame(corpus + corpus_size,
            payload_sizes[index]);
    }
    const size_t per_corpus = sizeof(payload_sizes) / sizeof(payload_sizes[0]);
    uint64_t rounds = requested / per_corpus;
    if (rounds == 0U) rounds = 1U;
    McStreamDecoder *decoder = make_decoder();
    size_t peak = 0U;
    const uint64_t initial_allocations = benchmark_allocation_count;
    uint64_t started = monotonic_ns();
    for (uint64_t round = 0U; round < rounds; ++round) {
        mc_stream_decoder_reset(decoder);
        McDecodedFrame frames[4];
        size_t count = 0U;
        McError error;
        BENCH_CHECK(mc_stream_decoder_feed(decoder, corpus, corpus_size,
            frames, per_corpus, &count, &error) == 0 && count == per_corpus);
        const size_t retained = mc_stream_decoder_retained_size(decoder);
        if (retained > peak) peak = retained;
        bench_sink += frames[3].payload.size;
    }
    mc_stream_decoder_destroy(decoder);
    const uint64_t operations = rounds * per_corpus;
    return (BenchResult){"mixed_packet_corpus", monotonic_ns() - started,
        operations, rounds * corpus_size,
        allocations_since(initial_allocations, operations), peak};
}

static void print_result(BenchResult value, bool final)
{
    const double ns_per_operation = (double)value.elapsed_ns
        / (double)value.operations;
    const double operations_per_second = (double)value.operations
        * 1.0e9 / (double)value.elapsed_ns;
    const double bytes_per_second = (double)value.bytes
        * 1.0e9 / (double)value.elapsed_ns;
    printf("{\"name\":\"%s\",\"elapsed_ns\":%" PRIu64
        ",\"operations\":%" PRIu64 ",\"bytes\":%" PRIu64
        ",\"ns_per_operation\":%.6f,\"operations_per_second\":%.6f"
        ",\"bytes_per_second\":%.6f,\"allocations_per_operation\":%.9f"
        ",\"peak_retained_bytes\":%zu}%s\n",
        value.name, value.elapsed_ns, value.operations, value.bytes,
        ns_per_operation, operations_per_second, bytes_per_second,
        value.allocations_per_operation, value.peak_retained_bytes,
        final ? "" : ",");
}

int main(int argc, char **argv)
{
    uint64_t iterations = UINT64_C(200000);
    if (argc == 2) {
        char *end = NULL;
        const unsigned long long parsed = strtoull(argv[1], &end, 10);
        if (end == argv[1] || *end != '\0' || parsed == 0U) return 2;
        iterations = (uint64_t)parsed;
    } else if (argc != 1) {
        return 2;
    }
    BenchResult results[] = {
        benchmark_varint(iterations * 4U),
        benchmark_movement_base(iterations),
        benchmark_packet(iterations, true),
        benchmark_packet(iterations, false),
        benchmark_nbt(iterations),
        benchmark_canonical(iterations),
        benchmark_frame(iterations / 4U, false),
        benchmark_frame(iterations / 16U, true),
        benchmark_streams(iterations / 2U, 1U),
        benchmark_streams(iterations / 2U, 32U),
        benchmark_streams(iterations / 2U, 256U),
        benchmark_burst(iterations),
        benchmark_mixed_corpus(iterations),
    };
    printf("{\"peak_resident_bytes\":%" PRIu64 ",\"cases\":[\n",
        peak_resident_bytes());
    const size_t count = sizeof(results) / sizeof(results[0]);
    for (size_t index = 0U; index < count; ++index) {
        print_result(results[index], index + 1U == count);
    }
    puts("]}");
    return bench_sink == UINT64_MAX ? 1 : 0;
}
