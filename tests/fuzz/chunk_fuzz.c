#include "api.h"
#include "fuzz_common.h"

#include <assert.h>
#include <stddef.h>
#include <string.h>

typedef union {
    max_align_t alignment;
    McChunkEnvelope chunk;
} ChunkOutput;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0U) return 0;
    static const int protocols[] = {47, 340, 754, 763, 768, 776};
    const int protocol = protocols[data[0] % 6U];
    const int32_t id = mc_packet_id(protocol, MC_STATE_PLAY,
        MC_PACKET_CLIENTBOUND, "map_chunk");
    assert(id >= 0);
    ChunkOutput first;
    ChunkOutput second;
    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));
    McPacketFamily first_family = MC_FAMILY_UNKNOWN;
    McPacketFamily second_family = MC_FAMILY_UNKNOWN;
    McError first_error;
    McError second_error;
    const int first_result = mc_decode_packet(protocol, MC_STATE_PLAY,
        MC_PACKET_CLIENTBOUND, id, data + 1U, size - 1U, MC_DECODE_STRICT,
        &first, sizeof(first), &first_family, &first_error);
    const int second_result = mc_decode_packet(protocol, MC_STATE_PLAY,
        MC_PACKET_CLIENTBOUND, id, data + 1U, size - 1U, MC_DECODE_STRICT,
        &second, sizeof(second), &second_family, &second_error);
    assert(first_result == second_result);
    assert(first_family == second_family);
    assert(first_error.code == second_error.code);
    assert(first_error.offset == second_error.offset);
    if (first_result == 0) {
        assert(memcmp(&first.chunk, &second.chunk, sizeof(first.chunk)) == 0);
    }
    if (first_result == 0 && protocol >= 757) {
        McChunkSectionIterator iterator;
        if (mc_chunk_section_iterator_init(&first.chunk, protocol, 24U,
                &iterator)) {
            McChunkSectionView section;
            while (mc_chunk_section_iterator_next(&iterator, &section)) {
                int32_t state = 0;
                (void)mc_chunk_section_block_state(&section, 0U, &state);
            }
        }
    }
    return 0;
}

MC_FUZZ_MAIN(LLVMFuzzerTestOneInput)
