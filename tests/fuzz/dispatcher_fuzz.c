#include "api.h"
#include "fuzz_common.h"

#include <assert.h>
#include <stddef.h>
#include <string.h>

typedef union {
    max_align_t alignment;
    unsigned char bytes[4096];
} AlignedOutput;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 4U) return 0;
    size_t protocol_count = 0U;
    const int *protocols = mc_supported_protocols(&protocol_count);
    const int protocol = protocols[(size_t)data[0] % protocol_count];
    const size_t count = mc_packet_count(protocol);
    if (count == 0U) return 0;
    McPacketInfo info;
    assert(mc_packet_at(protocol, (size_t)data[3] % count, &info));
    AlignedOutput first;
    AlignedOutput second;
    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));
    McPacketFamily first_family = MC_FAMILY_UNKNOWN;
    McPacketFamily second_family = MC_FAMILY_UNKNOWN;
    McError first_error;
    McError second_error;
    const int first_result = mc_decode_packet(protocol, info.state,
        info.direction,
        info.id, data + 4U, size - 4U, MC_DECODE_STRICT, &first,
        sizeof(first), &first_family, &first_error);
    const int second_result = mc_decode_packet(protocol, info.state,
        info.direction,
        info.id, data + 4U, size - 4U, MC_DECODE_STRICT, &second,
        sizeof(second), &second_family, &second_error);
    assert(first_result == second_result);
    assert(first_family == second_family);
    assert(first_error.code == second_error.code);
    assert(first_error.offset == second_error.offset);
    if (first_result == 0) assert(memcmp(&first, &second, sizeof(first)) == 0);
    return 0;
}

MC_FUZZ_MAIN(LLVMFuzzerTestOneInput)
