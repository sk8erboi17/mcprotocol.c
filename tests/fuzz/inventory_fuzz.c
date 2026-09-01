#include "api.h"
#include "fuzz_common.h"

#include <assert.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0U) return 0;
    size_t protocol_count = 0U;
    const int *protocols = mc_supported_protocols(&protocol_count);
    const int protocol = protocols[(size_t)data[0] % protocol_count];
    const McItemWireKind kind = (McItemWireKind)(data[0] % 3U);
    McReader first;
    McReader second;
    McError first_error;
    McError second_error;
    McItemStackView first_item;
    McItemStackView second_item;
    mc_reader_init_mode(&first, data + 1U, size - 1U, MC_DECODE_STRICT,
        &first_error);
    mc_reader_init_mode(&second, data + 1U, size - 1U, MC_DECODE_STRICT,
        &second_error);
    const bool first_ok = mc_reader_item_stack(&first, protocol, kind,
        &first_item) && mc_reader_finish(&first);
    const bool second_ok = mc_reader_item_stack(&second, protocol, kind,
        &second_item) && mc_reader_finish(&second);
    assert(first_ok == second_ok);
    assert(first.offset == second.offset);
    assert(first_error.code == second_error.code);
    if (first_ok) {
        assert(first_item.present == second_item.present);
        assert(first_item.encoded.size == second_item.encoded.size);
        assert(memcmp(&first_item, &second_item, sizeof(first_item)) == 0);
    }
    return 0;
}

MC_FUZZ_MAIN(LLVMFuzzerTestOneInput)
