#include "api.h"
#include "fuzz_common.h"

#include <assert.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    McError first_error;
    McError second_error;
    McReader first;
    McReader second;
    int32_t first_int = 0;
    int32_t second_int = 0;
    int64_t first_long = 0;
    int64_t second_long = 0;
    mc_reader_init_mode(&first, data, size, MC_DECODE_STRICT, &first_error);
    mc_reader_init_mode(&second, data, size, MC_DECODE_STRICT, &second_error);
    const bool first_ok = mc_reader_varint(&first, &first_int);
    const bool second_ok = mc_reader_varint(&second, &second_int);
    assert(first_ok == second_ok);
    assert(first_error.code == second_error.code);
    assert(first.offset == second.offset);
    if (first_ok) assert(first_int == second_int);

    mc_reader_init_mode(&first, data, size, MC_DECODE_STRICT, &first_error);
    mc_reader_init_mode(&second, data, size, MC_DECODE_STRICT, &second_error);
    const bool first_long_ok = mc_reader_varlong(&first, &first_long);
    const bool second_long_ok = mc_reader_varlong(&second, &second_long);
    assert(first_long_ok == second_long_ok);
    assert(first_error.code == second_error.code);
    assert(first.offset == second.offset);
    if (first_long_ok) assert(first_long == second_long);
    return 0;
}

MC_FUZZ_MAIN(LLVMFuzzerTestOneInput)
