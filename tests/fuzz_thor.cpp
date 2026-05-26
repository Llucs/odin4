#include <cstdint>
#include <cstddef>
#include "protocol/thor_protocol.h"
#include "odin4/fuzz_utils.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    try {
        if (size >= sizeof(OdinResponseBox)) {
            OdinResponseBox rsp;
            __builtin_memcpy(&rsp, data, sizeof(rsp));
            response_from_le(rsp);
        }

        if (size >= sizeof(OdinRequestBox)) {
            OdinRequestBox rq;
            __builtin_memcpy(&rq, data, sizeof(rq));
            (void) rq.id;
            (void) rq.data;
        }
    } catch (...) {
    }
    return 0;
}
