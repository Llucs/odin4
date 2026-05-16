#include <cstdint>
#include <cstddef>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    try {
        // chamar parser PIT aqui
        // exemplo:
        // PitData pit;
        // pit.Parse(data, size);

    } catch (...) {
    }

    return 0;
}