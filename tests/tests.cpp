#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include "odin4/odin4.h"
#include "firmware/firmware_package.h"

void test_version() {
    const char* version = odin4_get_version();
    assert(version != nullptr);
    std::string v_str(version);
    assert(!v_str.empty());
    std::cout << "test_version passed: " << v_str << std::endl;
}

void test_sanitize_filename() {
    assert(sanitize_filename("recovery.img.lz4") == "recovery");
    assert(sanitize_filename("system.img") == "system");
    assert(sanitize_filename("boot.bin") == "boot");
    assert(sanitize_filename("userdata.ext4.lz4") == "userdata");
    assert(sanitize_filename("unknown.ext") == "unknown.ext");
    std::cout << "test_sanitize_filename passed" << std::endl;
}

int main() {
    try {
        test_version();
        test_sanitize_filename();
        std::cout << "All tests passed successfully!" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    }
}
