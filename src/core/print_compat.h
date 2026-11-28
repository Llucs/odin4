#ifndef ODIN4_PRINT_COMPAT_H
#define ODIN4_PRINT_COMPAT_H

// <print> (C++23) is only shipped with GCC 14+ / recent libc++. Ubuntu 24.04 and Linux Mint 22
// ship GCC 13, whose libstdc++ has <format> but no <print>. Use the standard header when it is
// available and fall back to a tiny std::format based implementation otherwise.

#include <format>
#include <iostream>
#include <ostream>
#include <string_view>
#include <utility>

#if defined(__has_include)
#if __has_include(<print>)
#include <print>
#endif
#endif

namespace odin4 {

#if defined(__cpp_lib_print) && __cpp_lib_print >= 202207L

using std::print;
using std::println;

#else

template <typename... Args>
void print(std::ostream& os, std::format_string<Args...> fmt, Args&&... args) {
    os << std::format(fmt, std::forward<Args>(args)...);
}

template <typename... Args>
void print(std::format_string<Args...> fmt, Args&&... args) {
    std::cout << std::format(fmt, std::forward<Args>(args)...);
}

template <typename... Args>
void println(std::ostream& os, std::format_string<Args...> fmt, Args&&... args) {
    os << std::format(fmt, std::forward<Args>(args)...) << '\n';
}

template <typename... Args>
void println(std::format_string<Args...> fmt, Args&&... args) {
    std::cout << std::format(fmt, std::forward<Args>(args)...) << '\n';
}

#endif

} // namespace odin4

#endif // ODIN4_PRINT_COMPAT_H
