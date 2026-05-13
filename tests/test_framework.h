/*
 * Copyright (c) 2026 Llucs
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ODIN4_TESTS_TEST_FRAMEWORK_H
#define ODIN4_TESTS_TEST_FRAMEWORK_H

#include <iostream>
#include <string>
#include <vector>
#include <functional>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <cstdint>

namespace tests {

struct TestCase {
    std::string name;
    std::function<void()> func;
};

struct TestSuite {
    std::string name;
    std::vector<TestCase> tests;
    int passed = 0;
    int failed = 0;
};

inline std::vector<TestSuite>& get_suites() {
    static std::vector<TestSuite> suites;
    return suites;
}

inline void register_test(const std::string& suite_name, const std::string& test_name, std::function<void()> test_func) {
    auto& suites = get_suites();
    for (auto& s : suites) {
        if (s.name == suite_name) {
            s.tests.push_back({test_name, test_func});
            return;
        }
    }
    suites.push_back({suite_name, {{test_name, test_func}}});
}

struct TestRegister {
    TestRegister(const std::string& suite_name, const std::string& test_name, void (*test_func)()) {
        register_test(suite_name, test_name, test_func);
    }
};

#define REGISTER_TEST(suite, name) \
    static tests::TestRegister reg_##suite##_##name(#suite, #name, test_##suite##_##name)

#define EXPECT_EQ(a, b) do { \
    auto _a = (a); \
    auto _b = (b); \
    if (_a != _b) { \
        throw std::runtime_error("Expected " + std::to_string(_a) + " == " + std::to_string(_b)); \
    } \
} while(0)

#define EXPECT_NE(a, b) do { \
    auto _a = (a); \
    auto _b = (b); \
    if (_a == _b) { \
        throw std::runtime_error("Expected " + std::to_string(_a) + " != " + std::to_string(_b)); \
    } \
} while(0)

#define EXPECT_TRUE(cond) do { \
    if (!(cond)) { \
        throw std::runtime_error("Expected true but was false"); \
    } \
} while(0)

#define EXPECT_FALSE(cond) do { \
    if (cond) { \
        throw std::runtime_error("Expected false but was true"); \
    } \
} while(0)

#define EXPECT_STREQ(a, b) do { \
    std::string _a = (a); \
    std::string _b = (b); \
    if (_a != _b) { \
        throw std::runtime_error("Expected \"" + _a + "\" == \"" + _b + "\""); \
    } \
} while(0)

#define EXPECT_THROW(code) do { \
    bool _thrown = false; \
    try { \
        code; \
    } catch (...) { \
        _thrown = true; \
    } \
    if (!_thrown) { \
        throw std::runtime_error("Expected exception but none thrown"); \
    } \
} while(0)

inline int run_suite(const std::string& suite_name) {
    auto& suites = get_suites();
    int total_passed = 0;
    int total_failed = 0;
    
    for (auto& suite : suites) {
        if (!suite_name.empty() && suite.name != suite_name) {
            continue;
        }
        
        std::cout << "\n=== " << suite.name << " ===\n";
        
        for (auto& test : suite.tests) {
            try {
                test.func();
                std::cout << "[PASS] " << test.name << "\n";
                suite.passed++;
                total_passed++;
            } catch (const std::exception& e) {
                std::cout << "[FAIL] " << test.name << ": " << e.what() << "\n";
                suite.failed++;
                total_failed++;
            } catch (...) {
                std::cout << "[FAIL] " << test.name << ": unknown exception\n";
                suite.failed++;
                total_failed++;
            }
        }
    }
    
    return total_failed;
}

inline int run_all() {
    return run_suite("");
}

inline void print_summary() {
    auto& suites = get_suites();
    int total_passed = 0;
    int total_failed = 0;
    
    for (auto& s : suites) {
        total_passed += s.passed;
        total_failed += s.failed;
    }
    
    std::cout << "\n=== Summary ===\n";
    std::cout << "Passed: " << total_passed << "\n";
    std::cout << "Failed: " << total_failed << "\n";
}

}

#endif