/*
 * Copyright (c) 2026 Llucs
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#ifndef ODIN4_FUZZ_UTILS_H
#define ODIN4_FUZZ_UTILS_H

#include <vector>
#include <cstdint>
#include "core/odin_types.h"

// PIT parsing for fuzzing
auto fuzz_parse_pit_bytes(PitTable& pit_table, const std::vector<unsigned char>& pit_data) -> bool;

#endif