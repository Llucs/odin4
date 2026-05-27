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

#include "test_framework.h"
#include "../src/core/odin_types.h"
#include <cstring>
#include <vector>

void test_OdinTypes_ExitCode_Values() {
    EXPECT_EQ(static_cast<int>(ExitCode::Success), 0);
    EXPECT_EQ(static_cast<int>(ExitCode::Usage), 2);
    EXPECT_EQ(static_cast<int>(ExitCode::Usb), 3);
    EXPECT_EQ(static_cast<int>(ExitCode::Firmware), 4);
    EXPECT_EQ(static_cast<int>(ExitCode::Pit), 5);
    EXPECT_EQ(static_cast<int>(ExitCode::Protocol), 6);
}
REGISTER_TEST(OdinTypes, ExitCode_Values);

void test_OdinTypes_PitEntry_Size() {
    EXPECT_EQ(sizeof(PitEntry), 132u);
}
REGISTER_TEST(OdinTypes, PitEntry_Size);

void test_OdinTypes_PitEntry_Fields() {
    PitEntry entry = PitEntry();
    EXPECT_EQ(entry.binary_type, 0u);
    EXPECT_EQ(entry.device_type, 0u);
    EXPECT_EQ(entry.identifier, 0u);
    EXPECT_EQ(entry.attributes, 0u);
    EXPECT_EQ(entry.update_attributes, 0u);
    EXPECT_EQ(entry.block_size_or_offset, 0u);
    EXPECT_EQ(entry.block_count, 0u);
    EXPECT_EQ(entry.file_offset, 0u);
    EXPECT_EQ(entry.file_size, 0u);

    for (int i = 0; i < 32; i++) {
        EXPECT_EQ(entry.partition_name[i], '\0');
        EXPECT_EQ(entry.file_name[i], '\0');
        EXPECT_EQ(entry.fota_name[i], '\0');
    }
}
REGISTER_TEST(OdinTypes, PitEntry_Fields);

void test_OdinTypes_PitEntry_SetFields() {
    PitEntry entry = PitEntry();
    entry.binary_type = 1;
    entry.device_type = 2;
    entry.identifier = 3;
    entry.attributes = 4;
    entry.update_attributes = 5;
    entry.block_size_or_offset = 4096;
    entry.block_count = 1000;
    entry.file_offset = 0;
    entry.file_size = 4096000;

    EXPECT_EQ(entry.binary_type, 1u);
    EXPECT_EQ(entry.device_type, 2u);
    EXPECT_EQ(entry.identifier, 3u);
    EXPECT_EQ(entry.attributes, 4u);
    EXPECT_EQ(entry.update_attributes, 5u);
    EXPECT_EQ(entry.block_size_or_offset, 4096u);
    EXPECT_EQ(entry.block_count, 1000u);
    EXPECT_EQ(entry.file_offset, 0u);
    EXPECT_EQ(entry.file_size, 4096000u);
}
REGISTER_TEST(OdinTypes, PitEntry_SetFields);

void test_OdinTypes_PitEntry_SetNames() {
    PitEntry entry = PitEntry();
    const char* part_name = "SYSTEM";
    const char* file_name = "system.img.lz4";
    const char* fota_name = "FOTA";

    std::memcpy(entry.partition_name, part_name, 6);
    entry.partition_name[6] = '\0';
    std::memcpy(entry.file_name, file_name, 15);
    entry.file_name[15] = '\0';
    std::memcpy(entry.fota_name, fota_name, 4);
    entry.fota_name[4] = '\0';

    EXPECT_STREQ(entry.partition_name, "SYSTEM");
    EXPECT_STREQ(entry.file_name, "system.img.lz4");
    EXPECT_STREQ(entry.fota_name, "FOTA");
}
REGISTER_TEST(OdinTypes, PitEntry_SetNames);

void test_OdinTypes_PitTable_Init() {
    PitTable table = PitTable();
    EXPECT_EQ(table.entry_count, 0u);
    EXPECT_EQ(table.header_size, 0u);
    EXPECT_EQ(table.com_tar2[0], '\0');
    EXPECT_EQ(table.cpu_bl_id[0], '\0');
    EXPECT_EQ(table.lu_count, 0u);
    EXPECT_EQ(table.reserved, 0u);
    EXPECT_EQ(table.entries.size(), 0u);
}
REGISTER_TEST(OdinTypes, PitTable_Init);

void test_OdinTypes_PitTable_AddEntry() {
    PitTable table = PitTable();
    PitEntry entry = PitEntry();
    entry.identifier = 1;
    entry.partition_name[0] = 'A';

    table.entries.push_back(entry);

    EXPECT_EQ(table.entries.size(), 1u);
    EXPECT_EQ(table.entries[0].identifier, 1u);
}
REGISTER_TEST(OdinTypes, PitTable_AddEntry);

void test_OdinTypes_PitTable_DefaultValues() {
    PitTable table = PitTable();
    table.entry_count = 10;
    table.header_size = 512;
    std::memcpy(table.com_tar2, "PIT1200", 7);
    std::memcpy(table.cpu_bl_id, "SM-S908B", 8);
    table.lu_count = 1;
    table.reserved = 0;

    EXPECT_EQ(table.entry_count, 10u);
    EXPECT_EQ(table.header_size, 512u);
    EXPECT_EQ(std::memcmp(table.com_tar2, "PIT1200\0", 8), 0);
    EXPECT_EQ(std::memcmp(table.cpu_bl_id, "SM-S908B", 8), 0);
    EXPECT_EQ(table.lu_count, 1u);
    EXPECT_EQ(table.reserved, 0u);
}
REGISTER_TEST(OdinTypes, PitTable_DefaultValues);

void test_OdinTypes_PitTable_MultipleEntries() {
    PitTable table = PitTable();

    for (uint32_t i = 0; i < 5; i++) {
        PitEntry entry = PitEntry();
        entry.identifier = i;
        table.entries.push_back(entry);
    }

    EXPECT_EQ(table.entries.size(), 5u);

    for (uint32_t i = 0; i < 5; i++) {
        EXPECT_EQ(table.entries[i].identifier, i);
    }
}
REGISTER_TEST(OdinTypes, PitTable_MultipleEntries);

void test_OdinTypes_PitEntry_Alignment() {
    EXPECT_EQ(offsetof(PitEntry, binary_type), 0u);
    EXPECT_EQ(offsetof(PitEntry, device_type), 4u);
    EXPECT_EQ(offsetof(PitEntry, identifier), 8u);
    EXPECT_EQ(offsetof(PitEntry, attributes), 12u);
    EXPECT_EQ(offsetof(PitEntry, update_attributes), 16u);
    EXPECT_EQ(offsetof(PitEntry, block_size_or_offset), 20u);
    EXPECT_EQ(offsetof(PitEntry, block_count), 24u);
    EXPECT_EQ(offsetof(PitEntry, file_offset), 28u);
    EXPECT_EQ(offsetof(PitEntry, file_size), 32u);
    EXPECT_EQ(offsetof(PitEntry, partition_name), 36u);
}
REGISTER_TEST(OdinTypes, PitEntry_Alignment);