#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <variant>

#if defined(_WIN32) || defined(_WIN64)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace mem_hunt {

    enum class data_type {
        i8,
        i16,
        i32,
        i64,
        u8,
        u16,
        u32,
        u64,
        f32,
        f64,
        str,
        hex_bytes
    };

    enum class scan_condition {
        exact,
        increased,
        decreased,
        changed,
        unchanged,
        greater_than,
        less_than,
        between
    };

    size_t get_type_size(data_type t);
    const char* type_to_string(data_type t);
    data_type parse_type(const std::string& str);

    struct memory_region {
        uintptr_t base_address = 0;
        size_t size = 0;
        DWORD protection = 0;
        DWORD state = 0;
        DWORD type = 0;
        std::string module_name;

        bool is_readable() const {
            if (state != MEM_COMMIT) return false;
            if (protection & (PAGE_NOACCESS | PAGE_GUARD)) return false;
            return (protection & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                  PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        }

        bool is_writable() const {
            if (!is_readable()) return false;
            return (protection & (PAGE_READWRITE | PAGE_WRITECOPY |
                                  PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        }

        bool is_executable() const {
            if (state != MEM_COMMIT) return false;
            return (protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                  PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        }
    };

    struct module_info {
        std::string name;
        uintptr_t base_address = 0;
        size_t size = 0;
        std::string full_path;
    };

    struct scan_hit {
        uintptr_t address = 0;
        std::vector<uint8_t> previous_value;
        std::vector<uint8_t> current_value;
    };

    struct scan_filter {
        data_type type = data_type::i32;
        scan_condition condition = scan_condition::exact;
        std::vector<uint8_t> target_bytes;
        std::vector<uint8_t> target_bytes_secondary; // for between
        bool writable_only = true;
    };

} // namespace mem_hunt
