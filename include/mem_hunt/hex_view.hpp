#pragma once

#include "mem_hunt/process.hpp"
#include <string>
#include <vector>

namespace mem_hunt {

    class hex_view {
    public:
        static std::string dump(const process_handle& proc, uintptr_t address, size_t length = 128);
        static std::string dump_buffer(const uint8_t* buffer, size_t length, uintptr_t base_address = 0);
    };

} // namespace mem_hunt
