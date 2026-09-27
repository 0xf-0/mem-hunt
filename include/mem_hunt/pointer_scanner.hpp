#pragma once

#include "mem_hunt/process.hpp"
#include <vector>
#include <string>
#include <memory>

namespace mem_hunt {

    struct pointer_chain {
        std::string module_name;
        uintptr_t base_offset = 0;
        std::vector<int32_t> offsets;
        uintptr_t resolved_address = 0;

        std::string to_string() const;
    };

    class pointer_scanner {
    public:
        struct options {
            size_t max_depth = 2;
            int32_t max_offset = 2048;
            size_t max_results = 50;
        };

        static std::vector<pointer_chain> find_chains(
            const process_handle& proc,
            uintptr_t target_address,
            const options& opts = {}
        );
    };

} // namespace mem_hunt
