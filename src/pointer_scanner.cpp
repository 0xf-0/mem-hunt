#include "mem_hunt/pointer_scanner.hpp"
#include <sstream>
#include <iomanip>

namespace mem_hunt {

    std::string pointer_chain::to_string() const {
        std::ostringstream ss;
        ss << module_name << " + 0x" << std::hex << std::uppercase << base_offset;
        for (auto off : offsets) {
            ss << " -> [+" << std::dec << off << "]";
        }
        return ss.str();
    }

    std::vector<pointer_chain> pointer_scanner::find_chains(
        const process_handle& proc,
        uintptr_t target_address,
        const options& opts
    ) {
        std::vector<pointer_chain> chains;
        if (!proc.is_valid() || target_address == 0) return chains;

        auto modules = proc.get_modules();
        if (modules.empty()) return chains;

        // Level 1: Find static pointers in module memory pointing near target
        for (const auto& mod : modules) {
            std::vector<uint8_t> mod_data(mod.size);
            if (!proc.read_raw(mod.base_address, mod_data.data(), mod.size)) {
                continue;
            }

            for (size_t offset = 0; offset <= mod.size - sizeof(uintptr_t); offset += sizeof(uintptr_t)) {
                uintptr_t ptr_val = *reinterpret_cast<const uintptr_t*>(mod_data.data() + offset);
                if (ptr_val == 0) continue;

                // Direct hit (Level 1)
                int64_t diff = static_cast<int64_t>(target_address) - static_cast<int64_t>(ptr_val);
                if (diff >= -opts.max_offset && diff <= opts.max_offset) {
                    pointer_chain chain;
                    chain.module_name = mod.name;
                    chain.base_offset = offset;
                    chain.offsets.push_back(static_cast<int32_t>(diff));
                    chain.resolved_address = target_address;
                    chains.push_back(chain);

                    if (chains.size() >= opts.max_results) return chains;
                }
            }
        }

        // Level 2: Two-level pointer chain if requested and needed
        if (opts.max_depth >= 2 && chains.size() < opts.max_results) {
            auto regions = proc.get_regions(true);

            // Find heap pointers pointing to target_address
            struct IntermediatePointer {
                uintptr_t addr;
                int32_t offset;
            };
            std::vector<IntermediatePointer> intermediates;

            for (const auto& reg : regions) {
                std::vector<uint8_t> reg_buf(reg.size);
                if (!proc.read_raw(reg.base_address, reg_buf.data(), reg.size)) continue;

                for (size_t off = 0; off <= reg.size - sizeof(uintptr_t); off += sizeof(uintptr_t)) {
                    uintptr_t val = *reinterpret_cast<const uintptr_t*>(reg_buf.data() + off);
                    int64_t diff = static_cast<int64_t>(target_address) - static_cast<int64_t>(val);
                    if (diff >= -opts.max_offset && diff <= opts.max_offset) {
                        intermediates.push_back({ reg.base_address + off, static_cast<int32_t>(diff) });
                        if (intermediates.size() >= 500) break;
                    }
                }
                if (intermediates.size() >= 500) break;
            }

            // Now check if any module points to these intermediate addresses
            for (const auto& mod : modules) {
                std::vector<uint8_t> mod_data(mod.size);
                if (!proc.read_raw(mod.base_address, mod_data.data(), mod.size)) continue;

                for (const auto& inter : intermediates) {
                    for (size_t off = 0; off <= mod.size - sizeof(uintptr_t); off += sizeof(uintptr_t)) {
                        uintptr_t ptr_val = *reinterpret_cast<const uintptr_t*>(mod_data.data() + off);
                        int64_t diff = static_cast<int64_t>(inter.addr) - static_cast<int64_t>(ptr_val);
                        if (diff >= -opts.max_offset && diff <= opts.max_offset) {
                            pointer_chain chain;
                            chain.module_name = mod.name;
                            chain.base_offset = off;
                            chain.offsets.push_back(static_cast<int32_t>(diff));
                            chain.offsets.push_back(inter.offset);
                            chain.resolved_address = target_address;
                            chains.push_back(chain);

                            if (chains.size() >= opts.max_results) return chains;
                        }
                    }
                }
            }
        }

        return chains;
    }

} // namespace mem_hunt
