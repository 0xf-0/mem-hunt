#include "mem_hunt/hex_view.hpp"
#include <sstream>
#include <iomanip>

namespace mem_hunt {

    std::string hex_view::dump_buffer(const uint8_t* buffer, size_t length, uintptr_t base_address) {
        if (!buffer || length == 0) return {};

        std::ostringstream ss;
        const size_t bytes_per_line = 16;

        for (size_t i = 0; i < length; i += bytes_per_line) {
            // Address column
            ss << std::hex << std::uppercase << std::setw(16) << std::setfill('0') << (base_address + i) << "  ";

            // Hex bytes column
            for (size_t j = 0; j < bytes_per_line; ++j) {
                if (i + j < length) {
                    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i + j]) << " ";
                } else {
                    ss << "   ";
                }
                if (j == 7) ss << " ";
            }

            ss << " |";

            // ASCII column
            for (size_t j = 0; j < bytes_per_line; ++j) {
                if (i + j < length) {
                    uint8_t c = buffer[i + j];
                    ss << (c >= 32 && c <= 126 ? static_cast<char>(c) : '.');
                }
            }
            ss << "|\n";
        }

        return ss.str();
    }

    std::string hex_view::dump(const process_handle& proc, uintptr_t address, size_t length) {
        if (!proc.is_valid() || length == 0) return {};
        std::vector<uint8_t> buffer(length);
        if (!proc.read_raw(address, buffer.data(), length)) {
            return "[-] Failed to read memory at 0x" + std::to_string(address) + "\n";
        }
        return dump_buffer(buffer.data(), length, address);
    }

} // namespace mem_hunt
