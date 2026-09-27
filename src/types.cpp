#include "mem_hunt/types.hpp"
#include <algorithm>

namespace mem_hunt {

    size_t get_type_size(data_type t) {
        switch (t) {
            case data_type::i8:
            case data_type::u8:
                return 1;
            case data_type::i16:
            case data_type::u16:
                return 2;
            case data_type::i32:
            case data_type::u32:
            case data_type::f32:
                return 4;
            case data_type::i64:
            case data_type::u64:
            case data_type::f64:
                return 8;
            default:
                return 1;
        }
    }

    const char* type_to_string(data_type t) {
        switch (t) {
            case data_type::i8: return "i8";
            case data_type::i16: return "i16";
            case data_type::i32: return "i32";
            case data_type::i64: return "i64";
            case data_type::u8: return "u8";
            case data_type::u16: return "u16";
            case data_type::u32: return "u32";
            case data_type::u64: return "u64";
            case data_type::f32: return "f32";
            case data_type::f64: return "f64";
            case data_type::str: return "str";
            case data_type::hex_bytes: return "hex";
            default: return "unknown";
        }
    }

    data_type parse_type(const std::string& str) {
        std::string s = str;
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);

        if (s == "i8" || s == "byte" || s == "char") return data_type::i8;
        if (s == "i16" || s == "short") return data_type::i16;
        if (s == "i32" || s == "int" || s == "int32") return data_type::i32;
        if (s == "i64" || s == "long" || s == "int64") return data_type::i64;
        if (s == "u8") return data_type::u8;
        if (s == "u16") return data_type::u16;
        if (s == "u32" || s == "uint") return data_type::u32;
        if (s == "u64" || s == "ulong") return data_type::u64;
        if (s == "f32" || s == "float") return data_type::f32;
        if (s == "f64" || s == "double") return data_type::f64;
        if (s == "str" || s == "string") return data_type::str;
        if (s == "hex" || s == "bytes") return data_type::hex_bytes;

        return data_type::i32;
    }

} // namespace mem_hunt
