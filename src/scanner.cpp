#include "mem_hunt/scanner.hpp"
#include <cstring>
#include <cmath>

namespace mem_hunt {

    memory_scanner::memory_scanner(std::shared_ptr<process_handle> proc)
        : process_(std::move(proc)) {}

    void memory_scanner::set_process(std::shared_ptr<process_handle> proc) {
        process_ = std::move(proc);
        reset();
    }

    void memory_scanner::reset() {
        hits_.clear();
    }

    bool memory_scanner::matches_condition(const uint8_t* cur, const uint8_t* prev,
                                          const scan_filter& filter, size_t type_size) const {
        switch (filter.type) {
            case data_type::i32: {
                int32_t c = *reinterpret_cast<const int32_t*>(cur);
                int32_t target = *reinterpret_cast<const int32_t*>(filter.target_bytes.data());
                int32_t p = prev ? *reinterpret_cast<const int32_t*>(prev) : 0;

                switch (filter.condition) {
                    case scan_condition::exact: return c == target;
                    case scan_condition::increased: return prev && c > p;
                    case scan_condition::decreased: return prev && c < p;
                    case scan_condition::changed: return prev && c != p;
                    case scan_condition::unchanged: return prev && c == p;
                    case scan_condition::greater_than: return c > target;
                    case scan_condition::less_than: return c < target;
                    case scan_condition::between: {
                        int32_t high = *reinterpret_cast<const int32_t*>(filter.target_bytes_secondary.data());
                        return c >= target && c <= high;
                    }
                }
                break;
            }
            case data_type::i64: {
                int64_t c = *reinterpret_cast<const int64_t*>(cur);
                int64_t target = *reinterpret_cast<const int64_t*>(filter.target_bytes.data());
                int64_t p = prev ? *reinterpret_cast<const int64_t*>(prev) : 0;

                switch (filter.condition) {
                    case scan_condition::exact: return c == target;
                    case scan_condition::increased: return prev && c > p;
                    case scan_condition::decreased: return prev && c < p;
                    case scan_condition::changed: return prev && c != p;
                    case scan_condition::unchanged: return prev && c == p;
                    case scan_condition::greater_than: return c > target;
                    case scan_condition::less_than: return c < target;
                    case scan_condition::between: {
                        int64_t high = *reinterpret_cast<const int64_t*>(filter.target_bytes_secondary.data());
                        return c >= target && c <= high;
                    }
                }
                break;
            }
            case data_type::f32: {
                float c = *reinterpret_cast<const float*>(cur);
                float target = *reinterpret_cast<const float*>(filter.target_bytes.data());
                float p = prev ? *reinterpret_cast<const float*>(prev) : 0.0f;

                switch (filter.condition) {
                    case scan_condition::exact: return std::abs(c - target) < 0.0001f;
                    case scan_condition::increased: return prev && c > p;
                    case scan_condition::decreased: return prev && c < p;
                    case scan_condition::changed: return prev && std::abs(c - p) > 0.0001f;
                    case scan_condition::unchanged: return prev && std::abs(c - p) < 0.0001f;
                    case scan_condition::greater_than: return c > target;
                    case scan_condition::less_than: return c < target;
                    case scan_condition::between: {
                        float high = *reinterpret_cast<const float*>(filter.target_bytes_secondary.data());
                        return c >= target && c <= high;
                    }
                }
                break;
            }
            case data_type::f64: {
                double c = *reinterpret_cast<const double*>(cur);
                double target = *reinterpret_cast<const double*>(filter.target_bytes.data());
                double p = prev ? *reinterpret_cast<const double*>(prev) : 0.0;

                switch (filter.condition) {
                    case scan_condition::exact: return std::abs(c - target) < 0.000001;
                    case scan_condition::increased: return prev && c > p;
                    case scan_condition::decreased: return prev && c < p;
                    case scan_condition::changed: return prev && std::abs(c - p) > 0.000001;
                    case scan_condition::unchanged: return prev && std::abs(c - p) < 0.000001;
                    case scan_condition::greater_than: return c > target;
                    case scan_condition::less_than: return c < target;
                    case scan_condition::between: {
                        double high = *reinterpret_cast<const double*>(filter.target_bytes_secondary.data());
                        return c >= target && c <= high;
                    }
                }
                break;
            }
            case data_type::i16:
            case data_type::u16: {
                uint16_t c = *reinterpret_cast<const uint16_t*>(cur);
                uint16_t target = *reinterpret_cast<const uint16_t*>(filter.target_bytes.data());
                uint16_t p = prev ? *reinterpret_cast<const uint16_t*>(prev) : 0;

                switch (filter.condition) {
                    case scan_condition::exact: return c == target;
                    case scan_condition::increased: return prev && c > p;
                    case scan_condition::decreased: return prev && c < p;
                    case scan_condition::changed: return prev && c != p;
                    case scan_condition::unchanged: return prev && c == p;
                    default: return c == target;
                }
                break;
            }
            default: {
                // Byte comparison / raw buffer
                if (filter.condition == scan_condition::exact) {
                    return std::memcmp(cur, filter.target_bytes.data(), filter.target_bytes.size()) == 0;
                } else if (filter.condition == scan_condition::changed && prev) {
                    return std::memcmp(cur, prev, filter.target_bytes.size()) != 0;
                } else if (filter.condition == scan_condition::unchanged && prev) {
                    return std::memcmp(cur, prev, filter.target_bytes.size()) == 0;
                }
                break;
            }
        }
        return false;
    }

    size_t memory_scanner::first_scan(const scan_filter& filter, const std::function<void(float)>& progress) {
        reset();
        current_filter_ = filter;

        if (!process_ || !process_->is_valid()) return 0;

        auto regions = process_->get_regions(filter.writable_only);
        size_t type_size = get_type_size(filter.type);
        if (filter.type == data_type::str || filter.type == data_type::hex_bytes) {
            type_size = filter.target_bytes.size();
        }
        if (type_size == 0) return 0;

        size_t total_regions = regions.size();
        std::vector<uint8_t> buffer;

        for (size_t r = 0; r < total_regions; ++r) {
            const auto& reg = regions[r];
            if (reg.size < type_size) continue;

            buffer.resize(reg.size);
            if (!process_->read_raw(reg.base_address, buffer.data(), reg.size)) {
                continue;
            }

            size_t step = (filter.type == data_type::str || filter.type == data_type::hex_bytes) ? 1 : type_size;
            // Also allow alignment = 1 or alignment = 4
            if (step > 4) step = 4;

            for (size_t offset = 0; offset <= reg.size - type_size; offset += step) {
                const uint8_t* p = buffer.data() + offset;
                if (matches_condition(p, nullptr, filter, type_size)) {
                    scan_hit hit;
                    hit.address = reg.base_address + offset;
                    hit.previous_value.assign(p, p + type_size);
                    hit.current_value.assign(p, p + type_size);
                    hits_.push_back(hit);
                }
            }

            if (progress && total_regions > 0) {
                progress(static_cast<float>(r + 1) / total_regions);
            }
        }

        return hits_.size();
    }

    size_t memory_scanner::next_scan(const scan_filter& filter, const std::function<void(float)>& progress) {
        if (!process_ || !process_->is_valid() || hits_.empty()) return 0;

        current_filter_ = filter;
        size_t type_size = get_type_size(filter.type);
        if (filter.type == data_type::str || filter.type == data_type::hex_bytes) {
            type_size = filter.target_bytes.size();
        }

        std::vector<scan_hit> new_hits;
        new_hits.reserve(hits_.size());

        std::vector<uint8_t> cur_buf(type_size);

        for (size_t i = 0; i < hits_.size(); ++i) {
            auto& h = hits_[i];
            if (process_->read_raw(h.address, cur_buf.data(), type_size)) {
                if (matches_condition(cur_buf.data(), h.previous_value.data(), filter, type_size)) {
                    h.previous_value = h.current_value;
                    h.current_value = cur_buf;
                    new_hits.push_back(h);
                }
            }

            if (progress && (i % 1000 == 0 || i == hits_.size() - 1)) {
                progress(static_cast<float>(i + 1) / hits_.size());
            }
        }

        hits_ = std::move(new_hits);
        return hits_.size();
    }

    void memory_scanner::update_current_values() {
        if (!process_ || !process_->is_valid() || hits_.empty()) return;
        size_t type_size = get_type_size(current_filter_.type);
        std::vector<uint8_t> buf(type_size);

        for (auto& h : hits_) {
            if (process_->read_raw(h.address, buf.data(), type_size)) {
                h.current_value = buf;
            }
        }
    }

} // namespace mem_hunt
