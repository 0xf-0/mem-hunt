#pragma once

#include "mem_hunt/process.hpp"
#include "mem_hunt/types.hpp"
#include <vector>
#include <memory>
#include <functional>

namespace mem_hunt {

    class memory_scanner {
    private:
        std::shared_ptr<process_handle> process_;
        std::vector<scan_hit> hits_;
        scan_filter current_filter_;

        bool matches_condition(const uint8_t* current_buf, const uint8_t* prev_buf,
                               const scan_filter& filter, size_t type_size) const;

    public:
        memory_scanner() = default;
        explicit memory_scanner(std::shared_ptr<process_handle> proc);

        void set_process(std::shared_ptr<process_handle> proc);
        std::shared_ptr<process_handle> get_process() const { return process_; }

        size_t first_scan(const scan_filter& filter, const std::function<void(float)>& progress = nullptr);
        size_t next_scan(const scan_filter& filter, const std::function<void(float)>& progress = nullptr);

        void update_current_values();
        void reset();

        const std::vector<scan_hit>& get_hits() const { return hits_; }
        size_t get_hit_count() const { return hits_.size(); }
        const scan_filter& get_filter() const { return current_filter_; }
    };

} // namespace mem_hunt
