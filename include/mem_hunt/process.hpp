#pragma once

#include "mem_hunt/types.hpp"
#include <memory>
#include <optional>
#include <vector>
#include <string>

namespace mem_hunt {

    struct process_entry {
        DWORD pid = 0;
        std::string name;
    };

    class process_handle {
    private:
        HANDLE handle_ = nullptr;
        DWORD pid_ = 0;
        std::string name_;

    public:
        process_handle() = default;
        ~process_handle();

        process_handle(const process_handle&) = delete;
        process_handle& operator=(const process_handle&) = delete;

        process_handle(process_handle&& other) noexcept;
        process_handle& operator=(process_handle&& other) noexcept;

        static std::vector<process_entry> enumerate_processes();
        static std::optional<DWORD> find_pid_by_name(const std::string& name);

        bool attach(DWORD pid);
        bool attach(const std::string& name);
        void detach();

        bool is_valid() const { return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE; }
        HANDLE get_native_handle() const { return handle_; }
        DWORD get_pid() const { return pid_; }
        const std::string& get_name() const { return name_; }

        std::vector<memory_region> get_regions(bool writable_only = false) const;
        std::vector<module_info> get_modules() const;
        std::optional<module_info> find_module_for_address(uintptr_t addr) const;

        bool read_raw(uintptr_t addr, void* buf, size_t size) const;
        bool write_raw(uintptr_t addr, const void* buf, size_t size) const;

        template <typename T>
        std::optional<T> read(uintptr_t addr) const {
            T val{};
            if (read_raw(addr, &val, sizeof(T))) {
                return val;
            }
            return std::nullopt;
        }

        template <typename T>
        bool write(uintptr_t addr, const T& val) const {
            return write_raw(addr, &val, sizeof(T));
        }

        bool set_protection(uintptr_t addr, size_t size, DWORD new_protect, DWORD* old_protect = nullptr);
    };

} // namespace mem_hunt
