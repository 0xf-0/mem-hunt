#include "mem_hunt/process.hpp"
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>

namespace mem_hunt {

    process_handle::~process_handle() {
        detach();
    }

    process_handle::process_handle(process_handle&& other) noexcept
        : handle_(other.handle_), pid_(other.pid_), name_(std::move(other.name_)) {
        other.handle_ = nullptr;
        other.pid_ = 0;
    }

    process_handle& process_handle::operator=(process_handle&& other) noexcept {
        if (this != &other) {
            detach();
            handle_ = other.handle_;
            pid_ = other.pid_;
            name_ = std::move(other.name_);
            other.handle_ = nullptr;
            other.pid_ = 0;
        }
        return *this;
    }

    std::vector<process_entry> process_handle::enumerate_processes() {
        std::vector<process_entry> list;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return list;

        PROCESSENTRY32 pe{};
        pe.dwSize = sizeof(pe);

        if (Process32First(snapshot, &pe)) {
            do {
                list.push_back({ pe.th32ProcessID, std::string(pe.szExeFile) });
            } while (Process32Next(snapshot, &pe));
        }

        CloseHandle(snapshot);
        return list;
    }

    std::optional<DWORD> process_handle::find_pid_by_name(const std::string& name) {
        auto list = enumerate_processes();
        std::string target_lower = name;
        std::transform(target_lower.begin(), target_lower.end(), target_lower.begin(), ::tolower);

        for (const auto& p : list) {
            std::string n = p.name;
            std::transform(n.begin(), n.end(), n.begin(), ::tolower);
            if (n == target_lower) {
                return p.pid;
            }
        }
        return std::nullopt;
    }

    bool process_handle::attach(DWORD pid) {
        detach();
        handle_ = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!handle_) {
            handle_ = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, pid);
        }

        if (!handle_) return false;

        pid_ = pid;
        char buf[MAX_PATH]{};
        if (GetProcessImageFileNameA(handle_, buf, MAX_PATH)) {
            std::string path(buf);
            size_t idx = path.find_last_of("\\/");
            name_ = (idx != std::string::npos) ? path.substr(idx + 1) : path;
        } else {
            name_ = "pid_" + std::to_string(pid);
        }

        return true;
    }

    bool process_handle::attach(const std::string& name) {
        auto pid = find_pid_by_name(name);
        if (!pid) return false;
        return attach(*pid);
    }

    void process_handle::detach() {
        if (handle_ && handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
            handle_ = nullptr;
        }
        pid_ = 0;
        name_.clear();
    }

    std::vector<memory_region> process_handle::get_regions(bool writable_only) const {
        std::vector<memory_region> regions;
        if (!is_valid()) return regions;

        MEMORY_BASIC_INFORMATION mbi{};
        uintptr_t current_addr = 0;

        auto modules = get_modules();

        while (VirtualQueryEx(handle_, reinterpret_cast<LPCVOID>(current_addr), &mbi, sizeof(mbi))) {
            memory_region reg;
            reg.base_address = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            reg.size = mbi.RegionSize;
            reg.protection = mbi.Protect;
            reg.state = mbi.State;
            reg.type = mbi.Type;

            for (const auto& mod : modules) {
                if (reg.base_address >= mod.base_address &&
                    reg.base_address < mod.base_address + mod.size) {
                    reg.module_name = mod.name;
                    break;
                }
            }

            if (reg.is_readable()) {
                if (!writable_only || reg.is_writable()) {
                    regions.push_back(reg);
                }
            }

            current_addr += mbi.RegionSize;
            if (current_addr < reg.base_address) break; // overflow check
        }

        return regions;
    }

    std::vector<module_info> process_handle::get_modules() const {
        std::vector<module_info> modules;
        if (!is_valid()) return modules;

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid_);
        if (snapshot == INVALID_HANDLE_VALUE) return modules;

        MODULEENTRY32 me{};
        me.dwSize = sizeof(me);

        if (Module32First(snapshot, &me)) {
            do {
                modules.push_back({
                    std::string(me.szModule),
                    reinterpret_cast<uintptr_t>(me.modBaseAddr),
                    static_cast<size_t>(me.modBaseSize),
                    std::string(me.szExePath)
                });
            } while (Module32Next(snapshot, &me));
        }

        CloseHandle(snapshot);
        return modules;
    }

    std::optional<module_info> process_handle::find_module_for_address(uintptr_t addr) const {
        auto mods = get_modules();
        for (const auto& m : mods) {
            if (addr >= m.base_address && addr < m.base_address + m.size) {
                return m;
            }
        }
        return std::nullopt;
    }

    bool process_handle::read_raw(uintptr_t addr, void* buf, size_t size) const {
        if (!is_valid() || !buf || size == 0) return false;
        SIZE_T bytes_read = 0;
        return ReadProcessMemory(handle_, reinterpret_cast<LPCVOID>(addr), buf, size, &bytes_read) && bytes_read == size;
    }

    bool process_handle::write_raw(uintptr_t addr, const void* buf, size_t size) const {
        if (!is_valid() || !buf || size == 0) return false;
        DWORD old_protect = 0;
        VirtualProtectEx(handle_, reinterpret_cast<LPVOID>(addr), size, PAGE_EXECUTE_READWRITE, &old_protect);

        SIZE_T bytes_written = 0;
        BOOL ok = WriteProcessMemory(handle_, reinterpret_cast<LPVOID>(addr), buf, size, &bytes_written);

        if (old_protect) {
            VirtualProtectEx(handle_, reinterpret_cast<LPVOID>(addr), size, old_protect, &old_protect);
        }
        return ok && bytes_written == size;
    }

    bool process_handle::set_protection(uintptr_t addr, size_t size, DWORD new_protect, DWORD* old_protect) {
        if (!is_valid()) return false;
        DWORD prev = 0;
        BOOL ok = VirtualProtectEx(handle_, reinterpret_cast<LPVOID>(addr), size, new_protect, &prev);
        if (old_protect) *old_protect = prev;
        return ok != FALSE;
    }

} // namespace mem_hunt
