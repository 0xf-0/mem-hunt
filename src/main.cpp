#include "mem_hunt/process.hpp"
#include "mem_hunt/scanner.hpp"
#include "mem_hunt/pointer_scanner.hpp"
#include "mem_hunt/hex_view.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>

void print_banner() {
    std::cout << "  _ __ ___   ___ _ __ ___        | |__  _   _ _ __ | |_  \n"
                 " | '_ ` _ \\ / _ \\ '_ ` _ \\ _____| '_ \\| | | | '_ \\| __| \n"
                 " | | | | | |  __/ | | | | |_____| | | | |_| | | | | |_  \n"
                 " |_| |_| |_|\\___|_| |_| |_|     |_| |_|\\__,_|_| |_|\\__| \n"
                 " [0xf-0] process memory scanner & pointer pathfinder     \n\n";
}

void print_help() {
    std::cout << "Commands:\n"
                 "  attach <pid|name>             Attach to process\n"
                 "  detach                        Detach from current process\n"
                 "  map                           List committed memory regions\n"
                 "  modules                       List loaded modules\n"
                 "  scan <type> <value>           Initial memory scan (e.g. scan i32 100)\n"
                 "  next <type> <val|cond>        Filter current hits (exact, increased, decreased, changed)\n"
                 "  hits [max]                    Display list of current candidate addresses\n"
                 "  hex <addr> [length]           Display hex dump at address\n"
                 "  write <addr> <type> <val>     Write value to memory\n"
                 "  ptrscan <addr> [depth] [off]  Scan for pointer chains to address\n"
                 "  reset                         Clear current scan results\n"
                 "  help                          Display command reference\n"
                 "  exit / quit                   Exit program\n\n";
}

int main(int argc, char* argv[]) {
    print_banner();

    auto proc = std::make_shared<mem_hunt::process_handle>();
    mem_hunt::memory_scanner scanner(proc);

    // Parse command line flags if provided
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--pid" && i + 1 < argc) {
            DWORD pid = static_cast<DWORD>(std::stoul(argv[++i]));
            if (proc->attach(pid)) {
                std::cout << "[+] Attached to PID " << pid << " (" << proc->get_name() << ")\n";
            }
        } else if (arg == "--name" && i + 1 < argc) {
            std::string name = argv[++i];
            if (proc->attach(name)) {
                std::cout << "[+] Attached to process " << name << " (PID: " << proc->get_pid() << ")\n";
            }
        }
    }

    std::string line;
    while (true) {
        std::cout << "mem-hunt" << (proc->is_valid() ? " [" + proc->get_name() + ":" + std::to_string(proc->get_pid()) + "]" : "") << "> ";
        if (!std::getline(std::cin, line)) break;

        std::istringstream iss(line);
        std::string cmd;
        if (!(iss >> cmd)) continue;

        if (cmd == "exit" || cmd == "quit") {
            break;
        } else if (cmd == "help") {
            print_help();
        } else if (cmd == "attach") {
            std::string target;
            if (iss >> target) {
                bool ok = false;
                if (std::all_of(target.begin(), target.end(), ::isdigit)) {
                    ok = proc->attach(static_cast<DWORD>(std::stoul(target)));
                } else {
                    ok = proc->attach(target);
                }
                if (ok) {
                    std::cout << "[+] Attached to " << proc->get_name() << " (PID: " << proc->get_pid() << ")\n";
                    scanner.reset();
                } else {
                    std::cerr << "[-] Failed to attach to target: " << target << "\n";
                }
            } else {
                std::cout << "Usage: attach <pid|name>\n";
            }
        } else if (cmd == "detach") {
            proc->detach();
            scanner.reset();
            std::cout << "[+] Detached\n";
        } else if (cmd == "map") {
            if (!proc->is_valid()) {
                std::cout << "[-] Attach to a process first\n";
                continue;
            }
            auto regions = proc->get_regions();
            std::cout << "\n" << std::left << std::setw(18) << "BASE"
                      << std::left << std::setw(12) << "SIZE (KB)"
                      << std::left << std::setw(10) << "PERMS"
                      << std::left << std::setw(24) << "MODULE" << "\n";
            std::cout << std::string(64, '-') << "\n";

            for (const auto& r : regions) {
                std::string perms = (r.is_writable() ? "RW" : (r.is_readable() ? "R" : "--"));
                if (r.is_executable()) perms += "X";

                std::cout << "0x" << std::hex << std::setw(16) << r.base_address << std::dec
                          << std::left << std::setw(12) << (r.size / 1024)
                          << std::left << std::setw(10) << perms
                          << std::left << std::setw(24) << r.module_name << "\n";
            }
            std::cout << "\nTotal regions: " << regions.size() << "\n\n";
        } else if (cmd == "modules") {
            if (!proc->is_valid()) {
                std::cout << "[-] Attach to a process first\n";
                continue;
            }
            auto mods = proc->get_modules();
            std::cout << "\n" << std::left << std::setw(18) << "BASE"
                      << std::left << std::setw(14) << "SIZE"
                      << std::left << std::setw(24) << "MODULE"
                      << std::left << "PATH\n";
            std::cout << std::string(80, '-') << "\n";

            for (const auto& m : mods) {
                std::cout << "0x" << std::hex << std::setw(16) << m.base_address << std::dec
                          << std::left << std::setw(14) << m.size
                          << std::left << std::setw(24) << m.name
                          << m.full_path << "\n";
            }
            std::cout << "\n";
        } else if (cmd == "scan") {
            if (!proc->is_valid()) {
                std::cout << "[-] Attach to a process first\n";
                continue;
            }
            std::string stype, sval;
            if (iss >> stype >> sval) {
                mem_hunt::scan_filter filter;
                filter.type = mem_hunt::parse_type(stype);
                filter.condition = mem_hunt::scan_condition::exact;

                if (filter.type == mem_hunt::data_type::i32) {
                    int32_t val = std::stoi(sval);
                    filter.target_bytes.resize(4);
                    memcpy(filter.target_bytes.data(), &val, 4);
                } else if (filter.type == mem_hunt::data_type::i64) {
                    int64_t val = std::stoll(sval);
                    filter.target_bytes.resize(8);
                    memcpy(filter.target_bytes.data(), &val, 8);
                } else if (filter.type == mem_hunt::data_type::f32) {
                    float val = std::stof(sval);
                    filter.target_bytes.resize(4);
                    memcpy(filter.target_bytes.data(), &val, 4);
                }

                std::cout << "[*] Scanning memory for " << stype << " = " << sval << "...\n";
                size_t hits = scanner.first_scan(filter);
                std::cout << "[+] First scan found: " << hits << " hits\n";
            } else {
                std::cout << "Usage: scan <type> <value>  (e.g. scan i32 100)\n";
            }
        } else if (cmd == "next") {
            if (!proc->is_valid()) {
                std::cout << "[-] Attach to a process first\n";
                continue;
            }
            std::string stype, sval;
            if (iss >> stype) {
                mem_hunt::scan_filter filter = scanner.get_filter();

                if (stype == "increased") {
                    filter.condition = mem_hunt::scan_condition::increased;
                } else if (stype == "decreased") {
                    filter.condition = mem_hunt::scan_condition::decreased;
                } else if (stype == "changed") {
                    filter.condition = mem_hunt::scan_condition::changed;
                } else if (stype == "unchanged") {
                    filter.condition = mem_hunt::scan_condition::unchanged;
                } else {
                    if (iss >> sval) {
                        filter.type = mem_hunt::parse_type(stype);
                        filter.condition = mem_hunt::scan_condition::exact;

                        if (filter.type == mem_hunt::data_type::i32) {
                            int32_t val = std::stoi(sval);
                            filter.target_bytes.resize(4);
                            memcpy(filter.target_bytes.data(), &val, 4);
                        } else if (filter.type == mem_hunt::data_type::i64) {
                            int64_t val = std::stoll(sval);
                            filter.target_bytes.resize(8);
                            memcpy(filter.target_bytes.data(), &val, 8);
                        }
                    }
                }

                std::cout << "[*] Filtering " << scanner.get_hit_count() << " hits...\n";
                size_t hits = scanner.next_scan(filter);
                std::cout << "[+] Next scan hits remaining: " << hits << "\n";
            }
        } else if (cmd == "hits") {
            size_t max_print = 20;
            size_t user_max = 0;
            if (iss >> user_max && user_max > 0) max_print = user_max;

            const auto& hits = scanner.get_hits();
            std::cout << "\nTotal hits: " << hits.size() << " (showing up to " << max_print << ")\n";
            std::cout << std::left << std::setw(18) << "ADDRESS"
                      << std::left << std::setw(16) << "VALUE (I32)"
                      << "MODULE\n";
            std::cout << std::string(54, '-') << "\n";

            size_t count = (std::min)(hits.size(), max_print);
            for (size_t i = 0; i < count; ++i) {
                const auto& h = hits[i];
                int32_t val = 0;
                if (h.current_value.size() >= 4) {
                    memcpy(&val, h.current_value.data(), 4);
                }

                auto mod = proc->find_module_for_address(h.address);
                std::string mod_str = mod ? mod->name : "[heap/dynamic]";

                std::cout << "0x" << std::hex << std::setw(16) << h.address << std::dec
                          << std::left << std::setw(16) << val
                          << mod_str << "\n";
            }
            std::cout << "\n";
        } else if (cmd == "hex") {
            if (!proc->is_valid()) {
                std::cout << "[-] Attach to a process first\n";
                continue;
            }
            std::string saddr;
            size_t len = 64;
            if (iss >> saddr) {
                uintptr_t addr = std::stoull(saddr, nullptr, 16);
                iss >> len;
                std::cout << "\n" << mem_hunt::hex_view::dump(*proc, addr, len) << "\n";
            } else {
                std::cout << "Usage: hex <hex_address> [length]\n";
            }
        } else if (cmd == "write") {
            if (!proc->is_valid()) {
                std::cout << "[-] Attach to a process first\n";
                continue;
            }
            std::string saddr, stype, sval;
            if (iss >> saddr >> stype >> sval) {
                uintptr_t addr = std::stoull(saddr, nullptr, 16);
                auto type = mem_hunt::parse_type(stype);

                bool ok = false;
                if (type == mem_hunt::data_type::i32) {
                    int32_t val = std::stoi(sval);
                    ok = proc->write(addr, val);
                } else if (type == mem_hunt::data_type::i64) {
                    int64_t val = std::stoll(sval);
                    ok = proc->write(addr, val);
                } else if (type == mem_hunt::data_type::f32) {
                    float val = std::stof(sval);
                    ok = proc->write(addr, val);
                }

                std::cout << (ok ? "[+] Memory written successfully\n" : "[-] Write failed\n");
            } else {
                std::cout << "Usage: write <hex_addr> <type> <val>\n";
            }
        } else if (cmd == "ptrscan") {
            if (!proc->is_valid()) {
                std::cout << "[-] Attach to a process first\n";
                continue;
            }
            std::string saddr;
            size_t depth = 2;
            int32_t max_off = 2048;
            if (iss >> saddr) {
                uintptr_t addr = std::stoull(saddr, nullptr, 16);
                iss >> depth >> max_off;

                std::cout << "[*] Scanning for pointer chains to 0x" << std::hex << addr << std::dec
                          << " (depth: " << depth << ", max offset: " << max_off << ")...\n";

                mem_hunt::pointer_scanner::options opts;
                opts.max_depth = depth;
                opts.max_offset = max_off;

                auto chains = mem_hunt::pointer_scanner::find_chains(*proc, addr, opts);
                std::cout << "[+] Found " << chains.size() << " pointer chains:\n";
                for (size_t i = 0; i < chains.size(); ++i) {
                    std::cout << "  [" << i + 1 << "] " << chains[i].to_string() << "\n";
                }
                std::cout << "\n";
            } else {
                std::cout << "Usage: ptrscan <hex_addr> [max_depth] [max_offset]\n";
            }
        } else if (cmd == "reset") {
            scanner.reset();
            std::cout << "[+] Scan results reset\n";
        } else {
            std::cout << "Unknown command: '" << cmd << "'. Type 'help' for command list.\n";
        }
    }

    return 0;
}
