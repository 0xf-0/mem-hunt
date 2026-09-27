# mem-hunt

fast multi-threaded process memory scanner, pointer pathfinder & live hex inspector in c++17.

provides an interactive terminal environment and c++17 engine for reverse engineering, memory scanning, pointer chain traversal, and live memory inspection on windows.

### features

- **multi-threaded memory scanning**: scans committed memory pages across processes with configurable alignments and multi-pass filtering (`exact`, `increased`, `decreased`, `changed`, `unchanged`, `between`, `greater_than`, `less_than`).
- **supported types**: `i8`, `i16`, `i32`, `i64`, `u8`, `u16`, `u32`, `u64`, `f32`, `f64`, `str`, `hex`.
- **pointer pathfinder (pointer scanner)**: resolves static multi-level pointer chains (`module.dll + offset1 -> [offset2] -> target`) to handle dynamic heap allocations across process restarts.
- **interactive repl shell**: comprehensive command prompt with memory map visualizer, live candidate listing, memory freezing/poking, and safe memory writing.
- **live hex viewer**: formatted 16-byte hex dump with printable ascii sidebar and memory protection awareness.
- **zero external dependencies**: pure c++17 and win32 api.

### interactive commands

```text
  attach <pid|name>             attach to target process by pid or image name
  detach                        detach from current process
  map                           display virtual memory map (base, size, perms, module)
  modules                       list loaded pe modules and base addresses
  scan <type> <value>           run initial memory scan (e.g. scan i32 100)
  next <type> <val|condition>   filter hits (exact, increased, decreased, changed)
  hits [max]                    display candidate addresses and live values
  hex <addr> [length]           inspect memory in formatted hex dump
  write <addr> <type> <val>     safe memory write with virtualprotect handling
  ptrscan <addr> [depth] [off]  trace static pointer chains to dynamic address
  reset                         clear current scan session
  help                          display command reference
  exit / quit                   terminate session
```

### example session

```text
  _ __ ___   ___ _ __ ___        | |__  _   _ _ __ | |_  
 | '_ ` _ \ / _ \ '_ ` _ \ _____| '_ \| | | | '_ \| __| 
 | | | | | |  __/ | | | | |_____| | | | |_| | | | | |_  
 |_| |_| |_|\___|_| |_| |_|     |_| |_|\__,_|_| |_|\__| 
 [0xf-0] process memory scanner & pointer pathfinder     

mem-hunt> attach game.exe
[+] Attached to game.exe (PID: 14208)

mem-hunt [game.exe:14208]> scan i32 100
[*] Scanning memory for i32 = 100...
[+] First scan found: 312 hits

mem-hunt [game.exe:14208]> next i32 150
[*] Filtering 312 hits...
[+] Next scan hits remaining: 1

mem-hunt [game.exe:14208]> hits
Total hits: 1
ADDRESS           VALUE (I32)     MODULE
------------------------------------------------------
0x7ff6945f6000    150             game.exe

mem-hunt [game.exe:14208]> hex 0x7ff6945f6000 32
00007FF6945F6000  96 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00007FF6945F6010  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

mem-hunt [game.exe:14208]> ptrscan 0x213c5128b20 2 2048
[*] Scanning for pointer chains to 0x213c5128b20 (depth: 2, max offset: 2048)...
[+] Found pointer chain:
  [1] game.exe + 0x6160 -> [+32]
```

### c++ api usage

```cpp
#include <mem_hunt/process.hpp>
#include <mem_hunt/scanner.hpp>
#include <iostream>

int main() {
    auto proc = std::make_shared<mem_hunt::process_handle>();
    if (!proc->attach("target.exe")) return 1;

    mem_hunt::memory_scanner scanner(proc);
    
    mem_hunt::scan_filter filter;
    filter.type = mem_hunt::data_type::i32;
    filter.condition = mem_hunt::scan_condition::exact;
    int32_t val = 1337;
    filter.target_bytes.assign(reinterpret_cast<uint8_t*>(&val), reinterpret_cast<uint8_t*>(&val) + 4);

    size_t hits = scanner.first_scan(filter);
    std::cout << "found " << hits << " hits\n";

    return 0;
}
```

### build

```bash
cmake -B build
cmake --build build --config Release
```

### license

mit
