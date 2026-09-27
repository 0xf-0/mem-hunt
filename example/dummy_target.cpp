#include <iostream>
#include <vector>
#include <string>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#endif

struct PlayerStats {
    int32_t health = 500;
    int32_t shield = 100;
    int32_t level = 25;
};

struct Player {
    char name[32] = "ShadowOperative";
    PlayerStats stats;
};

// Global static pointer to test pointer pathfinding
Player* g_active_player = nullptr;

// Global score
int32_t g_score = 1337;

int main() {
    std::cout << "========================================\n";
    std::cout << "  mem-hunt Target Application Demo      \n";
    std::cout << "========================================\n\n";

    g_active_player = new Player();

    DWORD pid = GetCurrentProcessId();
    std::cout << "[+] Process PID: " << pid << "\n";
    std::cout << "[+] Address of g_score:        0x" << std::hex << reinterpret_cast<uintptr_t>(&g_score) << "\n";
    std::cout << "[+] Address of g_active_player: 0x" << reinterpret_cast<uintptr_t>(&g_active_player) << "\n";
    std::cout << "[+] Dynamic Player Object:     0x" << reinterpret_cast<uintptr_t>(g_active_player) << "\n";
    std::cout << "[+] Address of player health:  0x" << reinterpret_cast<uintptr_t>(&g_active_player->stats.health) << std::dec << "\n\n";

    std::cout << "Current State:\n";
    std::cout << "  g_score = " << g_score << "\n";
    std::cout << "  health  = " << g_active_player->stats.health << "\n\n";

    std::cout << "Commands:\n";
    std::cout << "  [1] Modify score (+100)\n";
    std::cout << "  [2] Damage health (-50)\n";
    std::cout << "  [3] Print current values\n";
    std::cout << "  [q] Quit\n\n";

    std::string line;
    while (true) {
        std::cout << "target> ";
        if (!std::getline(std::cin, line)) break;
        if (line == "q") break;
        if (line == "1") {
            g_score += 100;
            std::cout << "[+] g_score is now: " << g_score << "\n";
        } else if (line == "2") {
            g_active_player->stats.health -= 50;
            std::cout << "[+] health is now: " << g_active_player->stats.health << "\n";
        } else if (line == "3") {
            std::cout << "  g_score = " << g_score << " (0x" << std::hex << reinterpret_cast<uintptr_t>(&g_score) << std::dec << ")\n";
            std::cout << "  health  = " << g_active_player->stats.health << " (0x" << std::hex << reinterpret_cast<uintptr_t>(&g_active_player->stats.health) << std::dec << ")\n";
        }
    }

    delete g_active_player;
    return 0;
}
