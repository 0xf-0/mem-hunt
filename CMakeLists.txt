cmake_minimum_required(VERSION 3.14)
project(mem-hunt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(mem_hunt_core STATIC
    src/types.cpp
    src/process.cpp
    src/scanner.cpp
    src/pointer_scanner.cpp
    src/hex_view.cpp
)

target_include_directories(mem_hunt_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(mem_hunt_core PUBLIC psapi)

# CLI Tool
add_executable(mem-hunt src/main.cpp)
target_link_libraries(mem-hunt PRIVATE mem_hunt_core)

# Target demo application
add_executable(dummy_target example/dummy_target.cpp)
