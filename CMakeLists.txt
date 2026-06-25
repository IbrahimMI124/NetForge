cmake_minimum_required(VERSION 3.16)

project(router LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR})

add_executable(router
    src/main.cpp
    src/ethernet.cpp
    src/ipv4.cpp
    src/routing.cpp
    src/forwarding.cpp
)

target_include_directories(router PRIVATE src)

set(PCAP_LIBRARY_PATH /usr/lib/x86_64-linux-gnu/libpcap.so.1.10.4)
if(NOT EXISTS ${PCAP_LIBRARY_PATH})
    message(FATAL_ERROR "libpcap shared library not found at ${PCAP_LIBRARY_PATH}")
endif()

target_link_libraries(router PRIVATE ${PCAP_LIBRARY_PATH})

target_compile_options(router PRIVATE -Wall -Wextra -Wpedantic)
