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
    src/arp.cpp
)

target_include_directories(router PRIVATE src)

# Only the runtime library is needed — src/pcap.h vendors the handful of
# declarations this project uses, so no libpcap-dev headers are required.
# find_library() alone only finds the unversioned "libpcap.so" symlink that
# ships with libpcap-dev; fall back to globbing for the versioned runtime
# .so (e.g. libpcap.so.1.10.4) that a plain libpcap install provides.
find_library(PCAP_LIBRARY NAMES pcap)
if(NOT PCAP_LIBRARY)
    file(GLOB PCAP_VERSIONED_CANDIDATES
        /usr/lib/*/libpcap.so.*
        /usr/lib/libpcap.so.*
        /usr/local/lib/libpcap.so.*
    )
    if(PCAP_VERSIONED_CANDIDATES)
        list(GET PCAP_VERSIONED_CANDIDATES 0 PCAP_LIBRARY)
    endif()
endif()

if(NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap runtime library not found. Install libpcap (e.g. libpcap0.8) or libpcap-dev.")
endif()

target_link_libraries(router PRIVATE ${PCAP_LIBRARY})

target_compile_options(router PRIVATE -Wall -Wextra -Wpedantic)
