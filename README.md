# VirtualRouter

A minimal software router in modern C++ that captures Ethernet frames on Linux, performs IPv4 longest-prefix matching, and forwards packets between interfaces with libpcap and raw IPv4 sockets.

## What it does

- Captures packets from both router interfaces
- Parses Ethernet headers
- Parses IPv4 headers
- Builds a routing table
- Demonstrates IPv4 longest-prefix matching
- Decrements TTL
- Recomputes the IPv4 checksum
- Forwards packets to the interface chosen by route lookup
- Lets the kernel handle layer-2 delivery for the forwarded IPv4 packet
- Does not implement ICMP generation, fragmentation, or NAT

## Layout

- `src/main.cpp`
- `src/ethernet.cpp`
- `src/ethernet.hpp`
- `src/ipv4.cpp`
- `src/ipv4.hpp`
- `src/routing.cpp`
- `src/routing.hpp`
- `src/forwarding.cpp`
- `src/forwarding.hpp`
- `CMakeLists.txt`

## Prerequisites

- CMake
- A C++20 compiler
- libpcap development headers
- Root access or capture capabilities

## Build

```bash
cmake -S . -B build
cmake --build build
```

The executable is written to the repository root as `./router`.

## Run

```bash
sudo ./router routerA routerB
```

On startup, the program prints a forwarding-table self-check that proves `20.0.0.2` matches `20.0.0.0/24` on `routerB`.

## Expected test flow

Terminal 1:

```bash
sudo ./router routerA routerB
```

Terminal 2:

```bash
sudo ip netns exec hostA ping 20.0.0.2
```

You should see packets received on `routerA` and `routerB`, routing decisions in both directions, TTL decrement from 64 to 63, and forwarded frames. Once the lab routing and namespace wiring are in place, hostB should answer and the ping should complete.
