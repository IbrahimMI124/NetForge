# PROJECT_STATE.md

> **Purpose of this file.** This is the single source of truth for the project's
> current state. It is the handoff document between planning conversations (chat)
> and implementation sessions (Claude Code). Keep it **high-signal**: structure,
> status, decisions, and open questions — not a full code dump.
>
> **Maintenance rules (for Claude Code):**
> - Update this file at the end of each work session.
> - Keep sections short. If a section grows past ~1 screen, it probably contains
>   detail that belongs in code comments or a separate doc, not here.
> - When a decision is made, add it to the Decision Log with a one-line "why".
> - When something breaks or is left unfinished, record it under Known Issues /
>   Open Questions so the next session (or the planning chat) has ground truth.
> - Prefer editing existing entries over appending duplicates.

---

## 1. What this project is

NetForge is a minimal software (userspace) IPv4 router written in modern C++.
It captures Ethernet frames on two Linux interfaces via libpcap, parses the
Ethernet and IPv4 headers, performs longest-prefix-match route lookup, decrements
TTL, recomputes the IPv4 checksum, and re-injects the packet on the chosen egress
interface through a raw IPv4 socket (kernel handles L2 delivery). It is a learning /
resume portfolio project. "Done" for v1.0 = an end-to-end ping across the router
between two network namespaces succeeds. Out of scope by design: ICMP generation,
fragmentation, and NAT.

## 2. Tech stack

- **Language(s):** C++20
- **Framework(s):** none (standalone executable)
- **Key libraries:** libpcap (packet capture), POSIX raw sockets + `<arpa/inet.h>` / `<netinet/in.h>` (transmit + byte-order helpers)
- **Runtime / tooling:** CMake (>= 3.16) build; g++/clang C++20; Linux only (network namespaces, `veth`, `SO_BINDTODEVICE`, raw sockets → needs root/CAP_NET_RAW). `setup_lab.sh` builds the test topology via `ip netns`.
- **Data / storage:** none — routing table is an in-memory `std::vector<Route>`, hardcoded at startup.

## 3. Architecture overview

```
NetForge/
├── CMakeLists.txt          # build config; C++20, -Wall -Wextra -Wpedantic, outputs ./router to repo root
├── setup_lab.sh            # creates hostA/hostB netns + veth pairs + routerA/routerB interfaces for testing
├── README.md               # build/run/test instructions (note: still titled "VirtualRouter")
├── PROJECT_STATE.md        # this file
└── src/
    ├── main.cpp            # entry point; builds demo routing table, runs self-check, starts ForwardingEngine
    ├── ethernet.{hpp,cpp}  # parse 14-byte Ethernet header; MAC + EtherType formatting
    ├── ipv4.{hpp,cpp}      # parse IPv4 header (version/IHL/TTL/proto/checksum/src/dst); address formatting
    ├── routing.{hpp,cpp}   # CIDR parsing, RoutingTable class, longest-prefix-match lookup
    ├── forwarding.{hpp,cpp}# ForwardingEngine: pcap capture loop, TTL decrement, checksum recompute, sendto
    └── pcap.h              # vendored/local libpcap header
```

**How it flows:** `main` builds a hardcoded 2-route table (`10.0.0.0/24`→ifaceA,
`20.0.0.0/24`→ifaceB), runs a startup self-check, then hands it to `ForwardingEngine`.
The engine opens a non-blocking pcap capture handle per interface and a raw
`IPPROTO_RAW` transmit socket (with `IP_HDRINCL` + `SO_BINDTODEVICE`) per interface.
The main loop busy-polls both capture sources: for each frame →
`parseEthernetFrame` (must be IPv4 EtherType) → `parseIpv4Packet` →
`routingTable.lookup(dst)` → drop if no route / same-interface / TTL≤1, otherwise
decrement TTL, zero+recompute the IPv4 checksum, and `sendto` on the egress
interface's raw socket. Verbose per-packet decisions are printed to stdout.

## 4. Status board

| Area / Feature | Status | Notes |
|----------------|--------|-------|
| Ethernet parsing | ✅ done | Fixed 14-byte header; IPv4 EtherType recognized, others labeled "Unknown" |
| IPv4 header parsing | ✅ done | Validates version==4, IHL, length; extracts TTL/proto/checksum/addrs |
| CIDR / address parsing | ✅ done | `parseIpv4Address`, `parseCidrBlock`, contiguous-mask validation |
| Routing table + LPM lookup | ✅ done | Linear scan, longest-prefix wins; add/remove supported |
| Packet capture (libpcap) | ✅ done | Per-iface non-blocking handle, promisc, immediate mode, DLT_EN10MB only |
| TTL decrement + checksum recompute | ✅ done | Drops on TTL≤1; one's-complement checksum recompute |
| Forwarding / transmit | ✅ done | Raw `IPPROTO_RAW` socket, `IP_HDRINCL`, `SO_BINDTODEVICE`, kernel does L2/ARP |
| Startup self-check | ✅ done | Proves `20.0.0.2` matches `20.0.0.0/24` via `routerB` |
| Test lab (netns topology) | ✅ done | `setup_lab.sh` builds hostA↔routerA / routerB↔hostB |
| End-to-end ping across router | 🚧 in progress | README notes ping should complete "once lab routing/namespace wiring in place" — not confirmed here |
| ICMP generation | 🕳️ not started | Out of scope for v1.0 (no TTL-expired / dest-unreachable messages) |
| Fragmentation | 🕳️ not started | Out of scope for v1.0 |
| NAT | 🕳️ not started | Out of scope for v1.0 |
| Dynamic / configurable routes | 🕳️ not started | Table is hardcoded in `main.cpp::buildDemoRoutingTable` |
| Unit tests | 🕳️ not started | No test target or framework present |
| Async pcap callback path | 🧱 stubbed | `packetHandler` + `PacketContext` defined but unused (loop uses `pcap_next_ex`) |

## 5. Decision log

| Date | Decision | Why | Alternatives considered |
|------|----------|-----|-------------------------|
| 2026-06-25 | Transmit via raw `IPPROTO_RAW` socket with `IP_HDRINCL` | Let the kernel handle ARP / L2 framing instead of building Ethernet frames + doing ARP in userspace | `AF_PACKET`/`SOCK_RAW` raw Ethernet injection with manual ARP |
| 2026-06-25 | Route lookup = linear scan over a `std::vector<Route>` | Simple, correct, table is tiny (2 routes) | Trie / Patricia tree (overkill for scope) |
| 2026-06-25 | Non-blocking pcap + busy-poll loop with 1ms sleep | Fair polling across both interfaces without threads | `select()`/`poll()` on pcap fds (headers included but not wired); per-iface threads |
| 2026-06-25 | Hardcoded demo routing table in `main.cpp` | Keep v1.0 focused on the forwarding datapath, not config | CLI/file-based route configuration |
| 2026-06-25 | Scope excludes ICMP, fragmentation, NAT | Keep v1.0 a clean minimal-router demo | Full-featured router |

## 6. Known issues

- **Naming inconsistency:** repo/project is "NetForge" but `README.md` title and prose say "VirtualRouter".
- **Hardcoded libpcap path** in `CMakeLists.txt` (`/usr/lib/x86_64-linux-gnu/libpcap.so.1.10.4`) — non-portable, will FATAL_ERROR on other distros/arches/versions. Should use `find_package`/`find_library`/pkg-config.
- **Dead code:** `ForwardingEngine::packetHandler` and the `PacketContext` struct are defined but never used (the run loop calls `pcap_next_ex` directly). `<sys/select.h>` is included but no `select()` is used.
- **Busy-poll loop** wakes every ~1ms even when idle; minor CPU spin vs. a `select()`-based wait.
- **Hardcoded routing table** — cannot route any topology other than the `10.0.0.0/24` ↔ `20.0.0.0/24` lab without recompiling.
- **No ICMP feedback** — TTL-expired and no-route packets are silently dropped (only logged to stdout), so senders get no error.
- **End-to-end ping not verified** in this session; README hedges that it works only "once the lab routing and namespace wiring are in place."

## 7. Open questions

- Should routes be configurable (CLI args / config file) instead of hardcoded?
- Should the capture loop move to `select()`/`poll()` (or threads) and drop the busy-poll + unused async callback path?
- Is minimal ICMP (time-exceeded / destination-unreachable) in scope for a future version?
- Should the build detect libpcap portably (pkg-config / `find_library`) instead of a hardcoded `.so` path?
- Is there a target for automated tests (unit tests for parsing/LPM, integration test around the netns lab)?

## 8. Next steps

1. Verify the full end-to-end datapath: run `setup_lab.sh`, `sudo ./router routerA routerB`, and `ping 20.0.0.2` from hostA; confirm bidirectional forwarding and that the ping completes.
2. Make the libpcap dependency portable in `CMakeLists.txt` (pkg-config / `find_library`) and reconcile the "VirtualRouter" vs "NetForge" naming in the README.
3. Remove or wire up the unused `packetHandler`/`PacketContext` async path and decide on busy-poll vs `select()`.
4. (Stretch) Make the routing table configurable via CLI/file, and add unit tests for Ethernet/IPv4 parsing and longest-prefix match.

---

### How I (the human) use this file

- **Before planning in chat:** paste sections 1–4, 6, 7 into the chat so the
  planning conversation has current ground truth without me re-explaining.
- **After planning in chat:** drop the agreed plan into section 8 (and any new
  decisions into section 5), then hand the file to Claude Code as the next prompt.
- **Keep it in git.** Commit it alongside code changes so its history shows how
  the plan and the project evolved together.
