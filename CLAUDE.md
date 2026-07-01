# CLAUDE.md

<!--
  This file is read automatically by Claude Code at the start of every session in
  this repository. It is where the project's rules, architecture, and conventions
  are "locked in" so they don't have to be re-explained each time. It is committed
  to git, so it is shared with anyone who clones the repo.

  Keep it high-signal: rules that should ALWAYS apply, and a map of the codebase.
  Detailed status goes in PROJECT_STATE.md; study notes go in STUDY_GUIDE.md.
-->

## Project

NetForge — a minimal userspace IPv4 router in modern C++ (C++20). It captures
Ethernet frames on two Linux interfaces via libpcap, does longest-prefix-match
routing, decrements TTL, recomputes the IPv4 checksum, and re-injects packets on
the chosen egress interface through a raw IPv4 socket (the kernel handles L2/ARP).
This is a learning and portfolio project — clarity and correctness matter more
than performance or feature completeness.

## Companion docs (read/maintain these)

- **PROJECT_STATE.md** — living source of truth: status board, decision log,
  known issues, open questions, next steps.
- **STUDY_GUIDE.md** — the algorithms/code blocks worth studying, with `file:line`
  references and why each matters.

**Rule: keep both current.** After any meaningful code or structure change,
update PROJECT_STATE.md (status/decisions/issues) and STUDY_GUIDE.md (if a
referenced code block or line moved). Do this proactively, before ending a task.

## Build & run

```bash
cmake -S . -B build       # configure
cmake --build build       # compiles ./router into the repo root
sudo ./setup_lab.sh       # builds the netns test topology (hostA/routerA, routerB/hostB)
sudo ./router routerA routerB   # run the router (needs root / CAP_NET_RAW)
```

Test the datapath:
```bash
sudo ip netns exec hostA ping 20.0.0.2   # should traverse the router to hostB
```

## Architecture map

```
src/
├── main.cpp            # entry point: builds demo routing table, self-check, starts engine
├── ethernet.{hpp,cpp}  # parse 14-byte Ethernet header; MAC/EtherType formatting
├── ipv4.{hpp,cpp}      # parse IPv4 header; address formatting; byte-order conversion
├── routing.{hpp,cpp}   # CIDR parsing + RoutingTable + longest-prefix-match lookup (control plane)
└── forwarding.{hpp,cpp}# ForwardingEngine: pcap capture loop, TTL, checksum, raw-socket transmit (data plane)
```

Flow: capture (libpcap) → parse Ethernet → parse IPv4 → route lookup (LPM) →
drop or (decrement TTL → recompute checksum → sendto on egress raw socket).

## Conventions & rules

- **C++20**, built with `-Wall -Wextra -Wpedantic`. Keep it warning-clean.
- **Namespace:** all router code lives in `namespace router`.
- **Naming:** `camelCase` for functions/variables, `PascalCase` for types, trailing
  underscore for private members (`routes_`). Match the surrounding style.
- **Wire-format parsing:** read packets by explicit byte offsets (as the existing
  code does). Do NOT `reinterpret_cast` a raw buffer to a packed header struct —
  it's undefined behavior on alignment/aliasing grounds.
- **Byte order:** convert (`ntohl`/`htonl`) only at the parse/format boundary;
  keep everything internal in host order.
- **Scope guardrails (v1.0):** no ICMP generation, no fragmentation, no NAT. If a
  task would add one of these, flag it and confirm before expanding scope.
- **Comments:** explain *why*, matching the existing density — the code is meant
  to be read and studied, not just run.

## Git

- Don't commit or push unless asked.
- `build/` and the `router` binary are gitignored — never commit them.
- When asked to commit, end commit messages with the Co-Authored-By trailer.

## Naming note (known inconsistency)

The project is **NetForge**, but `README.md` still refers to it as "VirtualRouter".
Treat "NetForge" as the canonical name until the README is reconciled.
