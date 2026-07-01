# STUDY_GUIDE.md

> Curated list of the algorithms and code blocks in this repo most worth studying
> as a network engineer — what each one is, where it lives, and why it matters
> beyond "it compiles." Ordered roughly by conceptual priority, not file order.

---

## 1. Longest-prefix-match (LPM) route lookup

**Where:** `src/routing.cpp:126-143` (`RoutingTable::lookup`)

```cpp
for (const auto& route : routes_) {
    if ((destination & route.mask) != route.network) continue;
    const auto prefixLength = prefixLengthFromMask(route.mask);
    if (!bestRoute.has_value() || prefixLength > bestPrefixLength) {
        bestRoute = route;
        bestPrefixLength = prefixLength;
    }
}
```

**Why study it:** This is *the* core algorithm every IP router runs on every
packet, and this is the simplest possible correct implementation of it — a
linear scan that keeps the most-specific (highest prefix length) match. Real
routers (Linux kernel FIB, hardware ASICs, BGP routers with 900k+ routes) can't
afford O(n) per lookup, so they use tries (Patricia/radix trees), multibit
tries, or TCAM in hardware. Understanding this loop first makes the *reason*
those structures exist ("we need this same decision, but in O(prefix bits) or
O(1) instead of O(routes)") concrete instead of abstract. Good exercise: reimplement
this as a binary trie and compare.

**Also study alongside it:**
- `maskFromPrefixLength` / `isContiguousMask` (`routing.cpp:19-40`) — the bit
  tricks for turning `/24` into `0xFFFFFF00` and validating a mask is a legal
  contiguous CIDR mask (not `255.0.255.0`). The `(~mask & (~mask+1)) == 0`
  contiguity check is a classic "isolate lowest set bit" trick worth knowing cold.

---

## 2. IPv4 header checksum (one's-complement)

**Where:** `src/forwarding.cpp:87-100` (`computeIpv4HeaderChecksum`)

```cpp
std::uint32_t sum = 0;
for (...) sum += (16-bit big-endian word);
while ((sum >> 16U) != 0U) sum = (sum & 0xFFFFU) + (sum >> 16U);
return static_cast<std::uint16_t>(~sum);
```

**Why study it:** Every protocol you'll ever debug with Wireshark that says
"checksum incorrect" traces back to this exact algorithm (IPv4, and the
pseudo-header variant used by TCP/UDP/ICMP). The two things worth internalizing:
(1) it's a ones'-complement sum, so 16-bit carries wrap *back into the sum*
(the `while` loop folding `sum >> 16` back in) rather than being discarded —
that's what makes it a checksum instead of a simple additive hash; (2) the
checksum field itself must be zeroed before recomputing (`forwarding.cpp:288-289`)
because the field is part of the range being summed. This is the single most
transferable piece of protocol-implementation knowledge in the codebase.

---

## 3. TTL decrement + "why checksum must be redone here"

**Where:** `src/forwarding.cpp:274-293` (inside `handlePacket`)

**Why study it:** This is the smallest possible illustration of a rule that
trips people up: *any* field mutation in an IP header invalidates its checksum,
so TTL decrement and checksum recompute are inseparable — you cannot forward a
packet correctly by only doing one. Also worth noting the drop conditions
around it: TTL ≤ 1 is dropped (`forwarding.cpp:275`) rather than decremented to
0 and forwarded — this is the mechanism `traceroute` exploits (a real router
would ICMP a Time-Exceeded back; this project explicitly documents that it
doesn't, see README/PROJECT_STATE Known Issues). Understanding *what's missing*
here (no ICMP Time-Exceeded) is as instructive as what's present.

---

## 4. Ethernet + IPv4 header parsing (wire format → struct)

**Where:** `src/ethernet.cpp:9-23` (`parseEthernetFrame`), `src/ipv4.cpp:19-53` (`parseIpv4Packet`)

**Why study it:** These two functions are a compact reference for "how do you
actually read a packet off the wire byte-by-byte" — the kind of code you'd
otherwise only see buried inside Wireshark/libpcap dissectors or the Linux
kernel. Specific details worth internalizing:
- **Fixed offsets, not a bitfield struct:** dest MAC (0-5), src MAC (6-11),
  EtherType (12-13) — manual byte indexing is used instead of `#pragma pack`
  struct overlay, which avoids UB from strict-aliasing/alignment violations on
  network buffers. This is the *correct* way to parse wire formats in C++, and
  worth contrasting with the tempting-but-wrong `reinterpret_cast<Header*>(buf)`.
- **Version/IHL packed into one byte:** `data[0] >> 4` = version, `data[0] & 0x0F`
  = IHL in 32-bit words, `× 4` for byte length (`ipv4.cpp:26-28`). This nibble-packing
  is standard across IP/TCP headers (see also TCP data offset) — recognizing the
  pattern once means recognizing it everywhere.
- **Network byte order:** `ntohl`/`htonl` calls at the parse/format boundary
  (`ipv4.cpp:50-51`, `58`) show exactly where the "wire is big-endian, host may not
  be" conversion has to happen, and — importantly — *only there*. The rest of the
  codebase works in host order consistently, which is the discipline to copy.

---

## 5. CIDR string parsing → normalized network address

**Where:** `src/routing.cpp:61-91` (`parseCidrBlock`)

**Why study it:** Shows the full pipeline of turning `"10.1.1.5/24"` into a
canonical route (`network=10.1.1.0, mask=/24`), including the easy-to-forget
step: `network = *address & mask` (`routing.cpp:88`) — masking off host bits
even if the input had them set (a `/24` written as `10.1.1.5/24` should
normalize to `10.1.1.0/24`). This is exactly the kind of input-sanitization
question that comes up when writing config parsers for real router/firewall
config (Cisco/Juniper/iptables all silently or explicitly normalize this).

---

## 6. Raw socket transmit setup: `IP_HDRINCL` + `SO_BINDTODEVICE`

**Where:** `src/forwarding.cpp:61-85` (`openTransmitSocket`)

```cpp
socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
setsockopt(..., IPPROTO_IP, IP_HDRINCL, ...);
setsockopt(..., SOL_SOCKET, SO_BINDTODEVICE, interfaceName, ...);
```

**Why study it:** This is the architectural decision that lets the whole
project avoid writing an ARP implementation. `IP_HDRINCL` tells the kernel "I'm
supplying the full IP header myself, don't build one," while `SO_BINDTODEVICE`
pins egress to a specific interface — but critically, the kernel *still*
builds the Ethernet frame and resolves the next-hop MAC via its own ARP table.
This is the standard technique tools like `hping3`/`scapy` (in raw mode) use,
and it's worth comparing mentally against the alternative (`AF_PACKET` +
manual Ethernet header + your own ARP cache), which is what a "real" router
reimplementation (or a project's v2) would need to add if it stopped
delegating L2 to the kernel.

---

## 7. Non-blocking multi-interface capture loop

**Where:** `src/forwarding.cpp:158-215` (`pollCaptureSource`, `run`)

**Why study it:** A minimal but correct pattern for servicing multiple pcap
handles fairly without threads: each interface's handle is set non-blocking
(`pcap_setnonblock`, `forwarding.cpp:149`), and the main loop round-robins
`pcap_next_ex` across all of them, only sleeping when *neither* had data
(`forwarding.cpp:202-210`). This is worth studying specifically *because* it's
not how you'd do it in production (`select()`/`epoll()` on `pcap_get_selectable_fd()`
would avoid the busy-wait / 1ms sleep tradeoff) — the gap between this loop and
an event-driven one is a concrete, well-scoped improvement exercise (see
PROJECT_STATE.md §7 open questions).

---

## Suggested study order

1. Read `ipv4.cpp` + `ethernet.cpp` parsing first — establishes the wire-format vocabulary.
2. Then `routing.cpp` — LPM lookup and CIDR parsing, the "control plane" logic.
3. Then `forwarding.cpp` — where parsing + routing decisions meet the actual
   forward/drop path, checksum, and raw-socket transmit ("data plane").
4. Finally, use PROJECT_STATE.md §6/§7 (Known Issues / Open Questions) as a
   worklist: reimplementing LPM as a trie, adding ICMP Time-Exceeded, and
   switching the capture loop to `select()` are all natural next exercises that
   build directly on the algorithms above.
