#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <unordered_map>

namespace router {

// EtherType value for ARP payloads.
constexpr std::uint16_t etherTypeArp = 0x0806;

enum class ArpOperation : std::uint16_t {
    Request = 1,
    Reply = 2,
};

// The fields of an Ethernet/IPv4 ARP packet (RFC 826) -- the only hardware/protocol
// combination this router understands (hardware type 1, protocol type 0x0800).
struct ArpPacket {
    ArpOperation operation{};
    std::array<std::uint8_t, 6> senderMac{};
    std::uint32_t senderIp{};  // host order
    std::array<std::uint8_t, 6> targetMac{};
    std::uint32_t targetIp{};  // host order
};

// Parse the 28-byte ARP payload following the Ethernet header. Rejects anything
// that isn't Ethernet/IPv4 ARP or an unrecognized operation code.
std::optional<ArpPacket> parseArpPacket(const std::uint8_t* data, std::size_t length);
// Serialize an ARP packet into its 28-byte wire form.
std::array<std::uint8_t, 28> buildArpPacket(const ArpPacket& packet);

// IP -> MAC mappings learned from observed ARP traffic, aged out after a TTL --
// a minimal stand-in for a kernel neighbor table.
class ArpCache {
public:
    void insert(std::uint32_t ipAddress, const std::array<std::uint8_t, 6>& macAddress);
    // Returns the cached MAC, or nullopt if unresolved or expired (pruning expired entries).
    std::optional<std::array<std::uint8_t, 6>> lookup(std::uint32_t ipAddress);

private:
    struct Entry {
        std::array<std::uint8_t, 6> macAddress{};
        std::chrono::steady_clock::time_point expiresAt{};
    };

    std::unordered_map<std::uint32_t, Entry> entries_;
};

}  // namespace router
