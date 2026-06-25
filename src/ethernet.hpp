#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace router {

// Fixed-size Ethernet header fields needed for frame inspection.
struct EthernetFrame {
    std::array<std::uint8_t, 6> destinationMac{};
    std::array<std::uint8_t, 6> sourceMac{};
    std::uint16_t etherType{};
};

// EtherType value for IPv4 payloads.
constexpr std::uint16_t etherTypeIpv4 = 0x0800;

// Parse a raw Ethernet frame into a structured view of the header.
std::optional<EthernetFrame> parseEthernetFrame(const std::uint8_t* data, std::size_t length);
// Format a 6-byte MAC address as colon-separated lowercase hex.
std::string formatMacAddress(const std::array<std::uint8_t, 6>& address);
// Convert an EtherType value into a human-readable label.
std::string etherTypeName(std::uint16_t etherType);

}  // namespace router
