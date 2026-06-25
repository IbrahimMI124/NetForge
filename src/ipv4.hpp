#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace router {

// The IPv4 fields we need to inspect and print from a packet header.
struct Ipv4Packet {
    std::uint8_t version{};
    std::uint8_t headerLength{};
    std::uint8_t ttl{};
    std::uint8_t protocol{};
    std::uint16_t checksum{};
    std::string sourceAddress;
    std::string destinationAddress;
};

// Parse the IPv4 header from the payload portion of an Ethernet frame.
std::optional<Ipv4Packet> parseIpv4Packet(const std::uint8_t* data, std::size_t length);
// Convert a network-order IPv4 address to dotted-decimal text.
std::string formatIpv4Address(std::uint32_t address);
// Map the protocol byte to the standard transport protocol name.
std::string protocolName(std::uint8_t protocol);

}  // namespace router
