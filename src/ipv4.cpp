#include "ipv4.hpp"

#include <arpa/inet.h>

#include <array>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace router {

namespace {

// Minimum IPv4 header size without options.
constexpr std::size_t minimumIpv4HeaderLength = 20;

}  // namespace

std::optional<Ipv4Packet> parseIpv4Packet(const std::uint8_t* data, std::size_t length) {
    // Reject truncated payloads before reading any fixed header fields.
    if (data == nullptr || length < minimumIpv4HeaderLength) {
        return std::nullopt;
    }

    // The first byte contains the version and IHL fields.
    const auto version = static_cast<std::uint8_t>(data[0] >> 4U);
    const auto headerLengthWords = static_cast<std::uint8_t>(data[0] & 0x0FU);
    const auto headerLengthBytes = static_cast<std::size_t>(headerLengthWords) * 4U;

    // Only parse canonical IPv4 packets with a complete header.
    if (version != 4U || headerLengthBytes < minimumIpv4HeaderLength || length < headerLengthBytes) {
        return std::nullopt;
    }

    // Store the values used by the pretty printer.
    Ipv4Packet packet;
    packet.version = version;
    packet.headerLength = headerLengthWords;
    packet.ttl = data[8];
    packet.protocol = data[9];
    packet.checksum = static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[10]) << 8U) |
                                                static_cast<std::uint16_t>(data[11]));

    std::uint32_t sourceAddress = 0;
    std::uint32_t destinationAddress = 0;
    std::memcpy(&sourceAddress, data + 12, sizeof(sourceAddress));
    std::memcpy(&destinationAddress, data + 16, sizeof(destinationAddress));

    // Normalize to host order so routing and formatting both use the same representation.
    packet.sourceAddress = formatIpv4Address(ntohl(sourceAddress));
    packet.destinationAddress = formatIpv4Address(ntohl(destinationAddress));
    return packet;
}

std::string formatIpv4Address(std::uint32_t address) {
    std::array<char, INET_ADDRSTRLEN> buffer{};
    // Convert the host-order integer back to network order before printing.
    const std::uint32_t networkOrderAddress = htonl(address);
    const auto* converted = inet_ntop(AF_INET, &networkOrderAddress, buffer.data(), buffer.size());
    if (converted == nullptr) {
        return "0.0.0.0";
    }

    return std::string(converted);
}

std::string protocolName(std::uint8_t protocol) {
    // Translate the common protocol numbers used in introductory packet traces.
    switch (protocol) {
        case 1:
            return "ICMP";
        case 6:
            return "TCP";
        case 17:
            return "UDP";
        default: {
            std::ostringstream stream;
            stream << "Unknown (" << static_cast<int>(protocol) << ')';
            return stream.str();
        }
    }
}

}  // namespace router
