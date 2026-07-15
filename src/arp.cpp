#include "arp.hpp"

#include <algorithm>

namespace router {

namespace {

constexpr std::uint16_t arpHardwareTypeEthernet = 1;
constexpr std::uint16_t arpProtocolTypeIpv4 = 0x0800;
constexpr std::uint8_t arpHardwareAddressLength = 6;
constexpr std::uint8_t arpProtocolAddressLength = 4;
constexpr std::size_t arpPacketLength = 28;

// Temporary: shortened to 5s for testing expiry behavior (normally 60s, see PROJECT_STATE.md).
// Drop back to 60 once cache expiry is confirmed working.
constexpr std::chrono::seconds arpCacheTtl{5};

}  // namespace

std::optional<ArpPacket> parseArpPacket(const std::uint8_t* data, std::size_t length) {
    // Reject truncated payloads before reading any fixed fields.
    if (data == nullptr || length < arpPacketLength) {
        return std::nullopt;
    }

    // Only accept the one hardware/protocol combination this router understands:
    // Ethernet (type 1) carrying IPv4 (type 0x0800) addresses.
    const auto hardwareType = static_cast<std::uint16_t>((data[0] << 8U) | data[1]);
    const auto protocolType = static_cast<std::uint16_t>((data[2] << 8U) | data[3]);
    const auto hardwareLength = data[4];
    const auto protocolLength = data[5];
    const auto operation = static_cast<std::uint16_t>((data[6] << 8U) | data[7]);

    if (hardwareType != arpHardwareTypeEthernet || protocolType != arpProtocolTypeIpv4 ||
        hardwareLength != arpHardwareAddressLength || protocolLength != arpProtocolAddressLength) {
        return std::nullopt;
    }

    // Only request/reply are defined operations we act on (RFC 826 also permits
    // RARP-style codes we have no use for here).
    if (operation != static_cast<std::uint16_t>(ArpOperation::Request) &&
        operation != static_cast<std::uint16_t>(ArpOperation::Reply)) {
        return std::nullopt;
    }

    // Sender/target MAC and IP occupy fixed byte ranges after the 8-byte header;
    // addresses are big-endian on the wire, hence the manual shift-and-OR.
    ArpPacket packet;
    packet.operation = static_cast<ArpOperation>(operation);
    std::copy_n(data + 8, packet.senderMac.size(), packet.senderMac.begin());
    packet.senderIp = (static_cast<std::uint32_t>(data[14]) << 24U) | (static_cast<std::uint32_t>(data[15]) << 16U) |
                      (static_cast<std::uint32_t>(data[16]) << 8U) | static_cast<std::uint32_t>(data[17]);
    std::copy_n(data + 18, packet.targetMac.size(), packet.targetMac.begin());
    packet.targetIp = (static_cast<std::uint32_t>(data[24]) << 24U) | (static_cast<std::uint32_t>(data[25]) << 16U) |
                      (static_cast<std::uint32_t>(data[26]) << 8U) | static_cast<std::uint32_t>(data[27]);

    return packet;
}

std::array<std::uint8_t, 28> buildArpPacket(const ArpPacket& packet) {
    std::array<std::uint8_t, arpPacketLength> data{};

    // Fixed header: hardware/protocol type and address-length fields never vary
    // for the Ethernet/IPv4 case this router speaks.
    data[0] = static_cast<std::uint8_t>(arpHardwareTypeEthernet >> 8U);
    data[1] = static_cast<std::uint8_t>(arpHardwareTypeEthernet & 0xFFU);
    data[2] = static_cast<std::uint8_t>(arpProtocolTypeIpv4 >> 8U);
    data[3] = static_cast<std::uint8_t>(arpProtocolTypeIpv4 & 0xFFU);
    data[4] = arpHardwareAddressLength;
    data[5] = arpProtocolAddressLength;

    const auto operation = static_cast<std::uint16_t>(packet.operation);
    data[6] = static_cast<std::uint8_t>(operation >> 8U);
    data[7] = static_cast<std::uint8_t>(operation & 0xFFU);

    // Mirror of parseArpPacket's layout: sender fields, then target fields, IPs
    // written big-endian to match the wire format.
    std::copy_n(packet.senderMac.begin(), packet.senderMac.size(), data.begin() + 8);
    data[14] = static_cast<std::uint8_t>(packet.senderIp >> 24U);
    data[15] = static_cast<std::uint8_t>(packet.senderIp >> 16U);
    data[16] = static_cast<std::uint8_t>(packet.senderIp >> 8U);
    data[17] = static_cast<std::uint8_t>(packet.senderIp & 0xFFU);

    std::copy_n(packet.targetMac.begin(), packet.targetMac.size(), data.begin() + 18);
    data[24] = static_cast<std::uint8_t>(packet.targetIp >> 24U);
    data[25] = static_cast<std::uint8_t>(packet.targetIp >> 16U);
    data[26] = static_cast<std::uint8_t>(packet.targetIp >> 8U);
    data[27] = static_cast<std::uint8_t>(packet.targetIp & 0xFFU);

    return data;
}

void ArpCache::insert(std::uint32_t ipAddress, const std::array<std::uint8_t, 6>& macAddress) {
    entries_[ipAddress] = Entry{macAddress, std::chrono::steady_clock::now() + arpCacheTtl};
}

std::optional<std::array<std::uint8_t, 6>> ArpCache::lookup(std::uint32_t ipAddress) {
    const auto iterator = entries_.find(ipAddress);
    if (iterator == entries_.end()) {
        return std::nullopt;
    }

    if (std::chrono::steady_clock::now() >= iterator->second.expiresAt) {
        entries_.erase(iterator);
        return std::nullopt;
    }

    return iterator->second.macAddress;
}

}  // namespace router
