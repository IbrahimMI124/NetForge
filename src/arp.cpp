#include "arp.hpp"

#include <algorithm>

namespace router {

namespace {

constexpr std::uint16_t arpHardwareTypeEthernet = 1;
constexpr std::uint16_t arpProtocolTypeIpv4 = 0x0800;
constexpr std::uint8_t arpHardwareAddressLength = 6;
constexpr std::uint8_t arpProtocolAddressLength = 4;
constexpr std::size_t arpPacketLength = 28;

// Short TTL relative to a real host's ARP cache (K&R notes ~20 min typical) so cache
// expiry is easy to observe/exercise in this lab rather than waiting.
constexpr std::chrono::seconds arpCacheTtl{60};

}  // namespace

std::optional<ArpPacket> parseArpPacket(const std::uint8_t* data, std::size_t length) {
    if (data == nullptr || length < arpPacketLength) {
        return std::nullopt;
    }

    const auto hardwareType = static_cast<std::uint16_t>((data[0] << 8U) | data[1]);
    const auto protocolType = static_cast<std::uint16_t>((data[2] << 8U) | data[3]);
    const auto hardwareLength = data[4];
    const auto protocolLength = data[5];
    const auto operation = static_cast<std::uint16_t>((data[6] << 8U) | data[7]);

    if (hardwareType != arpHardwareTypeEthernet || protocolType != arpProtocolTypeIpv4 ||
        hardwareLength != arpHardwareAddressLength || protocolLength != arpProtocolAddressLength) {
        return std::nullopt;
    }

    if (operation != static_cast<std::uint16_t>(ArpOperation::Request) &&
        operation != static_cast<std::uint16_t>(ArpOperation::Reply)) {
        return std::nullopt;
    }

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

    data[0] = static_cast<std::uint8_t>(arpHardwareTypeEthernet >> 8U);
    data[1] = static_cast<std::uint8_t>(arpHardwareTypeEthernet & 0xFFU);
    data[2] = static_cast<std::uint8_t>(arpProtocolTypeIpv4 >> 8U);
    data[3] = static_cast<std::uint8_t>(arpProtocolTypeIpv4 & 0xFFU);
    data[4] = arpHardwareAddressLength;
    data[5] = arpProtocolAddressLength;

    const auto operation = static_cast<std::uint16_t>(packet.operation);
    data[6] = static_cast<std::uint8_t>(operation >> 8U);
    data[7] = static_cast<std::uint8_t>(operation & 0xFFU);

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
