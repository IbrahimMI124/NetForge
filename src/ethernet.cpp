#include "ethernet.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace router {

std::optional<EthernetFrame> parseEthernetFrame(const std::uint8_t* data, std::size_t length) {
    // Ethernet headers are always 14 bytes before any payload begins.
    constexpr std::size_t ethernetHeaderLength = 14;
    if (data == nullptr || length < ethernetHeaderLength) {
        return std::nullopt;
    }

    // Copy the fixed header fields out of the raw capture buffer.
    EthernetFrame frame;
    std::copy_n(data, frame.destinationMac.size(), frame.destinationMac.begin());
    std::copy_n(data + frame.destinationMac.size(), frame.sourceMac.size(), frame.sourceMac.begin());
    frame.etherType = static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[12]) << 8U) |
                                                 static_cast<std::uint16_t>(data[13]));
    return frame;
}

std::string formatMacAddress(const std::array<std::uint8_t, 6>& address) {
    // Build the address in the conventional aa:bb:cc:dd:ee:ff form.
    std::ostringstream stream;
    stream << std::hex << std::nouppercase << std::setfill('0');

    for (std::size_t index = 0; index < address.size(); ++index) {
        stream << std::setw(2) << static_cast<int>(address[index]);
        if (index + 1 < address.size()) {
            stream << ':';
        }
    }

    return stream.str();
}

std::string etherTypeName(std::uint16_t etherType) {
    // Only IPv4 is recognized in this first phase.
    if (etherType == etherTypeIpv4) {
        return "IPv4";
    }

    // Preserve unknown values so the capture output still stays informative.
    std::ostringstream stream;
    stream << "Unknown (0x" << std::hex << std::nouppercase << std::setw(4) << std::setfill('0')
           << etherType << ')';
    return stream.str();
}

}  // namespace router
