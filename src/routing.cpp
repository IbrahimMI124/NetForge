#include "routing.hpp"

#include "ipv4.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <bit>
#include <array>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace router {

namespace {

// Return a CIDR mask in host order from the prefix length.
std::uint32_t maskFromPrefixLength(std::uint8_t prefixLength) {
    if (prefixLength == 0U) {
        return 0U;
    }

    return 0xFFFFFFFFu << (32U - prefixLength);
}

// Count the number of leading network bits in a CIDR mask.
std::uint8_t prefixLengthFromMask(std::uint32_t mask) {
    return static_cast<std::uint8_t>(std::popcount(mask));
}

// Verify that the mask is contiguous from the most significant bit downward.
bool isContiguousMask(std::uint32_t mask) {
    if (mask == 0U) {
        return true;
    }

    const auto inverted = ~mask;
    return (inverted & (inverted + 1U)) == 0U;
}

}  // namespace

std::optional<std::uint32_t> parseIpv4Address(std::string_view text) {
    std::array<char, INET_ADDRSTRLEN> buffer{};
    if (text.size() >= buffer.size()) {
        return std::nullopt;
    }

    std::memcpy(buffer.data(), text.data(), text.size());
    buffer[text.size()] = '\0';

    in_addr address{};
    if (inet_pton(AF_INET, buffer.data(), &address) != 1) {
        return std::nullopt;
    }

    return ntohl(address.s_addr);
}

std::optional<CidrBlock> parseCidrBlock(std::string_view text) {
    const auto slashPosition = text.find('/');
    if (slashPosition == std::string_view::npos || slashPosition == 0U || slashPosition + 1U >= text.size()) {
        return std::nullopt;
    }

    const auto addressText = text.substr(0, slashPosition);
    const auto prefixText = text.substr(slashPosition + 1U);

    const auto address = parseIpv4Address(addressText);
    if (!address.has_value()) {
        return std::nullopt;
    }

    int prefixValue = -1;
    try {
        prefixValue = std::stoi(std::string(prefixText));
    } catch (...) {
        return std::nullopt;
    }

    if (prefixValue < 0 || prefixValue > 32) {
        return std::nullopt;
    }

    const auto prefixLength = static_cast<std::uint8_t>(prefixValue);
    const auto mask = maskFromPrefixLength(prefixLength);
    const auto network = *address & mask;

    return CidrBlock{network, mask, prefixLength};
}

std::string formatCidrBlock(std::uint32_t network, std::uint32_t mask) {
    std::ostringstream stream;
    stream << formatIpv4Address(network) << '/' << static_cast<int>(prefixLengthFromMask(mask));
    return stream.str();
}

void RoutingTable::addRoute(Route route) {
    // Reject malformed masks outright rather than silently matching nothing/everything.
    if (!isContiguousMask(route.mask)) {
        return;
    }

    // Normalize defensively even though parseCidrBlock already does this -- a Route
    // can also be constructed directly (as main.cpp's demo table does), and lookup's
    // equality check below assumes the stored network has no stray host bits set.
    route.network &= route.mask;
    routes_.push_back(std::move(route));
}

void RoutingTable::addRoute(std::uint32_t network, std::uint32_t mask, std::uint32_t nextHop, std::string interfaceName) {
    addRoute(Route{network, mask, nextHop, std::move(interfaceName)});
}

bool RoutingTable::removeRoute(const Route& route) {
    const auto beforeSize = routes_.size();
    routes_.erase(std::remove_if(routes_.begin(), routes_.end(), [&](const Route& current) {
                      return current.network == route.network && current.mask == route.mask &&
                             current.nextHop == route.nextHop && current.interfaceName == route.interfaceName;
                  }),
                  routes_.end());
    return routes_.size() != beforeSize;
}

bool RoutingTable::removeRoute(std::uint32_t network, std::uint32_t mask, std::uint32_t nextHop, std::string_view interfaceName) {
    return removeRoute(Route{network, mask, nextHop, std::string(interfaceName)});
}

std::optional<Route> RoutingTable::lookup(std::uint32_t destination) const {
    std::optional<Route> bestRoute;
    std::uint8_t bestPrefixLength = 0U;

    for (const auto& route : routes_) {
        // Masking the destination zeroes its host bits, leaving only the network
        // portion to compare against the route's (already-normalized) network --
        // this is CIDR matching at the bit level.
        if ((destination & route.mask) != route.network) {
            continue;
        }

        // Don't stop at the first match: multiple routes can legally overlap (e.g.
        // 10.0.0.0/8 and 10.0.0.0/24 both matching 10.0.0.5), and the one with the
        // most "must-match" bits -- the longest prefix -- is the correct answer.
        const auto prefixLength = prefixLengthFromMask(route.mask);
        if (!bestRoute.has_value() || prefixLength > bestPrefixLength) {
            bestRoute = route;
            bestPrefixLength = prefixLength;
        }
    }

    return bestRoute;
}

}  // namespace router