#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace router {

// A single IPv4 route entry used by the longest-prefix-match engine.
struct Route {
    std::uint32_t network{};
    std::uint32_t mask{};
    std::uint32_t nextHop{};
    std::string interfaceName;
};

// Parsed CIDR input such as 10.1.1.0/24.
struct CidrBlock {
    std::uint32_t network{};
    std::uint32_t mask{};
    std::uint8_t prefixLength{};
};

// Convert dotted-decimal text into a host-order IPv4 integer.
std::optional<std::uint32_t> parseIpv4Address(std::string_view text);
// Parse a CIDR string and normalize the network portion.
std::optional<CidrBlock> parseCidrBlock(std::string_view text);
// Format a network and mask back to the familiar CIDR notation.
std::string formatCidrBlock(std::uint32_t network, std::uint32_t mask);

// Store IPv4 routes and perform longest-prefix matching.
class RoutingTable {
public:
    void addRoute(Route route);
    void addRoute(std::uint32_t network, std::uint32_t mask, std::uint32_t nextHop, std::string interfaceName);

    bool removeRoute(const Route& route);
    bool removeRoute(std::uint32_t network, std::uint32_t mask, std::uint32_t nextHop, std::string_view interfaceName);

    std::optional<Route> lookup(std::uint32_t destination) const;

private:
    std::vector<Route> routes_;
};

}  // namespace router