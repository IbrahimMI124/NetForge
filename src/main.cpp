#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "forwarding.hpp"
#include "routing.hpp"

namespace {

// Build the route set used to verify and drive forwarding decisions.
router::RoutingTable buildDemoRoutingTable(const std::string& interfaceA, const std::string& interfaceB) {
    router::RoutingTable table;
    const auto ingressRoute = router::parseCidrBlock("10.0.0.0/24");
    const auto egressRoute = router::parseCidrBlock("20.0.0.0/24");

    if (!ingressRoute.has_value() || !egressRoute.has_value()) {
        throw std::runtime_error("Failed to build the demo routing table");
    }

    table.addRoute(ingressRoute->network, ingressRoute->mask, 0, interfaceA);
    table.addRoute(egressRoute->network, egressRoute->mask, 0, interfaceB);
    return table;
}

// Print a route in the compact CIDR form expected from a router lookup.
void printRouteMatch(const router::Route& route) {
    std::cout << "Route Match:\n";
    std::cout << router::formatCidrBlock(route.network, route.mask) << '\n';
    std::cout << "Interface: " << route.interfaceName << '\n';
}

// Run a startup check that proves the forwarding route picks the correct egress interface.
void verifyRoutingTableDemo(const router::RoutingTable& routingTable) {
    const auto destination = router::parseIpv4Address("20.0.0.2");
    if (!destination.has_value()) {
        throw std::runtime_error("Failed to parse demo destination address");
    }

    const auto matchedRoute = routingTable.lookup(*destination);
    if (!matchedRoute.has_value()) {
        throw std::runtime_error("Routing table demo did not find a match");
    }

    const auto expectedNetwork = router::parseIpv4Address("20.0.0.0");
    if (!expectedNetwork.has_value() || matchedRoute->interfaceName != "routerB" ||
        matchedRoute->network != *expectedNetwork) {
        throw std::runtime_error("Routing table demo expected 20.0.0.0/24 via routerB");
    }

    std::cout << "[FORWARDING TABLE SELF-CHECK]\n";
    std::cout << "Destination: 20.0.0.2\n";
    printRouteMatch(*matchedRoute);
    std::cout << '\n';
}

}  // namespace

int main(int argc, char* argv[]) {
    try {
        if (argc < 3) {
            throw std::runtime_error("Usage: ./router <interfaceA> <interfaceB>");
        }

        const std::vector<std::string> interfaces = {argv[1], argv[2]};

        const auto routingTable = buildDemoRoutingTable(interfaces[0], interfaces[1]);
        verifyRoutingTableDemo(routingTable);

        router::ForwardingEngine engine(interfaces, routingTable);
        engine.run();

        return 0;
    } catch (const std::exception& exception) {
        std::cerr << "router: " << exception.what() << '\n';
        return 1;
    }
}
