#pragma once

#include "routing.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

struct pcap_pkthdr;
using pcap_t = struct pcap;
using u_char = unsigned char;

namespace router {

// Forward packets from an ingress interface to an egress interface.
class ForwardingEngine {
public:
    ForwardingEngine(std::vector<std::string> interfaces, RoutingTable routingTable);
    ~ForwardingEngine();

    ForwardingEngine(const ForwardingEngine&) = delete;
    ForwardingEngine& operator=(const ForwardingEngine&) = delete;

    void run();

private:
    struct CaptureSource {
        std::string interfaceName;
        pcap_t* handle{};
    };

    struct PacketContext {
        ForwardingEngine* engine{};
        std::string interfaceName;
    };

    void openCaptureHandles();
    void openTransmitSocket(const std::string& interfaceName);
    void handlePacket(const std::string& incomingInterface, const pcap_pkthdr* header, const std::uint8_t* packet);
    bool pollCaptureSource(CaptureSource& captureSource);

    static void packetHandler(u_char* userData, const pcap_pkthdr* header, const u_char* packet);
    static std::uint16_t computeIpv4HeaderChecksum(const std::uint8_t* header, std::size_t headerLength);

    std::vector<std::string> interfaces_;
    RoutingTable routingTable_;
    std::vector<CaptureSource> captureSources_;
    std::map<std::string, int> transmitSockets_;
};

}  // namespace router