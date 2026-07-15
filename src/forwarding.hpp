#pragma once

#include "arp.hpp"
#include "ipv4.hpp"
#include "routing.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
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

    // This router's own address on one interface, queried once at startup --
    // needed to answer ARP requests for ourselves and to source ARP requests we send.
    struct InterfaceIdentity {
        std::array<std::uint8_t, 6> macAddress{};
        std::uint32_t ipAddress{};  // host order
    };

    // A fully-prepared IPv4 packet (TTL decremented, checksum already recomputed)
    // waiting only on its next hop's MAC before it can be framed and sent.
    struct PendingForward {
        std::string egressInterface;
        std::vector<std::uint8_t> ipv4Packet;
    };

    // Packets queued for one not-yet-resolved next hop, plus enough state to pace
    // ARP retries instead of re-requesting on every arriving packet.
    struct PendingArpResolution {
        std::vector<PendingForward> queuedPackets;
        std::chrono::steady_clock::time_point lastRequestAt{};
        int retryCount{0};
    };

    void openCaptureHandles();
    void openTransmitSocket(const std::string& interfaceName);
    void resolveInterfaceIdentity(const std::string& interfaceName);
    void handlePacket(const std::string& incomingInterface, const pcap_pkthdr* header, const std::uint8_t* packet);
    void handleArpPacket(const std::string& incomingInterface, const std::uint8_t* arpData, std::size_t length);
    void sendArpRequest(const std::string& interfaceName, std::uint32_t targetAddress);
    bool sendEthernetFrame(const std::string& interfaceName, const std::array<std::uint8_t, 6>& destinationMac,
                            std::uint16_t etherType, const std::uint8_t* payload, std::size_t payloadLength);
    void queuePendingForward(std::uint32_t nextHopAddress, const std::string& egressInterface,
                              std::vector<std::uint8_t> ipv4Packet);
    void flushPendingArpResolution(std::uint32_t ipAddress, const std::array<std::uint8_t, 6>& macAddress);
    bool pollCaptureSource(CaptureSource& captureSource);

    static std::uint16_t computeIpv4HeaderChecksum(const std::uint8_t* header, std::size_t headerLength);

    std::vector<std::string> interfaces_;
    RoutingTable routingTable_;
    std::vector<CaptureSource> captureSources_;
    std::map<std::string, int> transmitSockets_;
    std::map<std::string, InterfaceIdentity> interfaceIdentities_;
    ArpCache arpCache_;
    std::unordered_map<std::uint32_t, PendingArpResolution> pendingArpResolutions_;
};

}  // namespace router