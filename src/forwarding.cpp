#include "forwarding.hpp"

#include "ethernet.hpp"
#include "ipv4.hpp"
#include "pcap.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <csignal>
#include <cstring>
#include <chrono>
#include <thread>
#include <iostream>
#include <stdexcept>
#include <utility>

namespace {

// Ethernet headers are fixed at 14 bytes before the IPv4 payload begins.
constexpr std::size_t ethernetHeaderLength = 14;

// Track the active router object so Ctrl+C can stop the capture loop cleanly.
router::ForwardingEngine* g_activeEngine = nullptr;
volatile std::sig_atomic_t g_shouldStop = 0;

void handleSignal(int) {
    if (g_activeEngine != nullptr) {
        g_shouldStop = 1;
    }
}

}  // namespace

namespace router {

ForwardingEngine::ForwardingEngine(std::vector<std::string> interfaces, RoutingTable routingTable)
    : interfaces_(std::move(interfaces)), routingTable_(std::move(routingTable)) {}

ForwardingEngine::~ForwardingEngine() {
    for (auto& captureSource : captureSources_) {
        if (captureSource.handle != nullptr) {
            pcap_close(captureSource.handle);
            captureSource.handle = nullptr;
        }
    }

    for (auto& [interfaceName, socketHandle] : transmitSockets_) {
        if (socketHandle >= 0) {
            close(socketHandle);
            socketHandle = -1;
        }
    }
}

void ForwardingEngine::openTransmitSocket(const std::string& interfaceName) {
    if (transmitSockets_.contains(interfaceName)) {
        return;
    }

    // Send IPv4 packets through a raw socket and let the kernel handle link-layer delivery.
    const int transmitSocket = ::socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (transmitSocket < 0) {
        throw std::runtime_error(std::string("socket: ") + std::strerror(errno));
    }

    int enableHeaderInclude = 1;
    if (::setsockopt(transmitSocket, IPPROTO_IP, IP_HDRINCL, &enableHeaderInclude, sizeof(enableHeaderInclude)) < 0) {
        ::close(transmitSocket);
        throw std::runtime_error(std::string("setsockopt(IP_HDRINCL): ") + std::strerror(errno));
    }

    if (::setsockopt(transmitSocket, SOL_SOCKET, SO_BINDTODEVICE, interfaceName.c_str(),
                     static_cast<socklen_t>(interfaceName.size() + 1U)) < 0) {
        ::close(transmitSocket);
        throw std::runtime_error(std::string("setsockopt(SO_BINDTODEVICE): ") + std::strerror(errno));
    }

    transmitSockets_.emplace(interfaceName, transmitSocket);
}

std::uint16_t ForwardingEngine::computeIpv4HeaderChecksum(const std::uint8_t* header, std::size_t headerLength) {
    // IPv4 header checksum is the one's-complement sum of 16-bit header words.
    std::uint32_t sum = 0;
    for (std::size_t index = 0; index + 1U < headerLength; index += 2U) {
        sum += static_cast<std::uint32_t>((static_cast<std::uint16_t>(header[index]) << 8U) |
                                          static_cast<std::uint16_t>(header[index + 1U]));
    }

    while ((sum >> 16U) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    }

    return static_cast<std::uint16_t>(~sum);
}

void ForwardingEngine::openCaptureHandles() {
    if (interfaces_.empty()) {
        throw std::runtime_error("No interfaces configured for forwarding");
    }

    captureSources_.clear();
    captureSources_.reserve(interfaces_.size());

    for (const auto& interfaceName : interfaces_) {
        char errorBuffer[PCAP_ERRBUF_SIZE] = {};
        pcap_t* captureHandle = pcap_open_live(interfaceName.c_str(), 65535, 1, 1000, errorBuffer);
        if (captureHandle == nullptr) {
            throw std::runtime_error(errorBuffer);
        }

        if (pcap_datalink(captureHandle) != DLT_EN10MB) {
            pcap_close(captureHandle);
            throw std::runtime_error("This tool currently supports only Ethernet captures (DLT_EN10MB)");
        }

        if (pcap_setnonblock(captureHandle, 1, errorBuffer) < 0) {
            pcap_close(captureHandle);
            throw std::runtime_error(errorBuffer);
        }

        captureSources_.push_back(CaptureSource{interfaceName, captureHandle});
    }
}

bool ForwardingEngine::pollCaptureSource(CaptureSource& captureSource) {
    bool processedPacket = false;

    while (true) {
        pcap_pkthdr* header = nullptr;
        const u_char* packet = nullptr;
        const auto result = pcap_next_ex(captureSource.handle, &header, &packet);
        if (result == 1) {
            if (header != nullptr && packet != nullptr) {
                handlePacket(captureSource.interfaceName, header, packet);
                processedPacket = true;
            }
            continue;
        }

        if (result == 0) {
            break;
        }

        if (result == -1) {
            throw std::runtime_error(pcap_geterr(captureSource.handle));
        }

        break;
    }

    return processedPacket;
}

void ForwardingEngine::run() {
    openCaptureHandles();
    for (const auto& interfaceName : interfaces_) {
        openTransmitSocket(interfaceName);
    }

    g_activeEngine = this;
    std::signal(SIGINT, handleSignal);

    std::cout << "Forwarding on interfaces:";
    for (const auto& interfaceName : interfaces_) {
        std::cout << ' ' << interfaceName;
    }
    std::cout << "\nPress Ctrl+C to stop.\n\n";

    while (!g_shouldStop) {
        bool processedPacket = false;
        for (auto& captureSource : captureSources_) {
            processedPacket = pollCaptureSource(captureSource) || processedPacket;
        }

        if (!processedPacket) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    g_activeEngine = nullptr;
    g_shouldStop = 0;
}

void ForwardingEngine::packetHandler(u_char* userData, const pcap_pkthdr* header, const u_char* packet) {
    auto* context = reinterpret_cast<PacketContext*>(userData);
    if (context != nullptr && context->engine != nullptr) {
        context->engine->handlePacket(context->interfaceName, header, packet);
    }
}

void ForwardingEngine::handlePacket(const std::string& incomingInterface, const pcap_pkthdr* header,
                                    const u_char* packet) {
    const auto ethernetFrame = parseEthernetFrame(reinterpret_cast<const std::uint8_t*>(packet), header->caplen);
    if (!ethernetFrame.has_value() || ethernetFrame->etherType != etherTypeIpv4) {
        return;
    }

    if (header->caplen < ethernetHeaderLength) {
        return;
    }

    const auto* ipv4Start = reinterpret_cast<const std::uint8_t*>(packet + ethernetHeaderLength);
    const auto ipv4Packet = parseIpv4Packet(ipv4Start, header->caplen - ethernetHeaderLength);
    if (!ipv4Packet.has_value()) {
        return;
    }

    std::uint32_t destinationAddressNetworkOrder = 0;
    std::memcpy(&destinationAddressNetworkOrder, ipv4Start + 16, sizeof(destinationAddressNetworkOrder));
    const std::uint32_t destinationAddress = ntohl(destinationAddressNetworkOrder);

    const auto matchedRoute = routingTable_.lookup(destinationAddress);
    if (!matchedRoute.has_value()) {
        std::cout << "Received packet\n";
        std::cout << "Incoming:\n" << incomingInterface << "\n\n";
        std::cout << "Src:\n" << ipv4Packet->sourceAddress << "\n\n";
        std::cout << "Dst:\n" << ipv4Packet->destinationAddress << "\n\n";
        std::cout << "Dropped: no route\n\n";
        return;
    }

    if (matchedRoute->interfaceName == incomingInterface) {
        std::cout << "Received packet\n";
        std::cout << "Incoming:\n" << incomingInterface << "\n\n";
        std::cout << "Src:\n" << ipv4Packet->sourceAddress << "\n\n";
        std::cout << "Dst:\n" << ipv4Packet->destinationAddress << "\n\n";
        std::cout << "Matched:\n" << formatCidrBlock(matchedRoute->network, matchedRoute->mask) << "\n\n";
        std::cout << "Outgoing:\n" << matchedRoute->interfaceName << "\n\n";
        std::cout << "Dropped: incoming interface equals outgoing interface\n\n";
        return;
    }

    const auto headerLengthBytes = static_cast<std::size_t>(ipv4Packet->headerLength) * 4U;
    if (headerLengthBytes < 20U || header->caplen < ethernetHeaderLength + headerLengthBytes) {
        return;
    }

    std::vector<std::uint8_t> forwardedPacket(ipv4Start, ipv4Start + (header->caplen - ethernetHeaderLength));
    auto* forwardedHeader = forwardedPacket.data();

    const std::uint8_t ttlBefore = forwardedHeader[8];
    if (ttlBefore <= 1U) {
        std::cout << "Received packet\n";
        std::cout << "Incoming:\n" << incomingInterface << "\n\n";
        std::cout << "Src:\n" << ipv4Packet->sourceAddress << "\n\n";
        std::cout << "Dst:\n" << ipv4Packet->destinationAddress << "\n\n";
        std::cout << "Matched:\n" << formatCidrBlock(matchedRoute->network, matchedRoute->mask) << "\n\n";
        std::cout << "Outgoing:\n" << matchedRoute->interfaceName << "\n\n";
        std::cout << "TTL:\n" << static_cast<int>(ttlBefore) << " -> 0\n\n";
        std::cout << "Dropped: TTL expired\n\n";
        return;
    }

    forwardedHeader[8] = static_cast<std::uint8_t>(ttlBefore - 1U);
    forwardedHeader[10] = 0U;
    forwardedHeader[11] = 0U;

    const auto checksum = computeIpv4HeaderChecksum(forwardedHeader, headerLengthBytes);
    forwardedHeader[10] = static_cast<std::uint8_t>(checksum >> 8U);
    forwardedHeader[11] = static_cast<std::uint8_t>(checksum & 0xFFU);

    const auto transmitSocketIter = transmitSockets_.find(matchedRoute->interfaceName);
    if (transmitSocketIter == transmitSockets_.end()) {
        std::cout << "Received packet\n";
        std::cout << "Incoming:\n" << incomingInterface << "\n\n";
        std::cout << "Src:\n" << ipv4Packet->sourceAddress << "\n\n";
        std::cout << "Dst:\n" << ipv4Packet->destinationAddress << "\n\n";
        std::cout << "Matched:\n" << formatCidrBlock(matchedRoute->network, matchedRoute->mask) << "\n\n";
        std::cout << "Outgoing:\n" << matchedRoute->interfaceName << "\n\n";
        std::cout << "Dropped: no transmit socket\n\n";
        return;
    }

    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_addr.s_addr = htonl(matchedRoute->nextHop != 0U ? matchedRoute->nextHop : destinationAddress);

    const auto bytesSent = ::sendto(transmitSocketIter->second, forwardedPacket.data(), forwardedPacket.size(), 0,
                                    reinterpret_cast<sockaddr*>(&destination), sizeof(destination));

    std::cout << "Received packet\n";
    std::cout << "Incoming:\n" << incomingInterface << "\n\n";
    std::cout << "Src:\n" << ipv4Packet->sourceAddress << "\n\n";
    std::cout << "Dst:\n" << ipv4Packet->destinationAddress << "\n\n";
    std::cout << "Matched:\n" << formatCidrBlock(matchedRoute->network, matchedRoute->mask) << "\n\n";
    std::cout << "Outgoing:\n" << matchedRoute->interfaceName << "\n\n";
    std::cout << "TTL:\n" << static_cast<int>(ttlBefore) << " -> " << static_cast<int>(ttlBefore - 1U) << "\n\n";

    if (bytesSent < 0) {
        std::cout << "Dropped: transmit failed\n\n";
        return;
    }

    std::cout << "Forwarded\n\n";
}

}  // namespace router
