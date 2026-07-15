#include "forwarding.hpp"

#include "arp.hpp"
#include "ethernet.hpp"
#include "ipv4.hpp"
#include "pcap.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
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

// Ethernet's minimum frame size is 60 bytes (excluding the FCS the NIC appends);
// short payloads (e.g. an ARP request) must be padded up to it.
constexpr std::size_t minimumEthernetFrameLength = 60;

constexpr std::array<std::uint8_t, 6> broadcastMac = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// Cap how many packets we'll hold for one unresolved next hop so a persistently
// unreachable destination can't grow the queue without bound.
constexpr std::size_t maxQueuedPacketsPerResolution = 4;

// Re-request on a fixed interval rather than once per queued packet, and give up
// (dropping whatever's queued) after this many attempts elicit no reply --
// mirrors a real neighbor cache's bounded retry/incomplete-entry behavior.
constexpr std::chrono::milliseconds arpRetryInterval{1000};
constexpr int maxArpRetries = 3;

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

void ForwardingEngine::resolveInterfaceIdentity(const std::string& interfaceName) {
    // ioctl needs some open socket to operate through; its family/type is irrelevant
    // here since we're only asking the kernel about interface properties, not sending
    // data on it.
    const int helperSocket = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (helperSocket < 0) {
        throw std::runtime_error(std::string("socket(helper): ") + std::strerror(errno));
    }

    ifreq request{};
    std::strncpy(request.ifr_name, interfaceName.c_str(), IFNAMSIZ - 1);

    InterfaceIdentity identity{};

    // SIOCGIFHWADDR fills ifr_hwaddr.sa_data with the interface's own MAC -- needed
    // to act as the source address when we build Ethernet frames ourselves below.
    if (::ioctl(helperSocket, SIOCGIFHWADDR, &request) < 0) {
        const auto savedErrno = errno;
        ::close(helperSocket);
        throw std::runtime_error("ioctl(SIOCGIFHWADDR, " + interfaceName + "): " + std::strerror(savedErrno));
    }
    std::memcpy(identity.macAddress.data(), request.ifr_hwaddr.sa_data, identity.macAddress.size());

    // SIOCGIFADDR (re-using the same ifreq) fills ifr_addr with the interface's IPv4
    // address as configured at the OS level (e.g. by setup_lab.sh) -- this is what we
    // answer ARP requests for and what we source our own ARP requests from.
    if (::ioctl(helperSocket, SIOCGIFADDR, &request) < 0) {
        const auto savedErrno = errno;
        ::close(helperSocket);
        throw std::runtime_error("ioctl(SIOCGIFADDR, " + interfaceName + "): " + std::strerror(savedErrno));
    }
    const auto* addressIn = reinterpret_cast<sockaddr_in*>(&request.ifr_addr);
    identity.ipAddress = ntohl(addressIn->sin_addr.s_addr);

    ::close(helperSocket);
    interfaceIdentities_.emplace(interfaceName, identity);
}

void ForwardingEngine::openTransmitSocket(const std::string& interfaceName) {
    if (transmitSockets_.contains(interfaceName)) {
        return;
    }

    // AF_PACKET + SOCK_RAW hands the kernel a complete frame we build ourselves
    // (Ethernet header included), instead of an IP payload the kernel wraps and
    // ARPs for on our behalf (the old IPPROTO_RAW approach).
    const int transmitSocket = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (transmitSocket < 0) {
        throw std::runtime_error(std::string("socket(AF_PACKET): ") + std::strerror(errno));
    }

    const auto interfaceIndex = ::if_nametoindex(interfaceName.c_str());
    if (interfaceIndex == 0) {
        const auto savedErrno = errno;
        ::close(transmitSocket);
        throw std::runtime_error("if_nametoindex(" + interfaceName + "): " + std::strerror(savedErrno));
    }

    sockaddr_ll socketAddress{};
    socketAddress.sll_family = AF_PACKET;
    socketAddress.sll_protocol = htons(ETH_P_ALL);
    socketAddress.sll_ifindex = static_cast<int>(interfaceIndex);

    if (::bind(transmitSocket, reinterpret_cast<sockaddr*>(&socketAddress), sizeof(socketAddress)) < 0) {
        const auto savedErrno = errno;
        ::close(transmitSocket);
        throw std::runtime_error(std::string("bind(AF_PACKET): ") + std::strerror(savedErrno));
    }

    transmitSockets_.emplace(interfaceName, transmitSocket);
}

bool ForwardingEngine::sendEthernetFrame(const std::string& interfaceName,
                                         const std::array<std::uint8_t, 6>& destinationMac, std::uint16_t etherType,
                                         const std::uint8_t* payload, std::size_t payloadLength) {
    const auto transmitSocketIter = transmitSockets_.find(interfaceName);
    const auto identityIter = interfaceIdentities_.find(interfaceName);
    if (transmitSocketIter == transmitSockets_.end() || identityIter == interfaceIdentities_.end()) {
        return false;
    }

    // Build the 14-byte Ethernet header by hand: destination MAC first, then this
    // interface's own MAC as the source, then the EtherType -- exactly the layout
    // parseEthernetFrame reads on the receive side.
    std::vector<std::uint8_t> frame(ethernetHeaderLength + payloadLength);
    std::copy_n(destinationMac.begin(), destinationMac.size(), frame.begin());
    std::copy_n(identityIter->second.macAddress.begin(), identityIter->second.macAddress.size(), frame.begin() + 6);
    frame[12] = static_cast<std::uint8_t>(etherType >> 8U);
    frame[13] = static_cast<std::uint8_t>(etherType & 0xFFU);
    std::copy_n(payload, payloadLength, frame.begin() + static_cast<std::ptrdiff_t>(ethernetHeaderLength));

    if (frame.size() < minimumEthernetFrameLength) {
        frame.resize(minimumEthernetFrameLength, 0U);
    }

    // sendto on an AF_PACKET/SOCK_RAW socket needs a sockaddr_ll naming the egress
    // interface; sll_addr/sll_halen are set for completeness but the frame we wrote
    // above (not this struct) is what actually goes out with that destination MAC.
    const auto interfaceIndex = ::if_nametoindex(interfaceName.c_str());
    sockaddr_ll socketAddress{};
    socketAddress.sll_family = AF_PACKET;
    socketAddress.sll_protocol = htons(etherType);
    socketAddress.sll_ifindex = static_cast<int>(interfaceIndex);
    socketAddress.sll_halen = static_cast<unsigned char>(destinationMac.size());
    std::copy_n(destinationMac.begin(), destinationMac.size(), socketAddress.sll_addr);

    const auto bytesSent = ::sendto(transmitSocketIter->second, frame.data(), frame.size(), 0,
                                    reinterpret_cast<sockaddr*>(&socketAddress), sizeof(socketAddress));
    return bytesSent >= 0 && static_cast<std::size_t>(bytesSent) == frame.size();
}

void ForwardingEngine::sendArpRequest(const std::string& interfaceName, std::uint32_t targetAddress) {
    const auto identityIter = interfaceIdentities_.find(interfaceName);
    if (identityIter == interfaceIdentities_.end()) {
        return;
    }

    // A request has no known target MAC yet (that's the whole point of asking) --
    // leave it zeroed and broadcast the frame so every adapter on the segment sees it.
    ArpPacket request;
    request.operation = ArpOperation::Request;
    request.senderMac = identityIter->second.macAddress;
    request.senderIp = identityIter->second.ipAddress;
    request.targetMac = {};
    request.targetIp = targetAddress;

    const auto wireForm = buildArpPacket(request);
    sendEthernetFrame(interfaceName, broadcastMac, etherTypeArp, wireForm.data(), wireForm.size());
}

void ForwardingEngine::queuePendingForward(std::uint32_t nextHopAddress, const std::string& egressInterface,
                                           std::vector<std::uint8_t> ipv4Packet) {
    auto& pending = pendingArpResolutions_[nextHopAddress];

    // Give up on a resolution nobody is answering rather than retrying forever;
    // resetting it here means the packet that triggered this call starts a fresh
    // attempt cleanly instead of being silently folded into a dead one.
    if (pending.retryCount >= maxArpRetries &&
        std::chrono::steady_clock::now() - pending.lastRequestAt >= arpRetryInterval) {
        pending = PendingArpResolution{};
    }

    // Re-request on a fixed interval rather than once per packet -- every packet
    // arriving for the same unresolved destination should share one in-flight
    // request, not each trigger its own.
    if (std::chrono::steady_clock::now() - pending.lastRequestAt >= arpRetryInterval) {
        sendArpRequest(egressInterface, nextHopAddress);
        pending.lastRequestAt = std::chrono::steady_clock::now();
        ++pending.retryCount;
    }

    // Drop the oldest queued packet to make room rather than growing without bound
    // for a destination that may never answer.
    if (pending.queuedPackets.size() >= maxQueuedPacketsPerResolution) {
        pending.queuedPackets.erase(pending.queuedPackets.begin());
    }
    pending.queuedPackets.push_back(PendingForward{egressInterface, std::move(ipv4Packet)});
}

void ForwardingEngine::flushPendingArpResolution(std::uint32_t ipAddress,
                                                 const std::array<std::uint8_t, 6>& macAddress) {
    const auto pendingIter = pendingArpResolutions_.find(ipAddress);
    if (pendingIter == pendingArpResolutions_.end()) {
        return;
    }

    // The MAC is now known -- send everything that was waiting on it, in the order
    // it arrived, then forget this resolution entirely (a fresh one starts clean on
    // the next cache miss, if the entry ever expires).
    for (auto& queued : pendingIter->second.queuedPackets) {
        sendEthernetFrame(queued.egressInterface, macAddress, etherTypeIpv4, queued.ipv4Packet.data(),
                          queued.ipv4Packet.size());
    }
    pendingArpResolutions_.erase(pendingIter);
}

void ForwardingEngine::handleArpPacket(const std::string& incomingInterface, const std::uint8_t* arpData,
                                       std::size_t length) {
    const auto arpPacket = parseArpPacket(arpData, length);
    if (!arpPacket.has_value()) {
        return;
    }

    // Learn the sender's mapping opportunistically -- both requests and replies carry
    // it, and a real ARP cache accepts either as free information rather than making
    // a fresh request later.
    arpCache_.insert(arpPacket->senderIp, arpPacket->senderMac);
    flushPendingArpResolution(arpPacket->senderIp, arpPacket->senderMac);

    if (arpPacket->operation != ArpOperation::Request) {
        return;
    }

    const auto identityIter = interfaceIdentities_.find(incomingInterface);
    if (identityIter == interfaceIdentities_.end() || arpPacket->targetIp != identityIter->second.ipAddress) {
        return;
    }

    // Swap sender/target: we become the sender (our own MAC/IP), and the original
    // sender becomes the target we're answering -- then unicast it straight back,
    // since only the querier needs this answer.
    ArpPacket reply;
    reply.operation = ArpOperation::Reply;
    reply.senderMac = identityIter->second.macAddress;
    reply.senderIp = identityIter->second.ipAddress;
    reply.targetMac = arpPacket->senderMac;
    reply.targetIp = arpPacket->senderIp;

    const auto wireForm = buildArpPacket(reply);
    sendEthernetFrame(incomingInterface, arpPacket->senderMac, etherTypeArp, wireForm.data(), wireForm.size());
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
        pcap_t* captureHandle = pcap_create(interfaceName.c_str(), errorBuffer);
        if (captureHandle == nullptr) {
            throw std::runtime_error(errorBuffer);
        }

        if (pcap_set_snaplen(captureHandle, 65535) != 0) {
            pcap_close(captureHandle);
            throw std::runtime_error("Failed to set snaplen");
        }

        if (pcap_set_promisc(captureHandle, 1) != 0) {
            pcap_close(captureHandle);
            throw std::runtime_error("Failed to set promiscuous mode");
        }

        if (pcap_set_timeout(captureHandle, 1000) != 0) {
            pcap_close(captureHandle);
            throw std::runtime_error("Failed to set timeout");
        }

        if (pcap_set_immediate_mode(captureHandle, 1) != 0) {
            pcap_close(captureHandle);
            throw std::runtime_error("Failed to set immediate mode");
        }

        const int activateResult = pcap_activate(captureHandle);
        if (activateResult < 0) {
            std::string err(pcap_geterr(captureHandle));
            pcap_close(captureHandle);
            throw std::runtime_error("Failed to activate capture handle: " + err);
        }

        if (pcap_datalink(captureHandle) != DLT_EN10MB) {
            pcap_close(captureHandle);
            throw std::runtime_error("This tool currently supports only Ethernet captures (DLT_EN10MB)");
        }

        // We now transmit through this same interface via a raw AF_PACKET socket;
        // without this, promiscuous capture would loop our own ARP/IPv4 sends back
        // in as if they were received traffic.
        pcap_setdirection(captureHandle, PCAP_D_IN);

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
        resolveInterfaceIdentity(interfaceName);
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

void ForwardingEngine::handlePacket(const std::string& incomingInterface, const pcap_pkthdr* header,
                                    const u_char* packet) {
    const auto ethernetFrame = parseEthernetFrame(reinterpret_cast<const std::uint8_t*>(packet), header->caplen);
    if (!ethernetFrame.has_value() || header->caplen < ethernetHeaderLength) {
        return;
    }

    const auto* payload = reinterpret_cast<const std::uint8_t*>(packet + ethernetHeaderLength);
    const std::size_t payloadLength = header->caplen - ethernetHeaderLength;

    if (ethernetFrame->etherType == etherTypeArp) {
        handleArpPacket(incomingInterface, payload, payloadLength);
        return;
    }

    if (ethernetFrame->etherType != etherTypeIpv4) {
        return;
    }

    const auto* ipv4Start = payload;
    const auto ipv4Packet = parseIpv4Packet(ipv4Start, payloadLength);
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

    // Split-horizon: never bounce a packet back out the interface it arrived on --
    // it would mean the packet's own subnet is the best route to its destination,
    // so the sender should have delivered it directly rather than via this router.
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
    if (headerLengthBytes < 20U || payloadLength < headerLengthBytes) {
        return;
    }

    std::vector<std::uint8_t> forwardedPacket(ipv4Start, ipv4Start + payloadLength);
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

    // The next hop we need a MAC for: an explicit gateway if the route has one,
    // otherwise the destination itself is on the egress link (directly connected).
    const std::uint32_t nextHopAddress = matchedRoute->nextHop != 0U ? matchedRoute->nextHop : destinationAddress;
    const auto resolvedMac = arpCache_.lookup(nextHopAddress);

    std::cout << "Received packet\n";
    std::cout << "Incoming:\n" << incomingInterface << "\n\n";
    std::cout << "Src:\n" << ipv4Packet->sourceAddress << "\n\n";
    std::cout << "Dst:\n" << ipv4Packet->destinationAddress << "\n\n";
    std::cout << "Matched:\n" << formatCidrBlock(matchedRoute->network, matchedRoute->mask) << "\n\n";
    std::cout << "Outgoing:\n" << matchedRoute->interfaceName << "\n\n";
    std::cout << "TTL:\n" << static_cast<int>(ttlBefore) << " -> " << static_cast<int>(ttlBefore - 1U) << "\n\n";

    if (!resolvedMac.has_value()) {
        queuePendingForward(nextHopAddress, matchedRoute->interfaceName, std::move(forwardedPacket));
        std::cout << "Queued: no ARP entry for next hop yet, request sent\n\n";
        return;
    }

    const bool sent = sendEthernetFrame(matchedRoute->interfaceName, *resolvedMac, etherTypeIpv4,
                                        forwardedPacket.data(), forwardedPacket.size());
    if (!sent) {
        std::cout << "Dropped: transmit failed\n\n";
        return;
    }

    std::cout << "Forwarded\n\n";
}

}  // namespace router
