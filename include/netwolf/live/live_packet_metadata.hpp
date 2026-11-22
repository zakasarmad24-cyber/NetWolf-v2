#pragma once

#include <netwolf/core/models.hpp>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace netwolf::live {

    // ================================================================
    // NetWolf v2 - Live Packet Metadata
    //
    // Stage 7 purpose:
    // Define direct live metadata extracted from packets.
    //
    // Important:
    // - This file does NOT capture packets.
    // - This file does NOT depend on Npcap.
    // - It prepares the engine to receive DNS / HTTP Host / TLS SNI
    //   evidence from a future live packet sensor.
    // ================================================================

    enum class LivePacketMetadataType
    {
        Unknown,
        DnsQuery,
        DnsAnswer,
        HttpHost,
        TlsSni,
        EndpointObservation
    };


    inline std::string toString(
        LivePacketMetadataType type
    )
    {
        switch (type)
        {
        case LivePacketMetadataType::DnsQuery:
            return "DNS query";

        case LivePacketMetadataType::DnsAnswer:
            return "DNS answer";

        case LivePacketMetadataType::HttpHost:
            return "HTTP Host";

        case LivePacketMetadataType::TlsSni:
            return "TLS SNI";

        case LivePacketMetadataType::EndpointObservation:
            return "Endpoint observation";

        case LivePacketMetadataType::Unknown:
        default:
            return "Unknown packet metadata";
        }
    }


    struct LivePacketEndpoint
    {
        std::string localIp;
        uint16_t localPort = 0;

        std::string remoteIp;
        uint16_t remotePort = 0;

        netwolf::core::TransportProtocol protocol =
            netwolf::core::TransportProtocol::Unknown;
    };


    struct LivePacketMetadata
    {
        LivePacketMetadataType type =
            LivePacketMetadataType::Unknown;

        LivePacketEndpoint endpoint;

        // Examples:
        // - DNS query name
        // - HTTP Host value
        // - TLS SNI value
        std::string name;

        // For DNS answer:
        // domain -> resolvedIp
        std::string resolvedIp;

        // Human explanation for reports/debug.
        std::string reason;

        netwolf::core::ConfidenceLevel confidence =
            netwolf::core::ConfidenceLevel::Low;

        netwolf::core::Timestamp observedAt =
            netwolf::core::nowUtc();
    };


    // ------------------------------------------------------------
    // Operating-system family read automatically from a TCP SYN:
    // initial TTL + the order of TCP options differ per OS network stack.
    //   Windows       : initial TTL 128
    //   Apple         : TTL 64, options MSS,NOP,WS,NOP,NOP,TS,SACK  (iOS / macOS)
    //   Android/Linux : TTL 64, options MSS,SACK,TS,NOP,WS
    // ------------------------------------------------------------
    enum class LiveOsFamily : uint8_t
    {
        Unknown = 0,
        Windows = 1,
        Apple = 2,
        AndroidLinux = 3,
        Other = 4
    };

    inline const char* toString(LiveOsFamily family)
    {
        switch (family)
        {
        case LiveOsFamily::Windows:      return "Windows";
        case LiveOsFamily::Apple:        return "Apple";
        case LiveOsFamily::AndroidLinux: return "Android/Linux";
        case LiveOsFamily::Other:        return "Other OS";
        case LiveOsFamily::Unknown:
        default:                         return "Unknown";
        }
    }


    // A DHCP message seen on the hotspot: the name and OS label a device
    // announces when it joins (the same name Windows shows in its list of
    // connected devices).
    struct LiveDhcpObservation
    {
        std::string mac;           // "aa:bb:cc:dd:ee:ff"
        std::string ip;            // client address (may be empty in DISCOVER)
        std::string hostName;      // option 12 / 81
        std::string vendorClass;   // option 60, e.g. "android-dhcp-9", "MSFT 5.0"
        bool fromClient = true;
    };


    // Identity of one device on the hotspot, built automatically.
    struct LiveDeviceIdentity
    {
        std::string ip;
        std::string mac;

        std::string hostName;      // "Galaxy-Note8"
        std::string nameSource;    // "DHCP" / "Windows hotspot list"
        std::string vendorClass;

        std::string deviceType;    // "Android", "Apple iPhone (iOS)", "Windows", ...
        std::string typeEvidence;  // how the type was decided

        // TCP SYNs sent by the device itself (TTL not decreased).
        size_t ownSyns = 0;

        // TCP SYNs that passed THROUGH the device (TTL decreased):
        // the device is routing traffic of other devices behind it.
        size_t forwardedSyns = 0;
        bool forwarding = false;

        // OS families seen in the forwarded SYNs, e.g. { "Windows", "Apple" }.
        std::vector<std::string> platformsBehind;

        // Forwarded SYNs per OS family ("Apple" -> 12, ...).
        std::map<std::string, size_t> forwardedByPlatform;
    };


    // ------------------------------------------------------------
    // Hotspot flow model (continuous capture).
    //
    // One captured packet, reduced to the few header fields the flow
    // table needs. IPv4 addresses are kept as host-order integers so the
    // capture thread does not build strings for every packet.
    // ------------------------------------------------------------
    struct LivePacketFlowSample
    {
        uint32_t sourceIp = 0;
        uint32_t destinationIp = 0;
        uint16_t sourcePort = 0;
        uint16_t destinationPort = 0;

        netwolf::core::TransportProtocol protocol =
            netwolf::core::TransportProtocol::Unknown;

        uint32_t wireLength = 0;
        uint8_t tcpFlags = 0;

        // Ethernet source address and IP TTL of this packet.
        uint8_t sourceMac[6] = { 0, 0, 0, 0, 0, 0 };
        uint8_t ttl = 0;

        // Only for TCP SYN packets (connection start):
        // OS family of the sender's stack, and how many routers the packet
        // crossed before reaching the hotspot (0 = sent by the device itself).
        LiveOsFamily synOsFamily = LiveOsFamily::Unknown;
        uint8_t synHops = 0;

        // TLS ClientHello SNI carried by this exact packet (if any).
        std::string sniHost;

        netwolf::core::Timestamp at =
            netwolf::core::nowUtc();
    };


    // One client device connection seen on the hotspot adapter
    // (client ip:port <-> server ip:port), aggregated from every packet.
    struct LivePacketFlow
    {
        std::string clientIp;
        uint16_t clientPort = 0;

        std::string serverIp;
        uint16_t serverPort = 0;

        netwolf::core::TransportProtocol protocol =
            netwolf::core::TransportProtocol::Unknown;

        netwolf::core::Timestamp firstSeen =
            netwolf::core::nowUtc();

        netwolf::core::Timestamp lastSeen =
            netwolf::core::nowUtc();

        uint64_t bytesUp = 0;      // client -> server
        uint64_t bytesDown = 0;    // server -> client
        uint64_t packetsUp = 0;
        uint64_t packetsDown = 0;

        // TCP FIN or RST was seen: the connection is closing.
        bool closing = false;

        // Destination names observed in the traffic itself.
        std::string sniHost;    // from this flow's TLS ClientHello
        std::string dnsName;    // from a DNS answer that returned serverIp
    };

} // namespace netwolf::live