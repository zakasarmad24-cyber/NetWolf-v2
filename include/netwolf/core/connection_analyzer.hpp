#pragma once

#include "models.hpp"
#include "session_id.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace netwolf::core {

    // ================================================================
    // NetWolf v2 - Connection Analyzer
    // Layer 2: Analyzer
    //
    // Purpose:
    // 1. Convert ObservedConnection into stable ConnectionSession.
    // 2. Classify protocol, ports, encryption likelihood, and traffic type.
    // 3. Prepare the session for Destination Resolver and Origin Resolver.
    // ================================================================


    // ------------------------------------------------
    // Analyzer configuration
    // ------------------------------------------------

    struct ConnectionAnalyzerConfig
    {
        bool treatPort443AsEncrypted = true;
        bool treatUdp443AsQuic = true;
        bool treatPort53AsDns = true;
        bool treatPort80AsHttp = true;
        bool treatPort853AsSecureDns = true;
    };


    // ------------------------------------------------
    // Port classification result
    // ------------------------------------------------

    struct PortAnalysisResult
    {
        std::string serviceName;
        std::string serviceFamily;
        std::string connectionType;
        std::string reason;

        bool encryptedLikely = false;
        bool quicLikely = false;
        bool dnsLikely = false;
        bool httpLikely = false;
        bool httpsLikely = false;
    };


    // ------------------------------------------------
    // Connection Analyzer
    // ------------------------------------------------

    class ConnectionAnalyzer
    {
    public:
        explicit ConnectionAnalyzer(ConnectionAnalyzerConfig config = {});

        ConnectionSession analyze(const ObservedConnection& observed) const;

        std::vector<ConnectionSession> analyzeBatch(
            const std::vector<ObservedConnection>& observedConnections
        ) const;

    private:
        ConnectionAnalyzerConfig config_;

    private:
        PortAnalysisResult analyzePortAndProtocol(const ObservedConnection& observed) const;

        std::string makeProtocolLabel(const ObservedConnection& observed) const;

        std::string makeConnectionType(
            const ObservedConnection& observed,
            const PortAnalysisResult& portResult
        ) const;

        bool isLikelyEncrypted(
            const ObservedConnection& observed,
            const PortAnalysisResult& portResult
        ) const;

        static bool isWebPort(uint16_t port);
        static bool isDnsPort(uint16_t port);
        static bool isMailPort(uint16_t port);
        static bool isRemoteAccessPort(uint16_t port);
        static bool isDeveloperPort(uint16_t port);
        static bool isMessagingOrGamingPort(uint16_t port);
    };


    // ------------------------------------------------
    // Inline implementation
    // Keeping this analyzer header-only for now.
    // Later, if the project grows, we can move implementation
    // to connection_analyzer.cpp without changing public API.
    // ------------------------------------------------

    inline ConnectionAnalyzer::ConnectionAnalyzer(ConnectionAnalyzerConfig config)
        : config_(config)
    {
    }


    inline ConnectionSession ConnectionAnalyzer::analyze(const ObservedConnection& observed) const
    {
        ConnectionSession session;

        session.sessionId = makeSessionId(observed);
        session.observed = observed;

        const PortAnalysisResult portResult = analyzePortAndProtocol(observed);

        session.protocolLabel = makeProtocolLabel(observed);
        session.connectionType = makeConnectionType(observed, portResult);

        session.encryptedLikely = isLikelyEncrypted(observed, portResult);
        session.quicLikely = portResult.quicLikely;
        session.dnsLikely = portResult.dnsLikely;
        session.httpLikely = portResult.httpLikely;
        session.httpsLikely = portResult.httpsLikely;

        return session;
    }


    inline std::vector<ConnectionSession> ConnectionAnalyzer::analyzeBatch(
        const std::vector<ObservedConnection>& observedConnections
    ) const
    {
        std::vector<ConnectionSession> sessions;
        sessions.reserve(observedConnections.size());

        for (const auto& observed : observedConnections)
        {
            if (!observed.isOutbound())
                continue;

            sessions.push_back(analyze(observed));
        }

        return sessions;
    }


    inline PortAnalysisResult ConnectionAnalyzer::analyzePortAndProtocol(
        const ObservedConnection& observed
    ) const
    {
        PortAnalysisResult result;

        const uint16_t remotePort = observed.remotePort;
        const TransportProtocol protocol = observed.protocol;

        // -----------------------------
        // DNS
        // -----------------------------
        if (remotePort == 53 && config_.treatPort53AsDns)
        {
            result.serviceName = "DNS";
            result.serviceFamily = "Name resolution";
            result.connectionType = "DNS query/response traffic";
            result.reason = "Remote port 53 indicates DNS traffic.";
            result.dnsLikely = true;
            return result;
        }

        if (remotePort == 853 && config_.treatPort853AsSecureDns)
        {
            result.serviceName = "DNS-over-TLS";
            result.serviceFamily = "Name resolution";
            result.connectionType = "Encrypted DNS traffic";
            result.reason = "Remote port 853 indicates DNS-over-TLS traffic.";
            result.dnsLikely = true;
            result.encryptedLikely = true;
            return result;
        }

        // -----------------------------
        // HTTP / HTTPS / QUIC
        // -----------------------------
        if (remotePort == 80 && config_.treatPort80AsHttp)
        {
            result.serviceName = "HTTP";
            result.serviceFamily = "Web";
            result.connectionType = "Plain HTTP web traffic";
            result.reason = "Remote port 80 indicates HTTP traffic.";
            result.httpLikely = true;
            return result;
        }

        if (remotePort == 443 && protocol == TransportProtocol::TCP && config_.treatPort443AsEncrypted)
        {
            result.serviceName = "HTTPS";
            result.serviceFamily = "Web";
            result.connectionType = "Encrypted HTTPS web traffic";
            result.reason = "TCP remote port 443 indicates HTTPS/TLS traffic.";
            result.httpsLikely = true;
            result.encryptedLikely = true;
            return result;
        }

        if (remotePort == 443 && protocol == TransportProtocol::UDP && config_.treatUdp443AsQuic)
        {
            result.serviceName = "QUIC/HTTP3";
            result.serviceFamily = "Web";
            result.connectionType = "Encrypted QUIC/HTTP3 web traffic";
            result.reason = "UDP remote port 443 indicates likely QUIC/HTTP3 traffic.";
            result.quicLikely = true;
            result.httpsLikely = true;
            result.encryptedLikely = true;
            return result;
        }

        // -----------------------------
        // Mail
        // -----------------------------
        if (isMailPort(remotePort))
        {
            result.serviceName = "Mail service";
            result.serviceFamily = "Email";
            result.connectionType = "Email-related traffic";
            result.reason = "Remote port matches common email service ports.";
            result.encryptedLikely = (remotePort == 465 || remotePort == 587 || remotePort == 993 || remotePort == 995);
            return result;
        }

        // -----------------------------
        // Remote access
        // -----------------------------
        if (isRemoteAccessPort(remotePort))
        {
            result.serviceName = "Remote access";
            result.serviceFamily = "Remote administration";
            result.connectionType = "Remote access traffic";
            result.reason = "Remote port matches common remote access or administration ports.";
            result.encryptedLikely = (remotePort == 22 || remotePort == 3389);
            return result;
        }

        // -----------------------------
        // Developer / local service ports
        // -----------------------------
        if (isDeveloperPort(remotePort))
        {
            result.serviceName = "Developer or local service";
            result.serviceFamily = "Development";
            result.connectionType = "Developer/service traffic";
            result.reason = "Remote port matches common development or service ports.";
            return result;
        }

        // -----------------------------
        // Messaging / gaming / real-time
        // -----------------------------
        if (isMessagingOrGamingPort(remotePort))
        {
            result.serviceName = "Real-time application traffic";
            result.serviceFamily = "Messaging/Gaming/Voice";
            result.connectionType = "Real-time application traffic";
            result.reason = "Remote port matches common real-time application patterns.";
            return result;
        }

        // -----------------------------
        // Generic fallback, but not raw Unknown
        // -----------------------------
        result.serviceName = "IP service";
        result.serviceFamily = "General IP traffic";

        if (protocol == TransportProtocol::TCP)
        {
            result.connectionType = "Classified TCP IP traffic";
            result.reason = "No exact service matched; TCP protocol and remote port are still recorded.";
        }
        else if (protocol == TransportProtocol::UDP)
        {
            result.connectionType = "Classified UDP IP traffic";
            result.reason = "No exact service matched; UDP protocol and remote port are still recorded.";
        }
        else if (protocol == TransportProtocol::ICMP)
        {
            result.connectionType = "ICMP control traffic";
            result.reason = "ICMP traffic detected.";
        }
        else
        {
            result.connectionType = "Classified IP-only traffic";
            result.reason = "No exact service matched; the engine keeps an explained IP-only classification.";
        }

        return result;
    }


    inline std::string ConnectionAnalyzer::makeProtocolLabel(const ObservedConnection& observed) const
    {
        switch (observed.protocol)
        {
        case TransportProtocol::TCP:
            return "TCP";

        case TransportProtocol::UDP:
            return "UDP";

        case TransportProtocol::ICMP:
            return "ICMP";

        case TransportProtocol::Other:
            return "Other IP protocol";

        case TransportProtocol::Unknown:
            return "IP protocol not decoded";

        default:
            return "IP protocol not decoded";
        }
    }


    inline std::string ConnectionAnalyzer::makeConnectionType(
        const ObservedConnection& observed,
        const PortAnalysisResult& portResult
    ) const
    {
        if (!portResult.connectionType.empty())
            return portResult.connectionType;

        if (observed.protocol == TransportProtocol::TCP)
            return "Classified TCP IP traffic";

        if (observed.protocol == TransportProtocol::UDP)
            return "Classified UDP IP traffic";

        if (observed.protocol == TransportProtocol::ICMP)
            return "ICMP control traffic";

        return "Classified IP-only traffic";
    }


    inline bool ConnectionAnalyzer::isLikelyEncrypted(
        const ObservedConnection& observed,
        const PortAnalysisResult& portResult
    ) const
    {
        if (portResult.encryptedLikely)
            return true;

        if (observed.remotePort == 443 && config_.treatPort443AsEncrypted)
            return true;

        if (observed.remotePort == 853 && config_.treatPort853AsSecureDns)
            return true;

        return false;
    }


    inline bool ConnectionAnalyzer::isWebPort(uint16_t port)
    {
        return port == 80 ||
            port == 443 ||
            port == 8080 ||
            port == 8443;
    }


    inline bool ConnectionAnalyzer::isDnsPort(uint16_t port)
    {
        return port == 53 ||
            port == 853;
    }


    inline bool ConnectionAnalyzer::isMailPort(uint16_t port)
    {
        return port == 25 ||
            port == 110 ||
            port == 143 ||
            port == 465 ||
            port == 587 ||
            port == 993 ||
            port == 995;
    }


    inline bool ConnectionAnalyzer::isRemoteAccessPort(uint16_t port)
    {
        return port == 22 ||
            port == 23 ||
            port == 3389 ||
            port == 5900;
    }


    inline bool ConnectionAnalyzer::isDeveloperPort(uint16_t port)
    {
        return port == 3000 ||
            port == 3306 ||
            port == 5000 ||
            port == 5432 ||
            port == 6379 ||
            port == 8000 ||
            port == 8080 ||
            port == 9200;
    }


    inline bool ConnectionAnalyzer::isMessagingOrGamingPort(uint16_t port)
    {
        return port == 3478 ||
            port == 3479 ||
            port == 3480 ||
            port == 5004 ||
            port == 5005 ||
            port == 5222 ||
            port == 5223 ||
            port == 27015 ||
            port == 27016 ||
            port == 27017;
    }

} // namespace netwolf::core