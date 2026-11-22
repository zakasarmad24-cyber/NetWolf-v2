#pragma once

#include "live_packet_metadata.hpp"

#include <netwolf/core/models.hpp>

#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace netwolf::live {

    // ================================================================
    // NetWolf v2 - Live Packet Evidence Correlator
    //
    // Stage 7 purpose:
    // Correlate direct packet metadata with active observed connections.
    //
    // Matching priority:
    // 1. TLS SNI exact endpoint
    // 2. HTTP Host exact endpoint
    // 3. DNS Answer resolved IP
    // 4. DNS Query exact endpoint
    // 5. Endpoint observation
    //
    // Important:
    // - This does NOT use DNS cache.
    // - This only uses metadata inserted by direct packet sensors.
    // ================================================================

    struct LivePacketEvidenceCorrelation
    {
        bool matched = false;

        LivePacketMetadataType type =
            LivePacketMetadataType::Unknown;

        std::string domain;
        std::string resolvedIp;

        netwolf::core::ConfidenceLevel confidence =
            netwolf::core::ConfidenceLevel::Low;

        std::string reason;
        std::string limitations;
    };


    class LivePacketEvidenceCorrelator
    {
    public:
        std::optional<LivePacketEvidenceCorrelation> correlate(
            const netwolf::core::ObservedConnection& observed,
            const std::vector<LivePacketMetadata>& metadataItems
        ) const;

    private:
        static bool endpointMatches(
            const netwolf::core::ObservedConnection& observed,
            const LivePacketMetadata& metadata
        );

        static bool dnsAnswerMatches(
            const netwolf::core::ObservedConnection& observed,
            const LivePacketMetadata& metadata
        );

        static bool remoteIpMatches(
            const netwolf::core::ObservedConnection& observed,
            const LivePacketMetadata& metadata
        );

        static bool remoteServiceMatches(
            const netwolf::core::ObservedConnection& observed,
            const LivePacketMetadata& metadata
        );

        static int priority(
            const netwolf::core::ObservedConnection& observed,
            const LivePacketMetadata& metadata
        );

        static std::string selectDomain(
            const LivePacketMetadata& metadata
        );

        static LivePacketEvidenceCorrelation makeCorrelation(
            const netwolf::core::ObservedConnection& observed,
            const LivePacketMetadata& metadata,
            int score
        );
    };


    inline std::optional<LivePacketEvidenceCorrelation>
        LivePacketEvidenceCorrelator::correlate(
            const netwolf::core::ObservedConnection& observed,
            const std::vector<LivePacketMetadata>& metadataItems
        ) const
    {
        const LivePacketMetadata* best = nullptr;
        int bestScore = 0;

        for (const auto& item : metadataItems)
        {
            const int score =
                priority(
                    observed,
                    item
                );

            if (score <= 0)
                continue;

            if (best == nullptr ||
                score > bestScore ||
                (score == bestScore && item.observedAt > best->observedAt))
            {
                bestScore = score;
                best = &item;
            }
        }

        if (best == nullptr || bestScore <= 0)
            return std::nullopt;

        return makeCorrelation(
            observed,
            *best,
            bestScore
        );
    }


    inline bool LivePacketEvidenceCorrelator::endpointMatches(
        const netwolf::core::ObservedConnection& observed,
        const LivePacketMetadata& metadata
    )
    {
        if (metadata.endpoint.remoteIp.empty())
            return false;

        if (metadata.endpoint.remoteIp != observed.remoteIp)
            return false;

        if (metadata.endpoint.remotePort != 0 &&
            observed.remotePort != 0 &&
            metadata.endpoint.remotePort != observed.remotePort)
        {
            return false;
        }

        if (metadata.endpoint.localPort != 0 &&
            observed.localPort != 0 &&
            metadata.endpoint.localPort != observed.localPort)
        {
            return false;
        }

        if (metadata.endpoint.protocol != netwolf::core::TransportProtocol::Unknown &&
            observed.protocol != netwolf::core::TransportProtocol::Unknown &&
            metadata.endpoint.protocol != observed.protocol)
        {
            return false;
        }

        return true;
    }


    inline bool LivePacketEvidenceCorrelator::dnsAnswerMatches(
        const netwolf::core::ObservedConnection& observed,
        const LivePacketMetadata& metadata
    )
    {
        return
            metadata.type == LivePacketMetadataType::DnsAnswer &&
            !metadata.resolvedIp.empty() &&
            metadata.resolvedIp == observed.remoteIp;
    }


    inline bool LivePacketEvidenceCorrelator::remoteIpMatches(
        const netwolf::core::ObservedConnection& observed,
        const LivePacketMetadata& metadata
    )
    {
        if (observed.remoteIp.empty() ||
            metadata.endpoint.remoteIp.empty())
        {
            return false;
        }

        return metadata.endpoint.remoteIp == observed.remoteIp;
    }


    inline bool LivePacketEvidenceCorrelator::remoteServiceMatches(
        const netwolf::core::ObservedConnection& observed,
        const LivePacketMetadata& metadata
    )
    {
        if (!remoteIpMatches(observed, metadata))
            return false;

        if (metadata.endpoint.remotePort != 0 &&
            observed.remotePort != 0 &&
            metadata.endpoint.remotePort != observed.remotePort)
        {
            return false;
        }

        if (metadata.endpoint.protocol != netwolf::core::TransportProtocol::Unknown &&
            observed.protocol != netwolf::core::TransportProtocol::Unknown &&
            metadata.endpoint.protocol != observed.protocol)
        {
            return false;
        }

        return true;
    }


    inline int LivePacketEvidenceCorrelator::priority(
        const netwolf::core::ObservedConnection& observed,
        const LivePacketMetadata& metadata
    )
    {
        const bool endpointMatch =
            endpointMatches(
                observed,
                metadata
            );

        const bool remoteServiceMatch =
            remoteServiceMatches(
                observed,
                metadata
            );

        const bool remoteIpMatch =
            remoteIpMatches(
                observed,
                metadata
            );

        const bool dnsAnswerMatch =
            dnsAnswerMatches(
                observed,
                metadata
            );

        switch (metadata.type)
        {
        case LivePacketMetadataType::TlsSni:
            if (metadata.name.empty())
                return 0;

            if (endpointMatch)
                return 100;

            // Stage 8 live GUI fallback:
            // TLS ClientHello can be captured before/after the TCP table snapshot.
            // When the local ephemeral port no longer matches, still use a same
            // remote IP + remote service match as a strong correlation.
            if (remoteServiceMatch)
                return 92;

            if (remoteIpMatch)
                return 82;

            return 0;

        case LivePacketMetadataType::HttpHost:
            if (metadata.name.empty())
                return 0;

            if (endpointMatch)
                return 95;

            if (remoteServiceMatch)
                return 86;

            if (remoteIpMatch)
                return 76;

            return 0;

        case LivePacketMetadataType::DnsAnswer:
            return dnsAnswerMatch && !metadata.name.empty()
                ? 88
                : 0;

        case LivePacketMetadataType::DnsQuery:
            // DNS query metadata identifies the DNS server connection itself.
            // It should not be used to name unrelated HTTPS connections.
            return endpointMatch && !metadata.name.empty()
                ? 45
                : 0;

        case LivePacketMetadataType::EndpointObservation:
            if (endpointMatch)
                return 24;

            if (remoteServiceMatch)
                return 18;

            if (remoteIpMatch)
                return 12;

            return 0;

        case LivePacketMetadataType::Unknown:
        default:
            return 0;
        }
    }


    inline std::string LivePacketEvidenceCorrelator::selectDomain(
        const LivePacketMetadata& metadata
    )
    {
        if (!metadata.name.empty())
            return metadata.name;

        // Force a visible destination for every packet-observed connection.
        // When DNS/TLS evidence is not available yet, the remote endpoint is
        // still the real network destination and is better than an unknown row.
        if (metadata.type == LivePacketMetadataType::EndpointObservation &&
            !metadata.endpoint.remoteIp.empty())
        {
            std::string scheme = "tcp";

            if (metadata.endpoint.remotePort == 443 &&
                metadata.endpoint.protocol == netwolf::core::TransportProtocol::TCP)
            {
                scheme = "https";
            }
            else if (metadata.endpoint.remotePort == 80 &&
                metadata.endpoint.protocol == netwolf::core::TransportProtocol::TCP)
            {
                scheme = "http";
            }
            else if (metadata.endpoint.protocol == netwolf::core::TransportProtocol::UDP)
            {
                scheme = "udp";
            }

            std::string endpoint = scheme + "://" + metadata.endpoint.remoteIp;

            if ((scheme == "https" && metadata.endpoint.remotePort != 443) ||
                (scheme == "http" && metadata.endpoint.remotePort != 80) ||
                ((scheme == "tcp" || scheme == "udp") && metadata.endpoint.remotePort != 0))
            {
                endpoint += ":";
                endpoint += std::to_string(metadata.endpoint.remotePort);
            }

            return endpoint;
        }

        return "";
    }


    inline LivePacketEvidenceCorrelation
        LivePacketEvidenceCorrelator::makeCorrelation(
            const netwolf::core::ObservedConnection& observed,
            const LivePacketMetadata& metadata,
            int score
        )
    {
        LivePacketEvidenceCorrelation result;

        result.matched = true;
        result.type = metadata.type;
        result.domain = selectDomain(metadata);
        result.resolvedIp = metadata.resolvedIp;
        if (score >= 90)
        {
            result.confidence = metadata.confidence;
        }
        else if (score >= 80)
        {
            result.confidence = netwolf::core::ConfidenceLevel::MediumHigh;
        }
        else if (score >= 70)
        {
            result.confidence = netwolf::core::ConfidenceLevel::Medium;
        }
        else
        {
            result.confidence = metadata.confidence;
        }

        std::ostringstream reason;

        reason
            << "Direct packet metadata matched this live connection. "
            << "Metadata type: "
            << toString(metadata.type)
            << ". Match score: "
            << score
            << ". Connection endpoint: "
            << observed.localIp
            << ":"
            << observed.localPort
            << " -> "
            << observed.remoteIp
            << ":"
            << observed.remotePort
            << ".";

        if (!metadata.name.empty())
        {
            reason
                << " Name: "
                << metadata.name
                << ".";
        }

        if (!metadata.resolvedIp.empty())
        {
            reason
                << " Resolved IP: "
                << metadata.resolvedIp
                << ".";
        }

        if (!metadata.reason.empty())
        {
            reason
                << " Sensor reason: "
                << metadata.reason;
        }

        result.reason = reason.str();

        result.limitations =
            "This destination identity comes from direct packet metadata provided to the live engine. "
            "It does not use DNS cache or browser history. Accuracy depends on the packet sensor and protocol visibility.";

        return result;
    }

} // namespace netwolf::live