#pragma once

#include "live_packet_metadata.hpp"

#include <algorithm>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace netwolf::live {

    // ================================================================
    // NetWolf v2 - Live Packet Evidence Store
    //
    // Stage 7 purpose:
    // Store packet-derived metadata so the live engine can later
    // correlate packet evidence with live TCP/UDP sessions.
    //
    // Important:
    // - No DNS cache.
    // - No Windows cache.
    // - No remembered browser history.
    // - Only direct packet metadata inserted by a future packet sensor.
    // ================================================================

    struct LivePacketEvidenceStoreSummary
    {
        size_t totalItems = 0;
        size_t dnsQueries = 0;
        size_t dnsAnswers = 0;
        size_t httpHosts = 0;
        size_t tlsSni = 0;
        size_t endpointObservations = 0;

        std::string summaryText;
    };


    class LivePacketEvidenceStore
    {
    public:
        void add(
            const LivePacketMetadata& metadata
        );

        void clear();

        std::vector<LivePacketMetadata> findByRemoteEndpoint(
            const std::string& remoteIp,
            uint16_t remotePort
        ) const;

        std::vector<LivePacketMetadata> findByResolvedIp(
            const std::string& remoteIp
        ) const;

        LivePacketEvidenceStoreSummary summary() const;

    private:
        std::vector<LivePacketMetadata> items_;

    private:
        static bool sameRemoteEndpoint(
            const LivePacketMetadata& metadata,
            const std::string& remoteIp,
            uint16_t remotePort
        );
    };


    inline void LivePacketEvidenceStore::add(
        const LivePacketMetadata& metadata
    )
    {
        if (metadata.type == LivePacketMetadataType::Unknown)
            return;

        if (metadata.name.empty() &&
            metadata.resolvedIp.empty() &&
            metadata.endpoint.remoteIp.empty())
        {
            return;
        }

        items_.push_back(metadata);
    }


    inline void LivePacketEvidenceStore::clear()
    {
        items_.clear();
    }


    inline std::vector<LivePacketMetadata>
        LivePacketEvidenceStore::findByRemoteEndpoint(
            const std::string& remoteIp,
            uint16_t remotePort
        ) const
    {
        std::vector<LivePacketMetadata> result;

        for (const auto& item : items_)
        {
            if (sameRemoteEndpoint(
                item,
                remoteIp,
                remotePort
            ))
            {
                result.push_back(item);
            }
        }

        return result;
    }


    inline std::vector<LivePacketMetadata>
        LivePacketEvidenceStore::findByResolvedIp(
            const std::string& remoteIp
        ) const
    {
        std::vector<LivePacketMetadata> result;

        if (remoteIp.empty())
            return result;

        for (const auto& item : items_)
        {
            if (item.resolvedIp == remoteIp)
                result.push_back(item);
        }

        return result;
    }


    inline LivePacketEvidenceStoreSummary
        LivePacketEvidenceStore::summary() const
    {
        LivePacketEvidenceStoreSummary result;

        result.totalItems = items_.size();

        for (const auto& item : items_)
        {
            switch (item.type)
            {
            case LivePacketMetadataType::DnsQuery:
                ++result.dnsQueries;
                break;

            case LivePacketMetadataType::DnsAnswer:
                ++result.dnsAnswers;
                break;

            case LivePacketMetadataType::HttpHost:
                ++result.httpHosts;
                break;

            case LivePacketMetadataType::TlsSni:
                ++result.tlsSni;
                break;

            case LivePacketMetadataType::EndpointObservation:
                ++result.endpointObservations;
                break;

            case LivePacketMetadataType::Unknown:
            default:
                break;
            }
        }

        std::ostringstream out;

        out
            << "Packet evidence store: total="
            << result.totalItems
            << ", dnsQueries="
            << result.dnsQueries
            << ", dnsAnswers="
            << result.dnsAnswers
            << ", httpHosts="
            << result.httpHosts
            << ", tlsSni="
            << result.tlsSni
            << ", endpointObservations="
            << result.endpointObservations;

        result.summaryText = out.str();

        return result;
    }


    inline bool LivePacketEvidenceStore::sameRemoteEndpoint(
        const LivePacketMetadata& metadata,
        const std::string& remoteIp,
        uint16_t remotePort
    )
    {
        return
            metadata.endpoint.remoteIp == remoteIp &&
            metadata.endpoint.remotePort == remotePort;
    }

} // namespace netwolf::live