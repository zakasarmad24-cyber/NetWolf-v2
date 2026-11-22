#pragma once

#include "live_session_tracker.hpp"
#include "live_group_identity.hpp"
#include "live_packet_evidence_correlator.hpp"

#include <netwolf/core/engine.hpp>
#include <netwolf/core/models.hpp>
#include <netwolf/core/session_id.hpp>

#include <algorithm>
#include <cctype>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace netwolf::live {

    // ================================================================
    // NetWolf v2 - Live Session Group Adapter
    //
    // Stage 7 purpose:
    // Convert LiveSessionGroup objects into core::ConnectionGroup objects.
    //
    // This adapter now preserves live process evidence when available.
    // Exact destination identity still belongs to a later direct metadata layer.
    // ================================================================

    class LiveSessionGroupAdapter
    {
    public:
        std::vector<netwolf::core::ConnectionGroup> convert(
            const std::vector<LiveSessionGroup>& liveGroups,
            const netwolf::core::EngineEvidenceInput& evidenceInput,
            const std::vector<LivePacketMetadata>& packetMetadataItems
        ) const;

        std::vector<netwolf::core::ConnectionGroup> convert(
            const std::vector<LiveSessionGroup>& liveGroups,
            const netwolf::core::EngineEvidenceInput& evidenceInput
        ) const;

        std::vector<netwolf::core::ConnectionGroup> convert(
            const std::vector<LiveSessionGroup>& liveGroups
        ) const;

    private:
        netwolf::core::ConnectionGroup convertGroup(
            const LiveSessionGroup& liveGroup,
            size_t index,
            const netwolf::core::EngineEvidenceInput& evidenceInput,
            const std::vector<LivePacketMetadata>& packetMetadataItems
        ) const;

        netwolf::core::SubConnectionRecord convertSubConnection(
            const LiveSessionGroup& liveGroup,
            const LiveSessionSubConnection& liveSub,
            const netwolf::core::EngineEvidenceInput& evidenceInput,
            const std::vector<LivePacketMetadata>& packetMetadataItems
        ) const;

        static netwolf::core::ConnectionSession makeSession(
            const LiveSessionGroup& liveGroup,
            const netwolf::core::ObservedConnection& observed
        );

        static netwolf::core::AttributionResult makeLiveAttribution(
            const LiveSessionGroup& liveGroup,
            const netwolf::core::ObservedConnection& observed,
            const netwolf::core::EngineEvidenceInput& evidenceInput,
            const std::vector<LivePacketMetadata>& packetMetadataItems
        );

        static std::optional<netwolf::core::ProcessCandidate> findProcessCandidate(
            const netwolf::core::ObservedConnection& observed,
            const netwolf::core::EngineEvidenceInput& evidenceInput
        );

        static std::string makeGroupId(
            const LiveSessionGroup& liveGroup,
            size_t index
        );

        static std::string sanitizeIdPart(
            const std::string& value
        );

        static std::string buildConnectionType(
            const LiveSessionGroup& liveGroup,
            const netwolf::core::ObservedConnection& observed
        );

        static std::string processDisplayName(
            const std::optional<netwolf::core::ProcessCandidate>& process
        );

        static std::string formatBehaviorScore(
            const LiveGroupIdentity& identity
        );

        static std::string formatIndicatorFlag(
            bool value
        );
    };


    inline std::vector<netwolf::core::ConnectionGroup>
        LiveSessionGroupAdapter::convert(
            const std::vector<LiveSessionGroup>& liveGroups,
            const netwolf::core::EngineEvidenceInput& evidenceInput,
            const std::vector<LivePacketMetadata>& packetMetadataItems
        ) const
    {
        std::vector<netwolf::core::ConnectionGroup> result;
        result.reserve(liveGroups.size());

        size_t index = 0;

        for (const auto& liveGroup : liveGroups)
        {
            result.push_back(
                convertGroup(
                    liveGroup,
                    index,
                    evidenceInput,
                    packetMetadataItems
                )
            );

            ++index;
        }

        std::sort(
            result.begin(),
            result.end(),
            [](const netwolf::core::ConnectionGroup& a,
                const netwolf::core::ConnectionGroup& b)
            {
                if (a.deviceIp != b.deviceIp)
                    return a.deviceIp < b.deviceIp;

                if (a.subConnectionCount() != b.subConnectionCount())
                    return a.subConnectionCount() > b.subConnectionCount();

                return a.mainEntityName < b.mainEntityName;
            }
        );

        return result;
    }


    inline std::vector<netwolf::core::ConnectionGroup>
        LiveSessionGroupAdapter::convert(
            const std::vector<LiveSessionGroup>& liveGroups,
            const netwolf::core::EngineEvidenceInput& evidenceInput
        ) const
    {
        const std::vector<LivePacketMetadata> emptyPacketMetadata;

        return convert(
            liveGroups,
            evidenceInput,
            emptyPacketMetadata
        );
    }


    inline std::vector<netwolf::core::ConnectionGroup>
        LiveSessionGroupAdapter::convert(
            const std::vector<LiveSessionGroup>& liveGroups
        ) const
    {
        netwolf::core::EngineEvidenceInput emptyEvidence;
        return convert(liveGroups, emptyEvidence);
    }


    inline netwolf::core::ConnectionGroup
        LiveSessionGroupAdapter::convertGroup(
            const LiveSessionGroup& liveGroup,
            size_t index,
            const netwolf::core::EngineEvidenceInput& evidenceInput,
            const std::vector<LivePacketMetadata>& packetMetadataItems
        ) const
    {
        netwolf::core::ConnectionGroup group;

        group.groupId = makeGroupId(
            liveGroup,
            index
        );

        LiveGroupIdentityResolver identityResolver;
        const LiveGroupIdentity identity =
            identityResolver.resolve(liveGroup);

        group.deviceIp = liveGroup.deviceIp;

        group.mainEntityName = identity.mainEntityName.empty()
            ? "Live network service"
            : identity.mainEntityName;

        group.mainCategory = identity.category.empty()
            ? "Live transport/service grouping"
            : identity.category;

        group.mainCategory = "Live transport/service grouping";
        group.ownerProcessName = liveGroup.ownerProcessName.empty()
            ? "Process context unavailable"
            : liveGroup.ownerProcessName;

        group.firstSeen = liveGroup.firstSeen;
        group.lastSeen = liveGroup.lastSeen;

        group.totalBytes = 0;
        group.totalPackets = 0;

        group.groupConfidence = identity.confidence;

        std::ostringstream groupReason;

        if (!liveGroup.groupingReason.empty())
        {
            groupReason
                << liveGroup.groupingReason
                << " ";
        }

        groupReason
            << identity.reason
            << " Stage 7 output summary: behaviorScore="
            << formatBehaviorScore(identity)
            << ", behaviorLabel="
            << (identity.behaviorLabel.empty()
                ? "unlabeled"
                : identity.behaviorLabel)
            << ", possibleMultiClientRelayIndicator="
            << formatIndicatorFlag(
                identity.possibleMultiClientRelayIndicator
            )
            << ".";

        std::map<std::string, size_t> packetDomainCounts;
        std::map<std::string, netwolf::core::ConfidenceLevel> packetDomainConfidence;

        group.subConnections.reserve(
            liveGroup.subConnections.size()
        );

        for (const auto& liveSub : liveGroup.subConnections)
        {
            netwolf::core::SubConnectionRecord record =
                convertSubConnection(
                    liveGroup,
                    liveSub,
                    evidenceInput,
                    packetMetadataItems
                );

            if (!record.attribution.destinationDomain.empty())
            {
                const std::string domain =
                    record.attribution.destinationDomain;

                ++packetDomainCounts[domain];

                const auto existingConfidence =
                    packetDomainConfidence.find(domain);

                if (existingConfidence == packetDomainConfidence.end() ||
                    netwolf::core::confidenceScore(record.attribution.confidence) >
                    netwolf::core::confidenceScore(existingConfidence->second))
                {
                    packetDomainConfidence[domain] =
                        record.attribution.confidence;
                }
            }

            group.totalBytes += record.session.totalBytes();
            group.totalPackets += record.session.totalPackets();

            if (record.session.observed.firstSeen < group.firstSeen)
                group.firstSeen = record.session.observed.firstSeen;

            if (record.session.observed.lastSeen > group.lastSeen)
                group.lastSeen = record.session.observed.lastSeen;

            if (record.attribution.ownerProcess.has_value())
            {
                const std::string processName =
                    processDisplayName(record.attribution.ownerProcess);

                if (!processName.empty() &&
                    group.ownerProcessName == "Process context unavailable")
                {
                    group.ownerProcessName = processName;
                }

                if (!processName.empty() &&
                    group.mainEntityName == liveGroup.serviceLabel)
                {
                    group.mainEntityName =
                        processName + " / " + liveGroup.serviceLabel;
                }
            }

            group.subConnections.push_back(
                std::move(record)
            );
        }

        if (!packetDomainCounts.empty())
        {
            std::string selectedPacketDomain;
            size_t selectedPacketDomainCount = 0;
            netwolf::core::ConfidenceLevel selectedPacketConfidence =
                netwolf::core::ConfidenceLevel::None;

            for (const auto& entry : packetDomainCounts)
            {
                const auto confidenceFound =
                    packetDomainConfidence.find(entry.first);

                const netwolf::core::ConfidenceLevel candidateConfidence =
                    confidenceFound == packetDomainConfidence.end()
                        ? netwolf::core::ConfidenceLevel::None
                        : confidenceFound->second;

                if (selectedPacketDomain.empty() ||
                    entry.second > selectedPacketDomainCount ||
                    (entry.second == selectedPacketDomainCount &&
                     netwolf::core::confidenceScore(candidateConfidence) >
                     netwolf::core::confidenceScore(selectedPacketConfidence)))
                {
                    selectedPacketDomain = entry.first;
                    selectedPacketDomainCount = entry.second;
                    selectedPacketConfidence = candidateConfidence;
                }
            }

            if (!selectedPacketDomain.empty())
            {
                group.mainEntityName = selectedPacketDomain;
                group.mainCategory = "Direct packet metadata destination";
                group.groupConfidence = selectedPacketConfidence;

                group.groupingReason +=
                    " Direct packet metadata resolved the main destination as " +
                    selectedPacketDomain +
                    " using " +
                    std::to_string(selectedPacketDomainCount) +
                    " matched sub-connection(s).";
            }
        }

        if (group.mainEntityName.empty())
            group.mainEntityName = "Live network service";

        return group;
    }


    inline netwolf::core::SubConnectionRecord
        LiveSessionGroupAdapter::convertSubConnection(
            const LiveSessionGroup& liveGroup,
            const LiveSessionSubConnection& liveSub,
            const netwolf::core::EngineEvidenceInput& evidenceInput,
            const std::vector<LivePacketMetadata>& packetMetadataItems
        ) const
    {
        netwolf::core::SubConnectionRecord record;

        record.session = makeSession(
            liveGroup,
            liveSub.observed
        );

        record.attribution = makeLiveAttribution(
            liveGroup,
            liveSub.observed,
            evidenceInput,
            packetMetadataItems
        );

        return record;
    }


    inline netwolf::core::ConnectionSession
        LiveSessionGroupAdapter::makeSession(
            const LiveSessionGroup& liveGroup,
            const netwolf::core::ObservedConnection& observed
        )
    {
        netwolf::core::ConnectionSession session;

        session.sessionId =
            netwolf::core::makeSessionId(observed);

        session.observed = observed;

        session.protocolLabel = liveGroup.protocolLabel.empty()
            ? "Transport"
            : liveGroup.protocolLabel;

        session.connectionType =
            buildConnectionType(
                liveGroup,
                observed
            );

        session.encryptedLikely =
            observed.remotePort == 443 ||
            observed.remotePort == 853;

        session.httpsLikely =
            observed.remotePort == 443 &&
            observed.protocol == netwolf::core::TransportProtocol::TCP;

        session.httpLikely =
            observed.remotePort == 80 &&
            observed.protocol == netwolf::core::TransportProtocol::TCP;

        session.dnsLikely =
            observed.remotePort == 53;

        session.quicLikely =
            observed.remotePort == 443 &&
            observed.protocol == netwolf::core::TransportProtocol::UDP;

        return session;
    }


    inline netwolf::core::AttributionResult
        LiveSessionGroupAdapter::makeLiveAttribution(
            const LiveSessionGroup& liveGroup,
            const netwolf::core::ObservedConnection& observed,
            const netwolf::core::EngineEvidenceInput& evidenceInput,
            const std::vector<LivePacketMetadata>& packetMetadataItems
        )
    {
        const std::optional<netwolf::core::ProcessCandidate> process =
            findProcessCandidate(
                observed,
                evidenceInput
            );

        LiveGroupIdentityResolver identityResolver;
        const LiveGroupIdentity identity =
            identityResolver.resolve(liveGroup);

        LivePacketEvidenceCorrelator packetCorrelator;

        const std::optional<LivePacketEvidenceCorrelation> packetCorrelation =
            packetCorrelator.correlate(
                observed,
                packetMetadataItems
            );

        netwolf::core::AttributionResult attribution;

        attribution.type =
            process.has_value()
            ? netwolf::core::AttributionType::ProcessAssociated
            : netwolf::core::AttributionType::UnclassifiedExplained;

        attribution.destinationDomain.clear();

        const std::string processName =
            processDisplayName(process);

        attribution.entityName = identity.mainEntityName.empty()
            ? (
                processName.empty()
                ? "Live network service"
                : processName
                )
            : identity.mainEntityName;

        attribution.category = identity.category.empty()
            ? "Live transport/service grouping"
            : identity.category;

        attribution.trafficClass = identity.trafficClass.empty()
            ? buildConnectionType(
                liveGroup,
                observed
            )
            : identity.trafficClass;

        attribution.source =
            process.has_value()
            ? netwolf::core::EvidenceSource::ProcessContext
            : netwolf::core::EvidenceSource::PortProtocolHint;

        attribution.confidence =
            identity.confidence;

        attribution.ownerProcess = process;

        if (packetCorrelation.has_value() &&
            packetCorrelation->matched &&
            !packetCorrelation->domain.empty())
        {
            attribution.type =
                netwolf::core::AttributionType::ExactDestination;

            attribution.destinationDomain =
                packetCorrelation->domain;

            attribution.entityName =
                packetCorrelation->domain;

            attribution.category =
                "Direct packet metadata destination";

            attribution.trafficClass =
                identity.trafficClass.empty()
                ? buildConnectionType(
                    liveGroup,
                    observed
                )
                : identity.trafficClass;

            attribution.confidence =
                packetCorrelation->confidence;

            std::ostringstream packetReason;

            packetReason
                << packetCorrelation->reason
                << " "
                << identity.reason;

            attribution.reason =
                packetReason.str();

            std::ostringstream packetLimitations;

            packetLimitations
                << packetCorrelation->limitations
                << " "
                << identity.limitations;

            attribution.limitations =
                packetLimitations.str();
        }

        std::ostringstream attributionReason;

        attributionReason
            << identity.reason
            << " Stage 7 attribution summary: behaviorScore="
            << formatBehaviorScore(identity)
            << ", behaviorLabel="
            << (identity.behaviorLabel.empty()
                ? "unlabeled"
                : identity.behaviorLabel)
            << ", possibleMultiClientRelayIndicator="
            << formatIndicatorFlag(
                identity.possibleMultiClientRelayIndicator
            )
            << ".";

        attribution.reason = attributionReason.str();

        std::ostringstream attributionLimitations;

        attributionLimitations
            << identity.limitations
            << " Stage 7 note: this behavioral score is a live traffic pattern score, "
            << "not an attack verdict and not exact destination attribution.";

        attribution.limitations = attributionLimitations.str();

        if (packetCorrelation.has_value() &&
            packetCorrelation->matched &&
            !packetCorrelation->domain.empty())
        {
            attribution.type =
                netwolf::core::AttributionType::ExactDestination;

            attribution.destinationDomain =
                packetCorrelation->domain;

            attribution.entityName =
                packetCorrelation->domain;

            attribution.category =
                "Direct packet metadata destination";

            attribution.trafficClass =
                identity.trafficClass.empty()
                ? buildConnectionType(
                    liveGroup,
                    observed
                )
                : identity.trafficClass;

            attribution.confidence =
                packetCorrelation->confidence;

            switch (packetCorrelation->type)
            {
            case LivePacketMetadataType::TlsSni:
                attribution.source =
                    netwolf::core::EvidenceSource::TlsSni;
                break;

            case LivePacketMetadataType::HttpHost:
                attribution.source =
                    netwolf::core::EvidenceSource::HttpHost;
                break;

            case LivePacketMetadataType::DnsAnswer:
                attribution.source =
                    netwolf::core::EvidenceSource::DnsAnswer;
                break;

            case LivePacketMetadataType::DnsQuery:
                attribution.source =
                    netwolf::core::EvidenceSource::FreshDnsCorrelation;
                break;

            case LivePacketMetadataType::EndpointObservation:
                attribution.source =
                    netwolf::core::EvidenceSource::IpOnly;
                break;

            case LivePacketMetadataType::Unknown:
            default:
                attribution.source =
                    netwolf::core::EvidenceSource::PortProtocolHint;
                break;
            }

            std::ostringstream packetReason;

            packetReason
                << packetCorrelation->reason
                << " "
                << identity.reason;

            attribution.reason =
                packetReason.str();

            std::ostringstream packetLimitations;

            packetLimitations
                << packetCorrelation->limitations
                << " "
                << identity.limitations;

            attribution.limitations =
                packetLimitations.str();
        }

        return attribution;
    }


    inline std::optional<netwolf::core::ProcessCandidate>
        LiveSessionGroupAdapter::findProcessCandidate(
            const netwolf::core::ObservedConnection& observed,
            const netwolf::core::EngineEvidenceInput& evidenceInput
        )
    {
        const std::string sessionId =
            netwolf::core::makeSessionId(observed);

        const auto found =
            evidenceInput.processBySessionId.find(sessionId);

        if (found == evidenceInput.processBySessionId.end())
            return std::nullopt;

        const netwolf::core::ProcessObservation& observation =
            found->second;

        netwolf::core::ProcessCandidate candidate;

        candidate.pid = observation.pid;
        candidate.processName = observation.processName;
        candidate.processPath = observation.processPath;
        candidate.originClass = netwolf::core::OriginClass::UserApplication;
        candidate.observedAt = netwolf::core::nowUtc();

        return candidate;
    }


    inline std::string LiveSessionGroupAdapter::makeGroupId(
        const LiveSessionGroup& liveGroup,
        size_t index
    )
    {
        std::ostringstream id;

        id
            << "live_"
            << index
            << "_"
            << sanitizeIdPart(liveGroup.groupKey);

        return id.str();
    }


    inline std::string LiveSessionGroupAdapter::sanitizeIdPart(
        const std::string& value
    )
    {
        std::string result;
        result.reserve(value.size());

        for (unsigned char ch : value)
        {
            if (std::isalnum(ch) != 0)
            {
                result.push_back(
                    static_cast<char>(ch)
                );
            }
            else
            {
                result.push_back('_');
            }

            if (result.size() >= 80)
                break;
        }

        if (result.empty())
            return "group";

        return result;
    }


    inline std::string LiveSessionGroupAdapter::buildConnectionType(
        const LiveSessionGroup& liveGroup,
        const netwolf::core::ObservedConnection& observed
    )
    {
        std::string type;

        if (!liveGroup.serviceLabel.empty())
            type += liveGroup.serviceLabel;
        else
            type += "Live service";

        type += " over ";

        if (!liveGroup.protocolLabel.empty())
            type += liveGroup.protocolLabel;
        else
            type += "transport";

        if (!observed.transportState.empty())
        {
            type += " / ";
            type += observed.transportState;
        }

        return type;
    }


    inline std::string LiveSessionGroupAdapter::processDisplayName(
        const std::optional<netwolf::core::ProcessCandidate>& process
    )
    {
        if (!process.has_value())
            return "";

        if (!process->processName.empty())
            return process->processName;

        if (process->pid != 0)
            return "PID " + std::to_string(process->pid);

        return "";
    }

    inline std::string LiveSessionGroupAdapter::formatBehaviorScore(
        const LiveGroupIdentity& identity
    )
    {
        std::ostringstream output;

        output
            << static_cast<int>(identity.behaviorScore)
            << "/100";

        return output.str();
    }


    inline std::string LiveSessionGroupAdapter::formatIndicatorFlag(
        bool value
    )
    {
        return value ? "yes" : "no";
    }

} // namespace netwolf::live