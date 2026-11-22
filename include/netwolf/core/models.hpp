#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace netwolf::core {

    // ================================================================
    // NetWolf v2 - Core Data Models
    // Layer: Foundation
    //
    // This file represents the internal engine language.
    // It follows the PDF architecture:
    // Observed Connection -> ConnectionSession -> EvidenceStore
    // -> AttributionResult -> Grouped Connection -> Device Classification
    // ================================================================


    // ------------------------------------------------
    // Time helpers
    // ------------------------------------------------

    using Timestamp = std::chrono::system_clock::time_point;

    inline Timestamp nowUtc()
    {
        return std::chrono::system_clock::now();
    }


    // ------------------------------------------------
    // Protocol / traffic basics
    // ------------------------------------------------

    enum class IpVersion
    {
        IPv4,
        IPv6,
        Unknown
    };

    enum class TransportProtocol
    {
        TCP,
        UDP,
        ICMP,
        Other,
        Unknown
    };

    enum class TrafficDirection
    {
        Outbound,
        Inbound,
        Local,
        Unknown
    };


    // ------------------------------------------------
    // Evidence and attribution confidence
    // ------------------------------------------------

    enum class EvidenceSource
    {
        None,

        // Strong direct evidence
        TlsSni,
        HttpHost,
        DnsAnswer,

        // Correlated evidence
        FreshDnsCorrelation,

        // Medium evidence
        ProcessContext,

        // Weak/medium fallback evidence
        ProviderHint,
        PortProtocolHint,
        IpOnly
    };

    enum class ConfidenceLevel
    {
        None,
        Low,
        Medium,
        MediumHigh,
        High
    };

    inline std::string toString(ConfidenceLevel value)
    {
        switch (value)
        {
        case ConfidenceLevel::None:       return "None";
        case ConfidenceLevel::Low:        return "Low";
        case ConfidenceLevel::Medium:     return "Medium";
        case ConfidenceLevel::MediumHigh: return "Medium/High";
        case ConfidenceLevel::High:       return "High";
        default:                          return "None";
        }
    }

    inline int confidenceScore(ConfidenceLevel value)
    {
        switch (value)
        {
        case ConfidenceLevel::None:       return 0;
        case ConfidenceLevel::Low:        return 25;
        case ConfidenceLevel::Medium:     return 50;
        case ConfidenceLevel::MediumHigh: return 75;
        case ConfidenceLevel::High:       return 90;
        default:                          return 0;
        }
    }


    // ------------------------------------------------
    // Destination result types
    // No raw Unknown policy
    // ------------------------------------------------

    enum class AttributionType
    {
        ExactDestination,
        CorrelatedDestination,
        ProviderLevel,
        ProcessAssociated,
        EncryptedIpOnly,
        ClassifiedIpOnly,
        BackgroundSystem,
        UnclassifiedExplained
    };

    inline std::string toString(AttributionType value)
    {
        switch (value)
        {
        case AttributionType::ExactDestination:
            return "Exact destination";

        case AttributionType::CorrelatedDestination:
            return "Correlated destination";

        case AttributionType::ProviderLevel:
            return "Provider-level";

        case AttributionType::ProcessAssociated:
            return "Process-associated";

        case AttributionType::EncryptedIpOnly:
            return "Encrypted IP-only";

        case AttributionType::ClassifiedIpOnly:
            return "Classified IP-only";

        case AttributionType::BackgroundSystem:
            return "Background/System";

        case AttributionType::UnclassifiedExplained:
            return "Unclassified explained";

        default:
            return "Unclassified explained";
        }
    }


    // ------------------------------------------------
    // Process origin classification
    // ------------------------------------------------

    enum class OriginClass
    {
        UserApplication,
        DeveloperTool,
        BackgroundSystem,
        SecurityTool,
        UnknownButExplained
    };

    inline std::string toString(OriginClass value)
    {
        switch (value)
        {
        case OriginClass::UserApplication:    return "User/Application";
        case OriginClass::DeveloperTool:      return "Developer/Work tool";
        case OriginClass::BackgroundSystem:   return "Background/System";
        case OriginClass::SecurityTool:       return "Security tool";
        case OriginClass::UnknownButExplained:return "Unknown but explained";
        default:                              return "Unknown but explained";
        }
    }


    // ------------------------------------------------
    // Device behavior states
    // ------------------------------------------------

    enum class DeviceState
    {
        Normal,
        Heavy,
        Redflag
    };

    inline std::string toString(DeviceState state)
    {
        switch (state)
        {
        case DeviceState::Normal:
            return "Normal State";

        case DeviceState::Heavy:
            return "Heavy State";

        case DeviceState::Redflag:
            return "Redflag State";

        default:
            return "Normal State";
        }
    }


    // ------------------------------------------------
    // Raw observed outbound connection
    // Layer 1: Outbound Sensor
    // ------------------------------------------------

    struct ObservedConnection
    {
        std::string deviceIp;

        std::string localIp;
        uint16_t localPort = 0;

        std::string remoteIp;
        uint16_t remotePort = 0;

        IpVersion ipVersion = IpVersion::Unknown;
        TransportProtocol protocol = TransportProtocol::Unknown;
        TrafficDirection direction = TrafficDirection::Unknown;

        std::string transportState;

        Timestamp firstSeen = nowUtc();
        Timestamp lastSeen = nowUtc();

        uint64_t bytesSent = 0;
        uint64_t bytesReceived = 0;
        uint64_t packetsSent = 0;
        uint64_t packetsReceived = 0;

        std::string interfaceName;

        uint64_t totalBytes() const
        {
            return bytesSent + bytesReceived;
        }

        uint64_t totalPackets() const
        {
            return packetsSent + packetsReceived;
        }

        bool isOutbound() const
        {
            return direction == TrafficDirection::Outbound;
        }
    };


    // ------------------------------------------------
    // Evidence store
    // Layer 2/3/4: Analysis + Destination + Origin evidence
    // ------------------------------------------------

    struct DnsCandidate
    {
        std::string domain;
        std::string resolvedIp;
        Timestamp observedAt = nowUtc();
        bool fresh = false;
    };

    struct ProcessCandidate
    {
        uint32_t pid = 0;
        std::string processName;
        std::string processPath;
        OriginClass originClass = OriginClass::UnknownButExplained;
        Timestamp observedAt = nowUtc();
    };

    struct ProviderHint
    {
        std::string providerName;
        std::string category;
        std::string reason;
        ConfidenceLevel confidence = ConfidenceLevel::Low;
    };

    struct EvidenceStore
    {
        std::vector<DnsCandidate> dnsCandidates;

        std::vector<std::string> tlsSniCandidates;
        std::vector<std::string> httpHostCandidates;

        std::vector<ProcessCandidate> processCandidates;
        std::vector<ProviderHint> providerHints;

        bool hasTlsSni() const
        {
            return !tlsSniCandidates.empty();
        }

        bool hasHttpHost() const
        {
            return !httpHostCandidates.empty();
        }

        bool hasDns() const
        {
            return !dnsCandidates.empty();
        }

        bool hasFreshDns() const
        {
            return std::any_of(
                dnsCandidates.begin(),
                dnsCandidates.end(),
                [](const DnsCandidate& candidate)
                {
                    return candidate.fresh;
                }
            );
        }

        bool hasProcessContext() const
        {
            return !processCandidates.empty();
        }

        bool hasProviderHint() const
        {
            return !providerHints.empty();
        }
    };


    // ------------------------------------------------
    // Stable connection session
    // Layer 2: Analyzer
    // ------------------------------------------------

    struct ConnectionSession
    {
        std::string sessionId;

        ObservedConnection observed;
        EvidenceStore evidence;

        std::string protocolLabel;
        std::string connectionType;

        bool encryptedLikely = false;
        bool quicLikely = false;
        bool dnsLikely = false;
        bool httpLikely = false;
        bool httpsLikely = false;

        uint64_t totalBytes() const
        {
            return observed.totalBytes();
        }

        uint64_t totalPackets() const
        {
            return observed.totalPackets();
        }
    };


    // ------------------------------------------------
    // Attribution result
    // Layer 3/4: Destination Resolver + Origin Resolver
    // Mandatory triplet:
    // Identity + Classification + Explanation
    // ------------------------------------------------

    struct AttributionResult
    {
        AttributionType type = AttributionType::UnclassifiedExplained;

        std::string destinationDomain;
        std::string entityName;
        std::string category;
        std::string trafficClass;

        EvidenceSource source = EvidenceSource::None;
        ConfidenceLevel confidence = ConfidenceLevel::None;

        std::optional<ProcessCandidate> ownerProcess;

        std::string reason;
        std::string limitations;

        bool hasExactIdentity() const
        {
            return type == AttributionType::ExactDestination ||
                type == AttributionType::CorrelatedDestination;
        }

        std::string safeDisplayName() const
        {
            if (!entityName.empty())
                return entityName;

            if (!destinationDomain.empty())
                return destinationDomain;

            return toString(type);
        }
    };


    // ------------------------------------------------
    // Grouped main connection
    // Layer 5: Similar connection grouping
    // Example: Facebook main group with several sub-connections
    // ------------------------------------------------

    struct SubConnectionRecord
    {
        ConnectionSession session;
        AttributionResult attribution;
    };

    struct ConnectionGroup
    {
        std::string groupId;

        std::string deviceIp;
        std::string mainEntityName;
        std::string mainCategory;
        std::string ownerProcessName;

        std::vector<SubConnectionRecord> subConnections;

        Timestamp firstSeen = nowUtc();
        Timestamp lastSeen = nowUtc();

        uint64_t totalBytes = 0;
        uint64_t totalPackets = 0;

        ConfidenceLevel groupConfidence = ConfidenceLevel::None;

        std::string groupingReason;

        size_t subConnectionCount() const
        {
            return subConnections.size();
        }
    };


    // ------------------------------------------------
    // Connection report
    // Layer 6: Report Builder
    // ------------------------------------------------

    struct ConnectionReportSubConnection
    {
        std::string deviceIp;

        std::string localIp;
        uint16_t localPort = 0;

        std::string remoteIp;
        uint16_t remotePort = 0;

        std::string protocolLabel;
        std::string connectionType;
        std::string transportState;

        uint32_t pid = 0;
        std::string processName;
        std::string processPath;

        std::string entityName;
        std::string destinationDomain;
        std::string category;

        ConfidenceLevel confidence = ConfidenceLevel::None;

        uint64_t bytes = 0;

        std::string evidenceUsed;
        std::string reason;
        std::string limitations;
    };

    struct ConnectionReport
    {
        // Identity
        std::string entityName;
        std::string destinationDomain;
        std::string category;
        std::string source;
        ConfidenceLevel confidence = ConfidenceLevel::None;

        // Connection
        std::string connectionType;
        std::string deviceIp;
        std::string ownerProcess;
        size_t subConnectionCount = 0;
        uint64_t bytes = 0;

        std::vector<ConnectionReportSubConnection> subConnections;

        // Explanation
        std::string evidenceUsed;
        std::string reason;
        std::string limitations;
        DeviceState classificationState = DeviceState::Normal;
    };


    // ------------------------------------------------
    // Device scoring and final report
    // Layer 7/8/9: Normal / Heavy / Redflag
    // ------------------------------------------------

    struct DeviceScore
    {
        std::string deviceIp;

        size_t totalConnections = 0;
        size_t totalGroups = 0;
        size_t uniqueEntities = 0;
        size_t uniqueCategories = 0;
        size_t uniqueServices = 0;

        size_t concurrentConnections = 0;

        uint64_t totalBytes = 0;
        double trafficSharePercent = 0.0;

        double attributionCoveragePercent = 0.0;
        double dominantEntityRatioPercent = 0.0;

        double connectionIntensityScore = 0.0;
        double entityDiversityScore = 0.0;
        double serviceDiversityScore = 0.0;
        double concurrencyScore = 0.0;
        double trafficShareScore = 0.0;
        double sustainedActivityScore = 0.0;

        double dominantEntityPenalty = 0.0;
        double explainableHeavyUsagePenalty = 0.0;
        double weakAttributionPenalty = 0.0;

        double mcs = 0.0;

        DeviceState state = DeviceState::Normal;
        std::string reason;
    };

    struct DeviceReport
    {
        std::string deviceIp;
        DeviceState state = DeviceState::Normal;

        DeviceScore score;

        std::vector<ConnectionGroup> groups;
        std::vector<ConnectionReport> connectionReports;

        uint64_t totalBytes = 0;
        std::string summaryReason;
    };


    // ------------------------------------------------
    // Engine output
    // Final structured output for GUI or CLI
    // ------------------------------------------------

    struct EngineOutput
    {
        std::vector<DeviceReport> normalDevices;
        std::vector<DeviceReport> heavyDevices;
        std::vector<DeviceReport> redflagDevices;

        std::vector<ConnectionReport> allConnectionReports;

        bool empty() const
        {
            return normalDevices.empty() &&
                heavyDevices.empty() &&
                redflagDevices.empty() &&
                allConnectionReports.empty();
        }
    };

} // namespace netwolf::core