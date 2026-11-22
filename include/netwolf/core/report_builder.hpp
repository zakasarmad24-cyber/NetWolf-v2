#pragma once

#include "models.hpp"
#include "session_id.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace netwolf::core {

    // ================================================================
    // NetWolf v2 - Report Builder
    // Layer 6: Connection Report Builder
    //
    // Purpose:
    // 1. Convert grouped connections into structured report objects.
    // 2. Report fields follow the PDF:
    //    - Identity: entity_name, destination_domain, category, source, confidence
    //    - Connection: connection_type, device_ip, owner_process, sub_connection_count, bytes
    //    - Explanation: evidence_used, reason, limitations, classification_state
    // 3. Reports are engine output objects, not GUI layout.
    // ================================================================


    // ------------------------------------------------
    // Report builder configuration
    // ------------------------------------------------

    struct ReportBuilderConfig
    {
        bool includeSubConnectionEvidenceSummary = true;
        bool includeLimitations = true;
        bool preferMainGroupIdentity = true;
    };


    // ------------------------------------------------
    // Report Builder
    // ------------------------------------------------

    class ReportBuilder
    {
    public:
        explicit ReportBuilder(ReportBuilderConfig config = {});

        ConnectionReport buildConnectionReport(
            const ConnectionGroup& group,
            DeviceState state = DeviceState::Normal
        ) const;

        std::vector<ConnectionReport> buildConnectionReports(
            const std::vector<ConnectionGroup>& groups,
            DeviceState state = DeviceState::Normal
        ) const;

    private:
        ReportBuilderConfig config_;

    private:
        std::string selectEntityName(const ConnectionGroup& group) const;
        std::string selectDestinationDomain(const ConnectionGroup& group) const;
        std::string selectCategory(const ConnectionGroup& group) const;
        std::string selectConnectionType(const ConnectionGroup& group) const;
        std::string selectOwnerProcess(const ConnectionGroup& group) const;

        ConfidenceLevel selectConfidence(const ConnectionGroup& group) const;

        std::string buildEvidenceUsed(const ConnectionGroup& group) const;
        std::string buildReason(const ConnectionGroup& group, DeviceState state) const;
        std::string buildLimitations(const ConnectionGroup& group) const;

        static std::string evidenceSourceToString(EvidenceSource source);
        static std::string mostFrequentString(const std::vector<std::string>& values);
        static std::string joinSet(const std::set<std::string>& values, const std::string& separator);
    };


    // ------------------------------------------------
    // Inline implementation
    // ------------------------------------------------

    inline ReportBuilder::ReportBuilder(ReportBuilderConfig config)
        : config_(config)
    {
    }


    inline ConnectionReport ReportBuilder::buildConnectionReport(
        const ConnectionGroup& group,
        DeviceState state
    ) const
    {
        ConnectionReport report;

        // -----------------------------
        // Identity section
        // -----------------------------
        report.entityName = selectEntityName(group);
        report.destinationDomain = selectDestinationDomain(group);
        report.category = selectCategory(group);
        report.source = buildEvidenceUsed(group);
        report.confidence = selectConfidence(group);

        // -----------------------------
        // Connection section
        // -----------------------------
        report.connectionType = selectConnectionType(group);
        report.deviceIp = group.deviceIp;
        report.ownerProcess = selectOwnerProcess(group);
        report.subConnectionCount = group.subConnectionCount();
        report.bytes = group.totalBytes;

        report.subConnections.clear();
        report.subConnections.reserve(group.subConnections.size());

        for (const auto& sub : group.subConnections)
        {
            ConnectionReportSubConnection item;

            const ObservedConnection& observed =
                sub.session.observed;

            item.deviceIp = !trimCopy(observed.deviceIp).empty()
                ? observed.deviceIp
                : group.deviceIp;

            item.localIp = observed.localIp;
            item.localPort = observed.localPort;

            item.remoteIp = observed.remoteIp;
            item.remotePort = observed.remotePort;

            item.protocolLabel = !trimCopy(sub.session.protocolLabel).empty()
                ? sub.session.protocolLabel
                : "Transport";

            item.connectionType = !trimCopy(sub.session.connectionType).empty()
                ? sub.session.connectionType
                : "Classified connection";

            item.transportState = observed.transportState;

            item.bytes = sub.session.totalBytes();

            if (sub.attribution.ownerProcess.has_value())
            {
                item.pid = sub.attribution.ownerProcess->pid;
                item.processName = sub.attribution.ownerProcess->processName;
                item.processPath = sub.attribution.ownerProcess->processPath;
            }
            else
            {
                item.processName = group.ownerProcessName;
            }

            item.entityName = sub.attribution.entityName;
            item.destinationDomain = sub.attribution.destinationDomain;
            item.category = sub.attribution.category;
            item.confidence = sub.attribution.confidence;

            item.evidenceUsed = evidenceSourceToString(
                sub.attribution.source
            );

            item.reason = sub.attribution.reason;
            item.limitations = sub.attribution.limitations;

            report.subConnections.push_back(item);
        }

        // -----------------------------
        // Explanation section
        // -----------------------------
        report.evidenceUsed = buildEvidenceUsed(group);
        report.reason = buildReason(group, state);
        report.limitations = config_.includeLimitations
            ? buildLimitations(group)
            : "";

        report.classificationState = state;

        return report;
    }


    inline std::vector<ConnectionReport> ReportBuilder::buildConnectionReports(
        const std::vector<ConnectionGroup>& groups,
        DeviceState state
    ) const
    {
        std::vector<ConnectionReport> reports;
        reports.reserve(groups.size());

        for (const auto& group : groups)
        {
            reports.push_back(buildConnectionReport(group, state));
        }

        std::sort(
            reports.begin(),
            reports.end(),
            [](const ConnectionReport& a, const ConnectionReport& b)
            {
                if (a.deviceIp != b.deviceIp)
                    return a.deviceIp < b.deviceIp;

                if (a.subConnectionCount != b.subConnectionCount)
                    return a.subConnectionCount > b.subConnectionCount;

                return a.bytes > b.bytes;
            }
        );

        return reports;
    }


    inline std::string ReportBuilder::selectEntityName(const ConnectionGroup& group) const
    {
        if (config_.preferMainGroupIdentity && !trimCopy(group.mainEntityName).empty())
            return group.mainEntityName;

        std::vector<std::string> names;

        for (const auto& sub : group.subConnections)
        {
            if (!trimCopy(sub.attribution.entityName).empty())
                names.push_back(sub.attribution.entityName);
            else if (!trimCopy(sub.attribution.destinationDomain).empty())
                names.push_back(sub.attribution.destinationDomain);
            else
                names.push_back(toString(sub.attribution.type));
        }

        const std::string selected = mostFrequentString(names);

        if (!trimCopy(selected).empty())
            return selected;

        return "Explained connection group";
    }


    inline std::string ReportBuilder::selectDestinationDomain(const ConnectionGroup& group) const
    {
        std::vector<std::string> domains;

        for (const auto& sub : group.subConnections)
        {
            if (!trimCopy(sub.attribution.destinationDomain).empty())
                domains.push_back(sub.attribution.destinationDomain);
        }

        const std::string selected = mostFrequentString(domains);

        if (!trimCopy(selected).empty())
            return selected;

        return "No exact domain; explained by attribution type";
    }


    inline std::string ReportBuilder::selectCategory(const ConnectionGroup& group) const
    {
        if (!trimCopy(group.mainCategory).empty())
            return group.mainCategory;

        std::vector<std::string> categories;

        for (const auto& sub : group.subConnections)
        {
            if (!trimCopy(sub.attribution.category).empty())
                categories.push_back(sub.attribution.category);
        }

        const std::string selected = mostFrequentString(categories);

        if (!trimCopy(selected).empty())
            return selected;

        return "Classified traffic";
    }


    inline std::string ReportBuilder::selectConnectionType(const ConnectionGroup& group) const
    {
        std::vector<std::string> types;

        for (const auto& sub : group.subConnections)
        {
            if (!trimCopy(sub.session.connectionType).empty())
                types.push_back(sub.session.connectionType);
            else if (!trimCopy(sub.attribution.trafficClass).empty())
                types.push_back(sub.attribution.trafficClass);
        }

        const std::string selected = mostFrequentString(types);

        if (!trimCopy(selected).empty())
            return selected;

        return "Classified connection group";
    }


    inline std::string ReportBuilder::selectOwnerProcess(const ConnectionGroup& group) const
    {
        if (!trimCopy(group.ownerProcessName).empty())
            return group.ownerProcessName;

        std::vector<std::string> processes;

        for (const auto& sub : group.subConnections)
        {
            if (sub.attribution.ownerProcess.has_value())
            {
                const auto& process = sub.attribution.ownerProcess.value();

                if (!trimCopy(process.processName).empty())
                    processes.push_back(process.processName);
                else if (process.pid != 0)
                    processes.push_back("PID " + std::to_string(process.pid));
            }
        }

        const std::string selected = mostFrequentString(processes);

        if (!trimCopy(selected).empty())
            return selected;

        return "Process context unavailable";
    }


    inline ConfidenceLevel ReportBuilder::selectConfidence(const ConnectionGroup& group) const
    {
        ConfidenceLevel best = group.groupConfidence;

        for (const auto& sub : group.subConnections)
        {
            if (confidenceScore(sub.attribution.confidence) > confidenceScore(best))
                best = sub.attribution.confidence;
        }

        return best;
    }


    inline std::string ReportBuilder::buildEvidenceUsed(const ConnectionGroup& group) const
    {
        std::set<std::string> evidence;

        for (const auto& sub : group.subConnections)
        {
            evidence.insert(evidenceSourceToString(sub.attribution.source));

            if (sub.session.evidence.hasTlsSni())
                evidence.insert("TLS SNI metadata");

            if (sub.session.evidence.hasHttpHost())
                evidence.insert("HTTP Host metadata");

            if (sub.session.evidence.hasDns())
                evidence.insert("DNS evidence");

            if (sub.session.evidence.hasFreshDns())
                evidence.insert("Fresh DNS correlation");

            if (sub.session.evidence.hasProcessContext())
                evidence.insert("Process metadata");

            if (sub.session.evidence.hasProviderHint())
                evidence.insert("Provider/CDN hint");
        }

        if (evidence.empty())
            return "Explained IP/protocol classification";

        return joinSet(evidence, ", ");
    }


    inline std::string ReportBuilder::buildReason(
        const ConnectionGroup& group,
        DeviceState state
    ) const
    {
        std::ostringstream out;

        out
            << "Main connection group for "
            << selectEntityName(group)
            << " on device "
            << group.deviceIp
            << ". ";

        out
            << "The group contains "
            << group.subConnectionCount()
            << " sub-connection";

        if (group.subConnectionCount() != 1)
            out << "s";

        out << ". ";

        if (!trimCopy(group.groupingReason).empty())
        {
            out << group.groupingReason << " ";
        }
        else
        {
            out
                << "Connections were grouped using device IP, owner process, entity/category identity, and time window. ";
        }

        out
            << "Current device classification state is "
            << toString(state)
            << ".";

        return out.str();
    }


    inline std::string ReportBuilder::buildLimitations(const ConnectionGroup& group) const
    {
        std::set<std::string> limitations;

        for (const auto& sub : group.subConnections)
        {
            if (!trimCopy(sub.attribution.limitations).empty())
                limitations.insert(sub.attribution.limitations);

            if (!sub.attribution.hasExactIdentity())
            {
                limitations.insert(
                    "Some sub-connections do not have exact domain identity and are classified using explained fallback evidence."
                );
            }

            if (sub.session.encryptedLikely)
            {
                limitations.insert(
                    "Encrypted payload content is not inspected; attribution relies on metadata and connection behavior."
                );
            }
        }

        if (limitations.empty())
            return "No major attribution limitation recorded for this group.";

        return joinSet(limitations, " ");
    }


    inline std::string ReportBuilder::evidenceSourceToString(EvidenceSource source)
    {
        switch (source)
        {
        case EvidenceSource::None:
            return "No direct evidence";

        case EvidenceSource::TlsSni:
            return "TLS SNI";

        case EvidenceSource::HttpHost:
            return "HTTP Host";

        case EvidenceSource::DnsAnswer:
            return "DNS Answer";

        case EvidenceSource::FreshDnsCorrelation:
            return "Fresh DNS correlation";

        case EvidenceSource::ProcessContext:
            return "Process context";

        case EvidenceSource::ProviderHint:
            return "Provider/CDN hint";

        case EvidenceSource::PortProtocolHint:
            return "Port/protocol hint";

        case EvidenceSource::IpOnly:
            return "IP-only classification";

        default:
            return "Explained evidence";
        }
    }


    inline std::string ReportBuilder::mostFrequentString(
        const std::vector<std::string>& values
    )
    {
        std::map<std::string, int> counts;

        for (const auto& value : values)
        {
            const std::string cleaned = trimCopy(value);

            if (!cleaned.empty())
                counts[cleaned]++;
        }

        if (counts.empty())
            return "";

        auto best = std::max_element(
            counts.begin(),
            counts.end(),
            [](const auto& a, const auto& b)
            {
                if (a.second != b.second)
                    return a.second < b.second;

                return a.first > b.first;
            }
        );

        return best->first;
    }


    inline std::string ReportBuilder::joinSet(
        const std::set<std::string>& values,
        const std::string& separator
    )
    {
        std::ostringstream out;

        bool first = true;

        for (const auto& value : values)
        {
            if (trimCopy(value).empty())
                continue;

            if (!first)
                out << separator;

            out << value;
            first = false;
        }

        const std::string result = out.str();

        if (result.empty())
            return "Explained evidence";

        return result;
    }

} // namespace netwolf::core