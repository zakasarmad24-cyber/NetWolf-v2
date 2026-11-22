#pragma once

#include <netwolf/core/engine.hpp>
#include <netwolf/core/models.hpp>
#include <netwolf/core/session_id.hpp>

#include <algorithm>
#include <chrono>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace netwolf::live {

    // ================================================================
    // NetWolf v2 - Live Session Tracker
    //
    // Stage 7 purpose:
    // Build stable live main sessions from active tracked connections.
    //
    // Important:
    // - This layer does NOT identify destination names yet.
    // - It groups live active connections into main live sessions.
    // - Later, process/DNS/SNI/HTTP evidence can improve grouping.
    // ================================================================

    struct LiveSessionSubConnection
    {
        std::string connectionKey;

        netwolf::core::ObservedConnection observed;

        std::chrono::system_clock::time_point firstSeen =
            std::chrono::system_clock::now();

        std::chrono::system_clock::time_point lastSeen =
            std::chrono::system_clock::now();
    };


    struct LiveSessionGroup
    {
        std::string groupKey;

        std::string deviceIp;
        std::string protocolLabel;
        std::string serviceLabel;

        std::string ownerProcessName;
        uint32_t ownerPid = 0;

        uint16_t remotePort = 0;

        std::vector<LiveSessionSubConnection> subConnections;

        std::chrono::system_clock::time_point firstSeen =
            std::chrono::system_clock::now();

        std::chrono::system_clock::time_point lastSeen =
            std::chrono::system_clock::now();

        std::string groupingReason;

        size_t subConnectionCount() const
        {
            return subConnections.size();
        }
    };


    struct LiveSessionTrackerUpdate
    {
        std::vector<LiveSessionGroup> groups;

        size_t inputConnections = 0;
        size_t liveGroups = 0;
        size_t subConnections = 0;

        std::string summaryText;
    };


    class LiveSessionTracker
    {
    public:
        LiveSessionTrackerUpdate update(
            const std::vector<netwolf::core::ObservedConnection>& activeConnections
        );

        LiveSessionTrackerUpdate update(
            const std::vector<netwolf::core::ObservedConnection>& activeConnections,
            const netwolf::core::EngineEvidenceInput& evidenceInput
        );

        void clear();

    private:
        std::map<std::string, LiveSessionGroup> groups_;

    private:
        static std::string makeConnectionKey(
            const netwolf::core::ObservedConnection& connection
        );

        static std::string makeGroupKey(
            const netwolf::core::ObservedConnection& connection
        );

        static std::string protocolLabel(
            netwolf::core::TransportProtocol protocol
        );

        static std::string serviceLabel(
            netwolf::core::TransportProtocol protocol,
            uint16_t remotePort
        );

        static std::chrono::system_clock::time_point minTime(
            std::chrono::system_clock::time_point a,
            std::chrono::system_clock::time_point b
        );

        static std::chrono::system_clock::time_point maxTime(
            std::chrono::system_clock::time_point a,
            std::chrono::system_clock::time_point b
        );

        static std::string selectProcessName(
            const netwolf::core::ObservedConnection& connection,
            const netwolf::core::EngineEvidenceInput& evidenceInput
        );

        static uint32_t selectPid(
            const netwolf::core::ObservedConnection& connection,
            const netwolf::core::EngineEvidenceInput& evidenceInput
        );
    };


    inline LiveSessionTrackerUpdate LiveSessionTracker::update(
        const std::vector<netwolf::core::ObservedConnection>& activeConnections
    )
    {
        netwolf::core::EngineEvidenceInput emptyEvidence;

        return update(
            activeConnections,
            emptyEvidence
        );
    }


    inline LiveSessionTrackerUpdate LiveSessionTracker::update(
        const std::vector<netwolf::core::ObservedConnection>& activeConnections,
        const netwolf::core::EngineEvidenceInput& evidenceInput
    )
    {
        LiveSessionTrackerUpdate update;
        update.inputConnections = activeConnections.size();

        groups_.clear();

        for (const auto& connection : activeConnections)
        {
            const std::string processName =
                selectProcessName(
                    connection,
                    evidenceInput
                );

            const uint32_t pid =
                selectPid(
                    connection,
                    evidenceInput
                );

            const std::string groupKey =
                makeGroupKey(connection) +
                "|process=" + processName +
                "|pid=" + std::to_string(pid);

            const std::string connectionKey =
                makeConnectionKey(connection);

            auto found =
                groups_.find(groupKey);

            if (found == groups_.end())
            {
                LiveSessionGroup group;

                group.groupKey = groupKey;
                group.deviceIp = connection.deviceIp;
                group.protocolLabel = protocolLabel(connection.protocol);
                group.serviceLabel = serviceLabel(
                    connection.protocol,
                    connection.remotePort
                );

                group.ownerProcessName = processName;
                group.ownerPid = pid;

                group.remotePort = connection.remotePort;
                group.firstSeen = connection.firstSeen;
                group.lastSeen = connection.lastSeen;

                group.groupingReason =
                    "Grouped live active connections by device, process, transport protocol, and remote service port. "
                    "This is Stage 7 process-aware live grouping before destination identity enrichment.";

                LiveSessionSubConnection sub;
                sub.connectionKey = connectionKey;
                sub.observed = connection;
                sub.firstSeen = connection.firstSeen;
                sub.lastSeen = connection.lastSeen;

                group.subConnections.push_back(std::move(sub));

                groups_.emplace(
                    groupKey,
                    std::move(group)
                );
            }
            else
            {
                LiveSessionGroup& group =
                    found->second;

                LiveSessionSubConnection sub;
                sub.connectionKey = connectionKey;
                sub.observed = connection;
                sub.firstSeen = connection.firstSeen;
                sub.lastSeen = connection.lastSeen;

                group.firstSeen =
                    minTime(
                        group.firstSeen,
                        connection.firstSeen
                    );

                group.lastSeen =
                    maxTime(
                        group.lastSeen,
                        connection.lastSeen
                    );

                group.subConnections.push_back(std::move(sub));
            }
        }

        update.groups.reserve(groups_.size());

        for (const auto& item : groups_)
        {
            update.groups.push_back(item.second);
            update.subConnections += item.second.subConnectionCount();
        }

        std::sort(
            update.groups.begin(),
            update.groups.end(),
            [](const LiveSessionGroup& a, const LiveSessionGroup& b)
            {
                if (a.deviceIp != b.deviceIp)
                    return a.deviceIp < b.deviceIp;

                if (a.ownerProcessName != b.ownerProcessName)
                    return a.ownerProcessName < b.ownerProcessName;

                if (a.subConnectionCount() != b.subConnectionCount())
                    return a.subConnectionCount() > b.subConnectionCount();

                return a.remotePort < b.remotePort;
            }
        );

        update.liveGroups = update.groups.size();

        std::ostringstream summary;

        summary
            << "Live session tracker: input="
            << update.inputConnections
            << ", groups="
            << update.liveGroups
            << ", sub-connections="
            << update.subConnections
            << ", grouping=process+service";

        update.summaryText = summary.str();

        return update;
    }

    inline void LiveSessionTracker::clear()
    {
        groups_.clear();
    }


    inline std::string LiveSessionTracker::makeConnectionKey(
        const netwolf::core::ObservedConnection& connection
    )
    {
        std::string key;

        key += connection.deviceIp;
        key += "|";
        key += connection.localIp;
        key += ":";
        key += std::to_string(connection.localPort);
        key += "->";
        key += connection.remoteIp;
        key += ":";
        key += std::to_string(connection.remotePort);
        key += "|";
        key += protocolLabel(connection.protocol);

        return key;
    }


    inline std::string LiveSessionTracker::makeGroupKey(
        const netwolf::core::ObservedConnection& connection
    )
    {
        std::string key;

        key += "device=";
        key += connection.deviceIp;

        key += "|protocol=";
        key += protocolLabel(connection.protocol);

        key += "|service=";
        key += serviceLabel(
            connection.protocol,
            connection.remotePort
        );

        key += "|port=";
        key += std::to_string(connection.remotePort);

        return key;
    }


    inline std::string LiveSessionTracker::protocolLabel(
        netwolf::core::TransportProtocol protocol
    )
    {
        switch (protocol)
        {
        case netwolf::core::TransportProtocol::TCP:
            return "TCP";

        case netwolf::core::TransportProtocol::UDP:
            return "UDP";

        default:
            return "Transport";
        }
    }


    inline std::string LiveSessionTracker::serviceLabel(
        netwolf::core::TransportProtocol protocol,
        uint16_t remotePort
    )
    {
        if (protocol == netwolf::core::TransportProtocol::TCP)
        {
            switch (remotePort)
            {
            case 80:
                return "HTTP";
            case 443:
                return "HTTPS";
            case 53:
                return "DNS-over-TCP";
            case 853:
                return "DNS-over-TLS";
            case 22:
                return "SSH";
            case 3389:
                return "RDP";
            default:
                return "TCP service";
            }
        }

        if (protocol == netwolf::core::TransportProtocol::UDP)
        {
            switch (remotePort)
            {
            case 53:
                return "DNS";
            case 443:
                return "QUIC/HTTP3";
            case 123:
                return "NTP";
            default:
                return "UDP service";
            }
        }

        return "Network service";
    }


    inline std::chrono::system_clock::time_point LiveSessionTracker::minTime(
        std::chrono::system_clock::time_point a,
        std::chrono::system_clock::time_point b
    )
    {
        return a < b ? a : b;
    }


    inline std::chrono::system_clock::time_point LiveSessionTracker::maxTime(
        std::chrono::system_clock::time_point a,
        std::chrono::system_clock::time_point b
    )
    {
        return a > b ? a : b;
    }

    inline std::string LiveSessionTracker::selectProcessName(
        const netwolf::core::ObservedConnection& connection,
        const netwolf::core::EngineEvidenceInput& evidenceInput
    )
    {
        const std::string sessionId =
            netwolf::core::makeSessionId(connection);

        const auto found =
            evidenceInput.processBySessionId.find(sessionId);

        if (found == evidenceInput.processBySessionId.end())
            return "process_unavailable";

        if (!found->second.processName.empty())
            return found->second.processName;

        if (found->second.pid != 0)
            return "PID_" + std::to_string(found->second.pid);

        return "process_unavailable";
    }


    inline uint32_t LiveSessionTracker::selectPid(
        const netwolf::core::ObservedConnection& connection,
        const netwolf::core::EngineEvidenceInput& evidenceInput
    )
    {
        const std::string sessionId =
            netwolf::core::makeSessionId(connection);

        const auto found =
            evidenceInput.processBySessionId.find(sessionId);

        if (found == evidenceInput.processBySessionId.end())
            return 0;

        return found->second.pid;
    }

} // namespace netwolf::live