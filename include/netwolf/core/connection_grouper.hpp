#pragma once

#include "models.hpp"
#include "session_id.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace netwolf::core {

    // ================================================================
    // NetWolf v2 - Connection Grouper
    // Layer 5: Similar Connection Grouping
    //
    // Purpose:
    // 1. Group related sub-connections under one main connection.
    // 2. Example:
    //    graph.facebook.com + fbcdn.net + messenger endpoint
    //    -> Main group: Meta / Facebook
    // 3. Use grouping key:
    //    device_ip + owner_process + entity_name + category + time_window
    // ================================================================


    // ------------------------------------------------
    // Input pair for grouping
    // ------------------------------------------------

    struct AttributedSession
    {
        ConnectionSession session;
        AttributionResult attribution;
    };


    // ------------------------------------------------
    // Grouper configuration
    // ------------------------------------------------

    struct ConnectionGrouperConfig
    {
        // Connections inside the same time window may be grouped together.
        uint64_t groupingWindowSeconds = 60;

        // If true, grouping prefers entity name over exact domain.
        // This allows facebook.com + fbcdn.net + messenger endpoint
        // to become one Meta/Facebook group.
        bool groupByEntityName = true;

        // If true, process name becomes part of the grouping key.
        bool includeOwnerProcessInGroupKey = true;

        // If true, category becomes part of the grouping key.
        bool includeCategoryInGroupKey = true;
    };


    // ------------------------------------------------
    // Connection Grouper
    // ------------------------------------------------

    class ConnectionGrouper
    {
    public:
        explicit ConnectionGrouper(ConnectionGrouperConfig config = {});

        std::vector<ConnectionGroup> group(
            const std::vector<AttributedSession>& attributedSessions
        ) const;

    private:
        ConnectionGrouperConfig config_;

    private:
        uint64_t calculateTimeBucket(const Timestamp& time) const;

        std::string buildStableGroupKey(
            const ConnectionSession& session,
            const AttributionResult& attribution,
            uint64_t timeBucket
        ) const;

        std::string selectMainEntityName(
            const AttributionResult& attribution
        ) const;

        std::string selectOwnerProcessName(
            const AttributionResult& attribution
        ) const;

        std::string buildGroupingReason(
            const AttributionResult& attribution,
            uint64_t timeBucket
        ) const;

        void addSubConnection(
            ConnectionGroup& group,
            const ConnectionSession& session,
            const AttributionResult& attribution
        ) const;

        void finalizeGroup(ConnectionGroup& group) const;

        static Timestamp minTimestamp(Timestamp a, Timestamp b);
        static Timestamp maxTimestamp(Timestamp a, Timestamp b);
    };


    // ------------------------------------------------
    // Inline implementation
    // ------------------------------------------------

    inline ConnectionGrouper::ConnectionGrouper(ConnectionGrouperConfig config)
        : config_(config)
    {
    }


    inline std::vector<ConnectionGroup> ConnectionGrouper::group(
        const std::vector<AttributedSession>& attributedSessions
    ) const
    {
        std::map<std::string, ConnectionGroup> groups;

        for (const auto& item : attributedSessions)
        {
            const auto& session = item.session;
            const auto& attribution = item.attribution;

            const uint64_t timeBucket = calculateTimeBucket(session.observed.firstSeen);
            const std::string groupKey = buildStableGroupKey(
                session,
                attribution,
                timeBucket
            );

            auto found = groups.find(groupKey);

            if (found == groups.end())
            {
                ConnectionGroup newGroup;

                newGroup.groupId = "grp_" + toHex64(fnv1a64(groupKey));
                newGroup.deviceIp = session.observed.deviceIp;
                newGroup.mainEntityName = selectMainEntityName(attribution);
                newGroup.mainCategory = attribution.category.empty()
                    ? "Classified traffic"
                    : attribution.category;

                newGroup.ownerProcessName = selectOwnerProcessName(attribution);
                newGroup.firstSeen = session.observed.firstSeen;
                newGroup.lastSeen = session.observed.lastSeen;
                newGroup.groupConfidence = attribution.confidence;
                newGroup.groupingReason = buildGroupingReason(attribution, timeBucket);

                addSubConnection(newGroup, session, attribution);

                groups.emplace(groupKey, std::move(newGroup));
            }
            else
            {
                addSubConnection(found->second, session, attribution);
            }
        }

        std::vector<ConnectionGroup> result;
        result.reserve(groups.size());

        for (auto& item : groups)
        {
            finalizeGroup(item.second);
            result.push_back(std::move(item.second));
        }

        std::sort(
            result.begin(),
            result.end(),
            [](const ConnectionGroup& a, const ConnectionGroup& b)
            {
                if (a.deviceIp != b.deviceIp)
                    return a.deviceIp < b.deviceIp;

                if (a.subConnectionCount() != b.subConnectionCount())
                    return a.subConnectionCount() > b.subConnectionCount();

                return a.totalBytes > b.totalBytes;
            }
        );

        return result;
    }


    inline uint64_t ConnectionGrouper::calculateTimeBucket(const Timestamp& time) const
    {
        const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
            time.time_since_epoch()
        ).count();

        const uint64_t safeWindow = config_.groupingWindowSeconds == 0
            ? 60
            : config_.groupingWindowSeconds;

        if (seconds <= 0)
            return 0;

        return static_cast<uint64_t>(seconds) / safeWindow;
    }


    inline std::string ConnectionGrouper::buildStableGroupKey(
        const ConnectionSession& session,
        const AttributionResult& attribution,
        uint64_t timeBucket
    ) const
    {
        std::string entityPart;

        if (config_.groupByEntityName)
        {
            entityPart = attribution.entityName.empty()
                ? attribution.safeDisplayName()
                : attribution.entityName;
        }
        else
        {
            entityPart = attribution.destinationDomain.empty()
                ? attribution.safeDisplayName()
                : attribution.destinationDomain;
        }

        std::string processPart = "process_not_used";
        if (config_.includeOwnerProcessInGroupKey)
            processPart = selectOwnerProcessName(attribution);

        std::string categoryPart = "category_not_used";
        if (config_.includeCategoryInGroupKey)
        {
            categoryPart = attribution.category.empty()
                ? "classified_traffic"
                : attribution.category;
        }

        std::string key;

        key += "device=" + normalizeKeyPart(session.observed.deviceIp);
        key += "|process=" + normalizeKeyPart(processPart);
        key += "|entity=" + normalizeKeyPart(entityPart);
        key += "|category=" + normalizeKeyPart(categoryPart);
        key += "|bucket=" + std::to_string(timeBucket);

        return key;
    }


    inline std::string ConnectionGrouper::selectMainEntityName(
        const AttributionResult& attribution
    ) const
    {
        if (!attribution.entityName.empty())
            return attribution.entityName;

        if (!attribution.destinationDomain.empty())
            return attribution.destinationDomain;

        return toString(attribution.type);
    }


    inline std::string ConnectionGrouper::selectOwnerProcessName(
        const AttributionResult& attribution
    ) const
    {
        if (attribution.ownerProcess.has_value())
        {
            const auto& process = attribution.ownerProcess.value();

            if (!process.processName.empty())
                return process.processName;

            if (process.pid != 0)
                return "PID " + std::to_string(process.pid);
        }

        return "Process context unavailable";
    }


    inline std::string ConnectionGrouper::buildGroupingReason(
        const AttributionResult& attribution,
        uint64_t timeBucket
    ) const
    {
        std::string reason;

        reason += "Grouped by time window, device IP, owner process, entity name, and category. ";
        reason += "Time bucket: " + std::to_string(timeBucket) + ". ";

        if (!attribution.entityName.empty())
        {
            reason += "Main entity evidence: " + attribution.entityName + ". ";
        }
        else if (!attribution.destinationDomain.empty())
        {
            reason += "Main domain evidence: " + attribution.destinationDomain + ". ";
        }
        else
        {
            reason += "Main identity uses explained attribution type: ";
            reason += toString(attribution.type) + ". ";
        }

        reason += "This follows the engine rule that related sub-connections should appear under one main connection group.";

        return reason;
    }


    inline void ConnectionGrouper::addSubConnection(
        ConnectionGroup& group,
        const ConnectionSession& session,
        const AttributionResult& attribution
    ) const
    {
        SubConnectionRecord record;
        record.session = session;
        record.attribution = attribution;

        group.subConnections.push_back(std::move(record));

        group.totalBytes += session.totalBytes();
        group.totalPackets += session.totalPackets();

        group.firstSeen = minTimestamp(group.firstSeen, session.observed.firstSeen);
        group.lastSeen = maxTimestamp(group.lastSeen, session.observed.lastSeen);

        if (confidenceScore(attribution.confidence) > confidenceScore(group.groupConfidence))
            group.groupConfidence = attribution.confidence;

        if (group.mainEntityName.empty())
            group.mainEntityName = selectMainEntityName(attribution);

        if (group.mainCategory.empty())
            group.mainCategory = attribution.category.empty()
            ? "Classified traffic"
            : attribution.category;

        if (group.ownerProcessName.empty())
            group.ownerProcessName = selectOwnerProcessName(attribution);
    }


    inline void ConnectionGrouper::finalizeGroup(ConnectionGroup& group) const
    {
        if (group.mainEntityName.empty())
            group.mainEntityName = "Explained connection group";

        if (group.mainCategory.empty())
            group.mainCategory = "Classified traffic";

        if (group.ownerProcessName.empty())
            group.ownerProcessName = "Process context unavailable";

        if (group.groupingReason.empty())
        {
            group.groupingReason =
                "Connections were grouped using device, entity, category, process, and time-window evidence.";
        }

        std::sort(
            group.subConnections.begin(),
            group.subConnections.end(),
            [](const SubConnectionRecord& a, const SubConnectionRecord& b)
            {
                if (a.session.observed.remoteIp != b.session.observed.remoteIp)
                    return a.session.observed.remoteIp < b.session.observed.remoteIp;

                return a.session.observed.remotePort < b.session.observed.remotePort;
            }
        );
    }


    inline Timestamp ConnectionGrouper::minTimestamp(Timestamp a, Timestamp b)
    {
        return a < b ? a : b;
    }


    inline Timestamp ConnectionGrouper::maxTimestamp(Timestamp a, Timestamp b)
    {
        return a > b ? a : b;
    }

} // namespace netwolf::core