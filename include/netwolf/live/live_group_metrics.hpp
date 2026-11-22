#pragma once

#include "live_session_tracker.hpp"

#include <chrono>
#include <cstdint>
#include <set>
#include <sstream>
#include <string>

namespace netwolf::live {

    // ================================================================
    // NetWolf v2 - Live Group Metrics
    //
    // Stage 7 purpose:
    // Calculate live behavioral metrics for each live session group.
    //
    // Important:
    // - This layer does NOT identify exact destination names.
    // - It measures live behavior:
    //   fan-out, endpoint diversity, age, and sub-connection volume.
    // ================================================================

    struct LiveGroupMetrics
    {
        size_t subConnectionCount = 0;

        size_t uniqueRemoteIpCount = 0;
        size_t uniqueRemotePortCount = 0;
        size_t uniqueLocalPortCount = 0;

        uint64_t totalBytes = 0;
        uint64_t totalPackets = 0;

        int64_t ageSeconds = 0;

        std::string fanOutLabel;
        std::string volumeLabel;
        std::string summaryText;
    };


    class LiveGroupMetricsCalculator
    {
    public:
        LiveGroupMetrics calculate(
            const LiveSessionGroup& group
        ) const;

    private:
        static int64_t calculateAgeSeconds(
            const LiveSessionGroup& group
        );

        static std::string classifyFanOut(
            size_t subConnectionCount,
            size_t uniqueRemoteIpCount
        );

        static std::string classifyVolume(
            uint64_t totalBytes,
            uint64_t totalPackets
        );
    };


    inline LiveGroupMetrics LiveGroupMetricsCalculator::calculate(
        const LiveSessionGroup& group
    ) const
    {
        LiveGroupMetrics metrics;

        metrics.subConnectionCount =
            group.subConnectionCount();

        std::set<std::string> remoteIps;
        std::set<uint16_t> remotePorts;
        std::set<uint16_t> localPorts;

        for (const auto& sub : group.subConnections)
        {
            const auto& observed =
                sub.observed;

            if (!observed.remoteIp.empty())
                remoteIps.insert(observed.remoteIp);

            if (observed.remotePort > 0)
                remotePorts.insert(observed.remotePort);

            if (observed.localPort > 0)
                localPorts.insert(observed.localPort);

            metrics.totalBytes += observed.totalBytes();
            metrics.totalPackets += observed.totalPackets();
        }

        metrics.uniqueRemoteIpCount = remoteIps.size();
        metrics.uniqueRemotePortCount = remotePorts.size();
        metrics.uniqueLocalPortCount = localPorts.size();

        metrics.ageSeconds =
            calculateAgeSeconds(group);

        metrics.fanOutLabel =
            classifyFanOut(
                metrics.subConnectionCount,
                metrics.uniqueRemoteIpCount
            );

        metrics.volumeLabel =
            classifyVolume(
                metrics.totalBytes,
                metrics.totalPackets
            );

        std::ostringstream summary;

        summary
            << "subConnections="
            << metrics.subConnectionCount
            << ", uniqueRemoteIPs="
            << metrics.uniqueRemoteIpCount
            << ", uniqueRemotePorts="
            << metrics.uniqueRemotePortCount
            << ", uniqueLocalPorts="
            << metrics.uniqueLocalPortCount
            << ", ageSeconds="
            << metrics.ageSeconds
            << ", fanOut="
            << metrics.fanOutLabel
            << ", volume="
            << metrics.volumeLabel;

        metrics.summaryText = summary.str();

        return metrics;
    }


    inline int64_t LiveGroupMetricsCalculator::calculateAgeSeconds(
        const LiveSessionGroup& group
    )
    {
        const auto duration =
            group.lastSeen - group.firstSeen;

        const auto seconds =
            std::chrono::duration_cast<std::chrono::seconds>(
                duration
            ).count();

        if (seconds < 0)
            return 0;

        return seconds;
    }


    inline std::string LiveGroupMetricsCalculator::classifyFanOut(
        size_t subConnectionCount,
        size_t uniqueRemoteIpCount
    )
    {
        if (subConnectionCount >= 20 && uniqueRemoteIpCount >= 12)
            return "very high fan-out";

        if (subConnectionCount >= 10 && uniqueRemoteIpCount >= 6)
            return "high fan-out";

        if (subConnectionCount >= 5 && uniqueRemoteIpCount >= 3)
            return "moderate fan-out";

        if (subConnectionCount >= 3)
            return "low multi-connection fan-out";

        return "minimal fan-out";
    }


    inline std::string LiveGroupMetricsCalculator::classifyVolume(
        uint64_t totalBytes,
        uint64_t totalPackets
    )
    {
        if (totalBytes >= 100ull * 1024ull * 1024ull)
            return "high byte volume";

        if (totalBytes >= 10ull * 1024ull * 1024ull)
            return "moderate byte volume";

        if (totalPackets >= 1000)
            return "high packet count";

        if (totalPackets >= 100)
            return "moderate packet count";

        return "low observed volume";
    }

} // namespace netwolf::live