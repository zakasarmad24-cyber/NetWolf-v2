#pragma once

#include "live_session_tracker.hpp"
#include "live_group_metrics.hpp"
#include "live_behavior_scorer.hpp"

#include <netwolf/core/models.hpp>

#include <algorithm>
#include <cctype>
#include <set>
#include <sstream>
#include <string>

namespace netwolf::live {

    // ================================================================
    // NetWolf v2 - Live Group Identity
    //
    // Stage 7 purpose:
    // Give each live session group a clearer preliminary identity:
    // Process + Service + Behavior Pattern.
    //
    // Important:
    // - This does NOT identify exact destination domain.
    // - This does NOT use DNS cache.
    // - This prepares the engine for later direct metadata identity:
    //   DNS packets / HTTP Host / TLS SNI / provider evidence.
    // ================================================================

    struct LiveGroupIdentity
    {
        std::string mainEntityName;
        std::string category;
        std::string trafficClass;

        double behaviorScore = 0.0;
        std::string behaviorLabel;
        bool possibleMultiClientRelayIndicator = false;

        std::string reason;
        std::string limitations;

        netwolf::core::ConfidenceLevel confidence =
            netwolf::core::ConfidenceLevel::Low;
    };


    class LiveGroupIdentityResolver
    {
    public:
        LiveGroupIdentity resolve(
            const LiveSessionGroup& group
        ) const;

    private:
        static std::string normalizeProcessName(
            const std::string& processName
        );

        static std::string lowerCopy(
            std::string value
        );

        static bool contains(
            const std::string& value,
            const std::string& token
        );

        static bool isBrowserProcess(
            const std::string& process
        );

        static bool isDownloadManagerProcess(
            const std::string& process
        );

        static bool isDeveloperToolProcess(
            const std::string& process
        );

        static bool isSystemProcess(
            const std::string& process
        );

        static size_t uniqueRemoteIpCount(
            const LiveSessionGroup& group
        );

        static std::string behaviorLabel(
            const LiveSessionGroup& group
        );

        static std::string processFamilyLabel(
            const std::string& process
        );
    };


    inline LiveGroupIdentity LiveGroupIdentityResolver::resolve(
        const LiveSessionGroup& group
    ) const
    {
        LiveGroupIdentity identity;

        LiveGroupMetricsCalculator metricsCalculator;
        const LiveGroupMetrics metrics =
            metricsCalculator.calculate(group);

        LiveBehaviorScorer behaviorScorer;
        const LiveBehaviorScore behaviorScore =
            behaviorScorer.score(
                group,
                metrics
            );

        const std::string process =
            normalizeProcessName(group.ownerProcessName);

        const std::string service =
            group.serviceLabel.empty()
            ? "network service"
            : group.serviceLabel;

        const std::string behavior =
            behaviorScore.label.empty()
            ? metrics.fanOutLabel
            : behaviorScore.label;

        const std::string family =
            processFamilyLabel(process);

        identity.behaviorScore = behaviorScore.score;
        identity.behaviorLabel = behaviorScore.label;
        identity.possibleMultiClientRelayIndicator =
            behaviorScore.possibleMultiClientRelayIndicator;

        std::string visibleProcess =
            process;

        if (visibleProcess.empty() ||
            visibleProcess == "process_unavailable")
        {
            visibleProcess = "process unavailable";
        }

        identity.mainEntityName =
            visibleProcess + " / " + service + " / " + behavior;

        identity.trafficClass =
            service + " live traffic / " + behavior;

        if (behaviorScore.possibleMultiClientRelayIndicator)
        {
            identity.category = "Possible multi-client relay behavior indicator";
            identity.confidence = netwolf::core::ConfidenceLevel::Medium;
        }
        else if (isBrowserProcess(process))

        if (isBrowserProcess(process))
        {
            identity.category = "Browser application live traffic";
            identity.confidence = netwolf::core::ConfidenceLevel::Medium;
        }
        else if (isDownloadManagerProcess(process))
        {
            identity.category = "Download manager live traffic";
            identity.confidence = netwolf::core::ConfidenceLevel::Medium;
        }
        else if (isDeveloperToolProcess(process))
        {
            identity.category = "Developer tool live traffic";
            identity.confidence = netwolf::core::ConfidenceLevel::Medium;
        }
        else if (isSystemProcess(process))
        {
            identity.category = "Operating system service live traffic";
            identity.confidence = netwolf::core::ConfidenceLevel::Low;
        }
        else if (process.empty() || process == "process_unavailable")
        {
            identity.category = "Process-unattributed live traffic";
            identity.confidence = netwolf::core::ConfidenceLevel::Low;
        }
        else
        {
            identity.category = "Application live traffic";
            identity.confidence = netwolf::core::ConfidenceLevel::Medium;
        }

        std::ostringstream reason;

        reason
            << "Stage 7 live identity used process family, service label, "
            << "sub-connection count, remote endpoint diversity, local port diversity, "
            << "remote service diversity, live group age, and behavior scoring. "
            << "Process family: "
            << family
            << ". Service: "
            << service
            << ". Metrics: "
            << metrics.summaryText
            << ". Behavior: "
            << behaviorScore.explanation;

        identity.reason = reason.str();

        identity.limitations =
            "This is preliminary live behavioral identity only. It measures process, service, fan-out, endpoint diversity, local port diversity, and live age. It does not claim exact destination identity or prove an attack. Exact destination identity still requires direct live metadata such as DNS packets, HTTP Host, TLS SNI, or provider-level evidence.";

        return identity;
    }


    inline std::string LiveGroupIdentityResolver::normalizeProcessName(
        const std::string& processName
    )
    {
        std::string value = processName;

        if (value.empty())
            return "process_unavailable";

        return value;
    }


    inline std::string LiveGroupIdentityResolver::lowerCopy(
        std::string value
    )
    {
        std::transform(
            value.begin(),
            value.end(),
            value.begin(),
            [](unsigned char ch)
            {
                return static_cast<char>(
                    std::tolower(ch)
                    );
            }
        );

        return value;
    }


    inline bool LiveGroupIdentityResolver::contains(
        const std::string& value,
        const std::string& token
    )
    {
        return lowerCopy(value).find(lowerCopy(token)) != std::string::npos;
    }


    inline bool LiveGroupIdentityResolver::isBrowserProcess(
        const std::string& process
    )
    {
        return
            contains(process, "chrome") ||
            contains(process, "msedge") ||
            contains(process, "firefox") ||
            contains(process, "brave") ||
            contains(process, "opera");
    }


    inline bool LiveGroupIdentityResolver::isDownloadManagerProcess(
        const std::string& process
    )
    {
        return
            contains(process, "idman") ||
            contains(process, "internetdownloadmanager") ||
            contains(process, "fdm") ||
            contains(process, "download");
    }


    inline bool LiveGroupIdentityResolver::isDeveloperToolProcess(
        const std::string& process
    )
    {
        return
            contains(process, "devenv") ||
            contains(process, "code") ||
            contains(process, "git") ||
            contains(process, "python") ||
            contains(process, "node") ||
            contains(process, "cmake") ||
            contains(process, "msbuild");
    }


    inline bool LiveGroupIdentityResolver::isSystemProcess(
        const std::string& process
    )
    {
        return
            contains(process, "svchost") ||
            contains(process, "system") ||
            contains(process, "services") ||
            contains(process, "lsass") ||
            contains(process, "wininit");
    }


    inline size_t LiveGroupIdentityResolver::uniqueRemoteIpCount(
        const LiveSessionGroup& group
    )
    {
        std::set<std::string> ips;

        for (const auto& sub : group.subConnections)
        {
            if (!sub.observed.remoteIp.empty())
                ips.insert(sub.observed.remoteIp);
        }

        return ips.size();
    }


    inline std::string LiveGroupIdentityResolver::behaviorLabel(
        const LiveSessionGroup& group
    )
    {
        const size_t subCount =
            group.subConnectionCount();

        const size_t uniqueIps =
            uniqueRemoteIpCount(group);

        if (subCount >= 10 && uniqueIps >= 6)
            return "multi-endpoint high fan-out traffic";

        if (subCount >= 5 && uniqueIps >= 3)
            return "multi-endpoint traffic";

        if (subCount >= 3)
            return "multi-connection traffic";

        return "single or low-volume traffic";
    }


    inline std::string LiveGroupIdentityResolver::processFamilyLabel(
        const std::string& process
    )
    {
        if (isBrowserProcess(process))
            return "browser";

        if (isDownloadManagerProcess(process))
            return "download manager";

        if (isDeveloperToolProcess(process))
            return "developer tool";

        if (isSystemProcess(process))
            return "system service";

        if (process.empty() || process == "process_unavailable")
            return "unattributed process";

        return "application";
    }

} // namespace netwolf::live