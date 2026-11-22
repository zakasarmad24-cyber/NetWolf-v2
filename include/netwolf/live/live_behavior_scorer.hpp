#pragma once

#include "live_group_metrics.hpp"

#include <algorithm>
#include <sstream>
#include <string>

namespace netwolf::live {

    // ================================================================
    // NetWolf v2 - Live Behavior Scorer
    //
    // Stage 7 purpose:
    // Convert live group metrics into a preliminary behavioral score.
    //
    // Important:
    // - This does NOT claim an attack.
    // - This does NOT claim Evil Twin detection.
    // - It only labels behavior patterns that may deserve attention.
    // ================================================================

    struct LiveBehaviorScore
    {
        double score = 0.0;

        std::string label;
        std::string explanation;

        bool heavy = false;
        bool intensiveMultiEndpoint = false;
        bool possibleMultiClientRelayIndicator = false;
    };


    class LiveBehaviorScorer
    {
    public:
        LiveBehaviorScore score(
            const LiveSessionGroup& group,
            const LiveGroupMetrics& metrics
        ) const;

    private:
        static double clampScore(
            double value
        );

        static std::string labelForScore(
            double score
        );
    };


    inline LiveBehaviorScore LiveBehaviorScorer::score(
        const LiveSessionGroup& group,
        const LiveGroupMetrics& metrics
    ) const
    {
        LiveBehaviorScore result;

        double value = 0.0;

        // ------------------------------------------------------------
        // Sub-connection volume
        // ------------------------------------------------------------

        if (metrics.subConnectionCount >= 30)
            value += 28.0;
        else if (metrics.subConnectionCount >= 20)
            value += 22.0;
        else if (metrics.subConnectionCount >= 10)
            value += 16.0;
        else if (metrics.subConnectionCount >= 5)
            value += 8.0;

        // ------------------------------------------------------------
        // Remote IP diversity
        // ------------------------------------------------------------

        if (metrics.uniqueRemoteIpCount >= 15)
            value += 28.0;
        else if (metrics.uniqueRemoteIpCount >= 10)
            value += 22.0;
        else if (metrics.uniqueRemoteIpCount >= 6)
            value += 16.0;
        else if (metrics.uniqueRemoteIpCount >= 3)
            value += 8.0;

        // ------------------------------------------------------------
        // Local port diversity
        // Usually many local ephemeral ports means many parallel flows.
        // ------------------------------------------------------------

        if (metrics.uniqueLocalPortCount >= 30)
            value += 18.0;
        else if (metrics.uniqueLocalPortCount >= 15)
            value += 14.0;
        else if (metrics.uniqueLocalPortCount >= 8)
            value += 9.0;
        else if (metrics.uniqueLocalPortCount >= 4)
            value += 4.0;

        // ------------------------------------------------------------
        // Remote service diversity
        // ------------------------------------------------------------

        if (metrics.uniqueRemotePortCount >= 6)
            value += 12.0;
        else if (metrics.uniqueRemotePortCount >= 4)
            value += 8.0;
        else if (metrics.uniqueRemotePortCount >= 2)
            value += 4.0;

        // ------------------------------------------------------------
        // Sustained age
        // ------------------------------------------------------------

        if (metrics.ageSeconds >= 180)
            value += 10.0;
        else if (metrics.ageSeconds >= 60)
            value += 7.0;
        else if (metrics.ageSeconds >= 20)
            value += 3.0;

        // ------------------------------------------------------------
        // Volume label
        // Windows TCP table may not always provide bytes/packets,
        // but when available, use it as extra weak evidence.
        // ------------------------------------------------------------

        if (metrics.volumeLabel == "high byte volume")
            value += 10.0;
        else if (metrics.volumeLabel == "moderate byte volume")
            value += 6.0;
        else if (metrics.volumeLabel == "high packet count")
            value += 8.0;
        else if (metrics.volumeLabel == "moderate packet count")
            value += 4.0;

        result.score = clampScore(value);
        result.label = labelForScore(result.score);

        result.heavy =
            result.score >= 30.0;

        result.intensiveMultiEndpoint =
            result.score >= 50.0;

        result.possibleMultiClientRelayIndicator =
            result.score >= 70.0 &&
            metrics.subConnectionCount >= 20 &&
            metrics.uniqueRemoteIpCount >= 10 &&
            metrics.uniqueLocalPortCount >= 15;

        std::ostringstream explanation;

        explanation
            << "Live behavior score="
            << result.score
            << "/100. "
            << "Label: "
            << result.label
            << ". Metrics used: "
            << metrics.summaryText
            << ". ";

        if (result.possibleMultiClientRelayIndicator)
        {
            explanation
                << "The group shows a high number of simultaneous sub-connections, "
                << "high remote endpoint diversity, and high local port diversity. "
                << "This is treated only as a possible multi-client relay behavior indicator, "
                << "not as proof of a rogue gateway or attack.";
        }
        else if (result.intensiveMultiEndpoint)
        {
            explanation
                << "The group shows intensive multi-endpoint behavior that may deserve attention, "
                << "but it can also be normal for browsers, cloud tools, updates, or download managers.";
        }
        else if (result.heavy)
        {
            explanation
                << "The group is heavier than a minimal live connection group, "
                << "but it is still within a range that can be normal depending on the application.";
        }
        else
        {
            explanation
                << "The group currently looks like normal or low-intensity live traffic.";
        }

        (void)group;

        result.explanation = explanation.str();

        return result;
    }


    inline double LiveBehaviorScorer::clampScore(
        double value
    )
    {
        return std::max(
            0.0,
            std::min(
                100.0,
                value
            )
        );
    }


    inline std::string LiveBehaviorScorer::labelForScore(
        double score
    )
    {
        if (score >= 70.0)
            return "possible multi-client relay indicator";

        if (score >= 50.0)
            return "intensive multi-endpoint live group";

        if (score >= 30.0)
            return "heavy live group";

        return "normal live group";
    }

} // namespace netwolf::live