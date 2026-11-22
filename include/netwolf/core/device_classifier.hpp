#pragma once

#include "models.hpp"
#include "session_id.hpp"
#include "report_builder.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace netwolf::core {

    // ================================================================
    // NetWolf v2 - Device Classifier
    // Layer 7/8/9: Normal / Heavy / Redflag
    //
    // Purpose:
    // 1. Calculate device behavior metrics.
    // 2. Calculate MCS - Multi-Client Score.
    // 3. Classify each device into:
    //    - Normal State
    //    - Heavy State
    //    - Redflag State
    //
    // Important PDF rule:
    // Low attribution coverage reduces certainty.
    // The engine must not create a strong Redflag decision from weak identity
    // evidence alone.
    // ================================================================


    // ------------------------------------------------
    // Classifier configuration
    // ------------------------------------------------

    struct DeviceClassifierConfig
    {
        // MCS thresholds
        double heavyMcsThreshold = 40.0;
        double redflagMcsThreshold = 70.0;

        // Connection thresholds
        size_t heavyConnectionCount = 35;
        size_t redflagConnectionCount = 80;

        // Diversity thresholds
        size_t redflagUniqueEntities = 10;
        size_t redflagUniqueServices = 6;

        // Concurrency approximation threshold
        size_t redflagConcurrentConnections = 20;

        // Heavy usage threshold: traffic of the device's current connections.
        uint64_t heavyBytesThreshold = 50ull * 1024ull * 1024ull;

        // Heavy usage: many different destinations at once (many tabs / apps).
        size_t heavyUniqueEntities = 8;

        // NetWolf Evil Twin design:
        // Redflag is given ONLY by the Evil Twin algorithm (live device memory:
        // crowd -> collapse -> one device carrying everyone's activity).
        // Normal / Heavy are decided from the device's own usage, without the
        // MCS score or the device's share of the network traffic.
        // false = the original MCS-based Redflag rule.
        bool redflagOnlyFromEvilTwinVerdict = true;

        // Attribution coverage
        double minimumAttributionCoverageForStrongRedflag = 30.0;

        // Dominant entity behavior
        double dominantEntityPenaltyStartPercent = 70.0;
        double explainableHeavyDominantEntityPercent = 75.0;

        // Sustained behavior
        uint64_t sustainedWindowSeconds = 120;
        size_t sustainedMinimumConnections = 30;
    };


    // ------------------------------------------------
    // Device Classifier
    // ------------------------------------------------

    class DeviceClassifier
    {
    public:
        explicit DeviceClassifier(DeviceClassifierConfig config = {});

        EngineOutput classify(
            const std::vector<ConnectionGroup>& groups
        ) const;

        // evilTwinVerdicts: device IP -> evidence text, for the devices the
        // Evil Twin algorithm marked as suspicious. These become Redflag.
        EngineOutput classify(
            const std::vector<ConnectionGroup>& groups,
            const std::map<std::string, std::string>& evilTwinVerdicts
        ) const;

        DeviceReport classifyOneDevice(
            const std::string& deviceIp,
            const std::vector<ConnectionGroup>& groups,
            uint64_t networkTotalBytes,
            const std::string* evilTwinVerdict = nullptr
        ) const;

    private:
        DeviceClassifierConfig config_;

    private:
        DeviceScore calculateDeviceScore(
            const std::string& deviceIp,
            const std::vector<ConnectionGroup>& groups,
            uint64_t networkTotalBytes
        ) const;

        DeviceState decideState(DeviceScore& score) const;

        std::string buildDeviceReason(const DeviceScore& score) const;

        double calculateAttributionCoverage(
            const std::vector<ConnectionGroup>& groups,
            size_t totalConnections
        ) const;

        double calculateDominantEntityRatio(
            const std::vector<ConnectionGroup>& groups,
            size_t totalConnections
        ) const;

        double calculateSustainedActivityScore(
            const std::vector<ConnectionGroup>& groups,
            size_t totalConnections
        ) const;

        uint64_t calculateNetworkTotalBytes(
            const std::vector<ConnectionGroup>& groups
        ) const;

        static double clampScore(double value);
        static double percent(uint64_t part, uint64_t total);
        static double percentSize(size_t part, size_t total);
        static double scaledScore(double value, double fullScoreAt);
        static std::string safeMetricLine(const std::string& name, double value);
    };


    // ------------------------------------------------
    // Inline implementation
    // ------------------------------------------------

    inline DeviceClassifier::DeviceClassifier(DeviceClassifierConfig config)
        : config_(config)
    {
    }


    inline EngineOutput DeviceClassifier::classify(
        const std::vector<ConnectionGroup>& groups
    ) const
    {
        static const std::map<std::string, std::string> noVerdicts;
        return classify(groups, noVerdicts);
    }


    inline EngineOutput DeviceClassifier::classify(
        const std::vector<ConnectionGroup>& groups,
        const std::map<std::string, std::string>& evilTwinVerdicts
    ) const
    {
        EngineOutput output;

        std::map<std::string, std::vector<ConnectionGroup>> groupsByDevice;

        for (const auto& group : groups)
        {
            const std::string deviceKey = makeDeviceKey(group.deviceIp);
            groupsByDevice[deviceKey].push_back(group);
        }

        const uint64_t networkTotalBytes = calculateNetworkTotalBytes(groups);

        for (const auto& item : groupsByDevice)
        {
            const std::string& deviceIp = item.first;
            const std::vector<ConnectionGroup>& deviceGroups = item.second;

            const std::string* verdict = nullptr;

            for (const auto& [verdictIp, verdictText] : evilTwinVerdicts)
            {
                if (makeDeviceKey(verdictIp) == deviceIp)
                    verdict = &verdictText;
            }

            DeviceReport report = classifyOneDevice(
                deviceIp,
                deviceGroups,
                networkTotalBytes,
                verdict
            );

            for (const auto& connectionReport : report.connectionReports)
                output.allConnectionReports.push_back(connectionReport);

            switch (report.state)
            {
            case DeviceState::Normal:
                output.normalDevices.push_back(std::move(report));
                break;

            case DeviceState::Heavy:
                output.heavyDevices.push_back(std::move(report));
                break;

            case DeviceState::Redflag:
                output.redflagDevices.push_back(std::move(report));
                break;

            default:
                output.normalDevices.push_back(std::move(report));
                break;
            }
        }

        auto sortReports = [](std::vector<DeviceReport>& reports)
            {
                std::sort(
                    reports.begin(),
                    reports.end(),
                    [](const DeviceReport& a, const DeviceReport& b)
                    {
                        if (a.score.mcs != b.score.mcs)
                            return a.score.mcs > b.score.mcs;

                        return a.totalBytes > b.totalBytes;
                    }
                );
            };

        sortReports(output.normalDevices);
        sortReports(output.heavyDevices);
        sortReports(output.redflagDevices);

        return output;
    }


    inline DeviceReport DeviceClassifier::classifyOneDevice(
        const std::string& deviceIp,
        const std::vector<ConnectionGroup>& groups,
        uint64_t networkTotalBytes,
        const std::string* evilTwinVerdict
    ) const
    {
        DeviceReport report;

        report.deviceIp = deviceIp;
        report.groups = groups;

        DeviceScore score = calculateDeviceScore(
            deviceIp,
            groups,
            networkTotalBytes
        );

        score.state = decideState(score);
        score.reason = buildDeviceReason(score);

        if (evilTwinVerdict != nullptr)
        {
            score.state = DeviceState::Redflag;
            score.reason =
                "EVIL TWIN SUSPECT. " + *evilTwinVerdict +
                " Usage: " + std::to_string(score.totalConnections) +
                " connections, " + std::to_string(score.uniqueEntities) +
                " destinations.";
        }

        report.state = score.state;
        report.score = score;
        report.totalBytes = score.totalBytes;
        report.summaryReason = score.reason;

        ReportBuilder builder;
        report.connectionReports = builder.buildConnectionReports(
            groups,
            report.state
        );

        return report;
    }


    inline DeviceScore DeviceClassifier::calculateDeviceScore(
        const std::string& deviceIp,
        const std::vector<ConnectionGroup>& groups,
        uint64_t networkTotalBytes
    ) const
    {
        DeviceScore score;

        score.deviceIp = deviceIp;
        score.totalGroups = groups.size();

        std::set<std::string> uniqueEntities;
        std::set<std::string> uniqueCategories;
        std::set<std::string> uniqueServices;

        size_t maxGroupSubConnections = 0;

        for (const auto& group : groups)
        {
            score.totalBytes += group.totalBytes;
            score.totalConnections += group.subConnectionCount();

            maxGroupSubConnections = std::max(
                maxGroupSubConnections,
                group.subConnectionCount()
            );

            if (!trimCopy(group.mainEntityName).empty())
                uniqueEntities.insert(normalizeKeyPart(group.mainEntityName));

            if (!trimCopy(group.mainCategory).empty())
                uniqueCategories.insert(normalizeKeyPart(group.mainCategory));

            for (const auto& sub : group.subConnections)
            {
                if (!trimCopy(sub.attribution.entityName).empty())
                    uniqueEntities.insert(normalizeKeyPart(sub.attribution.entityName));
                else if (!trimCopy(sub.attribution.destinationDomain).empty())
                    uniqueEntities.insert(normalizeKeyPart(sub.attribution.destinationDomain));
                else
                    uniqueEntities.insert(normalizeKeyPart(toString(sub.attribution.type)));

                if (!trimCopy(sub.attribution.category).empty())
                    uniqueCategories.insert(normalizeKeyPart(sub.attribution.category));

                if (!trimCopy(sub.session.connectionType).empty())
                    uniqueServices.insert(normalizeKeyPart(sub.session.connectionType));
                else if (!trimCopy(sub.attribution.trafficClass).empty())
                    uniqueServices.insert(normalizeKeyPart(sub.attribution.trafficClass));
            }
        }

        score.uniqueEntities = uniqueEntities.size();
        score.uniqueCategories = uniqueCategories.size();
        score.uniqueServices = uniqueServices.size();

        // Approximation:
        // In this engine phase, concurrency is estimated by the largest grouped
        // sub-connection count. Later, the live sensor can replace this with
        // real timestamp overlap.
        score.concurrentConnections = maxGroupSubConnections;

        score.trafficSharePercent = percent(score.totalBytes, networkTotalBytes);
        score.attributionCoveragePercent = calculateAttributionCoverage(
            groups,
            score.totalConnections
        );

        score.dominantEntityRatioPercent = calculateDominantEntityRatio(
            groups,
            score.totalConnections
        );

        // Positive MCS parts
        score.connectionIntensityScore = scaledScore(
            static_cast<double>(score.totalConnections),
            static_cast<double>(config_.redflagConnectionCount)
        );

        score.entityDiversityScore = scaledScore(
            static_cast<double>(score.uniqueEntities),
            static_cast<double>(config_.redflagUniqueEntities)
        );

        score.serviceDiversityScore = scaledScore(
            static_cast<double>(score.uniqueServices),
            static_cast<double>(config_.redflagUniqueServices)
        );

        score.concurrencyScore = scaledScore(
            static_cast<double>(score.concurrentConnections),
            static_cast<double>(config_.redflagConcurrentConnections)
        );

        score.trafficShareScore = clampScore(score.trafficSharePercent);

        score.sustainedActivityScore = calculateSustainedActivityScore(
            groups,
            score.totalConnections
        );

        // Negative parts
        if (score.dominantEntityRatioPercent > config_.dominantEntityPenaltyStartPercent)
        {
            score.dominantEntityPenalty = std::min(
                25.0,
                (score.dominantEntityRatioPercent - config_.dominantEntityPenaltyStartPercent) * 0.8
            );
        }

        if (score.dominantEntityRatioPercent >= config_.explainableHeavyDominantEntityPercent &&
            score.uniqueEntities <= 3 &&
            score.totalBytes >= config_.heavyBytesThreshold)
        {
            score.explainableHeavyUsagePenalty = 25.0;
        }
        else if (score.dominantEntityRatioPercent >= 85.0 && score.uniqueCategories <= 2)
        {
            score.explainableHeavyUsagePenalty = 15.0;
        }

        if (score.attributionCoveragePercent < config_.minimumAttributionCoverageForStrongRedflag)
        {
            score.weakAttributionPenalty =
                (config_.minimumAttributionCoverageForStrongRedflag - score.attributionCoveragePercent) * 0.5;
        }

        // MCS formula
        // Balanced to detect multi-client-like behavior:
        // intensity + diversity + concurrency + share + sustained behavior
        // minus explainable heavy usage and weak attribution.
        score.mcs =
            (score.connectionIntensityScore * 0.25) +
            (score.entityDiversityScore * 0.20) +
            (score.serviceDiversityScore * 0.15) +
            (score.concurrencyScore * 0.15) +
            (score.trafficShareScore * 0.10) +
            (score.sustainedActivityScore * 0.15) -
            score.dominantEntityPenalty -
            score.explainableHeavyUsagePenalty -
            score.weakAttributionPenalty;

        score.mcs = clampScore(score.mcs);

        return score;
    }


    inline DeviceState DeviceClassifier::decideState(DeviceScore& score) const
    {
        if (config_.redflagOnlyFromEvilTwinVerdict)
        {
            // Normal / Heavy from the device's own usage only.
            const bool heavyByBytes =
                score.totalBytes >= config_.heavyBytesThreshold;

            const bool heavyByConnections =
                score.totalConnections >= config_.heavyConnectionCount;

            const bool heavyByDestinations =
                score.uniqueEntities >= config_.heavyUniqueEntities;

            return (heavyByBytes || heavyByConnections || heavyByDestinations)
                ? DeviceState::Heavy
                : DeviceState::Normal;
        }

        const bool strongConnectionIntensity =
            score.totalConnections >= config_.redflagConnectionCount;

        const bool strongDiversity =
            score.uniqueEntities >= config_.redflagUniqueEntities &&
            score.uniqueServices >= config_.redflagUniqueServices;

        const bool strongConcurrency =
            score.concurrentConnections >= config_.redflagConcurrentConnections;

        const bool enoughAttribution =
            score.attributionCoveragePercent >= config_.minimumAttributionCoverageForStrongRedflag;

        const bool extremelyStrongPattern =
            score.totalConnections >= config_.redflagConnectionCount * 2 &&
            score.uniqueEntities >= config_.redflagUniqueEntities &&
            score.uniqueServices >= config_.redflagUniqueServices;

        const bool redflagAllowed =
            enoughAttribution || extremelyStrongPattern;

        const bool redflagPattern =
            score.mcs >= config_.redflagMcsThreshold &&
            redflagAllowed &&
            (
                strongConnectionIntensity ||
                strongDiversity ||
                strongConcurrency
                );

        if (redflagPattern)
            return DeviceState::Redflag;

        const bool heavyByBytes =
            score.totalBytes >= config_.heavyBytesThreshold;

        const bool heavyByConnections =
            score.totalConnections >= config_.heavyConnectionCount;

        const bool heavyByMcs =
            score.mcs >= config_.heavyMcsThreshold;

        if (heavyByBytes || heavyByConnections || heavyByMcs)
            return DeviceState::Heavy;

        return DeviceState::Normal;
    }


    inline std::string DeviceClassifier::buildDeviceReason(
        const DeviceScore& score
    ) const
    {
        std::ostringstream out;

        out
            << "Device "
            << score.deviceIp
            << " classified as "
            << toString(score.state)
            << ". ";

        out
            << "MCS="
            << score.mcs
            << ", total connections="
            << score.totalConnections
            << ", groups="
            << score.totalGroups
            << ", unique entities="
            << score.uniqueEntities
            << ", unique services="
            << score.uniqueServices
            << ", concurrent estimate="
            << score.concurrentConnections
            << ", traffic share="
            << score.trafficSharePercent
            << "%, attribution coverage="
            << score.attributionCoveragePercent
            << "%, dominant entity ratio="
            << score.dominantEntityRatioPercent
            << "%. ";

        if (config_.redflagOnlyFromEvilTwinVerdict && score.state != DeviceState::Redflag)
        {
            std::vector<std::string> heavyReasons;

            if (score.totalBytes >= config_.heavyBytesThreshold)
                heavyReasons.push_back("large traffic (download / streaming)");

            if (score.totalConnections >= config_.heavyConnectionCount)
                heavyReasons.push_back("many connections (" + std::to_string(score.totalConnections) +
                    " >= " + std::to_string(config_.heavyConnectionCount) + ")");

            if (score.uniqueEntities >= config_.heavyUniqueEntities)
                heavyReasons.push_back("many destinations (" + std::to_string(score.uniqueEntities) +
                    " >= " + std::to_string(config_.heavyUniqueEntities) + ")");

            if (heavyReasons.empty())
            {
                out << "Reason: light usage (few connections, few destinations, small traffic). ";
            }
            else
            {
                out << "Reason: heavy usage: ";

                for (size_t index = 0; index < heavyReasons.size(); ++index)
                    out << (index > 0 ? ", " : "") << heavyReasons[index];

                out << ". Heavy usage alone is never an Evil Twin alert. ";
            }

            return out.str();
        }

        if (score.state == DeviceState::Redflag)
        {
            out
                << "Reason: high multi-client-like behavior indicators were observed: "
                << "connection intensity, diversity, concurrency, and traffic concentration. ";
        }
        else if (score.state == DeviceState::Heavy)
        {
            out
                << "Reason: the device shows heavy behavior, but the pattern is not strong enough "
                << "to be classified as Redflag under the current evidence and MCS rules. ";
        }
        else
        {
            out
                << "Reason: connection volume, diversity, and concurrency remain within normal range. ";
        }

        if (score.weakAttributionPenalty > 0.0)
        {
            out
                << "Weak attribution coverage reduced certainty, preventing an overconfident suspicious decision. ";
        }

        if (score.explainableHeavyUsagePenalty > 0.0)
        {
            out
                << "Explainable heavy usage penalty was applied because one dominant entity/service explains much of the activity. ";
        }

        return out.str();
    }


    inline double DeviceClassifier::calculateAttributionCoverage(
        const std::vector<ConnectionGroup>& groups,
        size_t totalConnections
    ) const
    {
        if (totalConnections == 0)
            return 0.0;

        size_t covered = 0;

        for (const auto& group : groups)
        {
            for (const auto& sub : group.subConnections)
            {
                const auto& attribution = sub.attribution;

                const bool directOrCorrelated =
                    attribution.type == AttributionType::ExactDestination ||
                    attribution.type == AttributionType::CorrelatedDestination;

                const bool explainedMediumOrBetter =
                    confidenceScore(attribution.confidence) >= confidenceScore(ConfidenceLevel::Medium);

                const bool notWeakIpOnly =
                    attribution.type != AttributionType::EncryptedIpOnly &&
                    attribution.type != AttributionType::ClassifiedIpOnly;

                if (directOrCorrelated || (explainedMediumOrBetter && notWeakIpOnly))
                    covered++;
            }
        }

        return percentSize(covered, totalConnections);
    }


    inline double DeviceClassifier::calculateDominantEntityRatio(
        const std::vector<ConnectionGroup>& groups,
        size_t totalConnections
    ) const
    {
        if (totalConnections == 0)
            return 0.0;

        std::map<std::string, size_t> entityCounts;

        for (const auto& group : groups)
        {
            std::string entity = group.mainEntityName;

            if (trimCopy(entity).empty())
                entity = "Explained connection group";

            entity = normalizeKeyPart(entity);

            entityCounts[entity] += group.subConnectionCount();
        }

        size_t maxCount = 0;

        for (const auto& item : entityCounts)
            maxCount = std::max(maxCount, item.second);

        return percentSize(maxCount, totalConnections);
    }


    inline double DeviceClassifier::calculateSustainedActivityScore(
        const std::vector<ConnectionGroup>& groups,
        size_t totalConnections
    ) const
    {
        if (groups.empty() || totalConnections == 0)
            return 0.0;

        Timestamp first = groups.front().firstSeen;
        Timestamp last = groups.front().lastSeen;

        for (const auto& group : groups)
        {
            if (group.firstSeen < first)
                first = group.firstSeen;

            if (group.lastSeen > last)
                last = group.lastSeen;
        }

        const auto durationSeconds = std::chrono::duration_cast<std::chrono::seconds>(
            last - first
        ).count();

        if (durationSeconds <= 0)
        {
            return totalConnections >= config_.sustainedMinimumConnections
                ? 35.0
                : 0.0;
        }

        const bool sustainedEnough =
            static_cast<uint64_t>(durationSeconds) >= config_.sustainedWindowSeconds;

        const bool connectionsEnough =
            totalConnections >= config_.sustainedMinimumConnections;

        if (!sustainedEnough && !connectionsEnough)
            return 0.0;

        double durationPart = scaledScore(
            static_cast<double>(durationSeconds),
            static_cast<double>(config_.sustainedWindowSeconds)
        );

        double connectionPart = scaledScore(
            static_cast<double>(totalConnections),
            static_cast<double>(config_.sustainedMinimumConnections)
        );

        return clampScore((durationPart * 0.45) + (connectionPart * 0.55));
    }


    inline uint64_t DeviceClassifier::calculateNetworkTotalBytes(
        const std::vector<ConnectionGroup>& groups
    ) const
    {
        uint64_t total = 0;

        for (const auto& group : groups)
            total += group.totalBytes;

        return total;
    }


    inline double DeviceClassifier::clampScore(double value)
    {
        if (value < 0.0)
            return 0.0;

        if (value > 100.0)
            return 100.0;

        return value;
    }


    inline double DeviceClassifier::percent(uint64_t part, uint64_t total)
    {
        if (total == 0)
            return 0.0;

        return (static_cast<double>(part) / static_cast<double>(total)) * 100.0;
    }


    inline double DeviceClassifier::percentSize(size_t part, size_t total)
    {
        if (total == 0)
            return 0.0;

        return (static_cast<double>(part) / static_cast<double>(total)) * 100.0;
    }


    inline double DeviceClassifier::scaledScore(double value, double fullScoreAt)
    {
        if (fullScoreAt <= 0.0)
            return 0.0;

        return clampScore((value / fullScoreAt) * 100.0);
    }


    inline std::string DeviceClassifier::safeMetricLine(
        const std::string& name,
        double value
    )
    {
        std::ostringstream out;
        out << name << "=" << value;
        return out.str();
    }

} // namespace netwolf::core