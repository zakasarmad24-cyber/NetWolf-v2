#pragma once

#include <netwolf/core/models.hpp>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <chrono>
#include <deque>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace netwolf::live {

    // ================================================================
    // NetWolf v2 - Live Connection Tracker
    //
    // Stage 7 purpose:
    // Convert repeated live observations into stable live connection state.
    //
    // Important:
    // This does not identify destination names yet.
    // It tracks lifecycle only:
    // - Connections: New / Active / Closed.
    // - Devices (memory across snapshots): first seen, last seen, how many
    //   client devices were active over time, which ones vanished recently
    //   and which ones appeared recently. This memory is what Evil Twin
    //   detection needs: "every device disappears, then one device returns
    //   carrying abnormal traffic" can only be seen across snapshots.
    //
    // The router (this PC, the access point the devices connect to) is
    // tracked but never counted as a client device.
    // ================================================================


    // ------------------------------------------------
    // Device memory configuration
    // ------------------------------------------------

    // ------------------------------------------------
    // Evil Twin algorithm (relative thresholds)
    //
    //   1. CROWD    : several client devices are active (types recorded,
    //                 normal activity of one person measured = baseline).
    //   2. COLLAPSE : most of them vanish within a short window.
    //   3. ALERT    : right after, one device carries the activity of many
    //                 people (destinations / connections far above the
    //                 per-person baseline) AND a fingerprint confirms it:
    //                 it forwards traffic of other devices (TTL), several
    //                 operating systems appear behind it, or it talks to the
    //                 same destinations the vanished devices used.
    // ------------------------------------------------
    struct LiveEvilTwinConfig
    {
        bool enabled = true;

        // Smallest crowd for which "everyone vanished" is meaningful: two
        // people (the attacker and one victim) are already a crowd.
        size_t minimumCrowdDevices = 2;

        // Share of the crowd that must vanish (0.8 = 80%). At most
        // max(1, (1 - collapseFraction) x crowd) devices of the crowd may
        // remain, so in small crowds "everyone but one vanished" counts.
        double collapseFraction = 0.8;

        // The crowd peak is searched in this window. It must be longer than
        // the hotspot flow idle time (45 s), because a device only counts
        // as gone once its connections went idle.
        int collapseWindowSeconds = 150;

        // After a collapse, the aggregating device must appear within this.
        int aggregationWindowSeconds = 240;

        // The aggregating device must carry at least this share of the
        // vanished people's activity (0.5 = half of them).
        double aggregationFraction = 0.5;

        // Destination overlap with the vanished devices that counts as a
        // confirming fingerprint (0.5 = half of its destinations), and the
        // smallest number of such destinations.
        double destinationOverlapFraction = 0.5;
        size_t destinationOverlapMin = 3;

        // Following the vanished devices. A vanished device is FOUND behind a
        // remaining device when, after the crowd peak, that device starts
        // forwarding connections of the vanished device's operating system,
        // or starts using the vanished device's own destinations. NAT hides
        // the victims' addresses, but not their TCP stack or their apps.
        double followFraction = 0.5;          // share of the vanished devices that must be found (at least one)
        size_t followMinSyns = 10;             // new forwarded connection starts of the device's OWN OS family
        size_t followMinSynsForeign = 5;       // ... of a DIFFERENT OS family (e.g. Apple behind an Android phone)
        double followDestinationShare = 0.5;   // share of the vanished device's own destinations
        size_t followMinDestinations = 3;

        // Monitoring must be continuous: a longer gap between snapshots
        // restarts the Evil Twin memory (no false collapse after a pause).
        int maxSnapshotGapSeconds = 10;

        // Window of the per-person baseline.
        int baselineWindowSeconds = 600;
    };


    // What the engine knows about one active client device in a snapshot.
    struct LiveDeviceProfile
    {
        std::string deviceIp;
        std::string displayName;      // host name or IP
        std::string deviceType;       // "Android", "Windows", ...

        size_t connections = 0;
        std::set<std::string> destinations;

        bool forwarding = false;
        size_t forwardedConnections = 0;
        std::vector<std::string> platformsBehind;

        // Forwarded connection starts per OS family ("Apple" -> 12).
        std::map<std::string, size_t> forwardedByPlatform;
    };


    struct LiveEvilTwinStatus
    {
        // "Watching", "Crowd", "Collapse", "ALERT", "Disabled"
        std::string phase = "Watching";

        size_t activeDevices = 0;
        size_t crowdPeak = 0;

        // Last collapse (if any).
        bool collapseActive = false;
        size_t collapseCrowdSize = 0;
        size_t collapseVanished = 0;
        int secondsSinceCollapse = -1;

        double baselineDestinations = 0.0;
        double baselineConnections = 0.0;

        // Device IP -> evidence text, for devices that raised the alert.
        std::map<std::string, std::string> verdicts;

        // Estimated people carried by each active device (activity / baseline).
        std::map<std::string, double> estimatedUsers;

        // During a collapse: the decision statistic of each device (an alert
        // is raised at 1.0 or more) and how many vanished devices were found
        // behind it.
        std::map<std::string, double> decisionScore;
        std::map<std::string, size_t> followedDevices;

        // Events that happened in THIS snapshot (for the experiment log).
        std::vector<std::string> events;

        std::string summary;
    };


    struct LiveConnectionTrackerConfig
    {
        // Window for "vanished recently", "new recently" and the recent peak.
        int recentWindowSeconds = 60;

        // How long the client-population history is kept.
        int populationHistorySeconds = 600;

        // A device not seen for this long is forgotten entirely.
        int deviceMemorySeconds = 600;

        // Addresses that always belong to the router (this PC). Devices seen
        // by the local Windows sensors are added to this set automatically.
        // 192.168.137.1 is the default Windows Mobile Hotspot gateway.
        std::vector<std::string> routerDeviceIps = { "192.168.137.1" };

        LiveEvilTwinConfig evilTwin;
    };


    // ------------------------------------------------
    // Remembered device and population history
    // ------------------------------------------------

    struct LiveDevicePresence
    {
        std::string deviceIp;

        // True for the router (this PC). Never counted as a client.
        bool router = false;

        std::chrono::system_clock::time_point firstSeen =
            std::chrono::system_clock::now();

        std::chrono::system_clock::time_point lastSeen =
            std::chrono::system_clock::now();

        // Connections in the current snapshot (0 = not active now).
        size_t currentConnections = 0;

        size_t peakConnections = 0;
        size_t seenSnapshots = 0;

        bool activeNow() const
        {
            return currentConnections > 0;
        }
    };


    struct LivePopulationSample
    {
        std::chrono::system_clock::time_point at =
            std::chrono::system_clock::now();

        size_t activeClientDevices = 0;
        size_t clientConnections = 0;
    };

    struct LiveConnectionTrackerUpdate
    {
        std::vector<netwolf::core::ObservedConnection> activeConnections;

        size_t inputConnections = 0;
        size_t newConnections = 0;
        size_t updatedConnections = 0;
        size_t closedConnections = 0;
        size_t activeConnectionsCount = 0;

        // Device memory (client devices only; the router is excluded).
        size_t knownClientDevices = 0;       // remembered clients
        size_t activeClientDevices = 0;      // clients with connections now
        size_t recentPeakClientDevices = 0;  // most clients active at once in the recent window
        size_t vanishedClientDevices = 0;    // active in the recent window, gone now
        size_t newClientDevices = 0;         // first seen within the recent window, active now

        // Every remembered device (router included, flagged), and the
        // client-population history, oldest first.
        std::vector<LiveDevicePresence> devices;
        std::vector<LivePopulationSample> populationHistory;

        std::string summaryText;
    };


    struct LiveTrackedConnection
    {
        netwolf::core::ObservedConnection observed;

        std::chrono::system_clock::time_point firstObservedAt =
            std::chrono::system_clock::now();

        std::chrono::system_clock::time_point lastObservedAt =
            std::chrono::system_clock::now();

        size_t seenCount = 0;
    };


    class LiveConnectionTracker
    {
    public:
        explicit LiveConnectionTracker(
            LiveConnectionTrackerConfig config = {}
        );

        LiveConnectionTrackerUpdate update(
            const std::vector<netwolf::core::ObservedConnection>& currentConnections
        );

        // routerDeviceIps: devices known to be the router (this PC) in this
        // snapshot, e.g. everything seen by the local Windows sensors.
        LiveConnectionTrackerUpdate update(
            const std::vector<netwolf::core::ObservedConnection>& currentConnections,
            const std::set<std::string>& routerDeviceIps
        );

        void clear();

        const LiveConnectionTrackerConfig& config() const;

        // Runs the Evil Twin algorithm on the active client devices of this
        // snapshot. captureGeneration changes when packet capture restarts;
        // that (or a long pause) restarts the Evil Twin memory.
        LiveEvilTwinStatus evaluateEvilTwin(
            const std::vector<LiveDeviceProfile>& activeDevices,
            uint64_t captureGeneration,
            std::chrono::system_clock::time_point now =
                std::chrono::system_clock::now()
        );

    private:
        LiveConnectionTrackerConfig config_;

        std::map<std::string, LiveTrackedConnection> tracked_;

        // Device memory, kept across snapshots.
        std::map<std::string, LiveDevicePresence> devices_;
        std::deque<LivePopulationSample> populationHistory_;

        // ---- Evil Twin memory ----
        struct ProfileTrace
        {
            std::set<std::string> destinations;
            std::map<std::string, size_t> forwarded;   // OS family -> forwarded starts
        };

        struct CrowdSample
        {
            std::chrono::system_clock::time_point at;
            std::set<std::string> devices;
            std::map<std::string, ProfileTrace> profiles;
        };

        struct BaselineSample
        {
            std::chrono::system_clock::time_point at;
            double destinations = 0.0;
            double connections = 0.0;
        };

        struct CollapseState
        {
            bool active = false;
            std::chrono::system_clock::time_point at;
            size_t crowdSize = 0;
            std::set<std::string> vanishedDevices;
            std::set<std::string> vanishedDestinations;
            std::map<std::string, size_t> vanishedTypes;
            double baselineDestinations = 1.0;
            double baselineConnections = 1.0;

            // What every device looked like at the crowd peak (before the
            // victims moved), and what each vanished device was.
            std::map<std::string, ProfileTrace> before;
            std::map<std::string, std::string> vanishedFamily;
            std::map<std::string, std::set<std::string>> vanishedDestinationSets;
            std::map<std::string, std::string> vanishedNames;

            // Each remaining device's own median activity before the peak.
            std::map<std::string, std::pair<double, double>> ownBaseline;   // destinations, connections
        };

        std::deque<CrowdSample> crowdSamples_;

        // Destinations each device used recently: device -> destination ->
        // (first seen, last seen), kept for the baseline window. Tells which
        // destinations are NEW for a device after the crowd peak.
        struct DestinationSeen
        {
            std::chrono::system_clock::time_point first;
            std::chrono::system_clock::time_point last;
        };

        std::map<std::string, std::map<std::string, DestinationSeen>> destinationHistory_;

        // Each device's own recent activity (connections, destinations),
        // kept for the baseline window. A heavy user is compared with its
        // own usual activity, not only with the crowd's median person.
        struct ActivitySample
        {
            std::chrono::system_clock::time_point at;
            double destinations = 0.0;
            double connections = 0.0;
        };

        std::map<std::string, std::deque<ActivitySample>> activityHistory_;
        std::deque<BaselineSample> baselineSamples_;
        std::map<std::string, LiveDeviceProfile> lastProfiles_;
        CollapseState collapse_;
        std::map<std::string, std::string> verdicts_;
        std::set<std::string> announcedCandidates_;
        bool evilTwinStarted_ = false;
        std::chrono::system_clock::time_point lastEvilTwinAt_{};
        uint64_t captureGeneration_ = 0;

        void resetEvilTwinMemory();

        static double median(std::vector<double> values);

        static std::string osFamilyOf(const std::string& deviceType);

    private:
        void updateDeviceMemory(
            const std::vector<netwolf::core::ObservedConnection>& currentConnections,
            const std::set<std::string>& routerDeviceIps,
            std::chrono::system_clock::time_point now,
            LiveConnectionTrackerUpdate& update
        );

        static std::string makeConnectionKey(
            const netwolf::core::ObservedConnection& connection
        );

        static std::string protocolKey(
            netwolf::core::TransportProtocol protocol
        );
    };


    inline LiveConnectionTracker::LiveConnectionTracker(
        LiveConnectionTrackerConfig config
    )
        : config_(std::move(config))
    {
    }


    inline const LiveConnectionTrackerConfig& LiveConnectionTracker::config() const
    {
        return config_;
    }


    inline LiveConnectionTrackerUpdate LiveConnectionTracker::update(
        const std::vector<netwolf::core::ObservedConnection>& currentConnections
    )
    {
        return update(
            currentConnections,
            std::set<std::string>{}
        );
    }


    inline LiveConnectionTrackerUpdate LiveConnectionTracker::update(
        const std::vector<netwolf::core::ObservedConnection>& currentConnections,
        const std::set<std::string>& routerDeviceIps
    )
    {
        LiveConnectionTrackerUpdate update;
        update.inputConnections = currentConnections.size();

        const auto now =
            std::chrono::system_clock::now();

        std::set<std::string> currentKeys;

        for (const auto& connection : currentConnections)
        {
            const std::string key =
                makeConnectionKey(connection);

            currentKeys.insert(key);

            auto found =
                tracked_.find(key);

            if (found == tracked_.end())
            {
                LiveTrackedConnection tracked;
                tracked.observed = connection;
                tracked.observed.firstSeen = connection.firstSeen;
                tracked.observed.lastSeen = now;
                tracked.firstObservedAt = now;
                tracked.lastObservedAt = now;
                tracked.seenCount = 1;

                tracked_.emplace(
                    key,
                    std::move(tracked)
                );

                ++update.newConnections;
            }
            else
            {
                LiveTrackedConnection& tracked =
                    found->second;

                const auto originalFirstSeen =
                    tracked.observed.firstSeen;

                tracked.observed = connection;
                tracked.observed.firstSeen = originalFirstSeen;
                tracked.observed.lastSeen = now;

                tracked.lastObservedAt = now;
                ++tracked.seenCount;

                ++update.updatedConnections;
            }
        }

        for (auto it = tracked_.begin(); it != tracked_.end(); )
        {
            if (currentKeys.find(it->first) == currentKeys.end())
            {
                it = tracked_.erase(it);
                ++update.closedConnections;
            }
            else
            {
                ++it;
            }
        }

        update.activeConnections.reserve(tracked_.size());

        for (const auto& item : tracked_)
        {
            update.activeConnections.push_back(item.second.observed);
        }

        update.activeConnectionsCount =
            update.activeConnections.size();

        updateDeviceMemory(
            currentConnections,
            routerDeviceIps,
            now,
            update
        );

        std::ostringstream summary;

        summary
            << "Live tracker: input="
            << update.inputConnections
            << ", new="
            << update.newConnections
            << ", updated="
            << update.updatedConnections
            << ", closed="
            << update.closedConnections
            << ", active="
            << update.activeConnectionsCount
            << " | client devices: now="
            << update.activeClientDevices
            << ", recent peak="
            << update.recentPeakClientDevices
            << ", vanished="
            << update.vanishedClientDevices
            << ", new="
            << update.newClientDevices
            << ", known="
            << update.knownClientDevices;

        update.summaryText = summary.str();

        return update;
    }


    inline void LiveConnectionTracker::updateDeviceMemory(
        const std::vector<netwolf::core::ObservedConnection>& currentConnections,
        const std::set<std::string>& routerDeviceIps,
        std::chrono::system_clock::time_point now,
        LiveConnectionTrackerUpdate& update
    )
    {
        const auto recentWindow =
            std::chrono::seconds(std::max(1, config_.recentWindowSeconds));

        const auto historyWindow =
            std::chrono::seconds(std::max(1, config_.populationHistorySeconds));

        const auto memoryWindow =
            std::chrono::seconds(std::max(1, config_.deviceMemorySeconds));

        auto isRouter = [&](const std::string& deviceIp)
            {
                if (routerDeviceIps.count(deviceIp) > 0)
                    return true;

                return std::find(
                    config_.routerDeviceIps.begin(),
                    config_.routerDeviceIps.end(),
                    deviceIp
                ) != config_.routerDeviceIps.end();
            };

        // 1. Connections per device in this snapshot.
        std::map<std::string, size_t> connectionsPerDevice;

        for (const auto& connection : currentConnections)
        {
            if (!connection.deviceIp.empty())
                ++connectionsPerDevice[connection.deviceIp];
        }

        // 2. Every remembered device starts as "not active now".
        for (auto& item : devices_)
            item.second.currentConnections = 0;

        // 3. Devices present in this snapshot.
        for (const auto& item : connectionsPerDevice)
        {
            auto found = devices_.find(item.first);

            if (found == devices_.end())
            {
                LiveDevicePresence device;
                device.deviceIp = item.first;
                device.firstSeen = now;
                device.lastSeen = now;

                found = devices_.emplace(
                    item.first,
                    std::move(device)
                ).first;
            }

            LiveDevicePresence& device = found->second;

            device.lastSeen = now;
            device.currentConnections = item.second;
            device.peakConnections = std::max(device.peakConnections, item.second);
            ++device.seenSnapshots;

            // Once identified as the router, a device stays the router.
            device.router = device.router || isRouter(item.first);
        }

        // 4. Forget devices not seen for a long time (bounded memory).
        for (auto it = devices_.begin(); it != devices_.end(); )
        {
            if (now - it->second.lastSeen > memoryWindow)
                it = devices_.erase(it);
            else
                ++it;
        }

        // 5. Client counts for this snapshot (router excluded).
        size_t activeClients = 0;
        size_t clientConnections = 0;

        for (const auto& item : devices_)
        {
            const LiveDevicePresence& device = item.second;

            if (device.router)
                continue;

            ++update.knownClientDevices;

            if (device.activeNow())
            {
                ++activeClients;
                clientConnections += device.currentConnections;

                if (now - device.firstSeen <= recentWindow)
                    ++update.newClientDevices;
            }
            else if (now - device.lastSeen <= recentWindow)
            {
                ++update.vanishedClientDevices;
            }
        }

        update.activeClientDevices = activeClients;

        // 6. Population history (bounded), then the recent peak.
        LivePopulationSample sample;
        sample.at = now;
        sample.activeClientDevices = activeClients;
        sample.clientConnections = clientConnections;

        populationHistory_.push_back(sample);

        while (!populationHistory_.empty() &&
            now - populationHistory_.front().at > historyWindow)
        {
            populationHistory_.pop_front();
        }

        for (const auto& item : populationHistory_)
        {
            if (now - item.at <= recentWindow)
            {
                update.recentPeakClientDevices = std::max(
                    update.recentPeakClientDevices,
                    item.activeClientDevices
                );
            }
        }

        // 7. Expose the memory to the rest of the engine.
        update.devices.reserve(devices_.size());

        for (const auto& item : devices_)
            update.devices.push_back(item.second);

        update.populationHistory.assign(
            populationHistory_.begin(),
            populationHistory_.end()
        );
    }


    inline void LiveConnectionTracker::clear()
    {
        tracked_.clear();
        devices_.clear();
        populationHistory_.clear();
        resetEvilTwinMemory();
        evilTwinStarted_ = false;
    }


    inline void LiveConnectionTracker::resetEvilTwinMemory()
    {
        crowdSamples_.clear();
        baselineSamples_.clear();
        lastProfiles_.clear();
        destinationHistory_.clear();
        activityHistory_.clear();
        collapse_ = CollapseState{};
        verdicts_.clear();
        announcedCandidates_.clear();
    }


    inline double LiveConnectionTracker::median(std::vector<double> values)
    {
        if (values.empty())
            return 0.0;

        std::sort(values.begin(), values.end());

        const size_t middle = values.size() / 2;

        return values.size() % 2 == 1
            ? values[middle]
            : (values[middle - 1] + values[middle]) / 2.0;
    }


    inline LiveEvilTwinStatus LiveConnectionTracker::evaluateEvilTwin(
        const std::vector<LiveDeviceProfile>& activeDevices,
        uint64_t captureGeneration,
        std::chrono::system_clock::time_point now
    )
    {
        const LiveEvilTwinConfig& cfg = config_.evilTwin;

        LiveEvilTwinStatus status;
        status.activeDevices = activeDevices.size();

        if (!cfg.enabled)
        {
            status.phase = "Disabled";
            status.summary = "Evil Twin detection is disabled.";
            return status;
        }

        auto secondsBetween = [](std::chrono::system_clock::time_point later,
            std::chrono::system_clock::time_point earlier)
            {
                return std::chrono::duration_cast<std::chrono::seconds>(later - earlier).count();
            };

        auto formatNumber = [](double value)
            {
                std::ostringstream out;
                out.setf(std::ios::fixed);
                out.precision(1);
                out << value;
                return out.str();
            };

        // ---- 0. Continuous monitoring ----
        if (evilTwinStarted_)
        {
            if (captureGeneration != captureGeneration_)
            {
                resetEvilTwinMemory();
                status.events.push_back("Packet capture restarted: Evil Twin memory restarted.");
            }
            else if (secondsBetween(now, lastEvilTwinAt_) > cfg.maxSnapshotGapSeconds)
            {
                resetEvilTwinMemory();
                status.events.push_back("Monitoring gap of " +
                    std::to_string(secondsBetween(now, lastEvilTwinAt_)) +
                    " s: Evil Twin memory restarted.");
            }
        }

        evilTwinStarted_ = true;
        lastEvilTwinAt_ = now;
        captureGeneration_ = captureGeneration;

        // ---- 1. Crowd memory ----
        CrowdSample sample;
        sample.at = now;

        for (const auto& profile : activeDevices)
        {
            sample.devices.insert(profile.deviceIp);
            lastProfiles_[profile.deviceIp] = profile;

            ProfileTrace& trace = sample.profiles[profile.deviceIp];
            trace.forwarded = profile.forwardedByPlatform;

            activityHistory_[profile.deviceIp].push_back(ActivitySample{
                now,
                static_cast<double>(profile.destinations.size()),
                static_cast<double>(profile.connections) });

            auto& history = destinationHistory_[profile.deviceIp];

            for (const auto& destination : profile.destinations)
            {
                auto found = history.find(destination);

                if (found == history.end())
                    history.emplace(destination, DestinationSeen{ now, now });
                else
                    found->second.last = now;
            }
        }

        for (auto device = activityHistory_.begin(); device != activityHistory_.end(); )
        {
            while (!device->second.empty() &&
                secondsBetween(now, device->second.front().at) > cfg.baselineWindowSeconds)
            {
                device->second.pop_front();
            }

            if (device->second.empty())
                device = activityHistory_.erase(device);
            else
                ++device;
        }

        for (auto device = destinationHistory_.begin(); device != destinationHistory_.end(); )
        {
            for (auto item = device->second.begin(); item != device->second.end(); )
            {
                if (secondsBetween(now, item->second.last) > cfg.baselineWindowSeconds)
                    item = device->second.erase(item);
                else
                    ++item;
            }

            if (device->second.empty())
                device = destinationHistory_.erase(device);
            else
                ++device;
        }

        crowdSamples_.push_back(sample);

        while (!crowdSamples_.empty() &&
            secondsBetween(now, crowdSamples_.front().at) > cfg.collapseWindowSeconds)
        {
            crowdSamples_.pop_front();
        }

        const CrowdSample* peak = nullptr;

        for (const auto& item : crowdSamples_)
        {
            if (peak == nullptr || item.devices.size() > peak->devices.size())
                peak = &item;
        }

        status.crowdPeak = peak != nullptr ? peak->devices.size() : 0;

        // Per-person baseline: median activity of one device while a crowd
        // is present.
        if (activeDevices.size() >= cfg.minimumCrowdDevices)
        {
            std::vector<double> destinations;
            std::vector<double> connections;

            for (const auto& profile : activeDevices)
            {
                destinations.push_back(static_cast<double>(profile.destinations.size()));
                connections.push_back(static_cast<double>(profile.connections));
            }

            baselineSamples_.push_back(BaselineSample{ now, median(destinations), median(connections) });
        }

        while (!baselineSamples_.empty() &&
            secondsBetween(now, baselineSamples_.front().at) > cfg.baselineWindowSeconds)
        {
            baselineSamples_.pop_front();
        }

        // ---- 2. Collapse ----
        if (!collapse_.active && peak != nullptr &&
            peak->devices.size() >= cfg.minimumCrowdDevices)
        {
            std::set<std::string> vanished;

            for (const auto& ip : peak->devices)
            {
                if (sample.devices.count(ip) == 0)
                    vanished.insert(ip);
            }

            // At most max(1, (1 - rho) x crowd) devices of the crowd remain.
            const size_t crowd = peak->devices.size();
            const size_t remaining = crowd - vanished.size();
            const size_t allowedRemaining = std::max<size_t>(1,
                static_cast<size_t>(std::floor((1.0 - cfg.collapseFraction) * static_cast<double>(crowd) + 1e-9)));

            if (!vanished.empty() && remaining <= allowedRemaining)
            {
                collapse_ = CollapseState{};
                collapse_.active = true;
                collapse_.at = now;
                collapse_.crowdSize = peak->devices.size();
                collapse_.vanishedDevices = vanished;

                std::vector<double> destinations;
                std::vector<double> connections;

                for (const auto& item : baselineSamples_)
                {
                    destinations.push_back(item.destinations);
                    connections.push_back(item.connections);
                }

                collapse_.baselineDestinations = std::max(1.0, median(destinations));
                collapse_.baselineConnections = std::max(1.0, median(connections));

                collapse_.before = peak->profiles;

                for (const auto& [ip, samples] : activityHistory_)
                {
                    std::vector<double> ownDestinations;
                    std::vector<double> ownConnections;

                    for (const auto& item : samples)
                    {
                        if (item.at > peak->at)
                            break;

                        ownDestinations.push_back(item.destinations);
                        ownConnections.push_back(item.connections);
                    }

                    // About half a minute of activity is needed to know a device.
                    if (ownDestinations.size() >= 30)
                        collapse_.ownBaseline[ip] = { median(ownDestinations), median(ownConnections) };
                }

                for (const auto& [ip, history] : destinationHistory_)
                {
                    ProfileTrace& trace = collapse_.before[ip];

                    for (const auto& [destination, seen] : history)
                    {
                        if (seen.first <= peak->at)
                            trace.destinations.insert(destination);
                    }
                }

                for (const auto& ip : vanished)
                {
                    const auto profile = lastProfiles_.find(ip);

                    if (profile == lastProfiles_.end())
                        continue;

                    collapse_.vanishedDestinations.insert(
                        profile->second.destinations.begin(),
                        profile->second.destinations.end()
                    );

                    ++collapse_.vanishedTypes[profile->second.deviceType.empty()
                        ? std::string("Unknown") : profile->second.deviceType];

                    collapse_.vanishedFamily[ip] = osFamilyOf(profile->second.deviceType);

                    // Everything the vanished device used recently.
                    std::set<std::string>& own = collapse_.vanishedDestinationSets[ip];
                    own = profile->second.destinations;

                    const auto history = destinationHistory_.find(ip);
                    if (history != destinationHistory_.end())
                        for (const auto& item : history->second)
                            own.insert(item.first);
                    collapse_.vanishedNames[ip] = profile->second.displayName.empty()
                        ? ip : profile->second.displayName;
                }

                const long long collapseSeconds = secondsBetween(now, peak->at);

                status.events.push_back(
                    "COLLAPSE: " + std::to_string(vanished.size()) + " of " +
                    std::to_string(peak->devices.size()) + " devices vanished within " +
                    std::to_string(collapseSeconds) + " s; " +
                    std::to_string(sample.devices.size()) + " remain. Baseline per person: " +
                    formatNumber(collapse_.baselineDestinations) + " destinations, " +
                    formatNumber(collapse_.baselineConnections) + " connections.");

                // Start a fresh crowd memory so the same peak does not trigger again.
                crowdSamples_.clear();
                crowdSamples_.push_back(sample);
            }
        }

        if (collapse_.active &&
            secondsBetween(now, collapse_.at) > cfg.aggregationWindowSeconds)
        {
            if (verdicts_.empty())
            {
                status.events.push_back(
                    "Collapse window ended: no device carried the vanished devices' activity (no alert).");
            }

            collapse_.active = false;
        }

        // ---- 3. Aggregating device ----
        // Two ways to recognise the device that took over the vanished crowd:
        //   A. it carries the activity of several people (relative to the
        //      per-person baseline) and a fingerprint confirms it;
        //   B. it forwards traffic, and the vanished devices are FOUND behind
        //      it: their operating system or their own destinations appear
        //      on it after the crowd peak.
        // Both give a score; 1.0 or more raises the alert.
        double neededUsers = 0.0;
        double neededFound = 0.0;

        if (collapse_.active)
        {
            neededUsers = std::max(
                2.0,
                cfg.aggregationFraction * static_cast<double>(collapse_.vanishedDevices.size())
            );

            neededFound = std::max(
                1.0,
                cfg.followFraction * static_cast<double>(collapse_.vanishedDevices.size())
            );
        }

        for (const auto& profile : activeDevices)
        {
            double baselineDestinations = collapse_.active
                ? collapse_.baselineDestinations
                : std::max(1.0, baselineSamples_.empty() ? 1.0 : baselineSamples_.back().destinations);

            double baselineConnections = collapse_.active
                ? collapse_.baselineConnections
                : std::max(1.0, baselineSamples_.empty() ? 1.0 : baselineSamples_.back().connections);

            // During a collapse, a device that was already there is also
            // compared with its own usual activity: carrying other people
            // means doing much more than this device itself used to do.
            if (collapse_.active)
            {
                const auto own = collapse_.ownBaseline.find(profile.deviceIp);

                if (own != collapse_.ownBaseline.end())
                {
                    baselineDestinations = std::max(baselineDestinations, own->second.first);
                    baselineConnections = std::max(baselineConnections, own->second.second);
                }
            }

            const double usersByDestinations =
                static_cast<double>(profile.destinations.size()) / baselineDestinations;

            const double usersByConnections =
                static_cast<double>(profile.connections) / baselineConnections;

            const double estimatedUsers = std::max(usersByDestinations, usersByConnections);

            status.estimatedUsers[profile.deviceIp] = estimatedUsers;

            if (!collapse_.active)
                continue;

            // What this device looked like at the crowd peak (empty for a
            // device that was not there).
            const auto beforeIt = collapse_.before.find(profile.deviceIp);
            const ProfileTrace* before = beforeIt != collapse_.before.end() ? &beforeIt->second : nullptr;

            // ---- A. Aggregation confirmed by a fingerprint ----
            // Overlap counts only destinations this device did NOT use at the
            // crowd peak: someone who simply keeps using the same popular
            // sites as the people who left is not carrying their traffic.
            size_t shared = 0;

            for (const auto& destination : profile.destinations)
            {
                if (before != nullptr && before->destinations.count(destination) != 0)
                    continue;

                if (collapse_.vanishedDestinations.count(destination) != 0)
                    ++shared;
            }

            const double overlap = profile.destinations.empty()
                ? 0.0
                : static_cast<double>(shared) / static_cast<double>(profile.destinations.size());

            // Forwarding compared with the crowd peak. Only an operating
            // system that was NOT behind this device before counts as new
            // forwarding: a phone that always shared its connection with its
            // own laptop, or always tunnelled a little traffic, is not a new
            // relay because the others left.
            size_t forwardedNew = 0;        // connection starts of NEW OS families
            size_t forwardedGrowth = 0;     // growth of all forwarding since the peak
            size_t newFamilies = 0;
            bool newFamilyConfirmed = false;

            // An OS family different from the device's own cannot come from a
            // tunnel or virtual system inside the device itself: it needs
            // less evidence than the device's own family.
            const std::string ownFamily = osFamilyOf(profile.deviceType);

            auto minSynsFor = [&](const std::string& family)
                {
                    return (!ownFamily.empty() && family != ownFamily)
                        ? cfg.followMinSynsForeign : cfg.followMinSyns;
                };

            for (const auto& [family, count] : profile.forwardedByPlatform)
            {
                size_t was = 0;

                if (before != nullptr)
                {
                    const auto wasIt = before->forwarded.find(family);
                    was = wasIt != before->forwarded.end() ? wasIt->second : 0;
                }

                if (count > was)
                    forwardedGrowth += count - was;

                if (was == 0 && count > 0)
                {
                    forwardedNew += count;
                    ++newFamilies;

                    if (count >= minSynsFor(family))
                        newFamilyConfirmed = true;
                }
            }

            const bool forwardingNew = profile.forwarding && newFamilyConfirmed;
            const bool overlapConfirms = shared >= cfg.destinationOverlapMin &&
                overlap + 1e-9 >= cfg.destinationOverlapFraction;
            const bool multiPlatform = newFamilies >= 2;
            const bool fingerprint = forwardingNew || multiPlatform || overlapConfirms;

            // Aggregation means carrying SEVERAL people: it needs at least two
            // vanished devices. One vanished device is handled by following (B).
            const double scoreAggregation =
                (fingerprint && collapse_.vanishedDevices.size() >= 2) ? estimatedUsers / neededUsers : 0.0;

            // ---- B. The vanished devices found behind this device ----
            std::vector<std::string> foundTexts;

            for (const auto& vanishedIp : collapse_.vanishedDevices)
            {
                if (vanishedIp == profile.deviceIp)
                    continue;   // a device that came back is not behind itself

                std::string reason;

                // Its operating system appears as NEW forwarded connection starts.
                const auto familyIt = collapse_.vanishedFamily.find(vanishedIp);
                const std::string family = familyIt != collapse_.vanishedFamily.end() ? familyIt->second : std::string();

                if (!family.empty())
                {
                    const auto nowIt = profile.forwardedByPlatform.find(family);
                    const size_t now = nowIt != profile.forwardedByPlatform.end() ? nowIt->second : 0;

                    size_t was = 0;

                    if (before != nullptr)
                    {
                        const auto wasIt = before->forwarded.find(family);
                        was = wasIt != before->forwarded.end() ? wasIt->second : 0;
                    }

                    if (was == 0 && now >= minSynsFor(family))
                        reason = std::to_string(now) + " " + family + " connection starts appeared behind it";
                }

                // Its own destinations (not used by this device before) appear here.
                const auto destinationsIt = collapse_.vanishedDestinationSets.find(vanishedIp);

                if (destinationsIt != collapse_.vanishedDestinationSets.end())
                {
                    size_t own = 0;
                    size_t carried = 0;

                    for (const auto& destination : destinationsIt->second)
                    {
                        if (before != nullptr && before->destinations.count(destination) != 0)
                            continue;

                        ++own;

                        if (profile.destinations.count(destination) != 0)
                            ++carried;
                    }

                    const size_t needed = std::max(
                        cfg.followMinDestinations,
                        static_cast<size_t>(std::ceil(cfg.followDestinationShare * static_cast<double>(own) - 1e-9)));

                    if (own >= cfg.followMinDestinations && carried >= needed)
                    {
                        reason += (reason.empty() ? "" : "; ") + std::to_string(carried) + " of its " +
                            std::to_string(own) + " own destinations appeared here";
                    }
                }

                if (!reason.empty())
                {
                    const auto nameIt = collapse_.vanishedNames.find(vanishedIp);
                    foundTexts.push_back((nameIt != collapse_.vanishedNames.end() ? nameIt->second : vanishedIp) +
                        " (" + reason + ")");
                }
            }

            // Following needs the device to forward traffic that is new:
            // a new OS behind it, or forwarding that grew by at least
            // followMinSyns per device found behind it.
            const bool forwardingForFound = profile.forwarding &&
                (forwardingNew || forwardedGrowth >= cfg.followMinSyns * std::max<size_t>(1, foundTexts.size()));

            const double scoreFollow = forwardingForFound
                ? static_cast<double>(foundTexts.size()) / neededFound
                : 0.0;

            const double score = std::max(scoreAggregation, scoreFollow);

            status.decisionScore[profile.deviceIp] = score;
            status.followedDevices[profile.deviceIp] = foundTexts.size();

            if (verdicts_.count(profile.deviceIp) != 0)
                continue;

            if (score + 1e-9 < 1.0)
            {
                if (estimatedUsers + 1e-9 >= neededUsers && !fingerprint &&
                    collapse_.vanishedDevices.size() >= 2 &&
                    announcedCandidates_.insert(profile.deviceIp).second)
                {
                    status.events.push_back(
                        "Candidate " + profile.displayName + " carries ~" + formatNumber(estimatedUsers) +
                        " people's activity but no fingerprint confirms it yet (no forwarding, overlap " +
                        std::to_string(static_cast<int>(overlap * 100.0 + 0.5)) + "%).");
                }

                continue;
            }

            std::ostringstream evidence;

            evidence
                << "(1) Crowd: " << collapse_.crowdSize << " devices were connected";

            if (!collapse_.vanishedTypes.empty())
            {
                evidence << " (";
                bool first = true;

                for (const auto& [type, count] : collapse_.vanishedTypes)
                {
                    evidence << (first ? "" : ", ") << count << " " << type;
                    first = false;
                }

                evidence << " vanished)";
            }

            evidence
                << ". (2) Collapse: " << collapse_.vanishedDevices.size() << " of "
                << collapse_.crowdSize << " vanished " << secondsBetween(now, collapse_.at)
                << " s ago. (3) Takeover by " << profile.displayName << ":";

            if (!foundTexts.empty())
            {
                evidence << " vanished devices found behind it: ";

                for (size_t index = 0; index < foundTexts.size(); ++index)
                    evidence << (index == 0 ? "" : ", ") << foundTexts[index];

                evidence << ";";
            }

            evidence
                << " it carries ~" << formatNumber(estimatedUsers) << " people's activity ("
                << profile.destinations.size() << " destinations vs "
                << formatNumber(collapse_.baselineDestinations) << " per person; "
                << profile.connections << " connections vs "
                << formatNumber(collapse_.baselineConnections) << " per person). Fingerprints:";

            if (profile.forwarding)
            {
                evidence << " forwards traffic of other devices (" << profile.forwardedConnections
                    << " connections with decreased TTL, " << forwardedGrowth << " since the crowd peak)";

                if (!profile.platformsBehind.empty())
                {
                    evidence << " from";

                    for (size_t index = 0; index < profile.platformsBehind.size(); ++index)
                        evidence << (index == 0 ? " " : ", ") << profile.platformsBehind[index];
                }

                evidence << ";";
            }

            evidence << " " << static_cast<int>(overlap * 100.0 + 0.5)
                << "% of its destinations are new for it and were used by the vanished devices.";

            verdicts_[profile.deviceIp] = evidence.str();

            status.events.push_back("ALERT: Evil Twin suspect " + profile.displayName +
                (profile.displayName == profile.deviceIp ? std::string() : " (" + profile.deviceIp + ")") +
                ". " + evidence.str());
        }

        // A latched alert stays while the device is connected.
        for (auto it = verdicts_.begin(); it != verdicts_.end(); )
        {
            if (sample.devices.count(it->first) == 0)
            {
                status.events.push_back("Alert cleared: " + it->first + " left the network.");
                it = verdicts_.erase(it);
            }
            else
            {
                ++it;
            }
        }

        // Forget profiles of devices gone longer than the device memory.
        for (auto it = lastProfiles_.begin(); it != lastProfiles_.end(); )
        {
            const auto presence = devices_.find(it->first);

            if (presence == devices_.end())
                it = lastProfiles_.erase(it);
            else
                ++it;
        }

        // ---- Status ----
        status.verdicts = verdicts_;
        status.collapseActive = collapse_.active;
        status.collapseCrowdSize = collapse_.crowdSize;
        status.collapseVanished = collapse_.vanishedDevices.size();
        status.secondsSinceCollapse = collapse_.active
            ? static_cast<int>(secondsBetween(now, collapse_.at))
            : -1;

        status.baselineDestinations = collapse_.active
            ? collapse_.baselineDestinations
            : (baselineSamples_.empty() ? 0.0 : baselineSamples_.back().destinations);

        status.baselineConnections = collapse_.active
            ? collapse_.baselineConnections
            : (baselineSamples_.empty() ? 0.0 : baselineSamples_.back().connections);

        std::ostringstream summary;

        if (!verdicts_.empty())
        {
            status.phase = "ALERT";
            summary << "EVIL TWIN ALERT: " << verdicts_.size() << " suspect device(s).";
        }
        else if (collapse_.active)
        {
            status.phase = "Collapse";
            summary << "Collapse: " << collapse_.vanishedDevices.size() << " of "
                << collapse_.crowdSize << " devices vanished " << status.secondsSinceCollapse
                << " s ago; watching for one device carrying their activity.";
        }
        else if (activeDevices.size() >= cfg.minimumCrowdDevices)
        {
            status.phase = "Crowd";
            summary << "Watching " << activeDevices.size() << " devices (peak "
                << status.crowdPeak << "); baseline per person "
                << formatNumber(status.baselineDestinations) << " destinations.";
        }
        else
        {
            status.phase = "Watching";
            summary << "Watching " << activeDevices.size() << " device(s); a crowd of "
                << cfg.minimumCrowdDevices << "+ is needed before a collapse can be judged.";
        }

        status.summary = summary.str();
        return status;
    }


    inline std::string LiveConnectionTracker::osFamilyOf(const std::string& deviceType)
    {
        std::string type;
        for (const char c : deviceType)
            type += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

        if (type.find("windows") != std::string::npos) return "Windows";

        if (type.find("apple") != std::string::npos || type.find("ios") != std::string::npos ||
            type.find("iphone") != std::string::npos || type.find("ipad") != std::string::npos ||
            type.find("mac") != std::string::npos)
            return "Apple";

        if (type.find("android") != std::string::npos || type.find("linux") != std::string::npos)
            return "Android/Linux";

        return std::string();
    }


    inline std::string LiveConnectionTracker::makeConnectionKey(
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
        key += protocolKey(connection.protocol);

        return key;
    }


    inline std::string LiveConnectionTracker::protocolKey(
        netwolf::core::TransportProtocol protocol
    )
    {
        return std::to_string(
            static_cast<int>(protocol)
        );
    }

} // namespace netwolf::live