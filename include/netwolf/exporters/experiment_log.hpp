#pragma once

#include <netwolf/live/live_engine_runner.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace netwolf::exporters {

    // ================================================================
    // NetWolf v2 - Experiment Log
    //
    // Records every Live Monitor snapshot to CSV files, so experiments can
    // be measured and reported (detection time, false alarms, identification
    // accuracy) without relying on screenshots.
    //
    // One folder per experiment: <exe folder>\experiments\YYYY-MM-DD_HH-MM-SS\
    // While Live Monitor runs, the log is also started automatically in
    // <Telecommunications Information Reports>\Session_...\data.
    //
    //   devices.csv  one row per device per snapshot (top 5 and ALL
    //                destinations of the device)
    //   summary.csv  one row per snapshot (population, Evil Twin phase)
    //   events.csv   joins, departures, state changes, forwarding,
    //                collapse and alerts, with exact time
    //   aliases.csv  D1, D2, ... -> real IP / MAC / name (keep PRIVATE;
    //                publish only the other files, which use the aliases)
    // ================================================================

    // ------------------------------------------------------------
    // Device aliases (D1, D2, ...) shared by the experiment log and the
    // periodic reports, so "D3" means the same device in both. Reset when a
    // new Live Monitor session starts.
    // ------------------------------------------------------------
    class DeviceAliases
    {
    public:
        static DeviceAliases& instance()
        {
            static DeviceAliases aliases;
            return aliases;
        }

        std::string aliasFor(const std::string& ip)
        {
            std::lock_guard<std::mutex> lock(mutex_);

            auto found = aliases_.find(ip);

            if (found != aliases_.end())
                return found->second;

            const std::string alias = "D" + std::to_string(aliases_.size() + 1);
            aliases_[ip] = alias;
            return alias;
        }

        // ip -> alias
        std::map<std::string, std::string> all() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return aliases_;
        }

        void reset()
        {
            std::lock_guard<std::mutex> lock(mutex_);
            aliases_.clear();
        }

    private:
        DeviceAliases() = default;

        mutable std::mutex mutex_;
        std::map<std::string, std::string> aliases_;
    };


    class ExperimentLog
    {
    public:
        static ExperimentLog& instance()
        {
            static ExperimentLog log;
            return log;
        }

        // Creates <baseFolder>/experiments/<timestamp>/ and starts logging.
        bool start(const std::filesystem::path& baseFolder, std::string& message)
        {
            return startInFolder(
                baseFolder / "experiments" / fileStamp(std::chrono::system_clock::now()),
                message);
        }

        // Starts logging into exactly this folder (used by the periodic
        // reports: <session folder>/data).
        bool startInFolder(const std::filesystem::path& folder, std::string& message)
        {
            std::lock_guard<std::mutex> lock(mutex_);

            closeLocked();

            const auto now = std::chrono::system_clock::now();

            std::error_code error;
            std::filesystem::create_directories(folder, error);

            if (error)
            {
                message = "Could not create the experiment folder: " + error.message();
                return false;
            }

            devices_.open(folder / "devices.csv");
            summary_.open(folder / "summary.csv");
            events_.open(folder / "events.csv");
            aliasesFile_ = folder / "aliases.csv";

            if (!devices_ || !summary_ || !events_)
            {
                closeLocked();
                message = "Could not create the CSV files in " + folder.string();
                return false;
            }

            devices_
                << "time,elapsed_s,device,type,state,connections,destinations,traffic_bytes,"
                   "forwarding,forwarded_connections,systems_behind,estimated_people,top_destinations,all_destinations\n";

            summary_
                << "time,elapsed_s,active_devices,crowd_peak,evil_twin_phase,collapse_vanished,"
                   "alerts,normal,heavy,redflag,flows,packets_captured\n";

            events_ << "time,elapsed_s,event,details\n";

            folder_ = folder;
            startedAt_ = now;
            active_ = true;
            aliasInfo_.clear();
            previousState_.clear();
            previousForwarding_.clear();

            writeEventLocked(now, "log_started", "Experiment log started");

            message = "Experiment log started: " + folder.string();
            return true;
        }

        void stop()
        {
            std::lock_guard<std::mutex> lock(mutex_);

            if (active_)
                writeEventLocked(std::chrono::system_clock::now(), "log_stopped", "Experiment log stopped");

            closeLocked();
        }

        bool active() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return active_;
        }

        std::string folder() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return active_ ? folder_.string() : std::string();
        }

        std::filesystem::path folderPath() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return active_ ? folder_ : std::filesystem::path();
        }

        // Called once per Live Monitor snapshot (engine worker thread).
        void record(const netwolf::live::LiveRunResult& result)
        {
            std::lock_guard<std::mutex> lock(mutex_);

            if (!active_)
                return;

            const auto now = std::chrono::system_clock::now();
            const std::string time = timeText(now);
            const std::string elapsed = elapsedText(now);

            const auto& output = result.engineRun.output;

            std::map<std::string, const netwolf::live::LiveDeviceIdentity*> identities;

            for (const auto& identity : result.deviceIdentities)
                identities[identity.ip] = &identity;

            std::map<std::string, std::string> currentState;
            std::map<std::string, bool> currentForwarding;

            auto writeDevice = [&](const netwolf::core::DeviceReport& device, const char* state)
                {
                    const std::string alias = aliasForLocked(device.deviceIp);

                    const auto identityIt = identities.find(device.deviceIp);
                    const netwolf::live::LiveDeviceIdentity* identity =
                        identityIt != identities.end() ? identityIt->second : nullptr;

                    if (identity != nullptr)
                        rememberAliasInfoLocked(alias, device.deviceIp, *identity);

                    // Top destinations by number of connections.
                    std::vector<std::pair<size_t, std::string>> groups;

                    for (const auto& group : device.groups)
                        groups.emplace_back(group.subConnectionCount(), group.mainEntityName);

                    std::sort(groups.begin(), groups.end(),
                        [](const auto& a, const auto& b) { return a.first > b.first; });

                    std::string top;
                    std::string all;

                    for (size_t index = 0; index < groups.size(); ++index)
                    {
                        const std::string item =
                            groups[index].second + " (" + std::to_string(groups[index].first) + ")";

                        if (index < 5)
                            top += (index > 0 ? "; " : "") + item;

                        all += (index > 0 ? "; " : "") + item;
                    }

                    std::string behind;

                    if (identity != nullptr)
                    {
                        for (size_t index = 0; index < identity->platformsBehind.size(); ++index)
                            behind += (index > 0 ? "+" : "") + identity->platformsBehind[index];
                    }

                    const auto people = result.evilTwin.estimatedUsers.find(device.deviceIp);

                    std::ostringstream peopleText;
                    peopleText << std::fixed << std::setprecision(2)
                        << (people != result.evilTwin.estimatedUsers.end() ? people->second : 0.0);

                    devices_
                        << time << ',' << elapsed << ','
                        << alias << ','
                        << csv(identity != nullptr ? identity->deviceType : std::string()) << ','
                        << state << ','
                        << device.score.totalConnections << ','
                        << device.score.uniqueEntities << ','
                        << device.score.totalBytes << ','
                        << (identity != nullptr && identity->forwarding ? "yes" : "no") << ','
                        << (identity != nullptr ? identity->forwardedSyns : 0) << ','
                        << csv(behind) << ','
                        << peopleText.str() << ','
                        << csv(top) << ','
                        << csv(all) << '\n';

                    currentState[device.deviceIp] = state;
                    currentForwarding[device.deviceIp] = identity != nullptr && identity->forwarding;
                };

            for (const auto& device : output.normalDevices)
                writeDevice(device, "Normal");

            for (const auto& device : output.heavyDevices)
                writeDevice(device, "Heavy");

            for (const auto& device : output.redflagDevices)
                writeDevice(device, "Redflag");

            // ---- Events: joins, departures, state changes, forwarding ----
            for (const auto& [ip, state] : currentState)
            {
                const std::string alias = aliasForLocked(ip);
                const auto previous = previousState_.find(ip);

                if (previous == previousState_.end())
                {
                    const auto identity = identities.find(ip);

                    writeEventLocked(now, "device_joined",
                        alias + " (" + (identity != identities.end()
                            ? identity->second->deviceType : std::string("type unknown")) +
                        ") state " + state);
                }
                else if (previous->second != state)
                {
                    writeEventLocked(now, "state_changed",
                        alias + ": " + previous->second + " -> " + state);
                }

                const bool forwardingNow = currentForwarding[ip];
                const auto forwardingBefore = previousForwarding_.find(ip);

                if (forwardingNow &&
                    (forwardingBefore == previousForwarding_.end() || !forwardingBefore->second))
                {
                    writeEventLocked(now, "forwarding_detected",
                        alias + " forwards traffic of other devices");
                }
            }

            for (const auto& [ip, state] : previousState_)
            {
                if (currentState.count(ip) == 0)
                    writeEventLocked(now, "device_left", aliasForLocked(ip) + " (was " + state + ")");
            }

            // ---- Evil Twin algorithm events (with real IPs replaced) ----
            for (const auto& event : result.evilTwin.events)
                writeEventLocked(now, "evil_twin", anonymizeLocked(event));

            previousState_ = std::move(currentState);
            previousForwarding_ = std::move(currentForwarding);

            // ---- Summary ----
            summary_
                << time << ',' << elapsed << ','
                << result.evilTwin.activeDevices << ','
                << result.evilTwin.crowdPeak << ','
                << result.evilTwin.phase << ','
                << result.evilTwin.collapseVanished << ','
                << result.evilTwin.verdicts.size() << ','
                << output.normalDevices.size() << ','
                << output.heavyDevices.size() << ','
                << output.redflagDevices.size() << ','
                << result.packetFlows.size() << ','
                << result.packetsCaptured << '\n';

            devices_.flush();
            summary_.flush();
            events_.flush();
            writeAliasesLocked();
        }

    private:
        ExperimentLog() = default;

        struct AliasInfo
        {
            std::string ip;
            std::string mac;
            std::string name;
            std::string type;
        };

        void closeLocked()
        {
            if (active_)
                writeAliasesLocked();

            devices_.close();
            summary_.close();
            events_.close();
            active_ = false;
        }

        std::string aliasForLocked(const std::string& ip)
        {
            const std::string alias = DeviceAliases::instance().aliasFor(ip);
            aliasInfo_[alias].ip = ip;
            return alias;
        }

        void rememberAliasInfoLocked(const std::string& alias, const std::string& ip,
            const netwolf::live::LiveDeviceIdentity& identity)
        {
            AliasInfo& info = aliasInfo_[alias];
            info.ip = ip;

            if (!identity.mac.empty()) info.mac = identity.mac;
            if (!identity.hostName.empty()) info.name = identity.hostName;
            if (!identity.deviceType.empty()) info.type = identity.deviceType;
        }

        // Events from the engine mention IPs / names: publishable files use aliases.
        std::string anonymizeLocked(std::string text) const
        {
            // Longest first, so "192.168.137.10" is not replaced inside "192.168.137.100".
            std::vector<std::pair<std::string, std::string>> secrets;

            for (const auto& [alias, info] : aliasInfo_)
            {
                if (!info.name.empty()) secrets.emplace_back(info.name, alias);
                if (!info.ip.empty()) secrets.emplace_back(info.ip, alias);
            }

            std::sort(secrets.begin(), secrets.end(),
                [](const auto& a, const auto& b) { return a.first.size() > b.first.size(); });

            for (const auto& [secret, alias] : secrets)
            {
                size_t position = 0;

                while ((position = text.find(secret, position)) != std::string::npos)
                {
                    const size_t end = position + secret.size();

                    // Whole addresses only: "…137.1" must not match "…137.15".
                    const bool digitAfter = end < text.size() &&
                        std::isdigit(static_cast<unsigned char>(text[end])) != 0;

                    if (digitAfter)
                    {
                        position = end;
                        continue;
                    }

                    text.replace(position, secret.size(), alias);
                    position += alias.size();
                }
            }

            return text;
        }

        void writeAliasesLocked()
        {
            std::ofstream out(aliasesFile_, std::ios::trunc);

            if (!out)
                return;

            out << "alias,ip,mac,name,type\n";

            for (const auto& [alias, info] : aliasInfo_)
            {
                out << alias << ',' << csv(info.ip) << ',' << csv(info.mac) << ','
                    << csv(info.name) << ',' << csv(info.type) << '\n';
            }
        }

        void writeEventLocked(std::chrono::system_clock::time_point at,
            const std::string& event, const std::string& details)
        {
            events_ << timeText(at) << ',' << elapsedText(at) << ',' << event << ',' << csv(details) << '\n';
        }

        std::string elapsedText(std::chrono::system_clock::time_point at) const
        {
            std::ostringstream out;
            out << std::fixed << std::setprecision(1)
                << std::chrono::duration<double>(at - startedAt_).count();
            return out.str();
        }

        static std::tm localTime(std::chrono::system_clock::time_point at)
        {
            const std::time_t raw = std::chrono::system_clock::to_time_t(at);
            std::tm local{};
#if defined(_WIN32)
            localtime_s(&local, &raw);
#else
            localtime_r(&raw, &local);
#endif
            return local;
        }

        static std::string timeText(std::chrono::system_clock::time_point at)
        {
            const std::tm local = localTime(at);
            const auto milliseconds =
                std::chrono::duration_cast<std::chrono::milliseconds>(at.time_since_epoch()).count() % 1000;

            std::ostringstream out;
            out << std::put_time(&local, "%Y-%m-%d %H:%M:%S") << '.'
                << std::setw(3) << std::setfill('0') << milliseconds;
            return out.str();
        }

        static std::string fileStamp(std::chrono::system_clock::time_point at)
        {
            const std::tm local = localTime(at);

            std::ostringstream out;
            out << std::put_time(&local, "%Y-%m-%d_%H-%M-%S");
            return out.str();
        }

        static std::string csv(const std::string& value)
        {
            if (value.find_first_of(",\"\n\r") == std::string::npos)
                return value;

            std::string quoted = "\"";

            for (const char c : value)
            {
                if (c == '"')
                    quoted += '"';

                quoted += c;
            }

            return quoted + "\"";
        }

    private:
        mutable std::mutex mutex_;
        bool active_ = false;

        std::filesystem::path folder_;
        std::filesystem::path aliasesFile_;
        std::chrono::system_clock::time_point startedAt_{};

        std::ofstream devices_;
        std::ofstream summary_;
        std::ofstream events_;

        std::map<std::string, AliasInfo> aliasInfo_;      // alias -> real identity
        std::map<std::string, std::string> previousState_;
        std::map<std::string, bool> previousForwarding_;
    };

} // namespace netwolf::exporters
