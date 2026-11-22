#pragma once

#include <netwolf/exporters/experiment_log.hpp>
#include <netwolf/live/live_engine_runner.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
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
    // NetWolf v2 - Telecommunications Information Reports
    //
    // While Live Monitor runs, the tool writes HTML reports by itself, so
    // an experiment can run unattended:
    //
    //   <exe folder>\Telecommunications Information Reports\
    //       Session_YYYY-MM-DD_HH-MM-SS\
    //           Report_01_<date>_<from>_to_<to>.html   every 15 minutes
    //           ALERT_<date>_<time>_<alias>.html        at the moment of an alert
    //           Final_Session_Report_<...>.html         when monitoring stops
    //           data\                                   experiment log CSVs
    //
    // Each report lists the devices (name, system, connections, all
    // destinations, traffic, state, forwarding evidence), the events with
    // exact times and the state of the Evil Twin detector.
    //
    // Identifier masking (on by default): device IPs keep only the network
    // part (192.168.137.xxx) and MACs only the manufacturer part, and the
    // devices are referred to as D1, D2, ... (same aliases as the CSV log).
    // ================================================================

    class TelecomReports
    {
    public:
        static TelecomReports& instance()
        {
            static TelecomReports reports;
            return reports;
        }

        static constexpr const char* kRootFolderName = "Telecommunications Information Reports";

        // Root folder of all sessions (for "Open Reports Folder").
        static std::filesystem::path rootFolder(const std::filesystem::path& baseFolder)
        {
            return baseFolder / kRootFolderName;
        }

        // Starts a monitoring session. Also starts the experiment log in
        // <session>\data, unless the user already runs one.
        bool begin(const std::filesystem::path& baseFolder, std::string& message)
        {
            std::lock_guard<std::mutex> lock(mutex_);

            endLocked();

            const auto now = std::chrono::system_clock::now();
            const std::filesystem::path folder =
                rootFolder(baseFolder) / ("Session_" + fileStamp(now));

            std::error_code error;
            std::filesystem::create_directories(folder, error);

            if (error)
            {
                message = "Could not create the reports folder: " + error.message();
                return false;
            }

            DeviceAliases::instance().reset();

            folder_ = folder;
            sessionStart_ = now;
            reportNumber_ = 0;
            reportsWritten_ = 0;
            lastReport_.clear();
            session_ = Period{};
            session_.from = now;
            period_ = Period{};
            period_.from = now;
            periodEnd_ = now + std::chrono::seconds(intervalSeconds_);
            flowBytes_.clear();
            previousState_.clear();
            previousForwarding_.clear();
            alerted_.clear();
            lastPackets_ = 0;
            haveLastPackets_ = false;
            active_ = true;

            addEventLocked(now, "monitoring_started", "Live Monitor started; reports every " +
                std::to_string(intervalSeconds_ / 60) + " minutes");

            // CSV data for the evaluation, in the same session folder.
            startedLog_ = false;

            if (!ExperimentLog::instance().active())
            {
                std::string logMessage;
                startedLog_ = ExperimentLog::instance().startInFolder(folder / "data", logMessage);
            }

            message = "Reports every " + std::to_string(intervalSeconds_ / 60) +
                " minutes: " + folder.string();
            return true;
        }

        // Writes the final report and closes the session.
        void end()
        {
            std::lock_guard<std::mutex> lock(mutex_);
            endLocked();
        }

        bool active() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return active_;
        }

        std::string folder() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return folder_.string();
        }

        size_t reportsWritten() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return reportsWritten_;
        }

        std::string lastReport() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return lastReport_;
        }

        void setMasking(bool enabled)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            masking_ = enabled;
        }

        bool masking() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return masking_;
        }

        // Report interval (15 minutes; shorter values are for tests).
        void setIntervalSeconds(int seconds)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            intervalSeconds_ = std::max(1, seconds);
        }

        // Called once per Live Monitor snapshot (engine worker thread).
        void record(const netwolf::live::LiveRunResult& result)
        {
            std::lock_guard<std::mutex> lock(mutex_);

            if (!active_)
                return;

            const auto now = std::chrono::system_clock::now();

            // Close finished 15-minute periods first.
            if (now >= periodEnd_)
            {
                period_.to = periodEnd_;
                writeReportLocked(ReportKind::Periodic, period_, std::string());

                period_ = Period{};
                period_.from = periodEnd_;

                while (periodEnd_ <= now)
                    periodEnd_ += std::chrono::seconds(intervalSeconds_);

                if (period_.from + std::chrono::seconds(intervalSeconds_) < periodEnd_)
                    period_.from = periodEnd_ - std::chrono::seconds(intervalSeconds_);
            }

            const Snapshot snapshot = readSnapshotLocked(result);

            updateLocked(period_, result, snapshot, now);
            updateLocked(session_, result, snapshot, now);

            detectEventsLocked(result, snapshot, now);

            // An alert is written at once, not at the end of the period.
            for (const auto& [ip, evidence] : result.evilTwin.verdicts)
            {
                if (alerted_.insert(ip).second)
                {
                    Period alertView = session_;
                    alertView.to = now;
                    writeReportLocked(ReportKind::Alert, alertView, ip);
                }
            }

            // A device that is no longer flagged can raise a new alert later.
            for (auto it = alerted_.begin(); it != alerted_.end();)
            {
                if (result.evilTwin.verdicts.count(*it) == 0)
                    it = alerted_.erase(it);
                else
                    ++it;
            }
        }

    private:
        TelecomReports() = default;

        using TimePoint = std::chrono::system_clock::time_point;

        enum class ReportKind { Periodic, Alert, Final };

        struct DeviceStats
        {
            std::string ip;
            std::string alias;
            std::string name;
            std::string nameSource;
            std::string type;
            std::string mac;

            TimePoint firstSeen{};
            TimePoint lastSeen{};
            size_t snapshots = 0;
            bool online = false;

            std::string currentState;
            int worstState = 0;            // 0 Normal, 1 Heavy, 2 Redflag

            size_t maxConnections = 0;
            size_t maxDestinations = 0;
            uint64_t trafficBytes = 0;

            size_t forwardedSyns = 0;
            std::set<std::string> platformsBehind;
            double maxPeople = 0.0;

            // destination -> largest number of simultaneous connections
            std::map<std::string, size_t> destinations;
        };

        struct Event
        {
            TimePoint at{};
            std::string kind;
            std::string details;            // raw; masked when rendered
        };

        struct Period
        {
            TimePoint from{};
            TimePoint to{};

            std::map<std::string, DeviceStats> devices;   // ip -> stats
            std::vector<Event> events;

            size_t snapshots = 0;
            size_t peakActive = 0;
            size_t crowdPeak = 0;
            size_t collapses = 0;
            uint64_t packets = 0;

            double baselineDestinations = 0.0;
            double baselineConnections = 0.0;
            std::string phase;

            std::map<std::string, std::string> verdicts;  // ip -> evidence
        };

        struct DeviceView
        {
            const netwolf::core::DeviceReport* report = nullptr;
            const char* state = "Normal";
            int rank = 0;
            const netwolf::live::LiveDeviceIdentity* identity = nullptr;
        };

        struct Snapshot
        {
            std::map<std::string, DeviceView> devices;    // ip -> view
            std::map<std::string, uint64_t> trafficDelta; // ip -> bytes since last snapshot
            uint64_t packetsDelta = 0;
        };

        // ------------------------------------------------------------ snapshot

        Snapshot readSnapshotLocked(const netwolf::live::LiveRunResult& result)
        {
            Snapshot snapshot;

            std::map<std::string, const netwolf::live::LiveDeviceIdentity*> identities;

            for (const auto& identity : result.deviceIdentities)
                identities[identity.ip] = &identity;

            auto add = [&](const std::vector<netwolf::core::DeviceReport>& list, const char* state, int rank)
                {
                    for (const auto& device : list)
                    {
                        DeviceView& view = snapshot.devices[device.deviceIp];
                        view.report = &device;
                        view.state = state;
                        view.rank = rank;

                        const auto found = identities.find(device.deviceIp);
                        view.identity = found != identities.end() ? found->second : nullptr;
                    }
                };

            const auto& output = result.engineRun.output;
            add(output.normalDevices, "Normal", 0);
            add(output.heavyDevices, "Heavy", 1);
            add(output.redflagDevices, "Redflag", 2);

            // Traffic: growth of every flow's byte counters since the last snapshot.
            std::map<std::string, uint64_t> seen;

            for (const auto& flow : result.packetFlows)
            {
                const std::string key =
                    flow.clientIp + ':' + std::to_string(flow.clientPort) + '>' +
                    flow.serverIp + ':' + std::to_string(flow.serverPort) + '/' +
                    std::to_string(static_cast<int>(flow.protocol));

                const uint64_t total = flow.bytesUp + flow.bytesDown;
                const auto previous = flowBytes_.find(key);
                const uint64_t before = previous != flowBytes_.end() ? previous->second : 0;

                snapshot.trafficDelta[flow.clientIp] += total >= before ? total - before : total;
                seen[key] = total;
            }

            flowBytes_ = std::move(seen);

            if (haveLastPackets_)
            {
                snapshot.packetsDelta = result.packetsCaptured >= lastPackets_
                    ? result.packetsCaptured - lastPackets_
                    : result.packetsCaptured;   // capture restarted
            }

            lastPackets_ = result.packetsCaptured;
            haveLastPackets_ = true;

            return snapshot;
        }

        void updateLocked(Period& period, const netwolf::live::LiveRunResult& result,
            const Snapshot& snapshot, TimePoint now)
        {
            for (auto& [ip, stats] : period.devices)
                stats.online = false;

            for (const auto& [ip, view] : snapshot.devices)
            {
                DeviceStats& stats = period.devices[ip];

                if (stats.snapshots == 0)
                {
                    stats.ip = ip;
                    stats.alias = DeviceAliases::instance().aliasFor(ip);
                    stats.firstSeen = now;
                }

                stats.lastSeen = now;
                ++stats.snapshots;
                stats.online = true;
                stats.currentState = view.state;
                stats.worstState = std::max(stats.worstState, view.rank);

                const auto& device = *view.report;
                stats.maxConnections = std::max(stats.maxConnections, device.score.totalConnections);
                stats.maxDestinations = std::max(stats.maxDestinations, device.score.uniqueEntities);

                for (const auto& group : device.groups)
                {
                    if (group.mainEntityName.empty())
                        continue;

                    size_t& count = stats.destinations[group.mainEntityName];
                    count = std::max(count, group.subConnectionCount());
                }

                if (view.identity != nullptr)
                {
                    const auto& identity = *view.identity;

                    if (!identity.hostName.empty()) stats.name = identity.hostName;
                    if (!identity.nameSource.empty()) stats.nameSource = identity.nameSource;
                    if (!identity.deviceType.empty()) stats.type = identity.deviceType;
                    if (!identity.mac.empty()) stats.mac = identity.mac;

                    stats.forwardedSyns = std::max(stats.forwardedSyns, identity.forwardedSyns);

                    for (const auto& platform : identity.platformsBehind)
                        stats.platformsBehind.insert(platform);
                }

                const auto people = result.evilTwin.estimatedUsers.find(ip);

                if (people != result.evilTwin.estimatedUsers.end())
                    stats.maxPeople = std::max(stats.maxPeople, people->second);

                const auto traffic = snapshot.trafficDelta.find(ip);

                if (traffic != snapshot.trafficDelta.end())
                    stats.trafficBytes += traffic->second;
            }

            const auto& evilTwin = result.evilTwin;

            ++period.snapshots;
            period.peakActive = std::max(period.peakActive, evilTwin.activeDevices);
            period.crowdPeak = std::max(period.crowdPeak, evilTwin.crowdPeak);
            period.packets += snapshot.packetsDelta;
            period.phase = evilTwin.phase;

            if (evilTwin.baselineDestinations > 0.0)
                period.baselineDestinations = evilTwin.baselineDestinations;

            if (evilTwin.baselineConnections > 0.0)
                period.baselineConnections = evilTwin.baselineConnections;

            for (const auto& [ip, evidence] : evilTwin.verdicts)
                period.verdicts[ip] = evidence;
        }

        // ------------------------------------------------------------ events

        void addEventLocked(TimePoint at, const std::string& kind, const std::string& details)
        {
            const Event event{ at, kind, details };

            for (Period* period : { &period_, &session_ })
            {
                if (period->events.size() < kMaxEvents)
                    period->events.push_back(event);
            }

            if (kind == "collapse")
            {
                ++period_.collapses;
                ++session_.collapses;
            }
        }

        void detectEventsLocked(const netwolf::live::LiveRunResult& result,
            const Snapshot& snapshot, TimePoint now)
        {
            std::map<std::string, std::string> currentState;
            std::map<std::string, bool> currentForwarding;

            for (const auto& [ip, view] : snapshot.devices)
            {
                const std::string alias = DeviceAliases::instance().aliasFor(ip);
                const auto previous = previousState_.find(ip);

                if (previous == previousState_.end())
                {
                    std::string who = alias;

                    if (view.identity != nullptr)
                    {
                        if (!view.identity->hostName.empty())
                            who += " " + view.identity->hostName;

                        if (!view.identity->deviceType.empty())
                            who += " (" + view.identity->deviceType + ")";
                    }

                    addEventLocked(now, "device_joined", who + " is active, state " + view.state);
                }
                else if (previous->second != view.state)
                {
                    addEventLocked(now, "state_changed", alias + ": " + previous->second + " -> " + view.state);
                }

                const bool forwarding = view.identity != nullptr && view.identity->forwarding;
                const auto before = previousForwarding_.find(ip);

                if (forwarding && (before == previousForwarding_.end() || !before->second))
                {
                    addEventLocked(now, "forwarding_detected", alias +
                        " forwards traffic of other devices (" +
                        std::to_string(view.identity->forwardedSyns) + " forwarded connection starts)");
                }

                currentState[ip] = view.state;
                currentForwarding[ip] = forwarding;
            }

            for (const auto& [ip, state] : previousState_)
            {
                if (currentState.count(ip) == 0)
                {
                    addEventLocked(now, "device_left",
                        DeviceAliases::instance().aliasFor(ip) + " is no longer active (was " + state + ")");
                }
            }

            for (const auto& text : result.evilTwin.events)
            {
                const auto startsWith = [&text](const char* prefix)
                    { return text.rfind(prefix, 0) == 0; };

                const std::string kind =
                    startsWith("ALERT:") ? "ALERT"
                    : startsWith("COLLAPSE:") ? "collapse"
                    : startsWith("Alert cleared") ? "alert_cleared"
                    : startsWith("Candidate") ? "candidate"
                    : "evil_twin";

                addEventLocked(now, kind, text);
            }

            previousState_ = std::move(currentState);
            previousForwarding_ = std::move(currentForwarding);
        }

        // ------------------------------------------------------------ session end

        void endLocked()
        {
            if (!active_)
                return;

            const auto now = std::chrono::system_clock::now();

            addEventLocked(now, "monitoring_stopped", "Live Monitor stopped");

            // The unfinished period still gets its report, then the summary.
            if (period_.snapshots > 0)
            {
                period_.to = now;
                writeReportLocked(ReportKind::Periodic, period_, std::string());
            }

            session_.to = now;
            writeReportLocked(ReportKind::Final, session_, std::string());

            // Stop the log only if it is still the one this session started
            // (the user may have started another one from the menu).
            if (startedLog_ && ExperimentLog::instance().folderPath() == folder_ / "data")
                ExperimentLog::instance().stop();

            startedLog_ = false;
            active_ = false;
        }

        // ------------------------------------------------------------ writing

        void writeReportLocked(ReportKind kind, const Period& period, const std::string& alertIp)
        {
            std::string fileName;

            const std::string day = dateText(period.from);
            const std::string from = clockText(period.from, false);
            const std::string to = clockText(period.to, false);

            if (kind == ReportKind::Periodic)
            {
                ++reportNumber_;

                std::ostringstream number;
                number << std::setw(2) << std::setfill('0') << reportNumber_;

                fileName = "Report_" + number.str() + "_" + day + "_" + from + "_to_" + to + ".html";
            }
            else if (kind == ReportKind::Alert)
            {
                fileName = "ALERT_" + dateText(period.to) + "_" + clockText(period.to, true) + "_" +
                    DeviceAliases::instance().aliasFor(alertIp) + ".html";
            }
            else
            {
                fileName = "Final_Session_Report_" + day + "_" + from + "_to_" + to + ".html";
            }

            std::ofstream out(folder_ / fileName, std::ios::binary | std::ios::trunc);

            if (!out)
                return;

            out << renderLocked(kind, period, alertIp);
            out.close();

            ++reportsWritten_;
            lastReport_ = fileName;
        }

        std::string renderLocked(ReportKind kind, const Period& period, const std::string& alertIp) const
        {
            std::ostringstream html;

            const std::string title =
                kind == ReportKind::Periodic ? "Periodic report #" + std::to_string(reportNumber_) +
                " (" + std::to_string(intervalSeconds_ / 60) + " minutes)"
                : kind == ReportKind::Alert ? "EVIL TWIN ALERT"
                : "Final session report";

            html << "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
                 << "<title>NetWolf v2 - " << escape(title) << "</title>"
                 << "<style>"
                 << "body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1d2433;background:#fff}"
                 << "h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:26px 0 8px;border-bottom:2px solid #e3e7ef;padding-bottom:4px}"
                 << ".sub{color:#5a6478;margin-bottom:14px}"
                 << "table{border-collapse:collapse;width:100%;font-size:13px}"
                 << "th,td{border:1px solid #d5dbe6;padding:5px 7px;text-align:left;vertical-align:top}"
                 << "th{background:#eef1f6}"
                 << ".meta td:first-child{width:220px;color:#5a6478}"
                 << ".cards{display:flex;flex-wrap:wrap;gap:10px}"
                 << ".card{border:1px solid #d5dbe6;border-radius:6px;padding:8px 12px;min-width:120px}"
                 << ".card b{display:block;font-size:20px}.card span{color:#5a6478;font-size:12px}"
                 << ".Normal{background:#e3f4e8;color:#17663a}.Heavy{background:#fff1d6;color:#8a5a00}"
                 << ".Redflag{background:#fde2e1;color:#a01b16;font-weight:bold}"
                 << ".badge{padding:1px 7px;border-radius:9px;font-size:12px;white-space:nowrap}"
                 << ".alert{border:2px solid #c62828;background:#fff4f3;padding:10px 14px;border-radius:6px;margin:12px 0}"
                 << ".ALERTrow td{background:#fff4f3;font-weight:bold}"
                 << ".muted{color:#5a6478;font-size:12px}"
                 << "</style></head><body>\n";

            html << "<h1>NetWolf v2 &mdash; Telecommunications Information Report</h1>\n"
                 << "<div class=\"sub\">" << escape(title) << "</div>\n";

            // ---- Report information ----
            html << "<table class=\"meta\">"
                 << row("Session started", fullTime(sessionStart_))
                 << row(kind == ReportKind::Alert ? "Covers" : "Period",
                     fullTime(period.from) + "  &rarr;  " + fullTime(period.to), true)
                 << row("Duration", durationText(period.to - period.from))
                 << row("Report generated", fullTime(std::chrono::system_clock::now()))
                 << row("Snapshots analysed", std::to_string(period.snapshots) + " (one per second)")
                 << row("Identifier masking", masking_
                     ? "ON (device IPs show only the network part, MACs only the manufacturer part)"
                     : "OFF (full identifiers: keep this report private)")
                 << "</table>\n";

            // ---- Alert box ----
            if (!period.verdicts.empty())
            {
                for (const auto& [ip, evidence] : period.verdicts)
                {
                    if (kind == ReportKind::Alert && ip != alertIp)
                        continue;

                    const auto stats = period.devices.find(ip);

                    html << "<div class=\"alert\"><b>Evil Twin alert: "
                         << escape(deviceLabel(ip, stats != period.devices.end() ? &stats->second : nullptr))
                         << "</b><br>" << escape(maskText(evidence)) << "</div>\n";
                }
            }

            // ---- Summary ----
            uint64_t traffic = 0;
            size_t redflag = 0;
            size_t heavy = 0;

            for (const auto& [ip, stats] : period.devices)
            {
                traffic += stats.trafficBytes;
                redflag += stats.worstState == 2 ? 1 : 0;
                heavy += stats.worstState == 1 ? 1 : 0;
            }

            size_t alerts = 0;

            for (const auto& event : period.events)
                alerts += event.kind == "ALERT" ? 1 : 0;

            html << "<h2>Summary</h2><div class=\"cards\">"
                 << card(std::to_string(period.devices.size()), "devices seen")
                 << card(std::to_string(period.peakActive), "peak active devices")
                 << card(std::to_string(period.crowdPeak), "crowd peak (Evil Twin)")
                 << card(std::to_string(heavy), "Heavy devices")
                 << card(std::to_string(redflag), "Redflag devices")
                 << card(std::to_string(period.collapses), "collapses")
                 << card(std::to_string(alerts), "alerts")
                 << card(bytesText(traffic), "traffic")
                 << card(std::to_string(period.packets), "packets captured")
                 << card(escape(period.phase.empty() ? "-" : period.phase), "detector phase at end")
                 << "</div>\n";

            // ---- Devices ----
            html << "<h2>Devices</h2>";

            if (period.devices.empty())
            {
                html << "<p class=\"muted\">No client devices were active in this period.</p>\n";
            }
            else
            {
                html << "<table><tr><th>Device</th><th>Name</th><th>System</th><th>IP</th><th>MAC</th>"
                     << "<th>First seen</th><th>Last seen</th><th>State (worst / now)</th>"
                     << "<th>Max connections</th><th>Max destinations</th><th>Traffic</th>"
                     << "<th>Forwarded connections</th><th>Systems behind</th><th>Est. people</th></tr>\n";

                for (const DeviceStats* stats : sortedDevices(period))
                {
                    const std::string worst = stateName(stats->worstState);
                    const std::string now = stats->online ? stats->currentState : std::string("offline");

                    std::string behind;

                    for (const auto& platform : stats->platformsBehind)
                        behind += (behind.empty() ? "" : ", ") + platform;

                    std::ostringstream people;
                    people << std::fixed << std::setprecision(1) << stats->maxPeople;

                    html << "<tr><td><b>" << escape(stats->alias) << "</b></td>"
                         << "<td>" << escape(stats->name.empty() ? "-" : stats->name)
                         << (stats->nameSource.empty() ? "" : "<br><span class=\"muted\">" + escape(stats->nameSource) + "</span>")
                         << "</td><td>" << escape(stats->type.empty() ? "unknown" : stats->type) << "</td>"
                         << "<td>" << escape(masking_ ? maskIp(stats->ip) : stats->ip) << "</td>"
                         << "<td>" << escape(stats->mac.empty() ? "-" : (masking_ ? maskMac(stats->mac) : stats->mac)) << "</td>"
                         << "<td>" << clockText(stats->firstSeen, true, ':') << "</td>"
                         << "<td>" << clockText(stats->lastSeen, true, ':') << "</td>"
                         << "<td><span class=\"badge " << worst << "\">" << worst << "</span> / " << escape(now) << "</td>"
                         << "<td>" << stats->maxConnections << "</td>"
                         << "<td>" << stats->maxDestinations << "</td>"
                         << "<td>" << bytesText(stats->trafficBytes) << "</td>"
                         << "<td>" << stats->forwardedSyns << "</td>"
                         << "<td>" << escape(behind.empty() ? "-" : behind) << "</td>"
                         << "<td>" << people.str() << "</td></tr>\n";
                }

                html << "</table>\n";

                // ---- Destinations ----
                html << "<h2>Destinations of each device</h2>"
                     << "<p class=\"muted\">Named automatically from TLS SNI, DNS answers or the IP owner (ASN). "
                     << "The number is the largest count of simultaneous connections to that destination.</p>\n"
                     << "<table><tr><th style=\"width:170px\">Device</th><th style=\"width:90px\">Destinations</th><th>List</th></tr>\n";

                for (const DeviceStats* stats : sortedDevices(period))
                {
                    std::vector<std::pair<size_t, std::string>> list;

                    for (const auto& [name, count] : stats->destinations)
                        list.emplace_back(count, name);

                    std::sort(list.begin(), list.end(),
                        [](const auto& a, const auto& b) { return a.first != b.first ? a.first > b.first : a.second < b.second; });

                    std::string text;

                    for (const auto& [count, name] : list)
                        text += (text.empty() ? "" : ", ") + escape(maskText(name)) + " (" + std::to_string(count) + ")";

                    html << "<tr><td><b>" << escape(stats->alias) << "</b> " << escape(stats->name) << "</td>"
                         << "<td>" << list.size() << "</td><td>" << (text.empty() ? "-" : text) << "</td></tr>\n";
                }

                html << "</table>\n";
            }

            // ---- Events ----
            html << "<h2>Events</h2>";

            if (period.events.empty())
            {
                html << "<p class=\"muted\">No events in this period.</p>\n";
            }
            else
            {
                html << "<table><tr><th style=\"width:150px\">Time</th><th style=\"width:150px\">Event</th><th>Details</th></tr>\n";

                for (const auto& event : period.events)
                {
                    html << "<tr" << (event.kind == "ALERT" ? " class=\"ALERTrow\"" : "") << ">"
                         << "<td>" << dateText(event.at) << " " << clockText(event.at, true, ':') << "</td>"
                         << "<td>" << escape(event.kind) << "</td>"
                         << "<td>" << escape(maskText(event.details)) << "</td></tr>\n";
                }

                if (period.events.size() >= kMaxEvents)
                    html << "<tr><td colspan=\"3\" class=\"muted\">Event list truncated; see data\\events.csv.</td></tr>\n";

                html << "</table>\n";
            }

            // ---- Detector ----
            const netwolf::live::LiveEvilTwinConfig settings{};

            std::ostringstream baseline;
            baseline << std::fixed << std::setprecision(1)
                     << period.baselineDestinations << " destinations / "
                     << period.baselineConnections << " connections";

            html << "<h2>Evil Twin detector</h2><table class=\"meta\">"
                 << row("Per-person baseline (median)", period.baselineDestinations > 0.0 ? baseline.str() : std::string("not learned yet (needs a crowd)"))
                 << row("Minimum crowd", std::to_string(settings.minimumCrowdDevices) + " devices")
                 << row("Collapse", "the crowd vanishes within " + std::to_string(settings.collapseWindowSeconds) +
                     " s; at most one device or " + percentText(1.0 - settings.collapseFraction) + " of the crowd remains")
                 << row("Takeover (A): aggregation", "one device carries max(2, " + percentText(settings.aggregationFraction) +
                     " of the vanished people) within " + std::to_string(settings.aggregationWindowSeconds) +
                     " s, confirmed by forwarding (TTL), several systems behind it, or destination overlap &ge; " +
                     percentText(settings.destinationOverlapFraction), true)
                 << row("Takeover (B): following", "one device forwards traffic and " + percentText(settings.followFraction) +
                     " of the vanished devices (at least one) are found behind it: their operating system or their own destinations appear on it")
                 << "</table>\n";

            html << "<p class=\"muted\" style=\"margin-top:24px\">Generated automatically by NetWolf v2. "
                 << "The tool reads packet headers, DNS answers, TLS SNI and DHCP options only; it does not decrypt or store content. "
                 << "Devices are referred to as D1, D2, ... (the same aliases as in data\\devices.csv).</p>\n"
                 << "</body></html>\n";

            return html.str();
        }

        // ------------------------------------------------------------ helpers

        std::vector<const DeviceStats*> sortedDevices(const Period& period) const
        {
            std::vector<const DeviceStats*> devices;

            for (const auto& [ip, stats] : period.devices)
                devices.push_back(&stats);

            std::sort(devices.begin(), devices.end(),
                [](const DeviceStats* a, const DeviceStats* b)
                {
                    const auto number = [](const std::string& alias)
                        { return alias.size() > 1 ? std::atoi(alias.c_str() + 1) : 0; };
                    return number(a->alias) < number(b->alias);
                });

            return devices;
        }

        std::string deviceLabel(const std::string& ip, const DeviceStats* stats) const
        {
            std::string label = DeviceAliases::instance().aliasFor(ip);

            if (stats != nullptr && !stats->name.empty())
                label += " " + stats->name;

            if (stats != nullptr && !stats->type.empty())
                label += " (" + stats->type + ")";

            if (!masking_)
                label += " " + ip;

            return label;
        }

        // Masked text: known device IPs become their alias; any other private
        // IPv4 address keeps only its network part.
        std::string maskText(std::string text) const
        {
            if (!masking_)
                return text;

            std::vector<std::pair<std::string, std::string>> known;

            for (const auto& [ip, alias] : DeviceAliases::instance().all())
                known.emplace_back(ip, alias);

            std::sort(known.begin(), known.end(),
                [](const auto& a, const auto& b) { return a.first.size() > b.first.size(); });

            for (const auto& [ip, alias] : known)
            {
                size_t position = 0;

                while ((position = text.find(ip, position)) != std::string::npos)
                {
                    const size_t end = position + ip.size();

                    if (!boundary(text, position, end))
                    {
                        position = end;
                        continue;
                    }

                    text.replace(position, ip.size(), alias);
                    position += alias.size();
                }
            }

            // Remaining private addresses.
            std::string result;
            size_t index = 0;

            while (index < text.size())
            {
                size_t length = 0;
                int octets[4]{};

                if (std::isdigit(static_cast<unsigned char>(text[index])) &&
                    (index == 0 || !isAddressChar(text[index - 1])) &&
                    parseIpv4(text, index, length, octets) &&
                    (index + length >= text.size() || !isAddressChar(text[index + length])) &&
                    isPrivate(octets))
                {
                    result += std::to_string(octets[0]) + '.' + std::to_string(octets[1]) + '.' +
                        std::to_string(octets[2]) + ".xxx";
                    index += length;
                    continue;
                }

                result += text[index];
                ++index;
            }

            return result;
        }

        static bool isAddressChar(char c)
        {
            return std::isdigit(static_cast<unsigned char>(c)) || c == '.';
        }

        static bool boundary(const std::string& text, size_t start, size_t end)
        {
            const bool before = start > 0 && std::isdigit(static_cast<unsigned char>(text[start - 1]));
            const bool after = end < text.size() && std::isdigit(static_cast<unsigned char>(text[end]));
            return !before && !after;
        }

        static bool parseIpv4(const std::string& text, size_t start, size_t& length, int (&octets)[4])
        {
            size_t index = start;

            for (int part = 0; part < 4; ++part)
            {
                if (part > 0)
                {
                    if (index >= text.size() || text[index] != '.')
                        return false;
                    ++index;
                }

                int value = 0;
                size_t digits = 0;

                while (index < text.size() && std::isdigit(static_cast<unsigned char>(text[index])) && digits < 3)
                {
                    value = value * 10 + (text[index] - '0');
                    ++index;
                    ++digits;
                }

                if (digits == 0 || value > 255)
                    return false;

                octets[part] = value;
            }

            length = index - start;
            return true;
        }

        static bool isPrivate(const int (&o)[4])
        {
            return o[0] == 10 ||
                (o[0] == 172 && o[1] >= 16 && o[1] <= 31) ||
                (o[0] == 192 && o[1] == 168) ||
                (o[0] == 169 && o[1] == 254);
        }

        static std::string maskIp(const std::string& ip)
        {
            const size_t dot = ip.rfind('.');
            return dot == std::string::npos ? std::string("xxx") : ip.substr(0, dot) + ".xxx";
        }

        // Keeps the manufacturer part (first three bytes) of a MAC address.
        static std::string maskMac(const std::string& mac)
        {
            std::string result;
            int separators = 0;

            for (const char c : mac)
            {
                if (c == ':' || c == '-')
                {
                    ++separators;
                    result += c;
                    continue;
                }

                result += separators >= 3 ? 'x' : c;
            }

            return result;
        }

        static std::string stateName(int rank)
        {
            return rank >= 2 ? "Redflag" : rank == 1 ? "Heavy" : "Normal";
        }

        static std::string escape(const std::string& text)
        {
            std::string out;
            out.reserve(text.size());

            for (const char c : text)
            {
                switch (c)
                {
                case '&': out += "&amp;"; break;
                case '<': out += "&lt;"; break;
                case '>': out += "&gt;"; break;
                case '"': out += "&quot;"; break;
                default: out += c; break;
                }
            }

            return out;
        }

        static std::string row(const std::string& name, const std::string& value, bool valueIsHtml = false)
        {
            return "<tr><td>" + escape(name) + "</td><td>" + (valueIsHtml ? value : escape(value)) + "</td></tr>";
        }

        static std::string card(const std::string& value, const std::string& label)
        {
            return "<div class=\"card\"><b>" + value + "</b><span>" + escape(label) + "</span></div>";
        }

        static std::string percentText(double fraction)
        {
            return std::to_string(static_cast<int>(fraction * 100.0 + 0.5)) + "%";
        }

        static std::string bytesText(uint64_t bytes)
        {
            std::ostringstream out;
            out << std::fixed << std::setprecision(bytes >= 1024ull * 1024ull * 1024ull ? 2 : 1);

            if (bytes >= 1024ull * 1024ull * 1024ull)
                out << bytes / (1024.0 * 1024.0 * 1024.0) << " GB";
            else if (bytes >= 1024ull * 1024ull)
                out << bytes / (1024.0 * 1024.0) << " MB";
            else if (bytes >= 1024ull)
                out << bytes / 1024.0 << " KB";
            else
                return std::to_string(bytes) + " B";

            return out.str();
        }

        static std::string durationText(std::chrono::system_clock::duration duration)
        {
            const long long seconds = std::max<long long>(0,
                std::chrono::duration_cast<std::chrono::seconds>(duration).count());

            std::ostringstream out;
            out << seconds / 3600 << " h " << (seconds / 60) % 60 << " min " << seconds % 60 << " s";
            return out.str();
        }

        static std::tm localTime(TimePoint at)
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

        static std::string format(TimePoint at, const char* pattern)
        {
            const std::tm local = localTime(at);
            std::ostringstream out;
            out << std::put_time(&local, pattern);
            return out.str();
        }

        static std::string dateText(TimePoint at) { return format(at, "%Y-%m-%d"); }

        // HH-MM(-SS) for file names, HH:MM(:SS) for display.
        static std::string clockText(TimePoint at, bool seconds, char separator = '-')
        {
            const std::string pattern = seconds
                ? std::string("%H") + separator + "%M" + separator + "%S"
                : std::string("%H") + separator + "%M";
            return format(at, pattern.c_str());
        }

        static std::string fullTime(TimePoint at) { return format(at, "%Y-%m-%d %H:%M:%S"); }

        static std::string fileStamp(TimePoint at) { return format(at, "%Y-%m-%d_%H-%M-%S"); }

    private:
        static constexpr size_t kMaxEvents = 5000;

        mutable std::mutex mutex_;
        bool active_ = false;
        bool masking_ = true;
        bool startedLog_ = false;
        int intervalSeconds_ = 15 * 60;

        std::filesystem::path folder_;
        TimePoint sessionStart_{};
        TimePoint periodEnd_{};

        Period period_;
        Period session_;

        size_t reportNumber_ = 0;
        size_t reportsWritten_ = 0;
        std::string lastReport_;

        std::map<std::string, uint64_t> flowBytes_;          // flow -> bytes at last snapshot
        std::map<std::string, std::string> previousState_;
        std::map<std::string, bool> previousForwarding_;
        std::set<std::string> alerted_;

        uint64_t lastPackets_ = 0;
        bool haveLastPackets_ = false;
    };

} // namespace netwolf::exporters
