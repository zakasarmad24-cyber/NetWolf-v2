#pragma once

#include <netwolf/core/engine.hpp>
#include <netwolf/live/live_engine_runner.hpp>

#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace netwolf::app {

    // ================================================================
    // NetWolf v2 - Application Types
    // Layer: App-facing DTOs / View-neutral models
    //
    // Purpose:
    // 1. Provide clean data structures for GUI/CLI.
    // 2. Keep GUI away from raw engine internals.
    // 3. Preserve engine output meaning:
    //    - Normal devices
    //    - Heavy devices
    //    - Redflag devices
    //    - Grouped main connections
    //    - Sub-connections count
    //    - Identity + Classification + Explanation
    //
    // This file does NOT define GUI layout.
    // This file does NOT run sensors.
    // This file does NOT classify traffic.
    // ================================================================


    // ------------------------------------------------
    // Device bucket for app-level presentation
    // ------------------------------------------------

    enum class AppDeviceBucket
    {
        Normal,
        Heavy,
        Redflag
    };


    inline std::string toString(AppDeviceBucket bucket)
    {
        switch (bucket)
        {
        case AppDeviceBucket::Normal:
            return "Normal Devices";

        case AppDeviceBucket::Heavy:
            return "Heavy Devices";

        case AppDeviceBucket::Redflag:
            return "Redflag Devices";

        default:
            return "Normal Devices";
        }
    }


    inline std::string toStateLabel(AppDeviceBucket bucket)
    {
        switch (bucket)
        {
        case AppDeviceBucket::Normal:
            return "Normal State";

        case AppDeviceBucket::Heavy:
            return "Heavy State";

        case AppDeviceBucket::Redflag:
            return "Redflag State";

        default:
            return "Normal State";
        }
    }


    // ------------------------------------------------
    // Connection row
    // One row represents one grouped/main connection,
    // not one raw packet.
    // ------------------------------------------------

    struct AppSubConnectionRow
    {
        std::string deviceIp;

        std::string localIp;
        uint16_t localPort = 0;

        std::string remoteIp;
        uint16_t remotePort = 0;

        std::string protocolLabel;
        std::string connectionType;
        std::string transportState;

        uint32_t pid = 0;
        std::string processName;
        std::string processPath;

        std::string entityName;
        std::string destinationDomain;
        std::string category;

        std::string confidenceLabel;
        int confidenceScore = 0;

        uint64_t bytes = 0;
        std::string bytesHuman;

        std::string evidenceUsed;
        std::string reason;
        std::string limitations;
    };

    struct AppConnectionRow
    {
        std::string stateLabel;
        std::string deviceIp;

        // Identity
        std::string entityName;
        std::string destinationDomain;
        std::string category;
        std::string confidenceLabel;
        int confidenceScore = 0;

        // Connection
        std::string connectionType;
        std::string ownerProcess;
        size_t subConnectionCount = 0;
        uint64_t bytes = 0;
        std::string bytesHuman;

        // Explanation
        std::string evidenceUsed;
        std::string reason;
        std::string limitations;

        std::vector<AppSubConnectionRow> subConnections;

        bool expandable = false;
    };


    // ------------------------------------------------
    // Device row
    // One row represents one device in Normal/Heavy/Redflag.
    // ------------------------------------------------

    struct AppDeviceRow
    {
        AppDeviceBucket bucket = AppDeviceBucket::Normal;

        std::string stateLabel;
        std::string deviceIp;

        double mcs = 0.0;

        size_t totalConnections = 0;
        size_t totalGroups = 0;

        size_t uniqueEntities = 0;
        size_t uniqueCategories = 0;
        size_t uniqueServices = 0;

        size_t concurrentConnectionsEstimate = 0;

        uint64_t totalBytes = 0;
        std::string totalBytesHuman;

        double trafficSharePercent = 0.0;
        double attributionCoveragePercent = 0.0;
        double dominantEntityRatioPercent = 0.0;

        std::string summaryReason;

        // Device identity (hotspot clients), found automatically.
        std::string hostName;
        std::string nameSource;
        std::string deviceType;
        std::string typeEvidence;
        std::string mac;
        bool forwarding = false;
        size_t forwardedSyns = 0;
        std::vector<std::string> platformsBehind;

        std::vector<AppConnectionRow> connections;

        bool hasConnections() const
        {
            return !connections.empty();
        }
    };


    // ------------------------------------------------
    // Dashboard/count summary
    // This is GUI-neutral.
    // A GUI can display it however it wants.
    // ------------------------------------------------

    struct AppDashboardCounts
    {
        size_t normalDevices = 0;
        size_t heavyDevices = 0;
        size_t redflagDevices = 0;

        size_t totalDevices = 0;

        size_t totalConnectionReports = 0;
        size_t normalConnectionReports = 0;
        size_t heavyConnectionReports = 0;
        size_t redflagConnectionReports = 0;

        size_t analyzedSessions = 0;
        size_t attributedSessions = 0;
        size_t connectionGroups = 0;

        bool hasRedflags() const
        {
            return redflagDevices > 0;
        }
    };


    // ------------------------------------------------
    // App dashboard snapshot
    // This is what GUI/CLI can consume later.
    // ------------------------------------------------

    struct AppDashboardSnapshot
    {
        std::string title = "NetWolf v2 Dashboard Snapshot";
        std::string statusLabel;
        std::string summaryText;

        bool stage7LiveOutput = false;
        size_t stage7LiveGroups = 0;
        size_t stage7LiveSubConnections = 0;
        std::string stage7DebugSummary;

        // One-line hotspot capture state for the LIVE MONITOR box.
        std::string hotspotLine;

        // Evil Twin algorithm state ("Watching", "Crowd", "Collapse", "ALERT").
        std::string evilTwinPhase;
        std::string evilTwinSummary;

        AppDashboardCounts counts;

        std::vector<AppDeviceRow> normalDevices;
        std::vector<AppDeviceRow> heavyDevices;
        std::vector<AppDeviceRow> redflagDevices;

        bool empty() const
        {
            return normalDevices.empty() &&
                heavyDevices.empty() &&
                redflagDevices.empty();
        }
    };


    // ------------------------------------------------
    // App type mapper
    // Converts engine/live outputs into app-facing rows.
    // ------------------------------------------------

    class AppTypeMapper
    {
    public:
        static AppDashboardSnapshot fromEngineRun(
            const netwolf::core::EngineRunResult& result,
            const std::string& statusLabel = "Engine Run"
        );

        static AppDashboardSnapshot fromLiveRun(
            const netwolf::live::LiveRunResult& result
        );

        static AppDashboardSnapshot fromOutput(
            const netwolf::core::EngineOutput& output,
            const std::string& statusLabel = "Engine Output"
        );

    private:
        static AppDashboardCounts buildCounts(
            const netwolf::core::EngineOutput& output
        );

        static AppDeviceRow makeDeviceRow(
            const netwolf::core::DeviceReport& device,
            AppDeviceBucket bucket
        );

        static AppConnectionRow makeConnectionRow(
            const netwolf::core::ConnectionReport& report
        );

        static void appendDeviceRows(
            std::vector<AppDeviceRow>& target,
            const std::vector<netwolf::core::DeviceReport>& source,
            AppDeviceBucket bucket
        );

        static size_t countConnectionReports(
            const std::vector<netwolf::core::DeviceReport>& devices
        );

        static std::string bytesToHuman(
            uint64_t bytes
        );

        static std::string formatDouble(
            double value,
            int precision = 2
        );
    };


    // ------------------------------------------------
    // Inline implementation
    // ------------------------------------------------

    inline AppDashboardSnapshot AppTypeMapper::fromEngineRun(
        const netwolf::core::EngineRunResult& result,
        const std::string& statusLabel
    )
    {
        AppDashboardSnapshot snapshot = fromOutput(
            result.output,
            statusLabel
        );

        snapshot.counts.analyzedSessions =
            result.trace.analyzedSessions.size();

        snapshot.counts.attributedSessions =
            result.trace.attributedSessions.size();

        snapshot.counts.connectionGroups =
            result.trace.groups.size();

        std::ostringstream summary;

        summary
            << "Analyzed sessions: "
            << snapshot.counts.analyzedSessions
            << ", attributed sessions: "
            << snapshot.counts.attributedSessions
            << ", connection groups: "
            << snapshot.counts.connectionGroups
            << ", devices: "
            << snapshot.counts.totalDevices
            << ".";

        snapshot.summaryText = summary.str();

        return snapshot;
    }


    inline AppDashboardSnapshot AppTypeMapper::fromLiveRun(
        const netwolf::live::LiveRunResult& result
    )
    {
        AppDashboardSnapshot snapshot = fromEngineRun(
            result.engineRun,
            netwolf::live::toString(result.status)
        );

        const bool hasStage7LiveGroups =
            !result.liveConnectionGroups.empty();

        snapshot.stage7LiveOutput =
            hasStage7LiveGroups;

        snapshot.stage7LiveGroups =
            result.liveConnectionGroups.size();

        snapshot.stage7LiveSubConnections =
            result.liveSessionUpdate.subConnections;

        snapshot.stage7DebugSummary =
            result.stage7DebugSummary;

        snapshot.evilTwinPhase = result.evilTwin.phase;
        snapshot.evilTwinSummary = result.evilTwin.summary;

        // Attach the automatic device identity (name, type, forwarding).
        for (auto* rows : { &snapshot.normalDevices, &snapshot.heavyDevices, &snapshot.redflagDevices })
        {
            for (auto& row : *rows)
            {
                for (const auto& identity : result.deviceIdentities)
                {
                    if (identity.ip != row.deviceIp)
                        continue;

                    row.hostName = identity.hostName;
                    row.nameSource = identity.nameSource;
                    row.deviceType = identity.deviceType;
                    row.typeEvidence = identity.typeEvidence;
                    row.mac = identity.mac;
                    row.forwarding = identity.forwarding;
                    row.forwardedSyns = identity.forwardedSyns;
                    row.platformsBehind = identity.platformsBehind;
                    break;
                }
            }
        }

        if (result.packetCaptureRunning || !result.packetFlows.empty())
        {
            std::ostringstream hotspot;

            hotspot
                << "Hotspot: "
                << result.hotspotClientDevices.size()
                << " device(s) | "
                << result.packetFlows.size()
                << " connection(s) | "
                << result.packetsCaptured
                << " packets";

            if (result.packetCaptureAdapterOpen)
                hotspot << " | " << result.packetCaptureAdapter;
            else
                hotspot << " | adapter not open: is Mobile Hotspot on?";

            snapshot.hotspotLine = hotspot.str();
        }

        snapshot.counts.analyzedSessions =
            result.summary.analyzedSessions;

        snapshot.counts.attributedSessions =
            result.summary.attributedSessions;

        // The groups that were classified and are shown in the panels
        // (the router's own groups are excluded in hotspot mode).
        snapshot.counts.connectionGroups =
            result.summary.connectionGroups;

        std::ostringstream summary;

        summary
            << result.summary.summaryText;

        if (hasStage7LiveGroups)
        {
            summary
                << " Stage 7 live backend active: "
                << result.liveConnectionGroups.size()
                << " live group(s), "
                << result.liveSessionUpdate.subConnections
                << " live sub-connection(s). ";
        }

        if (!result.connectionTrackerUpdate.summaryText.empty())
        {
            summary
                << result.connectionTrackerUpdate.summaryText
                << ". ";
        }

        if (!result.liveSessionUpdate.summaryText.empty())
        {
            summary
                << result.liveSessionUpdate.summaryText
                << ".";
        }

        snapshot.summaryText =
            summary.str();

        return snapshot;
    }

    inline AppDashboardSnapshot AppTypeMapper::fromOutput(
        const netwolf::core::EngineOutput& output,
        const std::string& statusLabel
    )
    {
        AppDashboardSnapshot snapshot;

        snapshot.statusLabel = statusLabel;
        snapshot.counts = buildCounts(output);

        appendDeviceRows(
            snapshot.normalDevices,
            output.normalDevices,
            AppDeviceBucket::Normal
        );

        appendDeviceRows(
            snapshot.heavyDevices,
            output.heavyDevices,
            AppDeviceBucket::Heavy
        );

        appendDeviceRows(
            snapshot.redflagDevices,
            output.redflagDevices,
            AppDeviceBucket::Redflag
        );

        std::ostringstream summary;

        summary
            << "Devices: "
            << snapshot.counts.totalDevices
            << " total, "
            << snapshot.counts.normalDevices
            << " normal, "
            << snapshot.counts.heavyDevices
            << " heavy, "
            << snapshot.counts.redflagDevices
            << " redflag. "
            << "Connection reports: "
            << snapshot.counts.totalConnectionReports
            << ".";

        snapshot.summaryText = summary.str();

        return snapshot;
    }


    inline AppDashboardCounts AppTypeMapper::buildCounts(
        const netwolf::core::EngineOutput& output
    )
    {
        AppDashboardCounts counts;

        counts.normalDevices = output.normalDevices.size();
        counts.heavyDevices = output.heavyDevices.size();
        counts.redflagDevices = output.redflagDevices.size();

        counts.totalDevices =
            counts.normalDevices +
            counts.heavyDevices +
            counts.redflagDevices;

        counts.normalConnectionReports =
            countConnectionReports(output.normalDevices);

        counts.heavyConnectionReports =
            countConnectionReports(output.heavyDevices);

        counts.redflagConnectionReports =
            countConnectionReports(output.redflagDevices);

        counts.totalConnectionReports =
            counts.normalConnectionReports +
            counts.heavyConnectionReports +
            counts.redflagConnectionReports;

        return counts;
    }


    inline AppDeviceRow AppTypeMapper::makeDeviceRow(
        const netwolf::core::DeviceReport& device,
        AppDeviceBucket bucket
    )
    {
        AppDeviceRow row;

        row.bucket = bucket;
        row.stateLabel = toStateLabel(bucket);
        row.deviceIp = device.deviceIp;

        row.mcs = device.score.mcs;

        row.totalConnections = device.score.totalConnections;
        row.totalGroups = device.score.totalGroups;

        row.uniqueEntities = device.score.uniqueEntities;
        row.uniqueCategories = device.score.uniqueCategories;
        row.uniqueServices = device.score.uniqueServices;

        row.concurrentConnectionsEstimate =
            device.score.concurrentConnections;

        row.totalBytes = device.totalBytes;
        row.totalBytesHuman = bytesToHuman(device.totalBytes);

        row.trafficSharePercent =
            device.score.trafficSharePercent;

        row.attributionCoveragePercent =
            device.score.attributionCoveragePercent;

        row.dominantEntityRatioPercent =
            device.score.dominantEntityRatioPercent;

        row.summaryReason = device.summaryReason;

        row.connections.reserve(device.connectionReports.size());

        for (const auto& report : device.connectionReports)
        {
            row.connections.push_back(
                makeConnectionRow(report)
            );
        }

        return row;
    }


    inline AppConnectionRow AppTypeMapper::makeConnectionRow(
        const netwolf::core::ConnectionReport& report
    )
    {
        AppConnectionRow row;

        row.stateLabel =
            netwolf::core::toString(report.classificationState);

        row.deviceIp = report.deviceIp;

        // Identity
        row.entityName = report.entityName;
        row.destinationDomain = report.destinationDomain;
        row.category = report.category;
        row.confidenceLabel = netwolf::core::toString(report.confidence);
        row.confidenceScore = netwolf::core::confidenceScore(report.confidence);

        // Connection
        row.connectionType = report.connectionType;
        row.ownerProcess = report.ownerProcess;
        row.subConnectionCount = report.subConnectionCount;
        row.bytes = report.bytes;
        row.bytesHuman = bytesToHuman(report.bytes);

        // Explanation
        row.evidenceUsed = report.evidenceUsed;
        row.reason = report.reason;
        row.limitations = report.limitations;

        row.subConnections.clear();
        row.subConnections.reserve(report.subConnections.size());

        for (const auto& sub : report.subConnections)
        {
            AppSubConnectionRow item;

            item.deviceIp = sub.deviceIp;

            item.localIp = sub.localIp;
            item.localPort = sub.localPort;

            item.remoteIp = sub.remoteIp;
            item.remotePort = sub.remotePort;

            item.protocolLabel = sub.protocolLabel;
            item.connectionType = sub.connectionType;
            item.transportState = sub.transportState;

            item.pid = sub.pid;
            item.processName = sub.processName;
            item.processPath = sub.processPath;

            item.entityName = sub.entityName;
            item.destinationDomain = sub.destinationDomain;
            item.category = sub.category;

            item.confidenceLabel = netwolf::core::toString(sub.confidence);
            item.confidenceScore = netwolf::core::confidenceScore(sub.confidence);

            item.bytes = sub.bytes;
            item.bytesHuman = bytesToHuman(sub.bytes);

            item.evidenceUsed = sub.evidenceUsed;
            item.reason = sub.reason;
            item.limitations = sub.limitations;

            row.subConnections.push_back(item);
        }

        row.expandable =
            !row.subConnections.empty() ||
            report.subConnectionCount > 1;

        return row;
    }


    inline void AppTypeMapper::appendDeviceRows(
        std::vector<AppDeviceRow>& target,
        const std::vector<netwolf::core::DeviceReport>& source,
        AppDeviceBucket bucket
    )
    {
        target.reserve(target.size() + source.size());

        for (const auto& device : source)
        {
            target.push_back(
                makeDeviceRow(device, bucket)
            );
        }
    }


    inline size_t AppTypeMapper::countConnectionReports(
        const std::vector<netwolf::core::DeviceReport>& devices
    )
    {
        size_t count = 0;

        for (const auto& device : devices)
        {
            count += device.connectionReports.size();
        }

        return count;
    }


    inline std::string AppTypeMapper::bytesToHuman(
        uint64_t bytes
    )
    {
        const double kb = 1024.0;
        const double mb = kb * 1024.0;
        const double gb = mb * 1024.0;

        std::ostringstream out;
        out << std::fixed << std::setprecision(2);

        if (bytes >= static_cast<uint64_t>(gb))
        {
            out << static_cast<double>(bytes) / gb << " GB";
        }
        else if (bytes >= static_cast<uint64_t>(mb))
        {
            out << static_cast<double>(bytes) / mb << " MB";
        }
        else if (bytes >= static_cast<uint64_t>(kb))
        {
            out << static_cast<double>(bytes) / kb << " KB";
        }
        else
        {
            out << bytes << " B";
        }

        return out.str();
    }


    inline std::string AppTypeMapper::formatDouble(
        double value,
        int precision
    )
    {
        std::ostringstream out;

        out
            << std::fixed
            << std::setprecision(precision)
            << value;

        return out.str();
    }

} // namespace netwolf::app