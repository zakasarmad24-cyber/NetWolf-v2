#pragma once

#include <netwolf/app/app_types.hpp>

#include <algorithm>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

namespace netwolf::gui {

    // ================================================================
    // NetWolf v2 - GUI Models
    // Layer: GUI-neutral data models
    //
    // Purpose:
    // 1. Prepare clean models for a future GUI.
    // 2. Keep GUI display data separate from:
    //    - Core engine
    //    - Sensors
    //    - App controller
    //    - CLI
    // 3. Represent the requested boxes:
    //    - Normal Devices
    //    - Heavy Devices
    //    - Redflag Devices
    //    - Connection details
    //
    // This file does NOT draw a GUI.
    // This file does NOT define button layout.
    // This file does NOT classify traffic.
    // It only converts AppDashboardSnapshot into GUI-ready data.
    // ================================================================


    // ------------------------------------------------
    // GUI severity
    // ------------------------------------------------

    enum class GuiSeverity
    {
        Normal,
        Heavy,
        Redflag
    };


    inline std::string toString(GuiSeverity severity)
    {
        switch (severity)
        {
        case GuiSeverity::Normal:
            return "Normal";

        case GuiSeverity::Heavy:
            return "Heavy";

        case GuiSeverity::Redflag:
            return "Redflag";

        default:
            return "Normal";
        }
    }


    inline std::string stateLabel(GuiSeverity severity)
    {
        switch (severity)
        {
        case GuiSeverity::Normal:
            return "Normal State";

        case GuiSeverity::Heavy:
            return "Heavy State";

        case GuiSeverity::Redflag:
            return "Redflag State";

        default:
            return "Normal State";
        }
    }


    // ------------------------------------------------
    // GUI status badge
    // ------------------------------------------------

    struct GuiStatusBadge
    {
        std::string label;
        std::string description;
        GuiSeverity severity = GuiSeverity::Normal;
    };


    // ------------------------------------------------
    // Small metric card
    // Example:
    // Title: "MCS"
    // Value: "72.40"
    // Hint: "Multi-Client Score"
    // ------------------------------------------------

    struct GuiMetricCard
    {
        std::string title;
        std::string value;
        std::string hint;
    };


    // ------------------------------------------------
    // Connection row shown under a device
    // One row = one grouped/main connection.
    // Sub-connection count tells the GUI whether it can expand.
    // ------------------------------------------------

    struct GuiSubConnectionRow
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

    struct GuiConnectionRow
    {
        std::string sourceDeviceIp;
        std::string destinationText;

        std::string entityName;
        std::string destinationDomain;
        std::string category;

        std::string connectionType;
        std::string ownerProcess;

        std::string confidenceLabel;
        int confidenceScore = 0;

        size_t subConnectionCount = 0;

        uint64_t bytes = 0;
        std::string bytesHuman;

        std::string evidenceUsed;
        std::string reason;
        std::string limitations;

        // Stage 8 GUI destination triage:
        // Known rows have a real DNS/TLS/HTTP destination and are shown first.
        // Unknown rows stay visible as pending until the background packet service
        // captures matching evidence; then the row automatically moves to Known.
        bool destinationKnown = false;
        bool directPacketDestination = false;
        std::string destinationStateText;

        std::vector<GuiSubConnectionRow> subConnections;

        bool expandable = false;
    };


    // ------------------------------------------------
    // Device card shown inside Normal / Heavy / Redflag boxes
    // ------------------------------------------------

    struct GuiDeviceCard
    {
        GuiSeverity severity = GuiSeverity::Normal;

        std::string stateLabel;
        std::string deviceIp;

        std::string title;
        std::string subtitle;

        double mcs = 0.0;
        std::string mcsText;

        size_t totalConnections = 0;
        size_t totalGroups = 0;

        size_t uniqueEntities = 0;
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

        std::vector<GuiMetricCard> metrics;
        std::vector<GuiConnectionRow> connections;

        bool hasExpandableConnections() const
        {
            for (const auto& connection : connections)
            {
                if (connection.expandable)
                    return true;
            }

            return false;
        }
    };


    // ------------------------------------------------
    // Device panel model
    // Represents one GUI box:
    // - Normal Devices
    // - Heavy Devices
    // - Redflag Devices
    // ------------------------------------------------

    struct GuiDevicePanel
    {
        GuiSeverity severity = GuiSeverity::Normal;

        std::string title;
        std::string subtitle;

        size_t deviceCount = 0;
        size_t connectionCount = 0;

        std::vector<GuiDeviceCard> devices;

        bool empty() const
        {
            return devices.empty();
        }
    };


    // ------------------------------------------------
    // Full dashboard model
    // This is what the GUI can consume later.
    // ------------------------------------------------

    struct GuiDashboardModel
    {
        std::string title = "NetWolf v2";
        std::string statusLabel;
        std::string summaryText;

        bool stage7LiveOutput = false;
        size_t stage7LiveGroups = 0;
        size_t stage7LiveSubConnections = 0;
        std::string stage7DebugSummary;

        std::string hotspotLine;

        std::string evilTwinPhase;
        std::string evilTwinSummary;

        GuiStatusBadge statusBadge;

        std::vector<GuiMetricCard> topMetrics;

        GuiDevicePanel normalPanel;
        GuiDevicePanel heavyPanel;
        GuiDevicePanel redflagPanel;

        bool hasAnyDevice() const
        {
            return !normalPanel.empty() ||
                !heavyPanel.empty() ||
                !redflagPanel.empty();
        }

        bool hasRedflags() const
        {
            return !redflagPanel.empty();
        }
    };


    // ------------------------------------------------
    // GUI model mapper
    // Converts AppDashboardSnapshot into GuiDashboardModel.
    // ------------------------------------------------

    class GuiModelMapper
    {
    public:
        static GuiDashboardModel fromDashboard(
            const netwolf::app::AppDashboardSnapshot& dashboard
        );

    private:
        static GuiDevicePanel makePanel(
            GuiSeverity severity,
            const std::vector<netwolf::app::AppDeviceRow>& devices
        );

        static GuiDeviceCard makeDeviceCard(
            const netwolf::app::AppDeviceRow& device
        );

        static GuiConnectionRow makeConnectionRow(
            const netwolf::app::AppConnectionRow& connection
        );

        static GuiStatusBadge makeStatusBadge(
            const netwolf::app::AppDashboardSnapshot& dashboard
        );

        static std::vector<GuiMetricCard> makeTopMetrics(
            const netwolf::app::AppDashboardSnapshot& dashboard
        );

        static std::vector<GuiMetricCard> makeDeviceMetrics(
            const netwolf::app::AppDeviceRow& device
        );

        static GuiSeverity severityFromBucket(
            netwolf::app::AppDeviceBucket bucket
        );

        static std::string panelTitle(
            GuiSeverity severity
        );

        static std::string panelSubtitle(
            GuiSeverity severity,
            size_t deviceCount,
            size_t connectionCount
        );

        static std::string makeDeviceTitle(
            const netwolf::app::AppDeviceRow& device
        );

        static std::string makeDeviceSubtitle(
            const netwolf::app::AppDeviceRow& device
        );

        static std::string formatDouble(
            double value,
            int precision = 2
        );

        static std::string formatPercent(
            double value
        );

        static bool hasUrlScheme(
            const std::string& value
        );

        static std::string destinationScheme(
            uint16_t remotePort,
            const std::string& connectionType,
            const std::string& protocolLabel = {}
        );

        static std::string formatHostDestination(
            const std::string& host,
            uint16_t remotePort,
            const std::string& connectionType,
            const std::string& protocolLabel = {}
        );

        static std::string formatEndpointDestination(
            const std::string& remoteIp,
            uint16_t remotePort,
            const std::string& connectionType,
            const std::string& protocolLabel = {}
        );

        static std::string safeText(
            const std::string& value,
            const std::string& fallback
        );

        static size_t countConnections(
            const std::vector<netwolf::app::AppDeviceRow>& devices
        );
    };


    // ------------------------------------------------
    // Inline implementation
    // ------------------------------------------------

    inline GuiDashboardModel GuiModelMapper::fromDashboard(
        const netwolf::app::AppDashboardSnapshot& dashboard
    )
    {
        GuiDashboardModel model;

        model.title = dashboard.title.empty()
            ? "NetWolf v2"
            : dashboard.title;

        model.statusLabel = dashboard.statusLabel;
        model.summaryText = dashboard.summaryText;

        model.stage7LiveOutput =
            dashboard.stage7LiveOutput;

        model.stage7LiveGroups =
            dashboard.stage7LiveGroups;

        model.stage7LiveSubConnections =
            dashboard.stage7LiveSubConnections;

        model.stage7DebugSummary =
            dashboard.stage7DebugSummary;

        model.hotspotLine =
            dashboard.hotspotLine;

        model.evilTwinPhase =
            dashboard.evilTwinPhase;

        model.evilTwinSummary =
            dashboard.evilTwinSummary;

        model.statusBadge = makeStatusBadge(dashboard);
        model.topMetrics = makeTopMetrics(dashboard);

        model.redflagPanel = makePanel(
            GuiSeverity::Redflag,
            dashboard.redflagDevices
        );

        model.heavyPanel = makePanel(
            GuiSeverity::Heavy,
            dashboard.heavyDevices
        );

        model.normalPanel = makePanel(
            GuiSeverity::Normal,
            dashboard.normalDevices
        );

        return model;
    }


    inline GuiDevicePanel GuiModelMapper::makePanel(
        GuiSeverity severity,
        const std::vector<netwolf::app::AppDeviceRow>& devices
    )
    {
        GuiDevicePanel panel;

        panel.severity = severity;
        panel.deviceCount = devices.size();
        panel.connectionCount = countConnections(devices);

        panel.title = panelTitle(severity);
        panel.subtitle = panelSubtitle(
            severity,
            panel.deviceCount,
            panel.connectionCount
        );

        panel.devices.reserve(devices.size());

        for (const auto& device : devices)
        {
            panel.devices.push_back(
                makeDeviceCard(device)
            );
        }

        return panel;
    }


    inline GuiDeviceCard GuiModelMapper::makeDeviceCard(
        const netwolf::app::AppDeviceRow& device
    )
    {
        GuiDeviceCard card;

        card.severity = severityFromBucket(device.bucket);
        card.stateLabel = device.stateLabel;
        card.deviceIp = device.deviceIp;

        card.title = makeDeviceTitle(device);
        card.subtitle = makeDeviceSubtitle(device);

        card.mcs = device.mcs;
        card.mcsText = formatDouble(device.mcs);

        card.totalConnections = device.totalConnections;
        card.totalGroups = device.totalGroups;

        card.uniqueEntities = device.uniqueEntities;
        card.uniqueServices = device.uniqueServices;
        card.concurrentConnectionsEstimate =
            device.concurrentConnectionsEstimate;

        card.totalBytes = device.totalBytes;
        card.totalBytesHuman = device.totalBytesHuman;

        card.trafficSharePercent = device.trafficSharePercent;
        card.attributionCoveragePercent =
            device.attributionCoveragePercent;
        card.dominantEntityRatioPercent =
            device.dominantEntityRatioPercent;

        card.summaryReason = device.summaryReason;

        card.hostName = device.hostName;
        card.nameSource = device.nameSource;
        card.deviceType = device.deviceType;
        card.typeEvidence = device.typeEvidence;
        card.mac = device.mac;
        card.forwarding = device.forwarding;
        card.forwardedSyns = device.forwardedSyns;
        card.platformsBehind = device.platformsBehind;

        card.metrics = makeDeviceMetrics(device);

        card.connections.reserve(device.connections.size());

        for (const auto& connection : device.connections)
        {
            card.connections.push_back(
                makeConnectionRow(connection)
            );
        }

        return card;
    }


    inline GuiConnectionRow GuiModelMapper::makeConnectionRow(
        const netwolf::app::AppConnectionRow& connection
    )
    {
        GuiConnectionRow row;

        row.sourceDeviceIp = safeText(
            connection.deviceIp,
            "Local device"
        );

        const std::string destinationDomainLower =
            netwolf::core::lowerCopy(connection.destinationDomain);

        const std::string entityNameLower =
            netwolf::core::lowerCopy(connection.entityName);

        const std::string categoryLower =
            netwolf::core::lowerCopy(connection.category);

        const std::string evidenceLower =
            netwolf::core::lowerCopy(connection.evidenceUsed);

        const bool destinationDomainIsUseful =
            !connection.destinationDomain.empty() &&
            destinationDomainLower.find("no exact domain") == std::string::npos &&
            destinationDomainLower.find("explained by") == std::string::npos &&
            destinationDomainLower.find("explained classification") == std::string::npos &&
            destinationDomainLower != "-";

        const bool directPacketEvidence =
            categoryLower.find("direct packet") != std::string::npos ||
            evidenceLower.find("tls sni") != std::string::npos ||
            evidenceLower.find("dns answer") != std::string::npos ||
            evidenceLower.find("http host") != std::string::npos;

        const bool entityLooksLikeProcessOnly =
            entityNameLower.find("pid ") == 0 ||
            entityNameLower.find("tcp service") != std::string::npos ||
            entityNameLower.find("normal live group") != std::string::npos ||
            entityNameLower.find("intensive") != std::string::npos ||
            entityNameLower.find("process") != std::string::npos;

        std::string fallbackRemoteIp;
        uint16_t fallbackRemotePort = 0;
        std::string fallbackProtocolLabel;
        std::string fallbackConnectionType = connection.connectionType;

        if (!connection.subConnections.empty())
        {
            const auto& firstSub = connection.subConnections.front();

            fallbackRemoteIp = firstSub.remoteIp;
            fallbackRemotePort = firstSub.remotePort;
            fallbackProtocolLabel = firstSub.protocolLabel;

            if (!firstSub.connectionType.empty())
                fallbackConnectionType = firstSub.connectionType;
        }

        row.destinationKnown = true;
        row.directPacketDestination = destinationDomainIsUseful && directPacketEvidence;

        if (destinationDomainIsUseful)
        {
            row.destinationText = formatHostDestination(
                connection.destinationDomain,
                fallbackRemotePort,
                fallbackConnectionType,
                fallbackProtocolLabel
            );

            row.destinationStateText = row.directPacketDestination
                ? "Known URL - direct DNS/TLS evidence"
                : "Known URL - correlated destination";
        }
        else if (!fallbackRemoteIp.empty())
        {
            row.destinationText = formatEndpointDestination(
                fallbackRemoteIp,
                fallbackRemotePort,
                fallbackConnectionType,
                fallbackProtocolLabel
            );

            row.destinationStateText =
                "Exact live remote endpoint";
        }
        else if (!connection.entityName.empty() && !entityLooksLikeProcessOnly)
        {
            row.destinationText = formatHostDestination(
                connection.entityName,
                fallbackRemotePort,
                fallbackConnectionType,
                fallbackProtocolLabel
            );

            row.destinationStateText =
                "Known URL by connection identity hint";
        }
        else
        {
            row.destinationText = "local://observed-connection";
            row.destinationStateText =
                "Observed local connection";
        }

        row.entityName = safeText(
            connection.entityName,
            "Explained connection group"
        );

        row.destinationDomain = safeText(
            connection.destinationDomain,
            "No exact domain; explained classification"
        );

        row.category = safeText(
            connection.category,
            "Classified traffic"
        );

        row.connectionType = safeText(
            connection.connectionType,
            "Classified connection"
        );

        row.ownerProcess = safeText(
            connection.ownerProcess,
            "Process context unavailable"
        );

        row.confidenceLabel = safeText(
            connection.confidenceLabel,
            "None"
        );

        row.confidenceScore = connection.confidenceScore;

        row.subConnectionCount = connection.subConnectionCount;

        row.bytes = connection.bytes;
        row.bytesHuman = safeText(
            connection.bytesHuman,
            "0 B"
        );

        row.evidenceUsed = safeText(
            connection.evidenceUsed,
            "Explained evidence"
        );

        row.reason = safeText(
            connection.reason,
            "No raw Unknown; connection is explained by available evidence."
        );

        row.limitations = safeText(
            connection.limitations,
            "No limitation text provided."
        );

        if (!destinationDomainIsUseful && !fallbackRemoteIp.empty())
        {
            row.reason =
                "NetWolf did not yet have a DNS/TLS hostname for this row, so it displays the exact live remote endpoint as a URL-style destination. "
                "When matching DNS/TLS/SNI evidence arrives, the endpoint is automatically upgraded to a human-readable host URL.";

            row.limitations =
                "Endpoint URL is exact at IP:port level. A hostname may be unavailable when traffic uses cached DNS, encrypted DNS, QUIC/ECH, or when ClientHello was not visible yet.";

            if (row.evidenceUsed.empty() || row.evidenceUsed == "Explained evidence")
                row.evidenceUsed = "Exact live endpoint";
        }

        row.subConnections.clear();
        row.subConnections.reserve(connection.subConnections.size());

        for (const auto& sub : connection.subConnections)
        {
            GuiSubConnectionRow item;

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

            if (!sub.destinationDomain.empty())
            {
                item.destinationDomain = formatHostDestination(
                    sub.destinationDomain,
                    sub.remotePort,
                    sub.connectionType,
                    sub.protocolLabel
                );
            }
            else if (!sub.remoteIp.empty())
            {
                item.destinationDomain = formatEndpointDestination(
                    sub.remoteIp,
                    sub.remotePort,
                    sub.connectionType,
                    sub.protocolLabel
                );
            }
            else
            {
                item.destinationDomain.clear();
            }

            item.category = sub.category;

            item.confidenceLabel = sub.confidenceLabel;
            item.confidenceScore = sub.confidenceScore;

            item.bytes = sub.bytes;
            item.bytesHuman = sub.bytesHuman;

            item.evidenceUsed = sub.evidenceUsed;
            item.reason = sub.reason;
            item.limitations = sub.limitations;

            row.subConnections.push_back(item);
        }

        row.expandable =
            connection.expandable ||
            !row.subConnections.empty() ||
            connection.subConnectionCount > 1;

        return row;
    }


    inline GuiStatusBadge GuiModelMapper::makeStatusBadge(
        const netwolf::app::AppDashboardSnapshot& dashboard
    )
    {
        GuiStatusBadge badge;

        if (dashboard.counts.redflagDevices > 0)
        {
            badge.label = "Redflag activity detected";
            badge.description =
                "At least one device is classified as Redflag based on multi-client-like indicators.";
            badge.severity = GuiSeverity::Redflag;
            return badge;
        }

        if (dashboard.counts.heavyDevices > 0)
        {
            badge.label = "Heavy activity observed";
            badge.description =
                "One or more devices show heavy but not strongly suspicious behavior.";
            badge.severity = GuiSeverity::Heavy;
            return badge;
        }

        badge.label = "Normal activity";
        badge.description =
            "No Redflag or Heavy device was reported by the current engine output.";
        badge.severity = GuiSeverity::Normal;

        return badge;
    }


    inline std::vector<GuiMetricCard> GuiModelMapper::makeTopMetrics(
        const netwolf::app::AppDashboardSnapshot& dashboard
    )
    {
        std::vector<GuiMetricCard> metrics;

        metrics.push_back({
            "Devices",
            std::to_string(dashboard.counts.totalDevices),
            "Classified devices"
            });

        metrics.push_back({
            "Normal",
            std::to_string(dashboard.counts.normalDevices),
            "Normal state"
            });

        metrics.push_back({
            "Heavy",
            std::to_string(dashboard.counts.heavyDevices),
            "Heavy state"
            });

        metrics.push_back({
            "Redflag",
            std::to_string(dashboard.counts.redflagDevices),
            "Suspicious state"
            });

        metrics.push_back({
            "Groups",
            std::to_string(dashboard.counts.connectionGroups),
            "Main groups"
            });

        metrics.push_back({
            "Reports",
            std::to_string(dashboard.counts.totalConnectionReports),
            "Report rows"
            });

        return metrics;
    }


    inline std::vector<GuiMetricCard> GuiModelMapper::makeDeviceMetrics(
        const netwolf::app::AppDeviceRow& device
    )
    {
        std::vector<GuiMetricCard> metrics;

        metrics.push_back({
            "MCS",
            formatDouble(device.mcs),
            "Multi-Client Score"
            });

        metrics.push_back({
            "Connections",
            std::to_string(device.totalConnections),
            "Total sub-connections observed for this device"
            });

        metrics.push_back({
            "Groups",
            std::to_string(device.totalGroups),
            "Grouped main connections"
            });

        metrics.push_back({
            "Entities",
            std::to_string(device.uniqueEntities),
            "Unique destination entities"
            });

        metrics.push_back({
            "Services",
            std::to_string(device.uniqueServices),
            "Unique service/traffic types"
            });

        metrics.push_back({
            "Traffic",
            device.totalBytesHuman,
            "Total observed bytes"
            });

        metrics.push_back({
            "Coverage",
            formatPercent(device.attributionCoveragePercent),
            "Attribution coverage"
            });

        metrics.push_back({
            "Dominant entity",
            formatPercent(device.dominantEntityRatioPercent),
            "How much one entity explains the activity"
            });

        return metrics;
    }


    inline GuiSeverity GuiModelMapper::severityFromBucket(
        netwolf::app::AppDeviceBucket bucket
    )
    {
        switch (bucket)
        {
        case netwolf::app::AppDeviceBucket::Normal:
            return GuiSeverity::Normal;

        case netwolf::app::AppDeviceBucket::Heavy:
            return GuiSeverity::Heavy;

        case netwolf::app::AppDeviceBucket::Redflag:
            return GuiSeverity::Redflag;

        default:
            return GuiSeverity::Normal;
        }
    }


    inline std::string GuiModelMapper::panelTitle(
        GuiSeverity severity
    )
    {
        switch (severity)
        {
        case GuiSeverity::Normal:
            return "Normal Devices";

        case GuiSeverity::Heavy:
            return "Heavy Devices";

        case GuiSeverity::Redflag:
            return "Redflag Devices";

        default:
            return "Devices";
        }
    }


    inline std::string GuiModelMapper::panelSubtitle(
        GuiSeverity severity,
        size_t deviceCount,
        size_t connectionCount
    )
    {
        std::ostringstream out;

        out
            << deviceCount
            << " device";

        if (deviceCount != 1)
            out << "s";

        out
            << ", "
            << connectionCount
            << " grouped connection";

        if (connectionCount != 1)
            out << "s";

        out << " - ";

        switch (severity)
        {
        case GuiSeverity::Normal:
            out << "expected behavior";
            break;

        case GuiSeverity::Heavy:
            out << "heavy but explainable behavior";
            break;

        case GuiSeverity::Redflag:
            out << "suspicious multi-client-like behavior";
            break;

        default:
            out << "classified behavior";
            break;
        }

        return out.str();
    }


    inline std::string GuiModelMapper::makeDeviceTitle(
        const netwolf::app::AppDeviceRow& device
    )
    {
        std::ostringstream out;

        out
            << device.deviceIp
            << " - "
            << device.stateLabel;

        return out.str();
    }


    inline std::string GuiModelMapper::makeDeviceSubtitle(
        const netwolf::app::AppDeviceRow& device
    )
    {
        std::ostringstream out;

        out
            << "MCS "
            << formatDouble(device.mcs)
            << " | "
            << device.totalConnections
            << " connections"
            << " | "
            << device.totalGroups
            << " groups"
            << " | "
            << device.totalBytesHuman;

        return out.str();
    }


    inline std::string GuiModelMapper::formatDouble(
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


    inline std::string GuiModelMapper::formatPercent(
        double value
    )
    {
        return formatDouble(value) + "%";
    }


    inline bool GuiModelMapper::hasUrlScheme(
        const std::string& value
    )
    {
        const std::string lowered = netwolf::core::lowerCopy(value);

        return lowered.rfind("http://", 0) == 0 ||
            lowered.rfind("https://", 0) == 0 ||
            lowered.rfind("tcp://", 0) == 0 ||
            lowered.rfind("udp://", 0) == 0 ||
            lowered.rfind("quic://", 0) == 0 ||
            lowered.rfind("local://", 0) == 0;
    }


    inline std::string GuiModelMapper::destinationScheme(
        uint16_t remotePort,
        const std::string& connectionType,
        const std::string& protocolLabel
    )
    {
        const std::string typeLower = netwolf::core::lowerCopy(connectionType);
        const std::string protocolLower = netwolf::core::lowerCopy(protocolLabel);

        // QUIC / HTTP3 runs over UDP 443: show it as quic://, not https://.
        if (typeLower.find("quic") != std::string::npos ||
            (remotePort == 443 && protocolLower.find("udp") != std::string::npos))
        {
            return "quic";
        }

        if (remotePort == 443 ||
            typeLower.find("https") != std::string::npos)
        {
            return "https";
        }

        if (remotePort == 80 ||
            typeLower.find("http") != std::string::npos)
        {
            return "http";
        }

        if (protocolLower.find("udp") != std::string::npos ||
            typeLower.find("udp") != std::string::npos)
        {
            return "udp";
        }

        return "tcp";
    }


    inline std::string GuiModelMapper::formatHostDestination(
        const std::string& host,
        uint16_t remotePort,
        const std::string& connectionType,
        const std::string& protocolLabel
    )
    {
        if (host.empty())
            return {};

        if (hasUrlScheme(host))
            return host;

        const std::string scheme = destinationScheme(
            remotePort,
            connectionType,
            protocolLabel
        );

        std::string result = scheme + "://" + host;

        if ((scheme == "https" && remotePort != 0 && remotePort != 443) ||
            (scheme == "http" && remotePort != 0 && remotePort != 80) ||
            (scheme == "quic" && remotePort != 0 && remotePort != 443) ||
            ((scheme == "tcp" || scheme == "udp") && remotePort != 0))
        {
            result += ":";
            result += std::to_string(remotePort);
        }

        return result;
    }


    inline std::string GuiModelMapper::formatEndpointDestination(
        const std::string& remoteIp,
        uint16_t remotePort,
        const std::string& connectionType,
        const std::string& protocolLabel
    )
    {
        if (remoteIp.empty())
            return {};

        return formatHostDestination(
            remoteIp,
            remotePort,
            connectionType,
            protocolLabel
        );
    }


    inline std::string GuiModelMapper::safeText(
        const std::string& value,
        const std::string& fallback
    )
    {
        if (value.empty())
            return fallback;

        return value;
    }


    inline size_t GuiModelMapper::countConnections(
        const std::vector<netwolf::app::AppDeviceRow>& devices
    )
    {
        size_t count = 0;

        for (const auto& device : devices)
        {
            count += device.connections.size();
        }

        return count;
    }

} // namespace netwolf::gui