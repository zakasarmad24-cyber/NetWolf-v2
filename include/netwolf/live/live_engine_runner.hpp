#pragma once

#include <netwolf/core/engine.hpp>
#include <netwolf/core/device_classifier.hpp>
#include <netwolf/sensors/outbound_sensor.hpp>

#include "live_connection_tracker.hpp"
#include "live_session_tracker.hpp"
#include "live_session_group_adapter.hpp"
#include "live_packet_metadata_sensor.hpp"
#include "live_packet_evidence_store.hpp"
#include "mock_packet_metadata_sensor.hpp"
#include "npcap_packet_metadata_sensor.hpp"
#include "live_packet_capture_service.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace netwolf::live {

    // ================================================================
    // NetWolf v2 - Live Engine Runner
    // Layer: Sensor-to-Engine Bridge
    //
    // Purpose:
    // 1. Collect snapshots from one or more outbound sensors.
    // 2. Merge observed connections and evidence into EngineInput.
    // 3. Run NetWolfEngine.
    // 4. Return structured output ready for GUI/CLI/reporting.
    //
    // This file does NOT define GUI layout.
    // This file does NOT perform packet capture itself.
    // It only coordinates sensors and core engine.
    // ================================================================


    // ------------------------------------------------
    // Runner status
    // ------------------------------------------------

    enum class LiveRunStatus
    {
        Ok,
        Partial,
        Failed
    };


    inline std::string toString(LiveRunStatus status)
    {
        switch (status)
        {
        case LiveRunStatus::Ok:
            return "OK";

        case LiveRunStatus::Partial:
            return "Partial";

        case LiveRunStatus::Failed:
            return "Failed";

        default:
            return "Failed";
        }
    }


    // ------------------------------------------------
    // Runner message
    // ------------------------------------------------

    struct LiveRunMessage
    {
        LiveRunStatus status = LiveRunStatus::Ok;

        std::string code;
        std::string message;
        std::string details;
    };


    // ------------------------------------------------
    // Runner configuration
    // ------------------------------------------------

    struct LiveEngineRunnerConfig
    {
        netwolf::sensors::SensorConfig sensorConfig;
        netwolf::core::EngineConfig engineConfig;

        // If true, runner continues even when one sensor returns Partial.
        bool allowPartialSensorResults = true;

        // If true, runner continues when one sensor fails,
        // as long as at least one other sensor produced usable data.
        bool continueIfOneSensorFails = true;

        // If true, sensor messages are copied into runner messages.
        bool keepSensorMessages = true;

        // If false, an empty sensor snapshot is treated as Partial.
        bool allowEmptySnapshot = true;

        // Stage 7:
        // If true, engine output classification uses live session groups
        // produced by LiveConnectionTracker -> LiveSessionTracker -> Adapter.
        bool useLiveSessionGroupsForOutput = true;

        // Stage 7 debug only:
        // Enables mock packet metadata so we can test packet-evidence ingestion
        // without Npcap / ETW / WinDivert.
        bool enableMockPacketMetadataSensor = false;

        // Stage 8 real packet metadata path.
        bool enableNpcapPacketMetadataSensor = false;

        // If true, Npcap runs continuously in a background service and the
        // runner only reads the latest evidence buffer. This is the correct
        // mode for GUI Live Monitor because it does not block the UI thread.
        bool useBackgroundPacketCaptureService = false;

        NpcapPacketMetadataSensorConfig npcapPacketMetadataSensor;

        size_t backgroundPacketEvidenceLimit = 12000;
        size_t backgroundPacketSensorResultLimit = 8;
        int backgroundPacketCaptureLoopSleepMs = 5;

        // Device memory (vanished / new devices, population history).
        // Only meaningful when the same runner is reused across snapshots.
        LiveConnectionTrackerConfig connectionTracker;

        // ---- Hotspot client devices (continuous Npcap capture) ----

        // Active hotspot flows become engine connections of the CLIENT
        // device (deviceIp = the phone's IP), named by their own TLS SNI /
        // DNS answers, then grouped by destination (Meta, Google, ...).
        bool useHotspotFlowsAsConnections = true;

        // Packet capture keeps the adapter open and tracks every packet.
        bool continuousPacketCapture = true;

        // Seconds without packets before a hotspot flow stops being active.
        int hotspotFlowIdleSeconds = 45;

        // If false, the router (this PC) is tracked for presence but left out
        // of the Normal / Heavy / Redflag panels: only client devices are
        // classified.
        bool classifyRouterDevice = true;
    };


    // ------------------------------------------------
    // Runner summary
    // ------------------------------------------------

    struct LiveRunSummary
    {
        size_t sensorCount = 0;
        size_t successfulSensors = 0;
        size_t partialSensors = 0;
        size_t failedSensors = 0;

        size_t observedConnections = 0;
        size_t analyzedSessions = 0;
        size_t attributedSessions = 0;
        size_t connectionGroups = 0;

        size_t normalDevices = 0;
        size_t heavyDevices = 0;
        size_t redflagDevices = 0;

        std::string summaryText;
    };


    // ------------------------------------------------
    // Full runner result
    // ------------------------------------------------

    struct LiveRunResult
    {
        LiveRunStatus status = LiveRunStatus::Ok;

        std::chrono::system_clock::time_point startedAt =
            std::chrono::system_clock::now();

        std::chrono::system_clock::time_point finishedAt =
            std::chrono::system_clock::now();

        std::vector<netwolf::sensors::SensorSnapshot> snapshots;

        netwolf::core::EngineInput engineInput;
        netwolf::core::EngineRunResult engineRun;

        LiveConnectionTrackerUpdate connectionTrackerUpdate;
        LiveSessionTrackerUpdate liveSessionUpdate;

        std::vector<netwolf::core::ConnectionGroup> liveConnectionGroups;
        std::string stage7DebugSummary;

        std::vector<LivePacketMetadataSensorResult> packetMetadataSensorResults;
        std::vector<LivePacketMetadata> packetMetadataItems;
        LivePacketEvidenceStoreSummary packetEvidenceSummary;

        // Hotspot capture (continuous mode).
        std::vector<LivePacketFlow> packetFlows;
        std::vector<LiveDeviceIdentity> deviceIdentities;
        uint64_t captureGeneration = 0;

        // Evil Twin algorithm state for this snapshot (phase, alerts, events).
        LiveEvilTwinStatus evilTwin;
        std::set<std::string> hotspotClientDevices;
        std::set<std::string> routerDevices;
        std::string packetCaptureStatus;
        std::string packetCaptureAdapter;
        bool packetCaptureAdapterOpen = false;
        bool packetCaptureRunning = false;
        uint64_t packetsCaptured = 0;

        LiveRunSummary summary;

        std::vector<LiveRunMessage> messages;

        bool success() const
        {
            return status == LiveRunStatus::Ok ||
                status == LiveRunStatus::Partial;
        }
    };


    // ------------------------------------------------
    // Live Engine Runner
    // ------------------------------------------------

    class LiveEngineRunner
    {
    public:
        explicit LiveEngineRunner(
            LiveEngineRunnerConfig config = {}
        );

        LiveRunResult runOnce(
            netwolf::sensors::IOutboundSensor& sensor
        ) const;

        LiveRunResult runOnce(
            const std::vector<netwolf::sensors::IOutboundSensor*>& sensors
        ) const;

    private:
        LiveEngineRunnerConfig config_;
        mutable LiveConnectionTracker connectionTracker_;
        mutable LiveSessionTracker liveSessionTracker_;
        mutable LiveSessionGroupAdapter liveSessionGroupAdapter_;

    private:
        netwolf::core::EngineInput buildEngineInput(
            const std::vector<netwolf::sensors::SensorSnapshot>& snapshots
        ) const;

        LiveRunSummary buildSummary(
            const LiveRunResult& result
        ) const;

        void addMessage(
            LiveRunResult& result,
            LiveRunStatus status,
            const std::string& code,
            const std::string& message,
            const std::string& details = {}
        ) const;

        void importSensorMessages(
            LiveRunResult& result,
            const netwolf::sensors::SensorSnapshot& snapshot
        ) const;

        static void mergeEvidenceInput(
            netwolf::core::EngineEvidenceInput& target,
            const netwolf::core::EngineEvidenceInput& source
        );

        static void mergeEvidenceStore(
            netwolf::core::EvidenceStore& target,
            const netwolf::core::EvidenceStore& source
        );

        static bool processObservationIsBetter(
            const netwolf::core::ProcessObservation& candidate,
            const netwolf::core::ProcessObservation& current
        );

        static std::string buildSummaryText(
            const LiveRunSummary& summary
        );

        static std::string buildStage7DebugSummary(
            const LiveRunResult& result
        );

        void collectPacketMetadataEvidence(
            LiveRunResult& result
        ) const;

        // Converts active hotspot flows into ObservedConnections of the
        // client devices and adds their SNI / DNS names as evidence.
        void appendHotspotFlowConnections(
            LiveRunResult& result
        ) const;
    };


    // ------------------------------------------------
    // Inline implementation
    // ------------------------------------------------

    inline LiveEngineRunner::LiveEngineRunner(
        LiveEngineRunnerConfig config
    )
        : config_(config),
        connectionTracker_(config_.connectionTracker)
    {
    }


    inline LiveRunResult LiveEngineRunner::runOnce(
        netwolf::sensors::IOutboundSensor& sensor
    ) const
    {
        std::vector<netwolf::sensors::IOutboundSensor*> sensors;
        sensors.push_back(&sensor);

        return runOnce(sensors);
    }


    inline LiveRunResult LiveEngineRunner::runOnce(
        const std::vector<netwolf::sensors::IOutboundSensor*>& sensors
    ) const
    {
        LiveRunResult result;

        result.startedAt = std::chrono::system_clock::now();
        result.status = LiveRunStatus::Ok;

        if (sensors.empty())
        {
            addMessage(
                result,
                LiveRunStatus::Failed,
                "no_sensors",
                "No sensors were provided to LiveEngineRunner.",
                "At least one IOutboundSensor instance is required."
            );

            result.finishedAt = std::chrono::system_clock::now();
            result.summary = buildSummary(result);
            return result;
        }

        // Stage 8:
        // For real packet capture, collect packet metadata before the TCP snapshot.
        // This gives Npcap time to observe TLS ClientHello / DNS packets first,
        // then the Windows TCP snapshot can capture the matching active connection.
        if (config_.enableNpcapPacketMetadataSensor &&
            !config_.enableMockPacketMetadataSensor)
        {
            collectPacketMetadataEvidence(result);

            addMessage(
                result,
                LiveRunStatus::Ok,
                "stage8_pre_snapshot_packet_metadata",
                "Stage 8 packet metadata was collected before TCP snapshot.",
                result.packetEvidenceSummary.summaryText
            );
        }

        for (const auto* sensor : sensors)
        {
            if (sensor == nullptr)
            {
                addMessage(
                    result,
                    LiveRunStatus::Partial,
                    "null_sensor",
                    "A null sensor pointer was skipped.",
                    "The runner continued with remaining sensors."
                );

                continue;
            }

            netwolf::sensors::SensorResult sensorResult =
                const_cast<netwolf::sensors::IOutboundSensor*>(sensor)
                ->captureSnapshot(config_.sensorConfig);

            result.snapshots.push_back(sensorResult.snapshot);

            if (config_.keepSensorMessages)
            {
                importSensorMessages(
                    result,
                    sensorResult.snapshot
                );
            }

            if (sensorResult.snapshot.status == netwolf::sensors::SensorStatus::Failed)
            {
                addMessage(
                    result,
                    LiveRunStatus::Partial,
                    "sensor_failed",
                    "A sensor failed during snapshot capture.",
                    "Sensor type: " + netwolf::sensors::toString(sensorResult.snapshot.sensorType)
                );

                if (!config_.continueIfOneSensorFails)
                {
                    result.status = LiveRunStatus::Failed;
                    result.finishedAt = std::chrono::system_clock::now();
                    result.summary = buildSummary(result);
                    return result;
                }
            }
            else if (sensorResult.snapshot.status == netwolf::sensors::SensorStatus::Partial)
            {
                addMessage(
                    result,
                    LiveRunStatus::Partial,
                    "sensor_partial",
                    "A sensor returned a partial snapshot.",
                    "Sensor type: " + netwolf::sensors::toString(sensorResult.snapshot.sensorType)
                );

                if (!config_.allowPartialSensorResults)
                {
                    result.status = LiveRunStatus::Failed;
                    result.finishedAt = std::chrono::system_clock::now();
                    result.summary = buildSummary(result);
                    return result;
                }
            }

            if (!config_.allowEmptySnapshot && sensorResult.snapshot.empty())
            {
                addMessage(
                    result,
                    LiveRunStatus::Partial,
                    "empty_snapshot",
                    "A sensor returned an empty snapshot.",
                    "Sensor type: " + netwolf::sensors::toString(sensorResult.snapshot.sensorType)
                );
            }
        }

        result.engineInput = buildEngineInput(result.snapshots);

        // The router is this PC: every device seen by the local Windows
        // socket-table sensors is the machine NetWolf runs on, not a client.
        std::set<std::string> routerDeviceIps;

        for (const auto& snapshot : result.snapshots)
        {
            if (snapshot.sensorType != netwolf::sensors::SensorType::LiveWindowsTcpTable)
                continue;

            for (const auto& connection : snapshot.observedConnections)
            {
                if (!connection.deviceIp.empty())
                    routerDeviceIps.insert(connection.deviceIp);
            }
        }

        result.routerDevices = routerDeviceIps;

        for (const auto& ip : config_.connectionTracker.routerDeviceIps)
            result.routerDevices.insert(ip);

        // Hotspot client devices: their connections come from packet capture.
        if (config_.useHotspotFlowsAsConnections &&
            !result.packetFlows.empty())
        {
            appendHotspotFlowConnections(result);

            std::ostringstream flowMessage;

            flowMessage
                << "Hotspot capture: "
                << result.packetFlows.size()
                << " active flow(s) from "
                << result.hotspotClientDevices.size()
                << " client device(s); packets captured="
                << result.packetsCaptured
                << ".";

            addMessage(
                result,
                LiveRunStatus::Ok,
                "hotspot_flows",
                "Hotspot client connections were added from continuous packet capture.",
                flowMessage.str()
            );
        }

        result.connectionTrackerUpdate =
            connectionTracker_.update(
                result.engineInput.observedConnections,
                routerDeviceIps
            );

        result.engineInput.observedConnections =
            result.connectionTrackerUpdate.activeConnections;

        addMessage(
            result,
            LiveRunStatus::Ok,
            "live_connection_tracker",
            "Live connection tracker updated active connection state.",
            result.connectionTrackerUpdate.summaryText
        );

        // The process-aware live session path is for this PC's own sockets.
        // Hotspot client flows are grouped by destination in the core engine.
        std::vector<netwolf::core::ObservedConnection> processAwareConnections;

        if (result.hotspotClientDevices.empty())
        {
            processAwareConnections = result.engineInput.observedConnections;
        }
        else
        {
            processAwareConnections.reserve(result.engineInput.observedConnections.size());

            for (const auto& connection : result.engineInput.observedConnections)
            {
                if (result.hotspotClientDevices.count(connection.deviceIp) == 0)
                    processAwareConnections.push_back(connection);
            }
        }

        result.liveSessionUpdate =
            liveSessionTracker_.update(
                processAwareConnections,
                result.engineInput.evidence
            );

        addMessage(
            result,
            LiveRunStatus::Ok,
            "live_session_tracker",
            "Live session tracker grouped active connections into live main sessions.",
            result.liveSessionUpdate.summaryText
        );

        if (result.packetMetadataItems.empty() ||
            config_.enableMockPacketMetadataSensor)
        {
            collectPacketMetadataEvidence(result);

            addMessage(
                result,
                LiveRunStatus::Ok,
                "packet_metadata_foundation",
                "Packet metadata evidence foundation is initialized.",
                result.packetEvidenceSummary.summaryText
            );
        }
        else
        {
            addMessage(
                result,
                LiveRunStatus::Ok,
                "packet_metadata_foundation",
                "Using pre-snapshot packet metadata evidence.",
                result.packetEvidenceSummary.summaryText
            );
        }

        result.liveConnectionGroups =
            liveSessionGroupAdapter_.convert(
                result.liveSessionUpdate.groups,
                result.engineInput.evidence,
                result.packetMetadataItems
            );

        std::ostringstream liveGroupMessage;

        liveGroupMessage
            << "Live session adapter produced "
            << result.liveConnectionGroups.size()
            << " core connection group(s) from "
            << result.liveSessionUpdate.subConnections
            << " live sub-connection(s).";

        addMessage(
            result,
            LiveRunStatus::Ok,
            "live_session_group_adapter",
            "Live session groups were adapted into core connection groups.",
            liveGroupMessage.str()
        );

        if (result.engineInput.observedConnections.empty())
        {
            addMessage(
                result,
                LiveRunStatus::Partial,
                "no_observed_connections",
                "No observed connections were available for the engine.",
                "The engine will run with an empty input."
            );
        }

        netwolf::core::NetWolfEngine engine(config_.engineConfig);
        result.engineRun = engine.run(result.engineInput);

        // ------------------------------------------------------------
        // Stage 7:
        // Replace snapshot-only grouping output with live session groups.
        // The old engine path still runs first so analyzer/origin behavior
        // remains available, but the final output can now be based on
        // LiveConnectionTracker -> LiveSessionTracker -> Adapter.
        // ------------------------------------------------------------
        //
        // Final output groups:
        // - hotspot client devices: destination-centric core engine groups
        //   (named by TLS SNI / DNS answer / offline ASN);
        // - other devices (this PC): process-aware live session groups;
        // - the router is left out when classifyRouterDevice is false.
        const bool haveHotspotClients =
            !result.hotspotClientDevices.empty();

        const bool useLiveGroups =
            config_.useLiveSessionGroupsForOutput &&
            !result.liveConnectionGroups.empty();

        if (haveHotspotClients || useLiveGroups || !config_.classifyRouterDevice)
        {
            const std::vector<netwolf::core::ConnectionGroup>& otherSource =
                useLiveGroups
                ? result.liveConnectionGroups
                : result.engineRun.trace.groups;

            std::vector<netwolf::core::ConnectionGroup> outputGroups;

            for (const auto& group : result.engineRun.trace.groups)
            {
                if (result.hotspotClientDevices.count(group.deviceIp) != 0 &&
                    result.routerDevices.count(group.deviceIp) == 0)
                {
                    outputGroups.push_back(group);

                    // A phone's processes are not visible from the router:
                    // label the origin as a hotspot client instead.
                    auto& clientGroup = outputGroups.back();

                    if (clientGroup.ownerProcessName.empty() ||
                        clientGroup.ownerProcessName == "Process context unavailable")
                    {
                        clientGroup.ownerProcessName = "Hotspot client";
                    }

                    for (auto& sub : clientGroup.subConnections)
                    {
                        if (sub.attribution.ownerProcess.has_value() &&
                            sub.attribution.ownerProcess->processName == "Process context unavailable")
                        {
                            sub.attribution.ownerProcess->processName = "Hotspot client";
                        }
                    }
                }
            }

            const size_t clientGroups = outputGroups.size();

            for (const auto& group : otherSource)
            {
                if (result.hotspotClientDevices.count(group.deviceIp) != 0)
                    continue;

                if (!config_.classifyRouterDevice &&
                    result.routerDevices.count(group.deviceIp) != 0)
                {
                    continue;
                }

                outputGroups.push_back(group);
            }

            result.engineRun.trace.groups = outputGroups;

            // ---- Evil Twin algorithm (client devices only) ----
            std::map<std::string, LiveDeviceProfile> profiles;

            for (const auto& group : outputGroups)
            {
                if (group.deviceIp.empty() || result.routerDevices.count(group.deviceIp) != 0)
                    continue;

                LiveDeviceProfile& profile = profiles[group.deviceIp];
                profile.deviceIp = group.deviceIp;
                profile.connections += group.subConnectionCount();

                if (!group.mainEntityName.empty())
                    profile.destinations.insert(group.mainEntityName);

                for (const auto& sub : group.subConnections)
                {
                    if (!sub.attribution.entityName.empty())
                        profile.destinations.insert(sub.attribution.entityName);
                }
            }

            std::vector<LiveDeviceProfile> activeProfiles;
            activeProfiles.reserve(profiles.size());

            for (auto& [ip, profile] : profiles)
            {
                profile.displayName = ip;

                for (const auto& identity : result.deviceIdentities)
                {
                    if (identity.ip != ip)
                        continue;

                    if (!identity.hostName.empty())
                        profile.displayName = identity.hostName;

                    profile.deviceType = identity.deviceType;
                    profile.forwarding = identity.forwarding;
                    profile.forwardedConnections = identity.forwardedSyns;
                    profile.platformsBehind = identity.platformsBehind;
                    profile.forwardedByPlatform = identity.forwardedByPlatform;
                    break;
                }

                activeProfiles.push_back(profile);
            }

            result.evilTwin =
                connectionTracker_.evaluateEvilTwin(
                    activeProfiles,
                    result.captureGeneration
                );

            netwolf::core::DeviceClassifier liveClassifier(
                config_.engineConfig.classifier
            );

            result.engineRun.output =
                liveClassifier.classify(
                    outputGroups,
                    result.evilTwin.verdicts
                );

            addMessage(
                result,
                LiveRunStatus::Ok,
                "evil_twin",
                "Evil Twin algorithm: " + result.evilTwin.phase,
                result.evilTwin.summary
            );

            std::ostringstream liveOutputMessage;

            liveOutputMessage
                << "Engine output uses "
                << outputGroups.size()
                << " group(s): "
                << clientGroups
                << " from hotspot client device(s), "
                << (outputGroups.size() - clientGroups)
                << " from "
                << (useLiveGroups ? "live session groups" : "core engine groups")
                << (config_.classifyRouterDevice
                    ? "."
                    : " (router / this PC excluded from classification).");

            addMessage(
                result,
                LiveRunStatus::Ok,
                "live_groups_output",
                "Engine output was rebuilt from live groups.",
                liveOutputMessage.str()
            );
        }

        result.stage7DebugSummary =
            buildStage7DebugSummary(result);

        addMessage(
            result,
            LiveRunStatus::Ok,
            "live_backend_debug_summary",
            "Live backend debug summary was generated.",
            result.stage7DebugSummary
        );

        result.finishedAt = std::chrono::system_clock::now();
        result.summary = buildSummary(result);

        // Final status decision.
        bool hasFailedMessage = false;
        bool hasPartialMessage = false;

        for (const auto& message : result.messages)
        {
            if (message.status == LiveRunStatus::Failed)
                hasFailedMessage = true;

            if (message.status == LiveRunStatus::Partial)
                hasPartialMessage = true;
        }

        if (hasFailedMessage)
            result.status = LiveRunStatus::Failed;
        else if (hasPartialMessage)
            result.status = LiveRunStatus::Partial;
        else
            result.status = LiveRunStatus::Ok;

        return result;
    }


    inline netwolf::core::EngineInput LiveEngineRunner::buildEngineInput(
        const std::vector<netwolf::sensors::SensorSnapshot>& snapshots
    ) const
    {
        netwolf::core::EngineInput input;

        for (const auto& snapshot : snapshots)
        {
            if (snapshot.status == netwolf::sensors::SensorStatus::Failed)
                continue;

            input.observedConnections.insert(
                input.observedConnections.end(),
                snapshot.observedConnections.begin(),
                snapshot.observedConnections.end()
            );

            mergeEvidenceInput(
                input.evidence,
                snapshot.evidence
            );
        }

        return input;
    }


    inline LiveRunSummary LiveEngineRunner::buildSummary(
        const LiveRunResult& result
    ) const
    {
        LiveRunSummary summary;

        summary.sensorCount = result.snapshots.size();

        for (const auto& snapshot : result.snapshots)
        {
            if (snapshot.status == netwolf::sensors::SensorStatus::Ok)
                summary.successfulSensors++;
            else if (snapshot.status == netwolf::sensors::SensorStatus::Partial)
                summary.partialSensors++;
            else if (snapshot.status == netwolf::sensors::SensorStatus::Failed)
                summary.failedSensors++;
        }

        summary.observedConnections =
            result.engineInput.observedConnections.size();

        summary.analyzedSessions =
            result.engineRun.trace.analyzedSessions.size();

        summary.attributedSessions =
            result.engineRun.trace.attributedSessions.size();

        summary.connectionGroups =
            result.engineRun.trace.groups.size();

        summary.normalDevices =
            result.engineRun.output.normalDevices.size();

        summary.heavyDevices =
            result.engineRun.output.heavyDevices.size();

        summary.redflagDevices =
            result.engineRun.output.redflagDevices.size();

        summary.summaryText = buildSummaryText(summary);

        return summary;
    }


    inline void LiveEngineRunner::addMessage(
        LiveRunResult& result,
        LiveRunStatus status,
        const std::string& code,
        const std::string& message,
        const std::string& details
    ) const
    {
        LiveRunMessage item;

        item.status = status;
        item.code = code;
        item.message = message;
        item.details = details;

        result.messages.push_back(item);

        if (status == LiveRunStatus::Failed)
        {
            result.status = LiveRunStatus::Failed;
        }
        else if (status == LiveRunStatus::Partial &&
            result.status == LiveRunStatus::Ok)
        {
            result.status = LiveRunStatus::Partial;
        }
    }


    inline void LiveEngineRunner::importSensorMessages(
        LiveRunResult& result,
        const netwolf::sensors::SensorSnapshot& snapshot
    ) const
    {
        for (const auto& sensorMessage : snapshot.messages)
        {
            LiveRunStatus mappedStatus = LiveRunStatus::Ok;

            if (sensorMessage.status == netwolf::sensors::SensorStatus::Failed)
                mappedStatus = LiveRunStatus::Failed;
            else if (sensorMessage.status == netwolf::sensors::SensorStatus::Partial)
                mappedStatus = LiveRunStatus::Partial;

            addMessage(
                result,
                mappedStatus,
                "sensor_" + sensorMessage.code,
                sensorMessage.message,
                sensorMessage.details
            );
        }
    }


    inline void LiveEngineRunner::mergeEvidenceInput(
        netwolf::core::EngineEvidenceInput& target,
        const netwolf::core::EngineEvidenceInput& source
    )
    {
        for (const auto& item : source.evidenceBySessionId)
        {
            const std::string& sessionId = item.first;
            const netwolf::core::EvidenceStore& sourceStore = item.second;

            auto found = target.evidenceBySessionId.find(sessionId);

            if (found == target.evidenceBySessionId.end())
            {
                target.evidenceBySessionId[sessionId] = sourceStore;
            }
            else
            {
                mergeEvidenceStore(found->second, sourceStore);
            }
        }

        for (const auto& item : source.processBySessionId)
        {
            const std::string& sessionId = item.first;
            const netwolf::core::ProcessObservation& sourceProcess = item.second;

            auto found = target.processBySessionId.find(sessionId);

            if (found == target.processBySessionId.end())
            {
                target.processBySessionId[sessionId] = sourceProcess;
            }
            else if (processObservationIsBetter(sourceProcess, found->second))
            {
                found->second = sourceProcess;
            }
        }
    }


    inline void LiveEngineRunner::mergeEvidenceStore(
        netwolf::core::EvidenceStore& target,
        const netwolf::core::EvidenceStore& source
    )
    {
        target.dnsCandidates.insert(
            target.dnsCandidates.end(),
            source.dnsCandidates.begin(),
            source.dnsCandidates.end()
        );

        for (const auto& sni : source.tlsSniCandidates)
        {
            if (std::find(target.tlsSniCandidates.begin(),
                target.tlsSniCandidates.end(),
                sni) == target.tlsSniCandidates.end())
            {
                target.tlsSniCandidates.push_back(sni);
            }
        }

        for (const auto& host : source.httpHostCandidates)
        {
            if (std::find(target.httpHostCandidates.begin(),
                target.httpHostCandidates.end(),
                host) == target.httpHostCandidates.end())
            {
                target.httpHostCandidates.push_back(host);
            }
        }

        target.processCandidates.insert(
            target.processCandidates.end(),
            source.processCandidates.begin(),
            source.processCandidates.end()
        );

        target.providerHints.insert(
            target.providerHints.end(),
            source.providerHints.begin(),
            source.providerHints.end()
        );
    }


    inline bool LiveEngineRunner::processObservationIsBetter(
        const netwolf::core::ProcessObservation& candidate,
        const netwolf::core::ProcessObservation& current
    )
    {
        const bool candidateHasName =
            !netwolf::core::trimCopy(candidate.processName).empty() &&
            netwolf::core::lowerCopy(candidate.processName) != "process context unavailable";

        const bool currentHasName =
            !netwolf::core::trimCopy(current.processName).empty() &&
            netwolf::core::lowerCopy(current.processName) != "process context unavailable";

        if (candidateHasName && !currentHasName)
            return true;

        const bool candidateHasPath =
            !netwolf::core::trimCopy(candidate.processPath).empty();

        const bool currentHasPath =
            !netwolf::core::trimCopy(current.processPath).empty();

        if (candidateHasPath && !currentHasPath)
            return true;

        if (candidate.pid != 0 && current.pid == 0)
            return true;

        return false;
    }


    inline std::string LiveEngineRunner::buildSummaryText(
        const LiveRunSummary& summary
    )
    {
        std::ostringstream out;

        out
            << "Sensors: "
            << summary.sensorCount
            << " total, "
            << summary.successfulSensors
            << " OK, "
            << summary.partialSensors
            << " partial, "
            << summary.failedSensors
            << " failed. ";

        out
            << "Observed connections: "
            << summary.observedConnections
            << ", analyzed sessions: "
            << summary.analyzedSessions
            << ", attributed sessions: "
            << summary.attributedSessions
            << ", groups: "
            << summary.connectionGroups
            << ". ";

        out
            << "Devices: "
            << summary.normalDevices
            << " normal, "
            << summary.heavyDevices
            << " heavy, "
            << summary.redflagDevices
            << " redflag.";

        return out.str();
    }

    inline std::string LiveEngineRunner::buildStage7DebugSummary(
        const LiveRunResult& result
    )
    {
        std::ostringstream output;

        output
            << "Live Backend Debug Summary\n"
            << "================================\n";

        output
            << "Connection tracker: "
            << result.connectionTrackerUpdate.summaryText
            << "\n";

        output
            << "Session tracker: "
            << result.liveSessionUpdate.summaryText
            << "\n";

        output
            << "Live core connection groups: "
            << result.liveConnectionGroups.size()
            << "\n";

        output
            << "Packet evidence: "
            << result.packetEvidenceSummary.summaryText
            << "\n";

        if (!result.packetMetadataSensorResults.empty())
        {
            output
                << "Packet metadata sensors:\n";

            for (const auto& sensorResult : result.packetMetadataSensorResults)
            {
                output
                    << "  - "
                    << sensorResult.summaryText()
                    << "\n";
            }
        }

        if (!result.packetMetadataItems.empty())
        {
            output
                << "Packet metadata samples:\n";

            auto printMetadataSample =
                [&](const LivePacketMetadata& item, size_t index)
                {
                    output
                        << "  #"
                        << index
                        << " "
                        << toString(item.type)
                        << " | name="
                        << (item.name.empty() ? "-" : item.name)
                        << " | resolvedIp="
                        << (item.resolvedIp.empty() ? "-" : item.resolvedIp)
                        << " | endpoint="
                        << item.endpoint.localIp
                        << ":"
                        << item.endpoint.localPort
                        << " -> "
                        << item.endpoint.remoteIp
                        << ":"
                        << item.endpoint.remotePort
                        << "\n";
                };

            size_t metadataIndex = 0;

            // Show strong identity evidence first.
            for (const auto& item : result.packetMetadataItems)
            {
                if (item.type != LivePacketMetadataType::TlsSni &&
                    item.type != LivePacketMetadataType::HttpHost &&
                    item.type != LivePacketMetadataType::DnsAnswer &&
                    item.type != LivePacketMetadataType::DnsQuery)
                {
                    continue;
                }

                printMetadataSample(item, metadataIndex);
                ++metadataIndex;

                if (metadataIndex >= 12)
                    break;
            }

            // Then show endpoint observations if there is still room.
            if (metadataIndex < 12)
            {
                for (const auto& item : result.packetMetadataItems)
                {
                    if (item.type != LivePacketMetadataType::EndpointObservation)
                        continue;

                    printMetadataSample(item, metadataIndex);
                    ++metadataIndex;

                    if (metadataIndex >= 12)
                        break;
                }
            }
        }

        output << "\n";

        size_t index = 0;

        for (const auto& group : result.liveConnectionGroups)
        {
            output
                << "#"
                << index
                << " "
                << group.mainEntityName
                << "\n";

            output
                << "  Device: "
                << group.deviceIp
                << "\n";

            output
                << "  Category: "
                << group.mainCategory
                << "\n";

            output
                << "  Owner process: "
                << group.ownerProcessName
                << "\n";

            output
                << "  Sub-connections: "
                << group.subConnectionCount()
                << "\n";

            output
                << "  Confidence: "
                << netwolf::core::toString(group.groupConfidence)
                << "\n";

            output
                << "  Reason: "
                << group.groupingReason
                << "\n";

            if (!group.subConnections.empty())
            {
                output
                    << "  First sub-connection sample:\n";

                const auto& sub =
                    group.subConnections.front();

                output
                    << "    "
                    << sub.session.observed.localIp
                    << ":"
                    << sub.session.observed.localPort
                    << " -> "
                    << sub.session.observed.remoteIp
                    << ":"
                    << sub.session.observed.remotePort
                    << " | "
                    << sub.session.connectionType
                    << "\n";
            }

            output << "\n";

            ++index;

            if (index >= 12)
            {
                output
                    << "... "
                    << (result.liveConnectionGroups.size() - index)
                    << " more group(s) not shown in debug summary.\n";
                break;
            }
        }

        return output.str();
    }

    inline void LiveEngineRunner::collectPacketMetadataEvidence(
        LiveRunResult& result
    ) const
    {
        LivePacketEvidenceStore store;

        result.packetMetadataSensorResults.clear();
        result.packetMetadataItems.clear();

        if (config_.enableMockPacketMetadataSensor)
        {
            MockPacketMetadataSensorConfig mockConfig;

            mockConfig.enabled = true;
            mockConfig.domain = "mock-stage7.local";
            mockConfig.httpHost = "mock-stage7.local";
            mockConfig.tlsSni = "mock-stage7.local";

            if (!result.engineInput.observedConnections.empty())
            {
                const auto& observed =
                    result.engineInput.observedConnections.front();

                mockConfig.localIp = observed.localIp;
                mockConfig.localPort = observed.localPort;

                mockConfig.remoteIp = observed.remoteIp;
                mockConfig.remotePort = observed.remotePort;
            }

            MockPacketMetadataSensor sensor(mockConfig);

            LivePacketMetadataSensorResult sensorResult =
                sensor.captureMetadataOnce();

            for (const auto& item : sensorResult.metadata)
            {
                store.add(item);
                result.packetMetadataItems.push_back(item);
            }

            result.packetMetadataSensorResults.push_back(
                std::move(sensorResult)
            );
        }

        if (config_.enableNpcapPacketMetadataSensor)
        {
            if (config_.useBackgroundPacketCaptureService)
            {
                LivePacketCaptureServiceConfig serviceConfig;

                serviceConfig.sensorConfig =
                    config_.npcapPacketMetadataSensor;

                serviceConfig.maxStoredMetadataItems =
                    config_.backgroundPacketEvidenceLimit;

                serviceConfig.maxStoredSensorResults =
                    config_.backgroundPacketSensorResultLimit;

                serviceConfig.loopSleepMs =
                    config_.backgroundPacketCaptureLoopSleepMs;

                serviceConfig.continuousCapture =
                    config_.continuousPacketCapture;

                serviceConfig.routerIps =
                    config_.connectionTracker.routerDeviceIps;

                serviceConfig.flowIdleSeconds =
                    config_.hotspotFlowIdleSeconds;

                LivePacketCaptureService::instance().start(serviceConfig);

                LivePacketCaptureServiceSnapshot snapshot =
                    LivePacketCaptureService::instance().snapshot();

                result.packetMetadataItems =
                    std::move(snapshot.metadataItems);

                result.packetFlows =
                    std::move(snapshot.activeFlows);

                result.deviceIdentities =
                    std::move(snapshot.devices);

                result.captureGeneration =
                    snapshot.generation;

                result.packetsCaptured =
                    snapshot.packetsCaptured;

                result.packetCaptureStatus =
                    snapshot.statusText;

                result.packetCaptureAdapter =
                    snapshot.adapterName;

                result.packetCaptureAdapterOpen =
                    snapshot.adapterOpen;

                result.packetCaptureRunning =
                    snapshot.running;

                result.packetMetadataSensorResults =
                    snapshot.sensorResults;

                for (const auto& item : result.packetMetadataItems)
                    store.add(item);

                if (result.packetMetadataSensorResults.empty())
                {
                    LivePacketMetadataSensorResult serviceResult;

                    serviceResult.status =
                        snapshot.running
                            ? LivePacketMetadataSensorStatus::Partial
                            : LivePacketMetadataSensorStatus::Unavailable;

                    serviceResult.sensorName =
                        "Background Npcap packet capture service";

                    serviceResult.message =
                        snapshot.statusText.empty()
                            ? "Background packet capture service has no sensor result yet."
                            : snapshot.statusText;

                    result.packetMetadataSensorResults.push_back(
                        std::move(serviceResult)
                    );
                }
            }
            else
            {
                NpcapPacketMetadataSensor sensor(
                    config_.npcapPacketMetadataSensor
                );

                LivePacketMetadataSensorResult sensorResult =
                    sensor.captureMetadataOnce();

                for (const auto& item : sensorResult.metadata)
                {
                    store.add(item);
                    result.packetMetadataItems.push_back(item);
                }

                result.packetMetadataSensorResults.push_back(
                    std::move(sensorResult)
                );
            }
        }

        result.packetEvidenceSummary =
            store.summary();
    }

    inline void LiveEngineRunner::appendHotspotFlowConnections(
        LiveRunResult& result
    ) const
    {
        auto& connections = result.engineInput.observedConnections;
        auto& evidence = result.engineInput.evidence.evidenceBySessionId;

        connections.reserve(connections.size() + result.packetFlows.size());

        for (const auto& flow : result.packetFlows)
        {
            if (flow.clientIp.empty() || flow.serverIp.empty())
                continue;

            // Never treat the router (this PC) as a hotspot client.
            if (result.routerDevices.count(flow.clientIp) != 0)
                continue;

            netwolf::core::ObservedConnection connection;

            connection.deviceIp = flow.clientIp;
            connection.localIp = flow.clientIp;
            connection.localPort = flow.clientPort;
            connection.remoteIp = flow.serverIp;
            connection.remotePort = flow.serverPort;
            connection.ipVersion = netwolf::core::IpVersion::IPv4;
            connection.protocol = flow.protocol;
            connection.direction = netwolf::core::TrafficDirection::Outbound;
            connection.transportState =
                flow.protocol == netwolf::core::TransportProtocol::TCP
                ? (flow.closing ? "Closing" : "Established")
                : "Active";
            connection.firstSeen = flow.firstSeen;
            connection.lastSeen = flow.lastSeen;
            connection.bytesSent = flow.bytesUp;
            connection.bytesReceived = flow.bytesDown;
            connection.packetsSent = flow.packetsUp;
            connection.packetsReceived = flow.packetsDown;
            connection.interfaceName = "Hotspot (Npcap)";

            netwolf::core::EvidenceStore& store =
                evidence[netwolf::core::makeSessionId(connection)];

            if (!flow.sniHost.empty())
                store.tlsSniCandidates.push_back(flow.sniHost);

            if (!flow.dnsName.empty())
            {
                netwolf::core::DnsCandidate candidate;
                candidate.domain = flow.dnsName;
                candidate.resolvedIp = flow.serverIp;
                candidate.observedAt = flow.lastSeen;
                candidate.fresh = true;

                store.dnsCandidates.push_back(std::move(candidate));
            }

            result.hotspotClientDevices.insert(flow.clientIp);
            connections.push_back(std::move(connection));
        }
    }

} // namespace netwolf::live