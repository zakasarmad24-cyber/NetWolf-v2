#pragma once

#include <netwolf/core/engine.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace netwolf::sensors {

    // ================================================================
    // NetWolf v2 - Outbound Sensor Interface
    // Layer 1: Outbound Detection
    //
    // Purpose:
    // 1. Define a clean sensor contract before platform-specific code.
    // 2. Convert real observations into netwolf::core::EngineInput.
    // 3. Keep Windows/Linux/PCAP/live capture separate from the core engine.
    // 4. Preserve the PDF architecture:
    //    Sensor -> Analyzer -> Destination Resolver -> Origin Resolver
    //    -> Grouper -> Classifier
    // ================================================================


    // ------------------------------------------------
    // Sensor type
    // ------------------------------------------------

    enum class SensorType
    {
        LiveWindowsTcpTable,
        LiveWindowsPacketCapture,
        PcapFile,
        SyntheticTest,
        Unknown
    };


    inline std::string toString(SensorType type)
    {
        switch (type)
        {
        case SensorType::LiveWindowsTcpTable:
            return "Live Windows TCP table";

        case SensorType::LiveWindowsPacketCapture:
            return "Live Windows packet capture";

        case SensorType::PcapFile:
            return "PCAP file";

        case SensorType::SyntheticTest:
            return "Synthetic test";

        case SensorType::Unknown:
        default:
            return "Unknown sensor type";
        }
    }


    // ------------------------------------------------
    // Sensor status
    // ------------------------------------------------

    enum class SensorStatus
    {
        Ok,
        Partial,
        Failed
    };


    inline std::string toString(SensorStatus status)
    {
        switch (status)
        {
        case SensorStatus::Ok:
            return "OK";

        case SensorStatus::Partial:
            return "Partial";

        case SensorStatus::Failed:
            return "Failed";

        default:
            return "Failed";
        }
    }


    // ------------------------------------------------
    // Sensor warning/error record
    // ------------------------------------------------

    struct SensorMessage
    {
        SensorStatus status = SensorStatus::Ok;

        std::string code;
        std::string message;
        std::string details;
    };


    // ------------------------------------------------
    // Sensor configuration
    // ------------------------------------------------

    struct SensorConfig
    {
        // Only outbound connections should enter the engine by default.
        bool captureOutboundOnly = true;

        // Include private/local LAN destinations.
        bool includePrivateDestinations = true;

        // Include loopback connections.
        bool includeLoopback = false;

        // Attach process metadata when the platform sensor can provide it.
        bool attachProcessEvidence = true;

        // Attach DNS/cache evidence when available.
        bool attachDnsEvidence = true;

        // Minimum bytes filter.
        // 0 means do not filter by bytes.
        uint64_t minimumTotalBytes = 0;

        // Snapshot label used by logs/reports.
        std::string snapshotLabel = "live-snapshot";
    };


    // ------------------------------------------------
    // Sensor snapshot
    // ------------------------------------------------

    struct SensorSnapshot
    {
        SensorType sensorType = SensorType::Unknown;
        SensorStatus status = SensorStatus::Ok;

        std::string label;

        std::chrono::system_clock::time_point capturedAt =
            std::chrono::system_clock::now();

        std::vector<netwolf::core::ObservedConnection> observedConnections;

        netwolf::core::EngineEvidenceInput evidence;

        std::vector<SensorMessage> messages;

        bool empty() const
        {
            return observedConnections.empty();
        }

        size_t connectionCount() const
        {
            return observedConnections.size();
        }
    };


    // ------------------------------------------------
    // Sensor result
    // This is what the GUI/live runner will receive.
    // ------------------------------------------------

    struct SensorResult
    {
        SensorSnapshot snapshot;

        bool success() const
        {
            return snapshot.status == SensorStatus::Ok ||
                snapshot.status == SensorStatus::Partial;
        }

        netwolf::core::EngineInput toEngineInput() const
        {
            netwolf::core::EngineInput input;

            input.observedConnections = snapshot.observedConnections;
            input.evidence = snapshot.evidence;

            return input;
        }
    };


    // ------------------------------------------------
    // Abstract outbound sensor interface
    // ------------------------------------------------

    class IOutboundSensor
    {
    public:
        virtual ~IOutboundSensor() = default;

        virtual SensorType type() const = 0;

        virtual SensorResult captureSnapshot(
            const SensorConfig& config
        ) = 0;
    };


    // ------------------------------------------------
    // Helper functions
    // ------------------------------------------------

    inline bool isLoopbackIp(const std::string& ip)
    {
        return ip.rfind("127.", 0) == 0 ||
            ip == "::1" ||
            ip == "localhost";
    }


    inline bool isPrivateIp(const std::string& ip)
    {
        return ip.rfind("10.", 0) == 0 ||
            ip.rfind("192.168.", 0) == 0 ||
            ip.rfind("172.16.", 0) == 0 ||
            ip.rfind("172.17.", 0) == 0 ||
            ip.rfind("172.18.", 0) == 0 ||
            ip.rfind("172.19.", 0) == 0 ||
            ip.rfind("172.20.", 0) == 0 ||
            ip.rfind("172.21.", 0) == 0 ||
            ip.rfind("172.22.", 0) == 0 ||
            ip.rfind("172.23.", 0) == 0 ||
            ip.rfind("172.24.", 0) == 0 ||
            ip.rfind("172.25.", 0) == 0 ||
            ip.rfind("172.26.", 0) == 0 ||
            ip.rfind("172.27.", 0) == 0 ||
            ip.rfind("172.28.", 0) == 0 ||
            ip.rfind("172.29.", 0) == 0 ||
            ip.rfind("172.30.", 0) == 0 ||
            ip.rfind("172.31.", 0) == 0;
    }


    inline bool shouldKeepObservedConnection(
        const netwolf::core::ObservedConnection& connection,
        const SensorConfig& config
    )
    {
        if (config.captureOutboundOnly && !connection.isOutbound())
            return false;

        if (!config.includeLoopback)
        {
            if (isLoopbackIp(connection.localIp) || isLoopbackIp(connection.remoteIp))
                return false;
        }

        if (!config.includePrivateDestinations)
        {
            if (isPrivateIp(connection.remoteIp))
                return false;
        }

        if (config.minimumTotalBytes > 0 &&
            connection.totalBytes() < config.minimumTotalBytes)
        {
            return false;
        }

        return true;
    }


    inline void addSensorMessage(
        SensorSnapshot& snapshot,
        SensorStatus status,
        const std::string& code,
        const std::string& message,
        const std::string& details = {}
    )
    {
        SensorMessage item;

        item.status = status;
        item.code = code;
        item.message = message;
        item.details = details;

        snapshot.messages.push_back(item);

        if (status == SensorStatus::Failed)
        {
            snapshot.status = SensorStatus::Failed;
        }
        else if (status == SensorStatus::Partial &&
            snapshot.status == SensorStatus::Ok)
        {
            snapshot.status = SensorStatus::Partial;
        }
    }

} // namespace netwolf::sensors