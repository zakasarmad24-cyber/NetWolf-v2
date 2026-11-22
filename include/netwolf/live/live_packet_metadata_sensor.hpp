#pragma once

#include "live_packet_metadata.hpp"

#include <sstream>
#include <string>
#include <vector>

namespace netwolf::live {

    // ================================================================
    // NetWolf v2 - Live Packet Metadata Sensor Interface
    //
    // Stage 7 purpose:
    // Define a unified interface for future direct packet metadata sensors.
    //
    // Examples of future implementations:
    // - NpcapPacketMetadataSensor
    // - EtwPacketMetadataSensor
    // - WinDivertPacketMetadataSensor
    // - MockPacketMetadataSensor for tests
    //
    // Important:
    // - This file does NOT depend on Npcap.
    // - This file does NOT capture packets by itself.
    // - It only defines the contract that packet sensors must follow.
    // ================================================================

    enum class LivePacketMetadataSensorStatus
    {
        Ok,
        Partial,
        Failed,
        Unavailable
    };


    inline std::string toString(
        LivePacketMetadataSensorStatus status
    )
    {
        switch (status)
        {
        case LivePacketMetadataSensorStatus::Ok:
            return "OK";

        case LivePacketMetadataSensorStatus::Partial:
            return "Partial";

        case LivePacketMetadataSensorStatus::Failed:
            return "Failed";

        case LivePacketMetadataSensorStatus::Unavailable:
            return "Unavailable";

        default:
            return "Unknown";
        }
    }


    struct LivePacketMetadataSensorResult
    {
        LivePacketMetadataSensorStatus status =
            LivePacketMetadataSensorStatus::Unavailable;

        std::string sensorName;
        std::string message;

        std::vector<LivePacketMetadata> metadata;

        bool success() const
        {
            return status == LivePacketMetadataSensorStatus::Ok ||
                status == LivePacketMetadataSensorStatus::Partial;
        }

        std::string summaryText() const
        {
            std::ostringstream out;

            out
                << "Packet metadata sensor: "
                << (sensorName.empty() ? "unnamed" : sensorName)
                << " | status="
                << toString(status)
                << " | items="
                << metadata.size();

            if (!message.empty())
            {
                out
                    << " | "
                    << message;
            }

            return out.str();
        }
    };


    class ILivePacketMetadataSensor
    {
    public:
        virtual ~ILivePacketMetadataSensor() = default;

        virtual std::string name() const = 0;

        virtual LivePacketMetadataSensorResult captureMetadataOnce() = 0;
    };

} // namespace netwolf::live