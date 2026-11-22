#pragma once

#include "models.hpp"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <string>

namespace netwolf::core {

    // ================================================================
    // NetWolf v2 - Session ID Helpers
    // Layer: Foundation helper
    //
    // Purpose:
    // 1. Generate stable IDs for ConnectionSession.
    // 2. Generate grouping keys for similar connections.
    // 3. Avoid random IDs so the engine can track connections over time.
    // ================================================================


    // ------------------------------------------------
    // String helpers
    // ------------------------------------------------

    inline std::string trimCopy(std::string value)
    {
        auto notSpace = [](unsigned char ch)
            {
                return !std::isspace(ch);
            };

        value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
        value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());

        return value;
    }

    inline std::string lowerCopy(std::string value)
    {
        std::transform(
            value.begin(),
            value.end(),
            value.begin(),
            [](unsigned char ch)
            {
                return static_cast<char>(std::tolower(ch));
            }
        );

        return value;
    }

    inline std::string normalizeKeyPart(const std::string& value)
    {
        std::string result = trimCopy(value);
        result = lowerCopy(result);

        if (result.empty())
            return "-";

        return result;
    }


    // ------------------------------------------------
    // Enum-to-key helpers
    // ------------------------------------------------

    inline std::string protocolKey(TransportProtocol protocol)
    {
        switch (protocol)
        {
        case TransportProtocol::TCP:     return "tcp";
        case TransportProtocol::UDP:     return "udp";
        case TransportProtocol::ICMP:    return "icmp";
        case TransportProtocol::Other:   return "other";
        case TransportProtocol::Unknown: return "unknown";
        default:                         return "unknown";
        }
    }

    inline std::string directionKey(TrafficDirection direction)
    {
        switch (direction)
        {
        case TrafficDirection::Outbound: return "outbound";
        case TrafficDirection::Inbound:  return "inbound";
        case TrafficDirection::Local:    return "local";
        case TrafficDirection::Unknown:  return "unknown";
        default:                         return "unknown";
        }
    }


    // ------------------------------------------------
    // Stable FNV-1a hash
    // std::hash is not used because we want predictable IDs.
    // ------------------------------------------------

    inline uint64_t fnv1a64(const std::string& text)
    {
        constexpr uint64_t offsetBasis = 14695981039346656037ull;
        constexpr uint64_t prime = 1099511628211ull;

        uint64_t hash = offsetBasis;

        for (unsigned char ch : text)
        {
            hash ^= static_cast<uint64_t>(ch);
            hash *= prime;
        }

        return hash;
    }

    inline std::string toHex64(uint64_t value)
    {
        std::ostringstream out;
        out << std::hex << std::setw(16) << std::setfill('0') << value;
        return out.str();
    }


    // ------------------------------------------------
    // Connection session key
    // This identifies one observed connection session.
    // ------------------------------------------------

    inline std::string makeSessionRawKey(const ObservedConnection& connection)
    {
        std::ostringstream key;

        key
            << normalizeKeyPart(connection.deviceIp) << "|"
            << normalizeKeyPart(connection.localIp) << ":"
            << connection.localPort << "|"
            << normalizeKeyPart(connection.remoteIp) << ":"
            << connection.remotePort << "|"
            << protocolKey(connection.protocol) << "|"
            << directionKey(connection.direction);

        return key.str();
    }

    inline std::string makeSessionId(const ObservedConnection& connection)
    {
        const std::string rawKey = makeSessionRawKey(connection);
        return "sess_" + toHex64(fnv1a64(rawKey));
    }


    // ------------------------------------------------
    // Entity key
    // Used by the grouping layer.
    // Prefer entity name, then domain, then attribution type.
    // This helps avoid raw Unknown grouping.
    // ------------------------------------------------

    inline std::string makeEntityKey(const AttributionResult& attribution)
    {
        if (!attribution.entityName.empty())
            return normalizeKeyPart(attribution.entityName);

        if (!attribution.destinationDomain.empty())
            return normalizeKeyPart(attribution.destinationDomain);

        return normalizeKeyPart(toString(attribution.type));
    }


    // ------------------------------------------------
    // Owner process key
    // Used by grouping.
    // ------------------------------------------------

    inline std::string makeProcessKey(const AttributionResult& attribution)
    {
        if (attribution.ownerProcess.has_value())
        {
            const auto& process = attribution.ownerProcess.value();

            if (!process.processName.empty())
                return normalizeKeyPart(process.processName);

            if (process.pid != 0)
                return "pid_" + std::to_string(process.pid);
        }

        return "process_explained_unavailable";
    }


    // ------------------------------------------------
    // Time bucket helper
    // Grouping should not merge connections forever.
    // For now, the bucket is passed from outside as an integer.
    // Later the engine can calculate it from timestamps.
    // ------------------------------------------------

    inline std::string makeTimeBucketKey(uint64_t timeBucket)
    {
        return "bucket_" + std::to_string(timeBucket);
    }


    // ------------------------------------------------
    // Group raw key
    // Matches the PDF grouping idea:
    // device_ip + process_name + entity_name + category + time_window
    // ------------------------------------------------

    inline std::string makeGroupRawKey(
        const ConnectionSession& session,
        const AttributionResult& attribution,
        uint64_t timeBucket
    )
    {
        std::ostringstream key;

        key
            << normalizeKeyPart(session.observed.deviceIp) << "|"
            << makeProcessKey(attribution) << "|"
            << makeEntityKey(attribution) << "|"
            << normalizeKeyPart(attribution.category) << "|"
            << makeTimeBucketKey(timeBucket);

        return key.str();
    }

    inline std::string makeGroupId(
        const ConnectionSession& session,
        const AttributionResult& attribution,
        uint64_t timeBucket
    )
    {
        const std::string rawKey = makeGroupRawKey(session, attribution, timeBucket);
        return "grp_" + toHex64(fnv1a64(rawKey));
    }


    // ------------------------------------------------
    // Device key
    // ------------------------------------------------

    inline std::string makeDeviceKey(const std::string& deviceIp)
    {
        return normalizeKeyPart(deviceIp);
    }

} // namespace netwolf::core