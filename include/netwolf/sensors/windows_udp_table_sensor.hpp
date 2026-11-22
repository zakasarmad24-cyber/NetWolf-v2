#pragma once

#include "outbound_sensor.hpp"

#include <netwolf/core/session_id.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

namespace netwolf::sensors {

    // ================================================================
    // NetWolf v2 - Windows UDP Table Sensor
    // Layer 1: Outbound Sensor / UDP Endpoint Support
    //
    // Purpose:
    // 1. Read UDP endpoints from Windows GetExtendedUdpTable.
    // 2. Attach PID/process context when available.
    // 3. Preserve honesty: Windows UDP table does NOT provide remote IP/port.
    // 4. Real UDP destination tracking for DNS/QUIC will be implemented later
    //    through a packet sensor or ETW/packet capture layer.
    //
    // Important:
    // This file is a UDP endpoint/process metadata collector.
    // It is NOT a full UDP remote-destination sensor.
    // ================================================================


    // ------------------------------------------------
    // UDP endpoint record
    // This is kept inside this sensor because Windows UDP table is endpoint-only.
    // ------------------------------------------------

    struct UdpEndpointRecord
    {
        std::string localIp;
        uint16_t localPort = 0;

        uint32_t pid = 0;
        std::string processName;
        std::string processPath;

        std::chrono::system_clock::time_point observedAt =
            std::chrono::system_clock::now();
    };


    // ------------------------------------------------
    // Sensor config
    // ------------------------------------------------

    struct WindowsUdpTableSensorConfig
    {
        bool skipWildcardLocalAddress = true;
        bool skipZeroLocalPort = true;

        bool resolveProcessName = true;

        // Default false:
        // Because UDP table does not contain remote destination.
        // If enabled, endpoint-only rows can be emitted as Local observations,
        // but they will not represent real outbound remote connections.
        bool emitEndpointOnlyLocalObservations = false;
    };


    // ------------------------------------------------
    // Windows UDP Table Sensor
    // ------------------------------------------------

    class WindowsUdpTableSensor final : public IOutboundSensor
    {
    public:
        explicit WindowsUdpTableSensor(
            WindowsUdpTableSensorConfig windowsConfig = {}
        );

        SensorType type() const override;

        SensorResult captureSnapshot(
            const SensorConfig& config
        ) override;

    private:
        WindowsUdpTableSensorConfig windowsConfig_;

    private:
#ifdef _WIN32
        SensorResult captureWindowsSnapshot(
            const SensorConfig& config
        );

        UdpEndpointRecord convertUdpRowToEndpoint(
            const MIB_UDPROW_OWNER_PID& row
        ) const;

        netwolf::core::ObservedConnection endpointToLocalObservation(
            const UdpEndpointRecord& endpoint
        ) const;

        netwolf::core::ProcessObservation buildProcessObservation(
            DWORD pid
        ) const;

        static std::string ipv4ToString(DWORD address);
        static uint16_t portFromNetworkOrder(DWORD port);

        static std::string queryProcessPath(DWORD pid);
        static std::string fileNameFromPath(const std::string& path);

        static bool isWildcardAddress(const std::string& ip);
#else
        SensorResult captureUnsupportedSnapshot(
            const SensorConfig& config
        );
#endif
    };


    // ------------------------------------------------
    // Inline implementation
    // ------------------------------------------------

    inline WindowsUdpTableSensor::WindowsUdpTableSensor(
        WindowsUdpTableSensorConfig windowsConfig
    )
        : windowsConfig_(windowsConfig)
    {
    }


    inline SensorType WindowsUdpTableSensor::type() const
    {
        // The global enum does not have a dedicated UDP-table value yet.
        // We keep this under LiveWindowsTcpTable family for now because it is
        // an OS table snapshot, not packet capture.
        return SensorType::LiveWindowsTcpTable;
    }


    inline SensorResult WindowsUdpTableSensor::captureSnapshot(
        const SensorConfig& config
    )
    {
#ifdef _WIN32
        return captureWindowsSnapshot(config);
#else
        return captureUnsupportedSnapshot(config);
#endif
    }


#ifdef _WIN32

    inline SensorResult WindowsUdpTableSensor::captureWindowsSnapshot(
        const SensorConfig& config
    )
    {
        SensorResult result;

        result.snapshot.sensorType = SensorType::LiveWindowsTcpTable;
        result.snapshot.status = SensorStatus::Ok;
        result.snapshot.label = config.snapshotLabel;
        result.snapshot.capturedAt = std::chrono::system_clock::now();

        DWORD bufferSize = 0;

        DWORD status = GetExtendedUdpTable(
            nullptr,
            &bufferSize,
            FALSE,
            AF_INET,
            UDP_TABLE_OWNER_PID,
            0
        );

        if (status != ERROR_INSUFFICIENT_BUFFER || bufferSize == 0)
        {
            addSensorMessage(
                result.snapshot,
                SensorStatus::Failed,
                "udp_table_size_failed",
                "Failed to calculate required UDP table buffer size.",
                "GetExtendedUdpTable did not return ERROR_INSUFFICIENT_BUFFER."
            );

            return result;
        }

        std::vector<unsigned char> buffer(bufferSize);

        auto* table = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(buffer.data());

        status = GetExtendedUdpTable(
            table,
            &bufferSize,
            FALSE,
            AF_INET,
            UDP_TABLE_OWNER_PID,
            0
        );

        if (status != NO_ERROR)
        {
            addSensorMessage(
                result.snapshot,
                SensorStatus::Failed,
                "udp_table_read_failed",
                "Failed to read Windows UDP endpoint table.",
                "GetExtendedUdpTable returned error code: " + std::to_string(status)
            );

            return result;
        }

        size_t endpointRowsSeen = 0;
        size_t endpointRowsEmitted = 0;

        for (DWORD i = 0; i < table->dwNumEntries; ++i)
        {
            const MIB_UDPROW_OWNER_PID& row = table->table[i];

            UdpEndpointRecord endpoint = convertUdpRowToEndpoint(row);

            if (windowsConfig_.skipWildcardLocalAddress &&
                isWildcardAddress(endpoint.localIp))
            {
                continue;
            }

            if (windowsConfig_.skipZeroLocalPort && endpoint.localPort == 0)
                continue;

            endpointRowsSeen++;

            if (!windowsConfig_.emitEndpointOnlyLocalObservations)
                continue;

            netwolf::core::ObservedConnection observed =
                endpointToLocalObservation(endpoint);

            if (!shouldKeepObservedConnection(observed, config))
                continue;

            result.snapshot.observedConnections.push_back(observed);
            endpointRowsEmitted++;

            if (config.attachProcessEvidence && windowsConfig_.resolveProcessName)
            {
                netwolf::core::ProcessObservation process;
                process.pid = endpoint.pid;
                process.processName = endpoint.processName;
                process.processPath = endpoint.processPath;

                const std::string sessionId =
                    netwolf::core::makeSessionId(observed);

                result.snapshot.evidence.processBySessionId[sessionId] = process;
            }
        }

        if (!windowsConfig_.emitEndpointOnlyLocalObservations)
        {
            addSensorMessage(
                result.snapshot,
                SensorStatus::Partial,
                "udp_endpoint_only_mode",
                "UDP endpoints were inspected, but no remote UDP connections were emitted.",
                "Windows UDP table does not expose remote IP/port. Use the future packet sensor for DNS/QUIC remote destination tracking. Endpoint rows seen: " +
                std::to_string(endpointRowsSeen)
            );
        }
        else if (endpointRowsEmitted == 0)
        {
            addSensorMessage(
                result.snapshot,
                SensorStatus::Partial,
                "udp_table_no_emitted_rows",
                "No UDP endpoint-only observations were emitted.",
                "This can happen because outbound-only filtering ignores Local endpoint-only records."
            );
        }

        return result;
    }


    inline UdpEndpointRecord WindowsUdpTableSensor::convertUdpRowToEndpoint(
        const MIB_UDPROW_OWNER_PID& row
    ) const
    {
        UdpEndpointRecord endpoint;

        endpoint.localIp = ipv4ToString(row.dwLocalAddr);
        endpoint.localPort = portFromNetworkOrder(row.dwLocalPort);

        endpoint.pid = static_cast<uint32_t>(row.dwOwningPid);
        endpoint.observedAt = std::chrono::system_clock::now();

        if (windowsConfig_.resolveProcessName)
        {
            const std::string path = queryProcessPath(row.dwOwningPid);
            const std::string fileName = fileNameFromPath(path);

            endpoint.processPath = path;

            if (!fileName.empty())
                endpoint.processName = fileName;
            else if (row.dwOwningPid != 0)
                endpoint.processName = "PID " + std::to_string(row.dwOwningPid);
            else
                endpoint.processName = "Process context unavailable";
        }

        return endpoint;
    }


    inline netwolf::core::ObservedConnection
        WindowsUdpTableSensor::endpointToLocalObservation(
            const UdpEndpointRecord& endpoint
        ) const
    {
        netwolf::core::ObservedConnection observed;

        observed.deviceIp = endpoint.localIp;

        observed.localIp = endpoint.localIp;
        observed.localPort = endpoint.localPort;

        // Windows UDP table does not provide remote endpoint.
        // We keep this explicit and non-deceptive.
        observed.remoteIp = "UDP remote endpoint unavailable";
        observed.remotePort = 0;

        observed.ipVersion = netwolf::core::IpVersion::IPv4;
        observed.protocol = netwolf::core::TransportProtocol::UDP;
        observed.direction = netwolf::core::TrafficDirection::Local;

        observed.firstSeen = netwolf::core::nowUtc();
        observed.lastSeen = observed.firstSeen;

        observed.bytesSent = 0;
        observed.bytesReceived = 0;
        observed.packetsSent = 0;
        observed.packetsReceived = 0;

        observed.interfaceName = "Windows UDP table endpoint-only";

        return observed;
    }


    inline netwolf::core::ProcessObservation
        WindowsUdpTableSensor::buildProcessObservation(DWORD pid) const
    {
        netwolf::core::ProcessObservation process;

        process.pid = static_cast<uint32_t>(pid);

        const std::string path = queryProcessPath(pid);
        const std::string fileName = fileNameFromPath(path);

        if (!fileName.empty())
            process.processName = fileName;
        else if (pid != 0)
            process.processName = "PID " + std::to_string(pid);
        else
            process.processName = "Process context unavailable";

        process.processPath = path;

        return process;
    }


    inline std::string WindowsUdpTableSensor::ipv4ToString(DWORD address)
    {
        IN_ADDR addr;
        addr.S_un.S_addr = address;

        char buffer[INET_ADDRSTRLEN] = {};

        const char* converted = InetNtopA(
            AF_INET,
            &addr,
            buffer,
            static_cast<DWORD>(sizeof(buffer))
        );

        if (!converted)
            return {};

        return std::string(buffer);
    }


    inline uint16_t WindowsUdpTableSensor::portFromNetworkOrder(DWORD port)
    {
        return ntohs(static_cast<u_short>(port));
    }


    inline std::string WindowsUdpTableSensor::queryProcessPath(DWORD pid)
    {
        if (pid == 0)
            return {};

        // Performance: same short-lived PID -> path cache as the TCP sensor,
        // so OpenProcess is not called for every endpoint on every refresh.
        struct CachedPath
        {
            std::string path;
            std::chrono::steady_clock::time_point at;
        };

        static std::mutex cacheMutex;
        static std::unordered_map<DWORD, CachedPath> cache;

        const auto now = std::chrono::steady_clock::now();
        const auto ttl = std::chrono::seconds(15);

        {
            std::lock_guard<std::mutex> lock(cacheMutex);

            const auto it = cache.find(pid);

            if (it != cache.end() && now - it->second.at < ttl)
                return it->second.path;
        }

        std::string result;

        HANDLE processHandle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            pid
        );

        if (processHandle)
        {
            char pathBuffer[MAX_PATH * 4] = {};
            DWORD pathSize = static_cast<DWORD>(sizeof(pathBuffer));

            const BOOL ok = QueryFullProcessImageNameA(
                processHandle,
                0,
                pathBuffer,
                &pathSize
            );

            CloseHandle(processHandle);

            if (ok && pathSize != 0)
                result.assign(pathBuffer, pathSize);
        }

        {
            std::lock_guard<std::mutex> lock(cacheMutex);

            if (cache.size() > 4096)
                cache.clear();

            cache[pid] = CachedPath{ result, now };
        }

        return result;
    }


    inline std::string WindowsUdpTableSensor::fileNameFromPath(
        const std::string& path
    )
    {
        if (path.empty())
            return {};

        const size_t pos1 = path.find_last_of('\\');
        const size_t pos2 = path.find_last_of('/');

        size_t pos = std::string::npos;

        if (pos1 == std::string::npos)
            pos = pos2;
        else if (pos2 == std::string::npos)
            pos = pos1;
        else
            pos = std::max(pos1, pos2);

        if (pos == std::string::npos)
            return path;

        if (pos + 1 >= path.size())
            return {};

        return path.substr(pos + 1);
    }


    inline bool WindowsUdpTableSensor::isWildcardAddress(const std::string& ip)
    {
        return ip.empty() ||
            ip == "0.0.0.0" ||
            ip == "::" ||
            ip == "*";
    }

#else

    inline SensorResult WindowsUdpTableSensor::captureUnsupportedSnapshot(
        const SensorConfig& config
    )
    {
        SensorResult result;

        result.snapshot.sensorType = SensorType::LiveWindowsTcpTable;
        result.snapshot.status = SensorStatus::Failed;
        result.snapshot.label = config.snapshotLabel;
        result.snapshot.capturedAt = std::chrono::system_clock::now();

        addSensorMessage(
            result.snapshot,
            SensorStatus::Failed,
            "unsupported_platform",
            "Windows UDP table sensor is only available on Windows.",
            "Compile this sensor on Windows to use GetExtendedUdpTable."
        );

        return result;
    }

#endif

} // namespace netwolf::sensors