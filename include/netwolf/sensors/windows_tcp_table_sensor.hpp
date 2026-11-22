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
    // NetWolf v2 - Windows TCP Table Sensor
    // Layer 1: Outbound Sensor
    //
    // Purpose:
    // 1. Read active TCP connections from Windows GetExtendedTcpTable.
    // 2. Convert them into core::ObservedConnection.
    // 3. Attach PID/process evidence when available.
    // 4. Keep packet capture separate; this is OS table observation.
    //
    // Note:
    // This sensor does not inspect payload.
    // It does not extract TLS SNI or HTTP Host.
    // It provides connection endpoints + PID/process context.
    // ================================================================


    // ------------------------------------------------
    // Sensor config
    // ------------------------------------------------

    struct WindowsTcpTableSensorConfig
    {
        bool includeEstablished = true;
        bool includeSynSent = false;
        bool includeCloseWait = false;

        bool skipZeroRemoteAddress = true;
        bool skipZeroRemotePort = true;

        bool resolveProcessName = true;

    };


    // ------------------------------------------------
    // Windows TCP Table Sensor
    // ------------------------------------------------

    class WindowsTcpTableSensor final : public IOutboundSensor
    {
    public:
        explicit WindowsTcpTableSensor(
            WindowsTcpTableSensorConfig windowsConfig = {}
        );

        SensorType type() const override;

        SensorResult captureSnapshot(
            const SensorConfig& config
        ) override;

    private:
        WindowsTcpTableSensorConfig windowsConfig_;

    private:
#ifdef _WIN32
        SensorResult captureWindowsSnapshot(
            const SensorConfig& config
        );

        bool shouldKeepTcpState(DWORD state) const;

        netwolf::core::ObservedConnection convertTcpRow(
            const MIB_TCPROW_OWNER_PID& row
        ) const;

        netwolf::core::ProcessObservation buildProcessObservation(
            DWORD pid
        ) const;

        static std::string ipv4ToString(DWORD address);
        static uint16_t portFromNetworkOrder(DWORD port);
        static std::string tcpStateToString(DWORD state);

        static std::string queryProcessPath(DWORD pid);
        static std::string fileNameFromPath(const std::string& path);
#else
        SensorResult captureUnsupportedSnapshot(
            const SensorConfig& config
        );
#endif
    };


    // ------------------------------------------------
    // Inline implementation
    // ------------------------------------------------

    inline WindowsTcpTableSensor::WindowsTcpTableSensor(
        WindowsTcpTableSensorConfig windowsConfig
    )
        : windowsConfig_(windowsConfig)
    {
    }


    inline SensorType WindowsTcpTableSensor::type() const
    {
        return SensorType::LiveWindowsTcpTable;
    }


    inline SensorResult WindowsTcpTableSensor::captureSnapshot(
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

    inline SensorResult WindowsTcpTableSensor::captureWindowsSnapshot(
        const SensorConfig& config
    )
    {
        SensorResult result;

        result.snapshot.sensorType = SensorType::LiveWindowsTcpTable;
        result.snapshot.status = SensorStatus::Ok;
        result.snapshot.label = config.snapshotLabel;
        result.snapshot.capturedAt = std::chrono::system_clock::now();

        DWORD bufferSize = 0;

        DWORD status = GetExtendedTcpTable(
            nullptr,
            &bufferSize,
            FALSE,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0
        );

        if (status != ERROR_INSUFFICIENT_BUFFER || bufferSize == 0)
        {
            addSensorMessage(
                result.snapshot,
                SensorStatus::Failed,
                "tcp_table_size_failed",
                "Failed to calculate required TCP table buffer size.",
                "GetExtendedTcpTable did not return ERROR_INSUFFICIENT_BUFFER."
            );

            return result;
        }

        std::vector<unsigned char> buffer(bufferSize);

        auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());

        status = GetExtendedTcpTable(
            table,
            &bufferSize,
            FALSE,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0
        );

        if (status != NO_ERROR)
        {
            addSensorMessage(
                result.snapshot,
                SensorStatus::Failed,
                "tcp_table_read_failed",
                "Failed to read Windows TCP connection table.",
                "GetExtendedTcpTable returned error code: " + std::to_string(status)
            );

            return result;
        }

        for (DWORD i = 0; i < table->dwNumEntries; ++i)
        {
            const MIB_TCPROW_OWNER_PID& row = table->table[i];

            if (!shouldKeepTcpState(row.dwState))
                continue;

            netwolf::core::ObservedConnection observed = convertTcpRow(row);

            if (windowsConfig_.skipZeroRemoteAddress &&
                (observed.remoteIp.empty() || observed.remoteIp == "0.0.0.0"))
            {
                continue;
            }

            if (windowsConfig_.skipZeroRemotePort && observed.remotePort == 0)
                continue;

            if (!shouldKeepObservedConnection(observed, config))
                continue;

            result.snapshot.observedConnections.push_back(observed);

            const std::string sessionId =
                netwolf::core::makeSessionId(observed);

            if (config.attachProcessEvidence && windowsConfig_.resolveProcessName)
            {
                netwolf::core::ProcessObservation process =
                    buildProcessObservation(row.dwOwningPid);

                result.snapshot.evidence.processBySessionId[sessionId] = process;
            }
        }

        if (result.snapshot.observedConnections.empty())
        {
            addSensorMessage(
                result.snapshot,
                SensorStatus::Partial,
                "tcp_table_empty",
                "No TCP connections were captured in this snapshot.",
                "This can be normal if no active TCP connections exist at capture time."
            );
        }

        return result;
    }


    inline bool WindowsTcpTableSensor::shouldKeepTcpState(DWORD state) const
    {
        switch (state)
        {
        case MIB_TCP_STATE_ESTAB:
            return windowsConfig_.includeEstablished;

        case MIB_TCP_STATE_SYN_SENT:
            return windowsConfig_.includeSynSent;

        case MIB_TCP_STATE_CLOSE_WAIT:
            return windowsConfig_.includeCloseWait;

        default:
            return false;
        }
    }


    inline netwolf::core::ObservedConnection WindowsTcpTableSensor::convertTcpRow(
        const MIB_TCPROW_OWNER_PID& row
    ) const
    {
        netwolf::core::ObservedConnection observed;

        observed.localIp = ipv4ToString(row.dwLocalAddr);
        observed.localPort = portFromNetworkOrder(row.dwLocalPort);

        observed.remoteIp = ipv4ToString(row.dwRemoteAddr);
        observed.remotePort = portFromNetworkOrder(row.dwRemotePort);

        // In this engine design, the observed device is the local endpoint.
        observed.deviceIp = observed.localIp;

        observed.ipVersion = netwolf::core::IpVersion::IPv4;
        observed.protocol = netwolf::core::TransportProtocol::TCP;
        observed.direction = netwolf::core::TrafficDirection::Outbound;
        observed.transportState = tcpStateToString(row.dwState);

        observed.firstSeen = netwolf::core::nowUtc();
        observed.lastSeen = observed.firstSeen;

        // Windows TCP table does not provide per-row byte counters here.
        // Packet/byte counters can be added later by packet capture sensor.
        observed.bytesSent = 0;
        observed.bytesReceived = 0;
        observed.packetsSent = 0;
        observed.packetsReceived = 0;

        observed.interfaceName = "Windows TCP table";

        return observed;
    }


    inline netwolf::core::ProcessObservation
        WindowsTcpTableSensor::buildProcessObservation(DWORD pid) const
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


    inline std::string WindowsTcpTableSensor::ipv4ToString(DWORD address)
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


    inline uint16_t WindowsTcpTableSensor::portFromNetworkOrder(DWORD port)
    {
        return ntohs(static_cast<u_short>(port));
    }


    inline std::string WindowsTcpTableSensor::tcpStateToString(DWORD state)
    {
        switch (state)
        {
        case MIB_TCP_STATE_CLOSED:     return "CLOSED";
        case MIB_TCP_STATE_LISTEN:     return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT:   return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:   return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB:      return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1:  return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2:  return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING:    return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK:   return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:  return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
        default:                       return "UNKNOWN_TCP_STATE";
        }
    }


    inline std::string WindowsTcpTableSensor::queryProcessPath(DWORD pid)
    {
        if (pid == 0)
            return {};

        // Performance: OpenProcess + QueryFullProcessImageName is expensive and
        // used to run for EVERY connection on EVERY refresh. Cache the result
        // per PID for a short time (failures too, so protected processes are
        // not re-opened every second). The short TTL limits PID-reuse errors.
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


    inline std::string WindowsTcpTableSensor::fileNameFromPath(
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

#else

    inline SensorResult WindowsTcpTableSensor::captureUnsupportedSnapshot(
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
            "Windows TCP table sensor is only available on Windows.",
            "Compile this sensor on Windows to use GetExtendedTcpTable."
        );

        return result;
    }

#endif

} // namespace netwolf::sensors