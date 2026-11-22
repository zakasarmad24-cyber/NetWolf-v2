#pragma once

#include "live_packet_evidence_store.hpp"
#include "npcap_packet_metadata_sensor.hpp"

#include <netwolf/core/asn_resolver.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <chrono>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>   // GetSystemDirectoryW (hosts.ics)
#endif

namespace netwolf::live {

    // ================================================================
    // NetWolf v2 - Live Packet Capture Service
    //
    // Purpose:
    // Keep Npcap capture OUTSIDE the GUI thread.
    //
    // Architecture (continuous mode, the default):
    // - A background worker opens the hotspot adapter ONCE and keeps
    //   reading every packet (no reopen per loop, no sampling).
    // - Every packet updates a flow table:
    //       client ip:port <-> server ip:port  (+ bytes, packets, last seen)
    //   so each connected device (phone, laptop) and each of its
    //   connections is visible, not only this PC.
    // - DNS answers and TLS SNI found in the traffic are kept as identity
    //   metadata and attached to the flows (destination names).
    // - GUI / LiveEngineRunner reads a quick snapshot of the active flows.
    //
    // The older sampling mode (open, read a few packets, close) is still
    // available with continuousCapture = false.
    // ================================================================

    struct LivePacketCaptureServiceConfig
    {
        NpcapPacketMetadataSensorConfig sensorConfig;

        // Identity metadata kept (DNS / TLS SNI).
        size_t maxStoredMetadataItems = 12000;
        size_t maxStoredSensorResults = 8;

        // Sampling mode only.
        int loopSleepMs = 40;

        // ---- Continuous mode ----
        bool continuousCapture = true;

        size_t maxPacketsPerBatch = 4000;
        int batchTimeBudgetMs = 200;
        int reopenDelayMs = 2000;

        // The router (this PC) on the hotspot side. Never a client device.
        std::vector<std::string> routerIps = { "192.168.137.1" };

        // A flow is active while packets keep arriving within this window.
        int flowIdleSeconds = 45;

        // DNS lookups are one tiny flow per query: expire them sooner.
        int dnsFlowIdleSeconds = 10;

        // After TCP FIN/RST the flow stays visible this long.
        int closedFlowGraceSeconds = 5;

        // Inactive flows are forgotten after this.
        int flowRetentionSeconds = 180;

        size_t maxFlows = 20000;

        size_t maxDnsNames = 8192;
        int dnsNameTtlSeconds = 1800;

        // Device names Windows already knows for hotspot clients
        // (%SystemRoot%\System32\drivers\etc\hosts.ics), re-read this often.
        int hostsIcsRefreshSeconds = 10;

        // A device "forwards" traffic of others once this many TCP SYNs with a
        // decreased TTL were seen from it.
        size_t forwardingMinSyns = 2;
    };


    struct LivePacketCaptureServiceSnapshot
    {
        bool running = false;
        std::string statusText;

        std::vector<LivePacketMetadata> metadataItems;
        std::vector<LivePacketMetadataSensorResult> sensorResults;
        LivePacketEvidenceStoreSummary evidenceSummary;

        // Continuous mode.
        bool continuousMode = false;
        bool adapterOpen = false;
        std::string adapterName;

        std::vector<LivePacketFlow> activeFlows;
        std::vector<LiveDeviceIdentity> devices;
        size_t trackedFlows = 0;

        // Changes every time the capture is (re)started.
        uint64_t generation = 0;
        size_t activeClientDevices = 0;
        uint64_t packetsCaptured = 0;
    };


    class LivePacketCaptureService
    {
    public:
        static LivePacketCaptureService& instance();

        ~LivePacketCaptureService();

        LivePacketCaptureService(const LivePacketCaptureService&) = delete;
        LivePacketCaptureService& operator=(const LivePacketCaptureService&) = delete;

        void start(
            const LivePacketCaptureServiceConfig& config
        );

        void stop();

        bool running() const;

        LivePacketCaptureServiceSnapshot snapshot() const;

        // Feeds one batch into the flow table exactly like the capture
        // thread does. Used by the capture thread and by tests.
        void ingestBatch(
            const LivePacketCaptureBatch& batch
        );

    private:
        LivePacketCaptureService() = default;

        void workerLoop();
        void samplingLoop();
        void continuousLoop();

        void sleepWhileRunning(int milliseconds) const;

        static void appendAndTrim(
            std::vector<LivePacketMetadata>& target,
            const std::vector<LivePacketMetadata>& incoming,
            size_t maxItems
        );

        struct FlowKey
        {
            uint32_t clientIp = 0;
            uint32_t serverIp = 0;
            uint16_t clientPort = 0;
            uint16_t serverPort = 0;
            uint8_t protocol = 0;

            bool operator<(const FlowKey& other) const
            {
                if (clientIp != other.clientIp) return clientIp < other.clientIp;
                if (serverIp != other.serverIp) return serverIp < other.serverIp;
                if (clientPort != other.clientPort) return clientPort < other.clientPort;
                if (serverPort != other.serverPort) return serverPort < other.serverPort;
                return protocol < other.protocol;
            }
        };

        struct FlowState
        {
            netwolf::core::TransportProtocol protocol =
                netwolf::core::TransportProtocol::Unknown;

            netwolf::core::Timestamp firstSeen;
            netwolf::core::Timestamp lastSeen;

            // Last packet SENT by the client device. Only this keeps a flow
            // active: after a device leaves, servers keep retransmitting to
            // its old address for minutes, and those packets must not make
            // a departed device look present.
            netwolf::core::Timestamp lastClientSeen{};
            bool clientSeen = false;

            uint64_t bytesUp = 0;
            uint64_t bytesDown = 0;
            uint64_t packetsUp = 0;
            uint64_t packetsDown = 0;

            bool closing = false;
            std::string sniHost;
        };

        struct NamedIp
        {
            std::string name;
            netwolf::core::Timestamp at;
        };

        struct DeviceState
        {
            std::string mac;
            netwolf::core::Timestamp lastSeen;

            // SYN counts per LiveOsFamily (index = enum value).
            std::array<size_t, 5> ownSyns{};
            std::array<size_t, 5> forwardedSyns{};
        };

        struct DhcpInfo
        {
            std::string hostName;
            std::string vendorClass;
        };

        // All helpers below expect mutex_ to be held.
        void mergeSampleLocked(const LivePacketFlowSample& sample);
        void purgeLocked(netwolf::core::Timestamp now);
        bool flowActiveLocked(const FlowKey& key, const FlowState& flow,
            netwolf::core::Timestamp now) const;
        bool isRouterIpLocked(uint32_t ip) const;
        void clearFlowStateLocked();

        void mergeDhcpLocked(const LiveDhcpObservation& observation);
        void refreshHostsIcsLocked();
        LiveDeviceIdentity buildIdentityLocked(uint32_t ip, const DeviceState& state) const;

    public:
        // Decides the device type from the collected evidence (used by tests).
        static void decideDeviceType(LiveDeviceIdentity& identity,
            const std::array<size_t, 5>& ownSyns);

        static std::string parseHostsIcsName(const std::string& rawName);

    private:
        static bool parseIpv4(const std::string& text, uint32_t& value);
        static std::string ipv4Text(uint32_t value);
        static bool isPrivateIpv4(uint32_t ip);
        static bool isMulticastOrBroadcast(uint32_t ip);

    private:
        mutable std::mutex mutex_;
        std::atomic_bool running_{ false };
        std::thread worker_;

        LivePacketCaptureServiceConfig config_;
        std::vector<LivePacketMetadata> metadataItems_;
        std::vector<LivePacketMetadataSensorResult> sensorResults_;
        std::string statusText_ = "Packet capture service is stopped.";

        // Continuous-mode state.
        std::set<uint32_t> routerIps_;
        std::map<FlowKey, FlowState> flows_;
        std::map<std::string, NamedIp> dnsNameByIp_;
        std::map<std::string, NamedIp> sniNameByIp_;

        // Device identity.
        std::map<uint32_t, DeviceState> devices_;
        std::map<std::string, DhcpInfo> dhcpByMac_;
        std::map<std::string, std::string> macByIp_;          // from DHCP
        std::map<std::string, std::string> hostsIcsNameByIp_;
        netwolf::core::Timestamp lastHostsIcsRead_{};
        bool continuousMode_ = false;
        bool adapterOpen_ = false;
        std::string adapterName_;
        uint64_t packetsCaptured_ = 0;
        uint64_t generation_ = 0;
        netwolf::core::Timestamp lastPurge_ = netwolf::core::nowUtc();
    };


    inline LivePacketCaptureService& LivePacketCaptureService::instance()
    {
        static LivePacketCaptureService service;
        return service;
    }


    inline LivePacketCaptureService::~LivePacketCaptureService()
    {
        stop();
    }


    inline void LivePacketCaptureService::start(
        const LivePacketCaptureServiceConfig& config
    )
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);

            if (!running_.load())
            {
                config_ = config;

                routerIps_.clear();

                for (const auto& text : config_.routerIps)
                {
                    uint32_t value = 0;

                    if (parseIpv4(text, value))
                        routerIps_.insert(value);
                }
            }
        }

        bool expected = false;

        if (!running_.compare_exchange_strong(expected, true))
        {
            return;
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            ++generation_;
        }

        worker_ = std::thread(
            [this]()
            {
                workerLoop();
            }
        );
    }


    inline void LivePacketCaptureService::stop()
    {
        const bool wasRunning = running_.exchange(false);

        if (wasRunning && worker_.joinable())
        {
            worker_.join();
        }

        std::lock_guard<std::mutex> lock(mutex_);
        statusText_ = "Packet capture service is stopped.";

        // A restarted monitor must not show connections from before the stop.
        clearFlowStateLocked();
    }


    inline bool LivePacketCaptureService::running() const
    {
        return running_.load();
    }


    inline LivePacketCaptureServiceSnapshot
        LivePacketCaptureService::snapshot() const
    {
        LivePacketCaptureServiceSnapshot result;

        std::lock_guard<std::mutex> lock(mutex_);

        result.running = running_.load();
        result.statusText = statusText_;
        result.metadataItems = metadataItems_;
        result.sensorResults = sensorResults_;

        result.continuousMode = continuousMode_;
        result.adapterOpen = adapterOpen_;
        result.adapterName = adapterName_;
        result.trackedFlows = flows_.size();
        result.packetsCaptured = packetsCaptured_;
        result.generation = generation_;

        const auto now = netwolf::core::nowUtc();
        std::set<uint32_t> clients;

        for (const auto& [key, flow] : flows_)
        {
            if (!flowActiveLocked(key, flow, now))
                continue;

            LivePacketFlow out;

            out.clientIp = ipv4Text(key.clientIp);
            out.clientPort = key.clientPort;
            out.serverIp = ipv4Text(key.serverIp);
            out.serverPort = key.serverPort;
            out.protocol = flow.protocol;
            out.firstSeen = flow.firstSeen;
            out.lastSeen = flow.lastSeen;
            out.bytesUp = flow.bytesUp;
            out.bytesDown = flow.bytesDown;
            out.packetsUp = flow.packetsUp;
            out.packetsDown = flow.packetsDown;
            out.closing = flow.closing;

            out.sniHost = flow.sniHost;

            if (out.sniHost.empty())
            {
                // The ClientHello of this flow was missed (it started before
                // the capture): reuse the SNI another flow sent to this server.
                const auto sni = sniNameByIp_.find(out.serverIp);

                if (sni != sniNameByIp_.end())
                    out.sniHost = sni->second.name;
            }

            const auto dns = dnsNameByIp_.find(out.serverIp);

            if (dns != dnsNameByIp_.end())
                out.dnsName = dns->second.name;

            result.activeFlows.push_back(std::move(out));
            clients.insert(key.clientIp);
        }

        result.activeClientDevices = clients.size();

        for (const auto& [ip, state] : devices_)
        {
            if (clients.count(ip) != 0 || now - state.lastSeen <= std::chrono::seconds(config_.flowIdleSeconds))
                result.devices.push_back(buildIdentityLocked(ip, state));
        }

        LivePacketEvidenceStore store;

        for (const auto& item : result.metadataItems)
            store.add(item);

        result.evidenceSummary = store.summary();

        return result;
    }


    inline void LivePacketCaptureService::workerLoop()
    {
        bool continuous = true;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            continuous = config_.continuousCapture;
            continuousMode_ = continuous;
        }

        if (continuous)
            continuousLoop();
        else
            samplingLoop();

        std::lock_guard<std::mutex> lock(mutex_);
        adapterOpen_ = false;
    }


    inline void LivePacketCaptureService::continuousLoop()
    {
        LivePacketCaptureServiceConfig configCopy;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            configCopy = config_;
            statusText_ = "Packet capture service is starting (continuous mode).";
        }

        // ONE sensor for the whole run: the adapter stays open.
        NpcapPacketMetadataSensor sensor(configCopy.sensorConfig);

        while (running_.load())
        {
            if (!sensor.continuousCaptureOpen())
            {
                std::string openMessage;
                const bool opened = sensor.openContinuousCapture(openMessage);

                {
                    std::lock_guard<std::mutex> lock(mutex_);

                    adapterOpen_ = opened;
                    adapterName_ = opened ? sensor.continuousAdapterName() : std::string();

                    LivePacketMetadataSensorResult openResult;
                    openResult.sensorName = sensor.name() + " (continuous)";
                    openResult.status = opened
                        ? LivePacketMetadataSensorStatus::Ok
                        : LivePacketMetadataSensorStatus::Partial;
                    openResult.message = openMessage;

                    sensorResults_.push_back(std::move(openResult));

                    if (sensorResults_.size() > configCopy.maxStoredSensorResults)
                        sensorResults_.erase(sensorResults_.begin());

                    statusText_ = opened
                        ? "Packet capture service is running (continuous). " + openMessage
                        : "Packet capture service is waiting for the adapter. " + openMessage;
                }

                if (!opened)
                {
                    sleepWhileRunning(configCopy.reopenDelayMs);
                    continue;
                }
            }

            {
                std::lock_guard<std::mutex> lock(mutex_);

                if (netwolf::core::nowUtc() - lastHostsIcsRead_ >=
                    std::chrono::seconds(configCopy.hostsIcsRefreshSeconds))
                {
                    refreshHostsIcsLocked();
                }
            }

            LivePacketCaptureBatch batch;

            const bool ok =
                sensor.readContinuousBatch(
                    configCopy.maxPacketsPerBatch,
                    configCopy.batchTimeBudgetMs,
                    batch
                );

            ingestBatch(batch);

            if (!ok)
            {
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    adapterOpen_ = false;
                    statusText_ =
                        "Packet capture adapter failed; reopening. " + batch.error;
                }

                sleepWhileRunning(configCopy.reopenDelayMs);
            }
        }

        sensor.closeContinuousCapture();
    }


    inline void LivePacketCaptureService::ingestBatch(
        const LivePacketCaptureBatch& batch
    )
    {
        std::lock_guard<std::mutex> lock(mutex_);

        packetsCaptured_ += batch.packetsRead;

        for (const auto& sample : batch.packets)
            mergeSampleLocked(sample);

        for (const auto& observation : batch.dhcp)
            mergeDhcpLocked(observation);

        const auto now = netwolf::core::nowUtc();

        for (const auto& item : batch.identity)
        {
            if (item.type == LivePacketMetadataType::DnsAnswer &&
                !item.resolvedIp.empty() && !item.name.empty())
            {
                dnsNameByIp_[item.resolvedIp] = NamedIp{ item.name, now };
            }
            else if (item.type == LivePacketMetadataType::TlsSni &&
                !item.endpoint.remoteIp.empty() && !item.name.empty())
            {
                sniNameByIp_[item.endpoint.remoteIp] = NamedIp{ item.name, now };
            }
        }

        appendAndTrim(
            metadataItems_,
            batch.identity,
            config_.maxStoredMetadataItems
        );

        if (now - lastPurge_ >= std::chrono::seconds(1))
        {
            purgeLocked(now);
            lastPurge_ = now;
        }
    }


    inline void LivePacketCaptureService::mergeSampleLocked(
        const LivePacketFlowSample& sample
    )
    {
        const uint32_t src = sample.sourceIp;
        const uint32_t dst = sample.destinationIp;

        if (src == 0 || dst == 0 || src == dst)
            return;

        if (isMulticastOrBroadcast(dst) || isMulticastOrBroadcast(src))
            return;

        // DHCP (UDP 67/68) is address housekeeping between a device and the
        // router, not a user connection.
        if (sample.protocol == netwolf::core::TransportProtocol::UDP &&
            (sample.sourcePort == 67 || sample.sourcePort == 68 ||
             sample.destinationPort == 67 || sample.destinationPort == 68))
        {
            return;
        }

        const bool srcRouter = isRouterIpLocked(src);
        const bool dstRouter = isRouterIpLocked(dst);

        // Traffic of the router (this PC) itself is not a client flow.
        if (srcRouter && dstRouter)
            return;

        // Which side is the client device?
        bool sourceIsClient = true;

        if (dstRouter)
            sourceIsClient = true;             // device -> router (e.g. DNS)
        else if (srcRouter)
            sourceIsClient = false;            // router -> device
        else if (isPrivateIpv4(src) != isPrivateIpv4(dst))
            sourceIsClient = isPrivateIpv4(src);   // device <-> Internet
        else
            sourceIsClient = sample.sourcePort >= sample.destinationPort; // ephemeral port

        FlowKey key;
        key.protocol =
            sample.protocol == netwolf::core::TransportProtocol::TCP ? 6 : 17;

        if (sourceIsClient)
        {
            key.clientIp = src;
            key.clientPort = sample.sourcePort;
            key.serverIp = dst;
            key.serverPort = sample.destinationPort;
        }
        else
        {
            key.clientIp = dst;
            key.clientPort = sample.destinationPort;
            key.serverIp = src;
            key.serverPort = sample.sourcePort;
        }

        // A client device is always a LAN address. Router <-> Internet
        // packets (this PC's own traffic) end up here and are dropped.
        if (!isPrivateIpv4(key.clientIp) || isRouterIpLocked(key.clientIp))
            return;

        auto found = flows_.find(key);

        const bool tcp = key.protocol == 6;
        const bool syn = tcp && (sample.tcpFlags & 0x02) != 0;
        const bool ack = tcp && (sample.tcpFlags & 0x10) != 0;
        const bool finOrRst = tcp && (sample.tcpFlags & 0x05) != 0;

        // A new SYN on a closed 4-tuple is a NEW connection (port reuse).
        if (found != flows_.end() && found->second.closing && syn && !ack)
        {
            flows_.erase(found);
            found = flows_.end();
        }

        if (found == flows_.end())
        {
            FlowState state;
            state.protocol = sample.protocol;
            state.firstSeen = sample.at;
            state.lastSeen = sample.at;

            found = flows_.emplace(key, std::move(state)).first;
        }

        FlowState& flow = found->second;

        if (sample.at > flow.lastSeen)
            flow.lastSeen = sample.at;

        if (sourceIsClient)
        {
            flow.bytesUp += sample.wireLength;
            ++flow.packetsUp;

            if (!flow.clientSeen || sample.at > flow.lastClientSeen)
                flow.lastClientSeen = sample.at;

            flow.clientSeen = true;
        }
        else
        {
            flow.bytesDown += sample.wireLength;
            ++flow.packetsDown;
        }

        if (finOrRst)
            flow.closing = true;

        if (!sample.sniHost.empty())
            flow.sniHost = sample.sniHost;

        // ---- Device identity: only packets SENT by the client device ----
        if (sourceIsClient)
        {
            DeviceState& device = devices_[key.clientIp];
            device.lastSeen = sample.at;

            static const char* hex = "0123456789abcdef";
            std::string mac;

            for (size_t index = 0; index < 6; ++index)
            {
                if (index > 0)
                    mac += ':';

                mac += hex[sample.sourceMac[index] >> 4];
                mac += hex[sample.sourceMac[index] & 0x0F];
            }

            if (mac != "00:00:00:00:00:00")
                device.mac = mac;

            if (sample.synOsFamily != LiveOsFamily::Unknown)
            {
                const size_t family = static_cast<size_t>(sample.synOsFamily);

                if (sample.synHops == 0)
                    ++device.ownSyns[family];
                else
                    ++device.forwardedSyns[family];
            }
        }
    }


    inline void LivePacketCaptureService::mergeDhcpLocked(
        const LiveDhcpObservation& observation
    )
    {
        if (observation.mac.empty())
            return;

        if (observation.fromClient)
        {
            DhcpInfo& info = dhcpByMac_[observation.mac];

            if (!observation.hostName.empty())
                info.hostName = observation.hostName;

            if (!observation.vendorClass.empty())
                info.vendorClass = observation.vendorClass;
        }

        if (!observation.ip.empty())
            macByIp_[observation.ip] = observation.mac;
    }


    inline std::string LivePacketCaptureService::parseHostsIcsName(
        const std::string& rawName
    )
    {
        // "Galaxy-Note8.mshome.net" -> "Galaxy-Note8"
        std::string name = rawName;

        const std::string suffix = ".mshome.net";

        if (name.size() > suffix.size())
        {
            std::string tail = name.substr(name.size() - suffix.size());

            for (char& c : tail)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

            if (tail == suffix)
                name.erase(name.size() - suffix.size());
        }

        return name;
    }


    inline void LivePacketCaptureService::refreshHostsIcsLocked()
    {
        lastHostsIcsRead_ = netwolf::core::nowUtc();

        std::filesystem::path path;

        // NETWOLF_HOSTS_ICS overrides the location (used by tests).
        const std::string overridePath =
            netwolf::core::readEnvironmentVariable("NETWOLF_HOSTS_ICS");

        if (!overridePath.empty())
        {
            path = overridePath;
        }
        else
        {
#if defined(_WIN32)
            wchar_t systemDirectory[260]{};

            const UINT length = GetSystemDirectoryW(systemDirectory, 260);

            if (length == 0 || length >= 260)
                return;

            path = std::filesystem::path(systemDirectory) / L"drivers" / L"etc" / L"hosts.ics";
#else
            return;
#endif
        }

        std::ifstream in(path);

        if (!in)
            return;

        std::map<std::string, std::string> names;
        std::string line;

        while (std::getline(in, line))
        {
            const size_t hash = line.find('#');

            if (hash != std::string::npos)
                line.erase(hash);

            std::istringstream fields(line);
            std::string ip;
            std::string host;

            if (!(fields >> ip >> host))
                continue;

            uint32_t value = 0;

            if (!parseIpv4(ip, value) || isRouterIpLocked(value))
                continue;

            names[ip] = parseHostsIcsName(host);
        }

        hostsIcsNameByIp_ = std::move(names);
    }


    inline void LivePacketCaptureService::decideDeviceType(
        LiveDeviceIdentity& identity,
        const std::array<size_t, 5>& ownSyns
    )
    {
        auto lower = [](std::string text)
            {
                for (char& c : text)
                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                return text;
            };

        const std::string name = lower(identity.hostName);
        const std::string vendor = lower(identity.vendorClass);

        auto nameHas = [&](const char* token)
            {
                return name.find(token) != std::string::npos;
            };

        // 1. The device's own TCP stack (SYNs with an untouched TTL).
        size_t bestCount = 0;
        LiveOsFamily stack = LiveOsFamily::Unknown;
        size_t totalOwn = 0;

        for (size_t family = 1; family < ownSyns.size(); ++family)
        {
            totalOwn += ownSyns[family];

            if (family != static_cast<size_t>(LiveOsFamily::Other) && ownSyns[family] > bestCount)
            {
                bestCount = ownSyns[family];
                stack = static_cast<LiveOsFamily>(family);
            }
        }

        // 2. The OS label the device announced in DHCP.
        const bool dhcpAndroid = vendor.find("android") != std::string::npos;
        const bool dhcpWindows = vendor.find("msft") != std::string::npos;
        const bool dhcpLinux = vendor.find("dhcpcd") != std::string::npos ||
            vendor.find("udhcp") != std::string::npos;

        std::ostringstream evidence;

        if (stack != LiveOsFamily::Unknown)
        {
            evidence << "TCP stack " << toString(stack)
                << " (" << bestCount << " of " << totalOwn << " connection starts)";
        }

        if (!identity.vendorClass.empty())
        {
            if (evidence.tellp() > 0)
                evidence << "; ";

            evidence << "DHCP label \"" << identity.vendorClass << "\"";
        }

        if (!identity.hostName.empty())
        {
            if (evidence.tellp() > 0)
                evidence << "; ";

            evidence << "name \"" << identity.hostName << "\"";
        }

        std::string type;

        switch (stack)
        {
        case LiveOsFamily::Windows:
            type = "Windows";
            break;

        case LiveOsFamily::Apple:
            if (nameHas("iphone"))
                type = "Apple iPhone (iOS)";
            else if (nameHas("ipad"))
                type = "Apple iPad (iPadOS)";
            else if (nameHas("mac"))
                type = "Apple Mac (macOS)";
            else
                type = "Apple (iOS / macOS)";
            break;

        case LiveOsFamily::AndroidLinux:
        {
            // Phones running Android announce it in DHCP, and their default
            // names carry the maker's model name.
            const bool androidName =
                nameHas("android") || nameHas("galaxy") || nameHas("pixel") ||
                nameHas("redmi") || nameHas("xiaomi") || nameHas("huawei") ||
                nameHas("honor") || nameHas("oppo") || nameHas("vivo") ||
                nameHas("realme") || nameHas("oneplus") || nameHas("nokia") ||
                nameHas("infinix") || nameHas("tecno") || nameHas("poco");

            if (dhcpAndroid || androidName)
                type = "Android";
            else if (dhcpLinux)
                type = "Linux";
            else
                type = "Android / Linux";
            break;
        }

        default:
            // No connection start seen yet: use what the device announced.
            if (dhcpAndroid)
                type = "Android";
            else if (dhcpWindows)
                type = "Windows";
            else if (dhcpLinux)
                type = "Linux";
            else if (nameHas("iphone") || nameHas("ipad") || nameHas("macbook"))
                type = "Apple (by name)";
            else
                type = "Detecting...";
            break;
        }

        identity.deviceType = type;
        identity.typeEvidence = evidence.str().empty()
            ? "Waiting for the device to open a connection."
            : evidence.str();
    }


    inline LiveDeviceIdentity LivePacketCaptureService::buildIdentityLocked(
        uint32_t ip,
        const DeviceState& state
    ) const
    {
        LiveDeviceIdentity identity;

        identity.ip = ipv4Text(ip);
        identity.mac = state.mac;

        const auto dhcpMac = macByIp_.find(identity.ip);

        if (identity.mac.empty() && dhcpMac != macByIp_.end())
            identity.mac = dhcpMac->second;

        auto dhcp = dhcpByMac_.find(identity.mac);

        // DHCP names the hardware address the device announced; use it if the
        // frames' source address differs (e.g. a wireless driver rewrote it).
        if (dhcp == dhcpByMac_.end() && dhcpMac != macByIp_.end())
            dhcp = dhcpByMac_.find(dhcpMac->second);

        if (dhcp != dhcpByMac_.end())
        {
            identity.hostName = dhcp->second.hostName;
            identity.vendorClass = dhcp->second.vendorClass;

            if (!identity.hostName.empty())
                identity.nameSource = "DHCP";
        }

        if (identity.hostName.empty())
        {
            const auto listed = hostsIcsNameByIp_.find(identity.ip);

            if (listed != hostsIcsNameByIp_.end() && !listed->second.empty())
            {
                identity.hostName = listed->second;
                identity.nameSource = "Windows hotspot list";
            }
        }

        for (const size_t count : state.ownSyns)
            identity.ownSyns += count;

        for (size_t family = 1; family < state.forwardedSyns.size(); ++family)
        {
            const size_t count = state.forwardedSyns[family];
            identity.forwardedSyns += count;

            if (count > 0)
            {
                identity.platformsBehind.push_back(toString(static_cast<LiveOsFamily>(family)));
                identity.forwardedByPlatform[toString(static_cast<LiveOsFamily>(family))] = count;
            }
        }

        identity.forwarding =
            identity.forwardedSyns >= std::max<size_t>(1, config_.forwardingMinSyns);

        decideDeviceType(identity, state.ownSyns);

        return identity;
    }


    inline bool LivePacketCaptureService::flowActiveLocked(
        const FlowKey& key,
        const FlowState& flow,
        netwolf::core::Timestamp now
    ) const
    {
        const auto idle = now - flow.lastSeen;

        if (flow.closing)
            return idle <= std::chrono::seconds(config_.closedFlowGraceSeconds);

        // Packets only FROM the server (retransmissions, push messages to an
        // address whose device has left) do not keep the flow active. A
        // present device always answers (TCP ACK, QUIC ACK, new requests).
        if (!flow.clientSeen)
            return false;

        const auto clientIdle = now - flow.lastClientSeen;

        const bool dns =
            key.protocol == 17 && key.serverPort == 53;

        const int idleSeconds =
            dns ? std::min(config_.dnsFlowIdleSeconds, config_.flowIdleSeconds)
                : config_.flowIdleSeconds;

        return clientIdle <= std::chrono::seconds(idleSeconds);
    }


    inline void LivePacketCaptureService::purgeLocked(
        netwolf::core::Timestamp now
    )
    {
        const auto retention = std::chrono::seconds(config_.flowRetentionSeconds);
        const auto grace = std::chrono::seconds(config_.closedFlowGraceSeconds);

        for (auto it = flows_.begin(); it != flows_.end(); )
        {
            const auto idle = now - it->second.lastSeen;

            if (idle > retention || (it->second.closing && idle > grace))
                it = flows_.erase(it);
            else
                ++it;
        }

        // Hard cap: drop the least recently seen flows.
        if (config_.maxFlows > 0 && flows_.size() > config_.maxFlows)
        {
            std::vector<std::pair<netwolf::core::Timestamp, FlowKey>> byAge;
            byAge.reserve(flows_.size());

            for (const auto& [key, flow] : flows_)
                byAge.emplace_back(flow.lastSeen, key);

            const size_t removeCount = flows_.size() - config_.maxFlows;

            std::nth_element(
                byAge.begin(),
                byAge.begin() + static_cast<std::ptrdiff_t>(removeCount),
                byAge.end(),
                [](const auto& a, const auto& b) { return a.first < b.first; }
            );

            for (size_t i = 0; i < removeCount; ++i)
                flows_.erase(byAge[i].second);
        }

        auto trimNames = [&](std::map<std::string, NamedIp>& names)
            {
                const auto ttl = std::chrono::seconds(config_.dnsNameTtlSeconds);

                for (auto it = names.begin(); it != names.end(); )
                {
                    if (now - it->second.at > ttl)
                        it = names.erase(it);
                    else
                        ++it;
                }

                if (config_.maxDnsNames > 0 && names.size() > config_.maxDnsNames)
                {
                    std::vector<std::pair<netwolf::core::Timestamp, std::string>> byAge;
                    byAge.reserve(names.size());

                    for (const auto& [ip, named] : names)
                        byAge.emplace_back(named.at, ip);

                    std::sort(byAge.begin(), byAge.end(),
                        [](const auto& a, const auto& b) { return a.first < b.first; });

                    const size_t removeCount = names.size() - config_.maxDnsNames;

                    for (size_t i = 0; i < removeCount; ++i)
                        names.erase(byAge[i].second);
                }
            };

        trimNames(dnsNameByIp_);
        trimNames(sniNameByIp_);

        for (auto it = devices_.begin(); it != devices_.end(); )
        {
            if (now - it->second.lastSeen > retention)
                it = devices_.erase(it);
            else
                ++it;
        }
    }


    inline bool LivePacketCaptureService::isRouterIpLocked(uint32_t ip) const
    {
        return routerIps_.find(ip) != routerIps_.end();
    }


    inline void LivePacketCaptureService::clearFlowStateLocked()
    {
        devices_.clear();
        flows_.clear();
        dnsNameByIp_.clear();
        sniNameByIp_.clear();
        packetsCaptured_ = 0;
        adapterOpen_ = false;
    }


    inline void LivePacketCaptureService::sleepWhileRunning(int milliseconds) const
    {
        const auto until =
            std::chrono::steady_clock::now() +
            std::chrono::milliseconds(milliseconds <= 0 ? 1 : milliseconds);

        while (running_.load() && std::chrono::steady_clock::now() < until)
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }


    inline bool LivePacketCaptureService::parseIpv4(
        const std::string& text,
        uint32_t& value
    )
    {
        uint32_t result = 0;
        uint32_t octet = 0;
        int digits = 0;
        int dots = 0;

        for (const char c : text)
        {
            if (c >= '0' && c <= '9')
            {
                octet = octet * 10 + static_cast<uint32_t>(c - '0');

                if (++digits > 3 || octet > 255)
                    return false;
            }
            else if (c == '.')
            {
                if (digits == 0 || ++dots > 3)
                    return false;

                result = (result << 8) | octet;
                octet = 0;
                digits = 0;
            }
            else
            {
                return false;
            }
        }

        if (dots != 3 || digits == 0)
            return false;

        value = (result << 8) | octet;
        return true;
    }


    inline std::string LivePacketCaptureService::ipv4Text(uint32_t value)
    {
        return std::to_string((value >> 24) & 0xFF) + "." +
            std::to_string((value >> 16) & 0xFF) + "." +
            std::to_string((value >> 8) & 0xFF) + "." +
            std::to_string(value & 0xFF);
    }


    inline bool LivePacketCaptureService::isPrivateIpv4(uint32_t ip)
    {
        const uint32_t a = ip >> 24;
        const uint32_t b = (ip >> 16) & 0xFF;

        return a == 10 ||
            (a == 172 && b >= 16 && b <= 31) ||
            (a == 192 && b == 168) ||
            (a == 169 && b == 254) ||
            (a == 100 && b >= 64 && b <= 127) ||   // carrier-grade NAT
            a == 127;
    }


    inline bool LivePacketCaptureService::isMulticastOrBroadcast(uint32_t ip)
    {
        if (ip >= 0xE0000000u)   // 224.0.0.0/4 multicast and 240/4, incl. 255.255.255.255
            return true;

        // Subnet broadcast of a private /24 (e.g. 192.168.137.255).
        return isPrivateIpv4(ip) && (ip & 0xFF) == 0xFF;
    }


    // ------------------------------------------------------------
    // Sampling mode (continuousCapture = false): the original loop.
    // ------------------------------------------------------------
    inline void LivePacketCaptureService::samplingLoop()
    {
        while (running_.load())
        {
            LivePacketCaptureServiceConfig configCopy;

            {
                std::lock_guard<std::mutex> lock(mutex_);
                configCopy = config_;
                statusText_ = "Packet capture service is running.";
            }

            NpcapPacketMetadataSensor sensor(
                configCopy.sensorConfig
            );

            LivePacketMetadataSensorResult sensorResult =
                sensor.captureMetadataOnce();

            {
                std::lock_guard<std::mutex> lock(mutex_);

                appendAndTrim(
                    metadataItems_,
                    sensorResult.metadata,
                    configCopy.maxStoredMetadataItems
                );

                sensorResults_.push_back(sensorResult);

                if (sensorResults_.size() > configCopy.maxStoredSensorResults)
                {
                    const size_t removeCount =
                        sensorResults_.size() - configCopy.maxStoredSensorResults;

                    sensorResults_.erase(
                        sensorResults_.begin(),
                        sensorResults_.begin() + static_cast<std::ptrdiff_t>(removeCount)
                    );
                }

                std::ostringstream status;

                status
                    << "Packet capture service is running. Last sensor status="
                    << toString(sensorResult.status)
                    << ", new metadata="
                    << sensorResult.metadata.size()
                    << ".";

                statusText_ = status.str();
            }

            sleepWhileRunning(configCopy.loopSleepMs);
        }
    }


    inline void LivePacketCaptureService::appendAndTrim(
        std::vector<LivePacketMetadata>& target,
        const std::vector<LivePacketMetadata>& incoming,
        size_t maxItems
    )
    {
        if (incoming.empty())
            return;

        target.insert(
            target.end(),
            incoming.begin(),
            incoming.end()
        );

        if (maxItems == 0)
        {
            target.clear();
            return;
        }

        if (target.size() > maxItems)
        {
            const size_t removeCount =
                target.size() - maxItems;

            target.erase(
                target.begin(),
                target.begin() + static_cast<std::ptrdiff_t>(removeCount)
            );
        }
    }

} // namespace netwolf::live
