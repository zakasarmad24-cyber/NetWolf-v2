#pragma once

#include "live_packet_metadata_sensor.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <initializer_list>
#include <sstream>
#include <string>
#include <vector>

#if defined(_WIN32) && defined(NETWOLF_HAS_NPCAP) && NETWOLF_HAS_NPCAP
#include <pcap.h>
#endif

namespace netwolf::live {

    // ================================================================
    // NetWolf v2 - Npcap Packet Metadata Sensor
    //
    // Stage 8 purpose:
    // First real packet-capture sensor skeleton.
    //
    // Current step:
    // - Verify that Npcap SDK is linked.
    // - Verify that pcap_findalldevs can see adapters.
    // - Do NOT parse packets yet.
    //
    // Later steps:
    // - Capture packet samples.
    // - Parse DNS query/answer.
    // - Parse HTTP Host.
    // - Parse TLS SNI.
    // ================================================================

    struct NpcapPacketMetadataSensorConfig
    {
        bool enabled = true;

        // For the debug message only.
        size_t maxAdapterNamesInMessage = 6;

        // Stage 8 skeleton capture settings.
        int snapLength = 65536;
        int readTimeoutMs = 100;
        bool promiscuousMode = false;

        // If non-empty, ONLY capture on adapters whose name/description
        // contains this text (case-insensitive). Use it to target the
        // Windows Mobile Hotspot adapter so the sensor sees every connected
        // device's traffic. A matching adapter is never skipped as "virtual".
        std::string preferredAdapterSubstring;

        size_t maxPacketsToRead = 80;

        // Attempts per adapter.
        // Keep this small because we may try several adapters.
        size_t maxReadAttemptsPerAdapter = 160;

        // How many adapters to try before giving up.
        size_t maxAdaptersToTry = 8;

        std::string captureFilter;

        // Skip adapters that usually do not carry normal Internet traffic.
        bool skipLikelyVirtualAdapters = true;

        // ---- Continuous capture (used by the background capture service) ----

        // If non-empty, the adapter that OWNS this IPv4 address is chosen
        // first. For Windows Mobile Hotspot this is the gateway address
        // 192.168.137.1, which picks the one active hotspot adapter even when
        // Windows lists several "Wi-Fi Direct Virtual" adapters.
        std::string preferredAdapterIpv4;

        // pcap read timeout while the adapter stays open. Small enough for a
        // quick stop(), large enough to not spin the CPU.
        int continuousReadTimeoutMs = 50;

        // Npcap kernel buffer. A larger buffer avoids dropped packets while
        // the flow table is being updated (busy hotspot / downloads).
        int kernelBufferBytes = 8 * 1024 * 1024;
    };


    // Result of one continuous-capture read batch.
    struct LivePacketCaptureBatch
    {
        // Every captured TCP/UDP IPv4 packet, reduced to its header fields.
        std::vector<LivePacketFlowSample> packets;

        // Destination identity found in those packets (DNS / TLS SNI).
        std::vector<LivePacketMetadata> identity;

        // Device names / OS labels announced in DHCP.
        std::vector<LiveDhcpObservation> dhcp;

        size_t packetsRead = 0;
        size_t timeoutReads = 0;

        // Non-empty when the adapter failed and the capture was closed.
        std::string error;
    };


    class NpcapPacketMetadataSensor final : public ILivePacketMetadataSensor
    {
    public:
        explicit NpcapPacketMetadataSensor(
            NpcapPacketMetadataSensorConfig config = {}
        );

        ~NpcapPacketMetadataSensor() override;

        // Owns an open capture handle in continuous mode: not copyable.
        NpcapPacketMetadataSensor(const NpcapPacketMetadataSensor&) = delete;
        NpcapPacketMetadataSensor& operator=(const NpcapPacketMetadataSensor&) = delete;

        std::string name() const override;

        // One-shot sampling (opens, reads a few packets, closes).
        LivePacketMetadataSensorResult captureMetadataOnce() override;

        // ---- Continuous capture: open the adapter ONCE and keep reading ----
        bool openContinuousCapture(std::string& statusMessage);

        bool continuousCaptureOpen() const;

        // Reads until maxPackets packets or timeBudgetMs elapsed.
        // Returns false if the adapter failed (the capture is then closed
        // and batch.error explains why).
        bool readContinuousBatch(
            size_t maxPackets,
            int timeBudgetMs,
            LivePacketCaptureBatch& batch
        );

        void closeContinuousCapture();

        const std::string& continuousAdapterName() const;

        // ---- Device fingerprint parsers (pure functions, no Npcap needed) ----

        // TCP SYN: OS family from initial TTL + TCP option order, and the
        // number of routers crossed (observed TTL below the initial TTL).
        static void fingerprintSyn(
            const unsigned char* tcpHeader,
            size_t tcpHeaderLength,
            uint8_t ttl,
            LiveOsFamily& family,
            uint8_t& hops
        );

        // DHCP / BOOTP payload (UDP 67/68). Returns false if not DHCP.
        static bool parseDhcp(
            const unsigned char* payload,
            size_t length,
            LiveDhcpObservation& observation
        );

    private:
        NpcapPacketMetadataSensorConfig config_;

        // pcap_t* kept as void* so this header stays usable without Npcap.
        void* continuousHandle_ = nullptr;
        int continuousDataLinkType_ = -1;
        std::string continuousAdapterText_;

    private:
#if defined(_WIN32) && defined(NETWOLF_HAS_NPCAP) && NETWOLF_HAS_NPCAP
        static bool adapterHasIpv4(
            const pcap_if_t* adapter,
            const std::string& ipv4
        );

        static bool parseFlowSample(
            const pcap_pkthdr* packetHeader,
            const unsigned char* packetData,
            int dataLinkType,
            LivePacketFlowSample& sample,
            LivePacketCaptureBatch& batch
        );

        static LivePacketEndpoint makeOrientedEndpoint(
            const std::string& sourceIp,
            uint16_t sourcePort,
            const std::string& destinationIp,
            uint16_t destinationPort,
            netwolf::core::TransportProtocol protocol
        );

        static std::string safeAdapterText(
            const pcap_if_t* adapter
        );

        static bool containsCaseInsensitive(
            const std::string& haystack,
            const std::string& needle
        );

        static void appendEndpointObservationFromPacket(
            const pcap_pkthdr* packetHeader,
            const unsigned char* packetData,
            int dataLinkType,
            std::vector<LivePacketMetadata>& output
        );

        static void appendDnsMetadataFromPacket(
            const LivePacketEndpoint& endpoint,
            const unsigned char* packetData,
            size_t length,
            size_t dnsOffset,
            std::vector<LivePacketMetadata>& output
        );

        static uint16_t readBigEndian16(
            const unsigned char* data,
            size_t offset,
            size_t length
        );

        static std::string ipv4ToString(
            const unsigned char* data,
            size_t offset,
            size_t length
        );

        static bool isPrivateIpv4(
            const std::string& ip
        );

        static bool readDnsName(
            const unsigned char* packetData,
            size_t dnsOffset,
            size_t length,
            size_t& cursor,
            std::string& outputName
        );

        static void appendTlsSniMetadataFromPacket(
            const LivePacketEndpoint& endpoint,
            const unsigned char* packetData,
            size_t length,
            size_t tcpPayloadOffset,
            std::vector<LivePacketMetadata>& output
        );

        static bool parseTlsClientHelloSni(
            const unsigned char* packetData,
            size_t length,
            size_t tlsOffset,
            std::string& sniHost
        );

        static uint32_t readBigEndian24(
            const unsigned char* data,
            size_t offset,
            size_t length
        );

#endif
    };


    inline NpcapPacketMetadataSensor::NpcapPacketMetadataSensor(
        NpcapPacketMetadataSensorConfig config
    )
        : config_(config)
    {
    }


    inline NpcapPacketMetadataSensor::~NpcapPacketMetadataSensor()
    {
        closeContinuousCapture();
    }


    inline std::string NpcapPacketMetadataSensor::name() const
    {
        return "Npcap packet metadata sensor";
    }


    inline bool NpcapPacketMetadataSensor::continuousCaptureOpen() const
    {
        return continuousHandle_ != nullptr;
    }


    inline const std::string& NpcapPacketMetadataSensor::continuousAdapterName() const
    {
        return continuousAdapterText_;
    }


    inline void NpcapPacketMetadataSensor::fingerprintSyn(
        const unsigned char* tcpHeader,
        size_t tcpHeaderLength,
        uint8_t ttl,
        LiveOsFamily& family,
        uint8_t& hops
    )
    {
        family = LiveOsFamily::Unknown;
        hops = 0;

        if (tcpHeader == nullptr || tcpHeaderLength < 20 || ttl == 0)
            return;

        // Initial TTL is the next standard value at or above the observed one.
        const int initial = ttl <= 64 ? 64 : (ttl <= 128 ? 128 : 255);
        hops = static_cast<uint8_t>(initial - ttl);

        // Option kinds in order (NOP=1, MSS=2, WS=3, SACK=4, TS=8, EOL=0).
        unsigned char kinds[16]{};
        size_t kindCount = 0;

        size_t offset = 20;

        while (offset < tcpHeaderLength && kindCount < sizeof(kinds))
        {
            const unsigned char kind = tcpHeader[offset];
            kinds[kindCount++] = kind;

            if (kind == 0)
                break;

            if (kind == 1)
            {
                ++offset;
                continue;
            }

            if (offset + 1 >= tcpHeaderLength)
                break;

            const unsigned char length = tcpHeader[offset + 1];

            if (length < 2)
                break;

            offset += length;
        }

        auto startsWith = [&](std::initializer_list<unsigned char> pattern)
            {
                if (kindCount < pattern.size())
                    return false;

                size_t index = 0;

                for (const unsigned char expected : pattern)
                {
                    if (kinds[index++] != expected)
                        return false;
                }

                return true;
            };

        if (initial == 128)
            family = LiveOsFamily::Windows;
        else if (initial == 64 && startsWith({ 2, 1, 3, 1, 1, 8, 4 }))
            family = LiveOsFamily::Apple;
        else if (initial == 64 && startsWith({ 2, 4, 8, 1, 3 }))
            family = LiveOsFamily::AndroidLinux;
        else
            family = LiveOsFamily::Other;
    }


    inline bool NpcapPacketMetadataSensor::parseDhcp(
        const unsigned char* payload,
        size_t length,
        LiveDhcpObservation& observation
    )
    {
        // BOOTP fixed header (236 bytes) + magic cookie 63 82 53 63.
        if (payload == nullptr || length < 240)
            return false;

        if (payload[236] != 0x63 || payload[237] != 0x82 ||
            payload[238] != 0x53 || payload[239] != 0x63)
        {
            return false;
        }

        const unsigned char op = payload[0];

        if (op != 1 && op != 2)
            return false;

        auto ipAt = [&](size_t offset) -> std::string
            {
                if (payload[offset] == 0 && payload[offset + 1] == 0 &&
                    payload[offset + 2] == 0 && payload[offset + 3] == 0)
                {
                    return {};
                }

                return std::to_string(payload[offset]) + "." +
                    std::to_string(payload[offset + 1]) + "." +
                    std::to_string(payload[offset + 2]) + "." +
                    std::to_string(payload[offset + 3]);
            };

        static const char* hex = "0123456789abcdef";
        observation.mac.clear();

        for (size_t index = 0; index < 6; ++index)
        {
            if (index > 0)
                observation.mac += ':';

            observation.mac += hex[payload[28 + index] >> 4];
            observation.mac += hex[payload[28 + index] & 0x0F];
        }

        observation.fromClient = op == 1;

        unsigned char messageType = 0;
        std::string requestedIp;
        std::string fqdn;

        size_t offset = 240;

        while (offset < length)
        {
            const unsigned char code = payload[offset];

            if (code == 255)
                break;

            if (code == 0)
            {
                ++offset;
                continue;
            }

            if (offset + 1 >= length)
                break;

            const size_t optionLength = payload[offset + 1];
            const size_t dataOffset = offset + 2;

            if (dataOffset + optionLength > length)
                break;

            const char* text = reinterpret_cast<const char*>(payload + dataOffset);

            switch (code)
            {
            case 53:
                if (optionLength >= 1)
                    messageType = payload[dataOffset];
                break;

            case 12:
                observation.hostName.assign(text, optionLength);
                break;

            case 60:
                observation.vendorClass.assign(text, optionLength);
                break;

            case 50:
                if (optionLength == 4)
                    requestedIp = ipAt(dataOffset);
                break;

            case 81:
                // Client FQDN: flags, rcode1, rcode2, then the name.
                if (optionLength > 3)
                    fqdn.assign(text + 3, optionLength - 3);
                break;

            default:
                break;
            }

            offset = dataOffset + optionLength;
        }

        if (observation.hostName.empty() && !fqdn.empty())
        {
            // Plain-text FQDN: keep the first label.
            const size_t dot = fqdn.find('.');
            observation.hostName = fqdn.substr(0, dot);
        }

        // Keep printable characters only.
        std::string cleaned;

        for (const char c : observation.hostName)
        {
            if (static_cast<unsigned char>(c) >= 0x20 && c != 0x7F)
                cleaned += c;
        }

        observation.hostName = cleaned;

        if (op == 1)
        {
            const std::string clientIp = ipAt(12);
            observation.ip = !clientIp.empty() ? clientIp : requestedIp;
        }
        else
        {
            // Server ACK (5) gives the address the device now owns.
            observation.ip = messageType == 5 ? ipAt(16) : std::string();
        }

        return true;
    }


    inline void NpcapPacketMetadataSensor::closeContinuousCapture()
    {
#if defined(_WIN32) && defined(NETWOLF_HAS_NPCAP) && NETWOLF_HAS_NPCAP
        if (continuousHandle_ != nullptr)
            pcap_close(static_cast<pcap_t*>(continuousHandle_));
#endif
        continuousHandle_ = nullptr;
        continuousDataLinkType_ = -1;
    }


    inline bool NpcapPacketMetadataSensor::openContinuousCapture(
        std::string& statusMessage
    )
    {
        closeContinuousCapture();
        continuousAdapterText_.clear();

        if (!config_.enabled)
        {
            statusMessage = "Npcap packet metadata sensor is disabled.";
            return false;
        }

#if defined(_WIN32) && defined(NETWOLF_HAS_NPCAP) && NETWOLF_HAS_NPCAP

        char errorBuffer[PCAP_ERRBUF_SIZE]{};
        pcap_if_t* allDevices = nullptr;

        if (pcap_findalldevs(&allDevices, errorBuffer) != 0)
        {
            statusMessage =
                std::string("pcap_findalldevs failed: ") + errorBuffer;
            return false;
        }

        // Candidate order:
        //   1. the adapter that owns preferredAdapterIpv4 (the hotspot gateway)
        //   2. adapters whose name/description contains preferredAdapterSubstring
        //   3. without any preference: every adapter that is not skipped
        std::vector<pcap_if_t*> candidates;

        const bool hasPreferredIp = !config_.preferredAdapterIpv4.empty();
        const bool hasPreferredText = !config_.preferredAdapterSubstring.empty();

        if (hasPreferredIp)
        {
            for (pcap_if_t* device = allDevices; device != nullptr; device = device->next)
            {
                if (device->name != nullptr && device->name[0] != '\0' &&
                    adapterHasIpv4(device, config_.preferredAdapterIpv4))
                {
                    candidates.push_back(device);
                }
            }
        }

        for (pcap_if_t* device = allDevices; device != nullptr; device = device->next)
        {
            if (device->name == nullptr || device->name[0] == '\0')
                continue;

            if (std::find(candidates.begin(), candidates.end(), device) != candidates.end())
                continue;

            const std::string adapterText = safeAdapterText(device);

            if (hasPreferredText)
            {
                if (containsCaseInsensitive(adapterText, config_.preferredAdapterSubstring))
                    candidates.push_back(device);

                continue;
            }

            if (hasPreferredIp)
                continue;

            if (config_.skipLikelyVirtualAdapters &&
                (adapterText.find("Wi-Fi Direct Virtual") != std::string::npos ||
                 adapterText.find("loopback") != std::string::npos ||
                 adapterText.find("Loopback") != std::string::npos))
            {
                continue;
            }

            candidates.push_back(device);
        }

        std::ostringstream tried;
        size_t attempts = 0;

        for (pcap_if_t* device : candidates)
        {
            if (attempts >= config_.maxAdaptersToTry)
                break;

            ++attempts;

            const std::string adapterText = safeAdapterText(device);

            char openErrorBuffer[PCAP_ERRBUF_SIZE]{};

            pcap_t* handle =
                pcap_open_live(
                    device->name,
                    config_.snapLength,
                    config_.promiscuousMode ? 1 : 0,
                    config_.continuousReadTimeoutMs <= 0 ? 50 : config_.continuousReadTimeoutMs,
                    openErrorBuffer
                );

            if (handle == nullptr)
            {
                tried << " [open failed: " << adapterText << ": " << openErrorBuffer << "]";
                continue;
            }

            const int dataLinkType = pcap_datalink(handle);

            if (dataLinkType != DLT_EN10MB)
            {
                tried << " [" << adapterText << ": unsupported dlt=" << dataLinkType << "]";
                pcap_close(handle);
                continue;
            }

            if (config_.kernelBufferBytes > 0)
                pcap_setbuff(handle, config_.kernelBufferBytes);

            std::string filterStatus = "no filter";

            if (!config_.captureFilter.empty())
            {
                bpf_program compiledFilter{};

                if (pcap_compile(handle, &compiledFilter, config_.captureFilter.c_str(),
                        1, PCAP_NETMASK_UNKNOWN) == 0)
                {
                    filterStatus =
                        pcap_setfilter(handle, &compiledFilter) == 0
                        ? "filter=[" + config_.captureFilter + "]"
                        : std::string("filter set failed: ") + pcap_geterr(handle);

                    pcap_freecode(&compiledFilter);
                }
                else
                {
                    filterStatus =
                        std::string("filter compile failed: ") + pcap_geterr(handle);
                }
            }

            continuousHandle_ = handle;
            continuousDataLinkType_ = dataLinkType;
            continuousAdapterText_ = adapterText;

            std::ostringstream message;
            message
                << "Continuous capture open on [" << adapterText << "], "
                << filterStatus
                << (config_.promiscuousMode ? ", promiscuous" : "")
                << ".";

            if (!tried.str().empty())
                message << " Skipped:" << tried.str();

            statusMessage = message.str();

            pcap_freealldevs(allDevices);
            return true;
        }

        pcap_freealldevs(allDevices);

        std::ostringstream message;
        message << "No capture adapter could be opened";

        if (hasPreferredIp)
            message << " (wanted the adapter that owns " << config_.preferredAdapterIpv4 << ")";

        if (hasPreferredText)
            message << " (wanted an adapter matching \"" << config_.preferredAdapterSubstring << "\")";

        message << ". Is the Mobile Hotspot turned on?";

        if (!tried.str().empty())
            message << " Tried:" << tried.str();

        statusMessage = message.str();
        return false;

#else
        statusMessage =
            "Npcap support is not enabled at build time. NETWOLF_HAS_NPCAP is 0 or missing.";
        return false;
#endif
    }


    inline bool NpcapPacketMetadataSensor::readContinuousBatch(
        size_t maxPackets,
        int timeBudgetMs,
        LivePacketCaptureBatch& batch
    )
    {
        if (continuousHandle_ == nullptr)
        {
            batch.error = "Continuous capture is not open.";
            return false;
        }

#if defined(_WIN32) && defined(NETWOLF_HAS_NPCAP) && NETWOLF_HAS_NPCAP

        pcap_t* handle = static_cast<pcap_t*>(continuousHandle_);

        const auto started = std::chrono::steady_clock::now();
        const auto budget = std::chrono::milliseconds(timeBudgetMs <= 0 ? 1 : timeBudgetMs);

        while (batch.packetsRead < maxPackets)
        {
            pcap_pkthdr* packetHeader = nullptr;
            const unsigned char* packetData = nullptr;

            const int nextResult = pcap_next_ex(handle, &packetHeader, &packetData);

            if (nextResult == 1)
            {
                if (packetHeader != nullptr && packetData != nullptr && packetHeader->caplen > 0)
                {
                    ++batch.packetsRead;

                    LivePacketFlowSample sample;

                    if (parseFlowSample(packetHeader, packetData, continuousDataLinkType_,
                            sample, batch))
                    {
                        batch.packets.push_back(std::move(sample));
                    }
                }
            }
            else if (nextResult == 0)
            {
                ++batch.timeoutReads;
            }
            else
            {
                batch.error =
                    std::string("pcap_next_ex failed on [") + continuousAdapterText_ +
                    "]: " + pcap_geterr(handle);

                closeContinuousCapture();
                return false;
            }

            if (std::chrono::steady_clock::now() - started >= budget)
                break;
        }

        return true;

#else
        (void)maxPackets;
        (void)timeBudgetMs;
        batch.error = "Npcap support is not enabled at build time.";
        return false;
#endif
    }


    inline LivePacketMetadataSensorResult
        NpcapPacketMetadataSensor::captureMetadataOnce()
    {
        LivePacketMetadataSensorResult result;

        result.sensorName = name();

        if (!config_.enabled)
        {
            result.status =
                LivePacketMetadataSensorStatus::Unavailable;

            result.message =
                "Npcap packet metadata sensor is disabled.";

            return result;
        }

#if defined(_WIN32) && defined(NETWOLF_HAS_NPCAP) && NETWOLF_HAS_NPCAP

        char errorBuffer[PCAP_ERRBUF_SIZE]{};

        pcap_if_t* allDevices = nullptr;

        const int findResult =
            pcap_findalldevs(
                &allDevices,
                errorBuffer
            );

        if (findResult != 0)
        {
            result.status =
                LivePacketMetadataSensorStatus::Failed;

            result.message =
                std::string("pcap_findalldevs failed: ") +
                errorBuffer;

            return result;
        }

        size_t adapterCount = 0;
        size_t reportedNames = 0;

        std::ostringstream message;

        message
            << "Npcap adapter enumeration succeeded. Adapters: ";

        for (pcap_if_t* device = allDevices;
            device != nullptr;
            device = device->next)
        {
            ++adapterCount;

            if (reportedNames < config_.maxAdapterNamesInMessage)
            {
                if (reportedNames > 0)
                    message << " | ";

                message << safeAdapterText(device);

                ++reportedNames;
            }
        }

        if (adapterCount == 0)
        {
            result.status =
                LivePacketMetadataSensorStatus::Partial;

            result.message =
                "Npcap is available, but no adapters were returned by pcap_findalldevs.";

            if (allDevices != nullptr)
                pcap_freealldevs(allDevices);

            return result;
        }

        if (adapterCount > reportedNames)
        {
            message
                << " | ... "
                << (adapterCount - reportedNames)
                << " more adapter(s)";
        }

        // ------------------------------------------------------------
        // Stage 8 skeleton capture:
        // Try multiple adapters until one actually reads packets.
        // This avoids stopping at inactive virtual adapters.
        // ------------------------------------------------------------
        size_t bestMetadataParsed = 0;
        std::string bestDataLinkName;
        int bestDataLinkType = -1;

        std::string bestAdapterName;
        size_t bestPacketsRead = 0;
        size_t bestReadAttempts = 0;
        size_t bestTimeoutReads = 0;

        size_t adaptersTried = 0;
        size_t adaptersOpened = 0;

        std::ostringstream triedAdapters;

        for (pcap_if_t* device = allDevices;
            device != nullptr &&
            adaptersTried < config_.maxAdaptersToTry;
            device = device->next)
        {
            if (device->name == nullptr ||
                device->name[0] == '\0')
            {
                continue;
            }

            ++adaptersTried;

            const std::string adapterText =
                safeAdapterText(device);

            // Targeting the Windows Mobile Hotspot adapter:
            // If a preferred adapter substring is set, only use adapters whose
            // name/description contains it, and never skip a matching one as
            // "virtual" (the hotspot IS a Wi-Fi Direct Virtual Adapter).
            const bool hasPreferredAdapter =
                !config_.preferredAdapterSubstring.empty();

            const bool matchesPreferredAdapter =
                hasPreferredAdapter &&
                containsCaseInsensitive(
                    adapterText,
                    config_.preferredAdapterSubstring
                );

            if (hasPreferredAdapter && !matchesPreferredAdapter)
                continue;

            if (config_.skipLikelyVirtualAdapters && !matchesPreferredAdapter)
            {
                if (adapterText.find("Wi-Fi Direct Virtual") != std::string::npos ||
                    adapterText.find("loopback") != std::string::npos ||
                    adapterText.find("Loopback") != std::string::npos)
                {
                    continue;
                }
            }

            char openErrorBuffer[PCAP_ERRBUF_SIZE]{};

            pcap_t* handle =
                pcap_open_live(
                    device->name,
                    config_.snapLength,
                    config_.promiscuousMode ? 1 : 0,
                    config_.readTimeoutMs,
                    openErrorBuffer
                );

            if (handle == nullptr)
            {
                if (adaptersTried <= 5)
                {
                    triedAdapters
                        << " [open failed: "
                        << adapterText
                        << "]";
                }

                continue;
            }

            ++adaptersOpened;

            size_t packetsRead = 0;
            size_t readAttempts = 0;
            size_t timeoutReads = 0;

            const int dataLinkType =
                pcap_datalink(handle);

            size_t metadataBeforeAdapter =
                result.metadata.size();

            std::string dataLinkName = "unknown";

            bool filterApplied = false;
            std::string filterStatus;

            if (!config_.captureFilter.empty())
            {
                bpf_program compiledFilter{};

                const int compileResult =
                    pcap_compile(
                        handle,
                        &compiledFilter,
                        config_.captureFilter.c_str(),
                        1,
                        PCAP_NETMASK_UNKNOWN
                    );

                if (compileResult == 0)
                {
                    const int setFilterResult =
                        pcap_setfilter(
                            handle,
                            &compiledFilter
                        );

                    if (setFilterResult == 0)
                    {
                        filterApplied = true;
                        filterStatus =
                            "filter applied: " + config_.captureFilter;
                    }
                    else
                    {
                        filterStatus =
                            std::string("filter set failed: ") +
                            pcap_geterr(handle);
                    }

                    pcap_freecode(&compiledFilter);
                }
                else
                {
                    filterStatus =
                        std::string("filter compile failed: ") +
                        pcap_geterr(handle);
                }
            }

            const char* dataLinkNameRaw =
                pcap_datalink_val_to_name(dataLinkType);

            if (dataLinkNameRaw != nullptr &&
                dataLinkNameRaw[0] != '\0')
            {
                dataLinkName = dataLinkNameRaw;
            }

            while (packetsRead < config_.maxPacketsToRead &&
                readAttempts < config_.maxReadAttemptsPerAdapter)
            {
                ++readAttempts;

                pcap_pkthdr* packetHeader = nullptr;
                const unsigned char* packetData = nullptr;

                const int nextResult =
                    pcap_next_ex(
                        handle,
                        &packetHeader,
                        &packetData
                    );

                if (nextResult == 1)
                {
                    if (packetHeader != nullptr &&
                        packetData != nullptr &&
                        packetHeader->caplen > 0)
                    {
                        ++packetsRead;

                        appendEndpointObservationFromPacket(
                            packetHeader,
                            packetData,
                            dataLinkType,
                            result.metadata
                        );
                    }
                }
                else if (nextResult == 0)
                {
                    ++timeoutReads;
                    continue;
                }
                else
                {
                    break;
                }
            }

            const size_t metadataAfterAdapter =
                result.metadata.size();

            const size_t metadataParsedForAdapter =
                metadataAfterAdapter - metadataBeforeAdapter;

            pcap_close(handle);

            if (adaptersTried <= 5)
            {
                triedAdapters
                    << " ["
                    << adapterText
                    << ": dlt="
                    << dataLinkType
                    << "/"
                    << dataLinkName;

                if (!config_.captureFilter.empty())
                {
                    triedAdapters
                        << ", filter="
                        << (filterApplied ? "yes" : "no");
                }

                triedAdapters
                    << ", packets="
                    << packetsRead
                    << ", metadata="
                    << metadataParsedForAdapter
                    << ", attempts="
                    << readAttempts
                    << ", timeouts="
                    << timeoutReads
                    << "]";
            }

            if (packetsRead > bestPacketsRead ||
                metadataParsedForAdapter > bestMetadataParsed)
            {
                bestPacketsRead = packetsRead;
                bestReadAttempts = readAttempts;
                bestTimeoutReads = timeoutReads;
                bestMetadataParsed = metadataParsedForAdapter;
                bestDataLinkType = dataLinkType;
                bestDataLinkName = dataLinkName;
                bestAdapterName = adapterText;
            }

            if (packetsRead > 0)
            {
                break;
            }
        }

        if (allDevices != nullptr)
            pcap_freealldevs(allDevices);

        message
            << ". Capture skeleton: adaptersTried="
            << adaptersTried
            << ", adaptersOpened="
            << adaptersOpened;

        if (!triedAdapters.str().empty())
        {
            message
                << ", tried="
                << triedAdapters.str();
        }

        if (bestAdapterName.empty())
        {
            result.status =
                LivePacketMetadataSensorStatus::Partial;

            message
                << ". No adapter could be opened for live capture.";

            result.message =
                message.str();

            return result;
        }

        if (!config_.captureFilter.empty())
        {
            message
                << ". Capture filter requested=["
                << config_.captureFilter
                << "]";
        }

        message
            << ". Best adapter=["
            << bestAdapterName
            << "], dlt="
            << bestDataLinkType
            << "/"
            << bestDataLinkName
            << ", packetsRead="
            << bestPacketsRead
            << ", metadataParsed="
            << bestMetadataParsed
            << ", readAttempts="
            << bestReadAttempts
            << ", timeouts="
            << bestTimeoutReads
            << ".";

        result.status =
            bestPacketsRead > 0
            ? LivePacketMetadataSensorStatus::Ok
            : LivePacketMetadataSensorStatus::Partial;

        result.message =
            message.str();

        // No packet metadata yet.
        // This step only proves live packet reading works.
        // result.metadata.clear();

        return result;

#else

        result.status =
            LivePacketMetadataSensorStatus::Unavailable;

        result.message =
            "Npcap support is not enabled at build time. NETWOLF_HAS_NPCAP is 0 or missing.";

        return result;

#endif
    }

#if defined(_WIN32) && defined(NETWOLF_HAS_NPCAP) && NETWOLF_HAS_NPCAP

    inline std::string NpcapPacketMetadataSensor::safeAdapterText(
        const pcap_if_t* adapter
    )
    {
        if (adapter == nullptr)
            return "unknown-adapter";

        std::ostringstream out;

        if (adapter->description != nullptr &&
            adapter->description[0] != '\0')
        {
            out << adapter->description;
        }
        else if (adapter->name != nullptr &&
            adapter->name[0] != '\0')
        {
            out << adapter->name;
        }
        else
        {
            out << "unnamed-adapter";
        }

        return out.str();
    }

    inline bool NpcapPacketMetadataSensor::containsCaseInsensitive(
        const std::string& haystack,
        const std::string& needle
    )
    {
        if (needle.empty())
            return false;

        std::string h = haystack;
        std::string n = needle;

        for (char& c : h)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

        for (char& c : n)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

        return h.find(n) != std::string::npos;
    }

    inline bool NpcapPacketMetadataSensor::adapterHasIpv4(
        const pcap_if_t* adapter,
        const std::string& ipv4
    )
    {
        if (adapter == nullptr || ipv4.empty())
            return false;

        for (const pcap_addr* address = adapter->addresses;
            address != nullptr;
            address = address->next)
        {
            if (address->addr == nullptr || address->addr->sa_family != AF_INET)
                continue;

            const auto* inet =
                reinterpret_cast<const sockaddr_in*>(address->addr);

            const auto* bytes =
                reinterpret_cast<const unsigned char*>(&inet->sin_addr);

            const std::string text =
                std::to_string(bytes[0]) + "." + std::to_string(bytes[1]) + "." +
                std::to_string(bytes[2]) + "." + std::to_string(bytes[3]);

            if (text == ipv4)
                return true;
        }

        return false;
    }


    inline LivePacketEndpoint NpcapPacketMetadataSensor::makeOrientedEndpoint(
        const std::string& sourceIp,
        uint16_t sourcePort,
        const std::string& destinationIp,
        uint16_t destinationPort,
        netwolf::core::TransportProtocol protocol
    )
    {
        // Same orientation rule as appendEndpointObservationFromPacket:
        // the private side is "local"; otherwise keep packet direction.
        LivePacketEndpoint endpoint;
        endpoint.protocol = protocol;

        if (!isPrivateIpv4(sourceIp) && isPrivateIpv4(destinationIp))
        {
            endpoint.localIp = destinationIp;
            endpoint.localPort = destinationPort;
            endpoint.remoteIp = sourceIp;
            endpoint.remotePort = sourcePort;
        }
        else
        {
            endpoint.localIp = sourceIp;
            endpoint.localPort = sourcePort;
            endpoint.remoteIp = destinationIp;
            endpoint.remotePort = destinationPort;
        }

        return endpoint;
    }


    inline bool NpcapPacketMetadataSensor::parseFlowSample(
        const pcap_pkthdr* packetHeader,
        const unsigned char* packetData,
        int dataLinkType,
        LivePacketFlowSample& sample,
        LivePacketCaptureBatch& batch
    )
    {
        std::vector<LivePacketMetadata>& identityOutput = batch.identity;

        // Light header parse for EVERY packet: no strings unless the packet
        // carries DNS, DHCP or a TLS handshake.
        if (packetHeader == nullptr || packetData == nullptr)
            return false;

        if (dataLinkType != DLT_EN10MB)
            return false;

        const size_t length = static_cast<size_t>(packetHeader->caplen);

        if (length < 14)
            return false;

        size_t ipOffset = 14;
        uint16_t etherType = readBigEndian16(packetData, 12, length);

        if (etherType == 0x8100 && length >= 18)
        {
            etherType = readBigEndian16(packetData, 16, length);
            ipOffset = 18;
        }

        if (etherType != 0x0800 || length < ipOffset + 20)
            return false;

        for (size_t index = 0; index < 6; ++index)
            sample.sourceMac[index] = packetData[6 + index];

        sample.ttl = packetData[ipOffset + 8];

        const unsigned char versionAndIhl = packetData[ipOffset];

        if ((versionAndIhl >> 4) != 4 || (versionAndIhl & 0x0F) < 5)
            return false;

        const size_t ipHeaderLength =
            static_cast<size_t>(versionAndIhl & 0x0F) * 4;

        const unsigned char protocol = packetData[ipOffset + 9];

        if (protocol != 6 && protocol != 17)
            return false;

        // Only the first fragment carries the transport header.
        const uint16_t fragmentField = readBigEndian16(packetData, ipOffset + 6, length);

        if ((fragmentField & 0x1FFF) != 0)
            return false;

        const size_t transportOffset = ipOffset + ipHeaderLength;

        if (length < transportOffset + 4)
            return false;

        auto readIp = [&](size_t offset) -> uint32_t
            {
                return (static_cast<uint32_t>(packetData[offset]) << 24) |
                    (static_cast<uint32_t>(packetData[offset + 1]) << 16) |
                    (static_cast<uint32_t>(packetData[offset + 2]) << 8) |
                    static_cast<uint32_t>(packetData[offset + 3]);
            };

        sample.sourceIp = readIp(ipOffset + 12);
        sample.destinationIp = readIp(ipOffset + 16);
        sample.sourcePort = readBigEndian16(packetData, transportOffset, length);
        sample.destinationPort = readBigEndian16(packetData, transportOffset + 2, length);

        if (sample.sourcePort == 0 || sample.destinationPort == 0)
            return false;

        sample.protocol =
            protocol == 6
            ? netwolf::core::TransportProtocol::TCP
            : netwolf::core::TransportProtocol::UDP;

        sample.wireLength = static_cast<uint32_t>(packetHeader->len);
        sample.at = netwolf::core::nowUtc();

        if (protocol == 6)
        {
            if (length < transportOffset + 20)
                return true;

            sample.tcpFlags = packetData[transportOffset + 13];

            const size_t tcpHeaderLength =
                static_cast<size_t>(packetData[transportOffset + 12] >> 4) * 4;

            // Connection start (SYN without ACK): fingerprint the sender's OS.
            if ((sample.tcpFlags & 0x12) == 0x02 &&
                tcpHeaderLength >= 20 &&
                length >= transportOffset + tcpHeaderLength)
            {
                fingerprintSyn(
                    packetData + transportOffset,
                    tcpHeaderLength,
                    sample.ttl,
                    sample.synOsFamily,
                    sample.synHops
                );
            }

            const size_t payloadOffset = transportOffset + tcpHeaderLength;

            // 0x16 = TLS handshake record: only then is the SNI parser run.
            if (tcpHeaderLength >= 20 &&
                length > payloadOffset + 5 &&
                packetData[payloadOffset] == 0x16)
            {
                const size_t before = identityOutput.size();

                appendTlsSniMetadataFromPacket(
                    makeOrientedEndpoint(
                        ipv4ToString(packetData, ipOffset + 12, length), sample.sourcePort,
                        ipv4ToString(packetData, ipOffset + 16, length), sample.destinationPort,
                        sample.protocol),
                    packetData,
                    length,
                    payloadOffset,
                    identityOutput
                );

                if (identityOutput.size() > before)
                    sample.sniHost = identityOutput.back().name;
            }

            return true;
        }

        // UDP 67/68: DHCP carries the device name and OS label.
        if ((sample.sourcePort == 68 && sample.destinationPort == 67) ||
            (sample.sourcePort == 67 && sample.destinationPort == 68))
        {
            LiveDhcpObservation observation;

            if (parseDhcp(packetData + transportOffset + 8,
                    length > transportOffset + 8 ? length - (transportOffset + 8) : 0,
                    observation))
            {
                batch.dhcp.push_back(std::move(observation));
            }

            return true;
        }

        // UDP: DNS answers name the servers every device talks to.
        if (sample.sourcePort == 53 || sample.destinationPort == 53)
        {
            const size_t dnsOffset = transportOffset + 8;

            if (length > dnsOffset)
            {
                appendDnsMetadataFromPacket(
                    makeOrientedEndpoint(
                        ipv4ToString(packetData, ipOffset + 12, length), sample.sourcePort,
                        ipv4ToString(packetData, ipOffset + 16, length), sample.destinationPort,
                        sample.protocol),
                    packetData,
                    length,
                    dnsOffset,
                    identityOutput
                );
            }
        }

        return true;
    }


    inline void NpcapPacketMetadataSensor::appendEndpointObservationFromPacket(
        const pcap_pkthdr* packetHeader,
        const unsigned char* packetData,
        int dataLinkType,
        std::vector<LivePacketMetadata>& output
    )
    {
        if (packetHeader == nullptr ||
            packetData == nullptr)
        {
            return;
        }

        const size_t length =
            static_cast<size_t>(packetHeader->caplen);

        // Stage 8 first parser supports Ethernet frames only.
        if (dataLinkType != DLT_EN10MB)
            return;

        if (length < 14)
            return;

        size_t ipOffset = 14;

        uint16_t etherType =
            readBigEndian16(
                packetData,
                12,
                length
            );

        // Optional VLAN tag.
        if (etherType == 0x8100 && length >= 18)
        {
            etherType =
                readBigEndian16(
                    packetData,
                    16,
                    length
                );

            ipOffset = 18;
        }

        // IPv4 only for this first step.
        if (etherType != 0x0800)
            return;

        if (length < ipOffset + 20)
            return;

        const unsigned char versionAndIhl =
            packetData[ipOffset];

        const unsigned char version =
            static_cast<unsigned char>(
                versionAndIhl >> 4
                );

        const unsigned char ihl =
            static_cast<unsigned char>(
                versionAndIhl & 0x0F
                );

        if (version != 4 || ihl < 5)
            return;

        const size_t ipHeaderLength =
            static_cast<size_t>(ihl) * 4;

        if (length < ipOffset + ipHeaderLength + 4)
            return;

        const unsigned char protocol =
            packetData[ipOffset + 9];

        if (protocol != 6 && protocol != 17)
            return;

        const std::string sourceIp =
            ipv4ToString(
                packetData,
                ipOffset + 12,
                length
            );

        const std::string destinationIp =
            ipv4ToString(
                packetData,
                ipOffset + 16,
                length
            );

        if (sourceIp.empty() || destinationIp.empty())
            return;

        const size_t transportOffset =
            ipOffset + ipHeaderLength;

        if (length < transportOffset + 4)
            return;

        const uint16_t sourcePort =
            readBigEndian16(
                packetData,
                transportOffset,
                length
            );

        const uint16_t destinationPort =
            readBigEndian16(
                packetData,
                transportOffset + 2,
                length
            );

        if (sourcePort == 0 || destinationPort == 0)
            return;

        LivePacketMetadata metadata;

        metadata.type =
            LivePacketMetadataType::EndpointObservation;

        metadata.confidence =
            netwolf::core::ConfidenceLevel::Medium;

        metadata.endpoint.protocol =
            protocol == 6
            ? netwolf::core::TransportProtocol::TCP
            : netwolf::core::TransportProtocol::UDP;

        const bool sourceLooksLocal =
            isPrivateIpv4(sourceIp);

        const bool destinationLooksLocal =
            isPrivateIpv4(destinationIp);

        if (sourceLooksLocal && !destinationLooksLocal)
        {
            metadata.endpoint.localIp = sourceIp;
            metadata.endpoint.localPort = sourcePort;

            metadata.endpoint.remoteIp = destinationIp;
            metadata.endpoint.remotePort = destinationPort;
        }
        else if (!sourceLooksLocal && destinationLooksLocal)
        {
            metadata.endpoint.localIp = destinationIp;
            metadata.endpoint.localPort = destinationPort;

            metadata.endpoint.remoteIp = sourceIp;
            metadata.endpoint.remotePort = sourcePort;
        }
        else
        {
            // Fallback: preserve packet direction.
            metadata.endpoint.localIp = sourceIp;
            metadata.endpoint.localPort = sourcePort;

            metadata.endpoint.remoteIp = destinationIp;
            metadata.endpoint.remotePort = destinationPort;
        }

        std::ostringstream reason;

        reason
            << "Npcap endpoint observation parsed from live IPv4 "
            << (protocol == 6 ? "TCP" : "UDP")
            << " packet: "
            << sourceIp
            << ":"
            << sourcePort
            << " -> "
            << destinationIp
            << ":"
            << destinationPort
            << ".";

        metadata.reason =
            reason.str();

        output.push_back(metadata);

        // DNS parser: UDP/53 only in this first step.
        if (protocol == 17 &&
            (sourcePort == 53 || destinationPort == 53))
        {
            const size_t dnsOffset =
                transportOffset + 8; // UDP header size

            if (length > dnsOffset)
            {
                appendDnsMetadataFromPacket(
                    metadata.endpoint,
                    packetData,
                    length,
                    dnsOffset,
                    output
                );
            }
        }

        // TLS SNI parser: TCP/443 ClientHello only in this first step.
        if (protocol == 6 &&
            (sourcePort == 443 || destinationPort == 443))
        {
            if (length >= transportOffset + 20)
            {
                const unsigned char tcpDataOffsetByte =
                    packetData[transportOffset + 12];

                const unsigned char tcpHeaderWords =
                    static_cast<unsigned char>(
                        tcpDataOffsetByte >> 4
                        );

                const size_t tcpHeaderLength =
                    static_cast<size_t>(tcpHeaderWords) * 4;

                if (tcpHeaderLength >= 20 &&
                    length > transportOffset + tcpHeaderLength)
                {
                    const size_t tcpPayloadOffset =
                        transportOffset + tcpHeaderLength;

                    appendTlsSniMetadataFromPacket(
                        metadata.endpoint,
                        packetData,
                        length,
                        tcpPayloadOffset,
                        output
                    );
                }
            }
        }
}

    inline uint16_t NpcapPacketMetadataSensor::readBigEndian16(
        const unsigned char* data,
        size_t offset,
        size_t length
    )
    {
        if (data == nullptr || offset + 1 >= length)
            return 0;

        return static_cast<uint16_t>(
            (static_cast<uint16_t>(data[offset]) << 8) |
            static_cast<uint16_t>(data[offset + 1])
            );
    }


    inline std::string NpcapPacketMetadataSensor::ipv4ToString(
        const unsigned char* data,
        size_t offset,
        size_t length
    )
    {
        if (data == nullptr || offset + 3 >= length)
            return "";

        std::ostringstream out;

        out
            << static_cast<int>(data[offset])
            << "."
            << static_cast<int>(data[offset + 1])
            << "."
            << static_cast<int>(data[offset + 2])
            << "."
            << static_cast<int>(data[offset + 3]);

        return out.str();
    }


    inline bool NpcapPacketMetadataSensor::isPrivateIpv4(
        const std::string& ip
    )
    {
        if (ip.rfind("10.", 0) == 0)
            return true;

        if (ip.rfind("192.168.", 0) == 0)
            return true;

        if (ip.rfind("127.", 0) == 0)
            return true;

        if (ip.rfind("169.254.", 0) == 0)
            return true;

        if (ip.rfind("172.", 0) == 0)
        {
            const size_t firstDot =
                ip.find('.');

            if (firstDot == std::string::npos)
                return false;

            const size_t secondDot =
                ip.find(
                    '.',
                    firstDot + 1
                );

            if (secondDot == std::string::npos)
                return false;

            try
            {
                const int secondOctet =
                    std::stoi(
                        ip.substr(
                            firstDot + 1,
                            secondDot - firstDot - 1
                        )
                    );

                return secondOctet >= 16 &&
                    secondOctet <= 31;
            }
            catch (...)
            {
                return false;
            }
        }

        return false;
    }

    inline void NpcapPacketMetadataSensor::appendDnsMetadataFromPacket(
        const LivePacketEndpoint& endpoint,
        const unsigned char* packetData,
        size_t length,
        size_t dnsOffset,
        std::vector<LivePacketMetadata>& output
    )
    {
        if (packetData == nullptr)
            return;

        if (length < dnsOffset + 12)
            return;

        const uint16_t flags =
            readBigEndian16(
                packetData,
                dnsOffset + 2,
                length
            );

        const uint16_t questionCount =
            readBigEndian16(
                packetData,
                dnsOffset + 4,
                length
            );

        const uint16_t answerCount =
            readBigEndian16(
                packetData,
                dnsOffset + 6,
                length
            );

        const bool isResponse =
            (flags & 0x8000) != 0;

        size_t cursor =
            dnsOffset + 12;

        std::vector<std::string> questionNames;

        const uint16_t maxQuestions =
            questionCount > 8
            ? 8
            : questionCount;

        for (uint16_t i = 0; i < maxQuestions; ++i)
        {
            std::string queryName;

            if (!readDnsName(
                packetData,
                dnsOffset,
                length,
                cursor,
                queryName
            ))
            {
                return;
            }

            if (cursor + 4 > length)
                return;

            const uint16_t queryType =
                readBigEndian16(
                    packetData,
                    cursor,
                    length
                );

            cursor += 4; // qtype + qclass

            if (!queryName.empty())
            {
                questionNames.push_back(queryName);

                if (!isResponse)
                {
                    LivePacketMetadata queryMetadata;

                    queryMetadata.type =
                        LivePacketMetadataType::DnsQuery;

                    queryMetadata.endpoint =
                        endpoint;

                    queryMetadata.name =
                        queryName;

                    queryMetadata.confidence =
                        netwolf::core::ConfidenceLevel::Medium;

                    std::ostringstream reason;

                    reason
                        << "Npcap DNS query parsed from live UDP/53 packet. "
                        << "Query name: "
                        << queryName
                        << ". Query type: "
                        << queryType
                        << ".";

                    queryMetadata.reason =
                        reason.str();

                    output.push_back(queryMetadata);
                }
            }
        }

        if (!isResponse)
            return;

        const uint16_t maxAnswers =
            answerCount > 24
            ? 24
            : answerCount;

        for (uint16_t i = 0; i < maxAnswers; ++i)
        {
            std::string answerName;

            if (!readDnsName(
                packetData,
                dnsOffset,
                length,
                cursor,
                answerName
            ))
            {
                return;
            }

            if (cursor + 10 > length)
                return;

            const uint16_t answerType =
                readBigEndian16(
                    packetData,
                    cursor,
                    length
                );

            const uint16_t answerClass =
                readBigEndian16(
                    packetData,
                    cursor + 2,
                    length
                );

            const uint16_t dataLength =
                readBigEndian16(
                    packetData,
                    cursor + 8,
                    length
                );

            cursor += 10;

            if (cursor + dataLength > length)
                return;

            // A record only in this first step.
            if (answerType == 1 &&
                answerClass == 1 &&
                dataLength == 4)
            {
                const std::string resolvedIp =
                    ipv4ToString(
                        packetData,
                        cursor,
                        length
                    );

                std::string domain =
                    answerName;

                if (domain.empty() &&
                    !questionNames.empty())
                {
                    domain =
                        questionNames.front();
                }

                if (!domain.empty() &&
                    !resolvedIp.empty())
                {
                    LivePacketMetadata answerMetadata;

                    answerMetadata.type =
                        LivePacketMetadataType::DnsAnswer;

                    answerMetadata.endpoint =
                        endpoint;

                    answerMetadata.name =
                        domain;

                    answerMetadata.resolvedIp =
                        resolvedIp;

                    answerMetadata.confidence =
                        netwolf::core::ConfidenceLevel::High;

                    std::ostringstream reason;

                    reason
                        << "Npcap DNS answer parsed from live UDP/53 packet. "
                        << "Domain: "
                        << domain
                        << ". Resolved IPv4: "
                        << resolvedIp
                        << ".";

                    answerMetadata.reason =
                        reason.str();

                    output.push_back(answerMetadata);
                }
            }

            cursor += dataLength;
        }
    }


    inline bool NpcapPacketMetadataSensor::readDnsName(
        const unsigned char* packetData,
        size_t dnsOffset,
        size_t length,
        size_t& cursor,
        std::string& outputName
    )
    {
        outputName.clear();

        if (packetData == nullptr ||
            cursor >= length)
        {
            return false;
        }

        std::ostringstream name;

        size_t current =
            cursor;

        size_t nextCursor =
            cursor;

        bool jumped =
            false;

        int jumps =
            0;

        while (current < length &&
            jumps < 16)
        {
            const unsigned char labelLength =
                packetData[current];

            if (labelLength == 0)
            {
                if (!jumped)
                    nextCursor = current + 1;

                cursor = nextCursor;
                outputName = name.str();

                return true;
            }

            // DNS compression pointer.
            if ((labelLength & 0xC0) == 0xC0)
            {
                if (current + 1 >= length)
                    return false;

                const uint16_t pointer =
                    static_cast<uint16_t>(
                        ((labelLength & 0x3F) << 8) |
                        packetData[current + 1]
                        );

                const size_t target =
                    dnsOffset + pointer;

                if (target >= length)
                    return false;

                if (!jumped)
                    nextCursor = current + 2;

                current = target;
                jumped = true;
                ++jumps;

                continue;
            }

            // Unsupported label form.
            if ((labelLength & 0xC0) != 0)
                return false;

            ++current;

            if (current + labelLength > length)
                return false;

            if (name.tellp() > 0)
                name << ".";

            for (size_t i = 0; i < labelLength; ++i)
            {
                const unsigned char ch =
                    packetData[current + i];

                if (ch >= 32 && ch <= 126)
                    name << static_cast<char>(ch);
                else
                    name << "-";
            }

            current += labelLength;

            if (!jumped)
                nextCursor = current;
        }

        return false;
    }

    inline void NpcapPacketMetadataSensor::appendTlsSniMetadataFromPacket(
        const LivePacketEndpoint& endpoint,
        const unsigned char* packetData,
        size_t length,
        size_t tcpPayloadOffset,
        std::vector<LivePacketMetadata>& output
    )
    {
        std::string sniHost;

        if (!parseTlsClientHelloSni(
            packetData,
            length,
            tcpPayloadOffset,
            sniHost
        ))
        {
            return;
        }

        if (sniHost.empty())
            return;

        LivePacketMetadata metadata;

        metadata.type =
            LivePacketMetadataType::TlsSni;

        metadata.endpoint =
            endpoint;

        metadata.name =
            sniHost;

        metadata.confidence =
            netwolf::core::ConfidenceLevel::High;

        std::ostringstream reason;

        reason
            << "Npcap TLS SNI parsed from live TCP/443 ClientHello packet. "
            << "SNI host: "
            << sniHost
            << ".";

        metadata.reason =
            reason.str();

        output.push_back(metadata);
    }


    inline bool NpcapPacketMetadataSensor::parseTlsClientHelloSni(
        const unsigned char* packetData,
        size_t length,
        size_t tlsOffset,
        std::string& sniHost
    )
    {
        sniHost.clear();

        if (packetData == nullptr)
            return false;

        // TLS record header:
        // content_type(1), version(2), length(2)
        if (length < tlsOffset + 5)
            return false;

        const unsigned char contentType =
            packetData[tlsOffset];

        // 0x16 = handshake
        if (contentType != 0x16)
            return false;

        const uint16_t recordLength =
            readBigEndian16(
                packetData,
                tlsOffset + 3,
                length
            );

        if (recordLength == 0)
            return false;

        const size_t handshakeOffset =
            tlsOffset + 5;

        if (length < handshakeOffset + 4)
            return false;

        const size_t recordEnd =
            tlsOffset + 5 + recordLength;

        if (recordEnd > length)
            return false;

        const unsigned char handshakeType =
            packetData[handshakeOffset];

        // 0x01 = ClientHello
        if (handshakeType != 0x01)
            return false;

        const uint32_t handshakeLength =
            readBigEndian24(
                packetData,
                handshakeOffset + 1,
                length
            );

        if (handshakeLength == 0)
            return false;

        const size_t clientHelloOffset =
            handshakeOffset + 4;

        const size_t clientHelloEnd =
            clientHelloOffset + handshakeLength;

        if (clientHelloEnd > recordEnd ||
            clientHelloEnd > length)
        {
            return false;
        }

        size_t cursor =
            clientHelloOffset;

        // legacy_version(2) + random(32)
        if (cursor + 34 > clientHelloEnd)
            return false;

        cursor += 34;

        // session_id
        if (cursor + 1 > clientHelloEnd)
            return false;

        const unsigned char sessionIdLength =
            packetData[cursor];

        cursor += 1;

        if (cursor + sessionIdLength > clientHelloEnd)
            return false;

        cursor += sessionIdLength;

        // cipher_suites
        if (cursor + 2 > clientHelloEnd)
            return false;

        const uint16_t cipherSuitesLength =
            readBigEndian16(
                packetData,
                cursor,
                length
            );

        cursor += 2;

        if (cursor + cipherSuitesLength > clientHelloEnd)
            return false;

        cursor += cipherSuitesLength;

        // compression_methods
        if (cursor + 1 > clientHelloEnd)
            return false;

        const unsigned char compressionMethodsLength =
            packetData[cursor];

        cursor += 1;

        if (cursor + compressionMethodsLength > clientHelloEnd)
            return false;

        cursor += compressionMethodsLength;

        // extensions
        if (cursor + 2 > clientHelloEnd)
            return false;

        const uint16_t extensionsLength =
            readBigEndian16(
                packetData,
                cursor,
                length
            );

        cursor += 2;

        if (cursor + extensionsLength > clientHelloEnd)
            return false;

        const size_t extensionsEnd =
            cursor + extensionsLength;

        while (cursor + 4 <= extensionsEnd)
        {
            const uint16_t extensionType =
                readBigEndian16(
                    packetData,
                    cursor,
                    length
                );

            const uint16_t extensionLength =
                readBigEndian16(
                    packetData,
                    cursor + 2,
                    length
                );

            cursor += 4;

            if (cursor + extensionLength > extensionsEnd)
                return false;

            // 0 = server_name extension
            if (extensionType == 0)
            {
                size_t serverNameCursor =
                    cursor;

                if (serverNameCursor + 2 > cursor + extensionLength)
                    return false;

                const uint16_t serverNameListLength =
                    readBigEndian16(
                        packetData,
                        serverNameCursor,
                        length
                    );

                serverNameCursor += 2;

                const size_t serverNameListEnd =
                    serverNameCursor + serverNameListLength;

                if (serverNameListEnd > cursor + extensionLength)
                    return false;

                while (serverNameCursor + 3 <= serverNameListEnd)
                {
                    const unsigned char nameType =
                        packetData[serverNameCursor];

                    const uint16_t nameLength =
                        readBigEndian16(
                            packetData,
                            serverNameCursor + 1,
                            length
                        );

                    serverNameCursor += 3;

                    if (serverNameCursor + nameLength > serverNameListEnd)
                        return false;

                    // name_type 0 = host_name
                    if (nameType == 0 && nameLength > 0)
                    {
                        std::ostringstream host;

                        for (uint16_t i = 0; i < nameLength; ++i)
                        {
                            const unsigned char ch =
                                packetData[serverNameCursor + i];

                            if (ch >= 32 && ch <= 126)
                                host << static_cast<char>(ch);
                            else
                                return false;
                        }

                        sniHost =
                            host.str();

                        return !sniHost.empty();
                    }

                    serverNameCursor += nameLength;
                }
            }

            cursor += extensionLength;
        }

        return false;
    }


    inline uint32_t NpcapPacketMetadataSensor::readBigEndian24(
        const unsigned char* data,
        size_t offset,
        size_t length
    )
    {
        if (data == nullptr || offset + 2 >= length)
            return 0;

        return
            (static_cast<uint32_t>(data[offset]) << 16) |
            (static_cast<uint32_t>(data[offset + 1]) << 8) |
            static_cast<uint32_t>(data[offset + 2]);
    }

#endif

} // namespace netwolf::live