#pragma once

#include "live_packet_metadata_sensor.hpp"

#include <string>
#include <vector>

namespace netwolf::live {

    // ================================================================
    // NetWolf v2 - Mock Packet Metadata Sensor
    //
    // Stage 7 purpose:
    // Test packet-evidence ingestion without Npcap / ETW / WinDivert.
    //
    // Important:
    // - This is NOT real packet capture.
    // - This should only be enabled for debug/testing.
    // - It proves that the packet metadata path works before adding Npcap.
    // ================================================================

    struct MockPacketMetadataSensorConfig
    {
        bool enabled = true;

        std::string localIp = "192.168.1.10";
        std::string remoteIp = "93.184.216.34";

        uint16_t localPort = 52000;
        uint16_t remotePort = 443;

        std::string domain = "example.com";
        std::string httpHost = "example.com";
        std::string tlsSni = "example.com";
    };


    class MockPacketMetadataSensor final : public ILivePacketMetadataSensor
    {
    public:
        explicit MockPacketMetadataSensor(
            MockPacketMetadataSensorConfig config = {}
        );

        std::string name() const override;

        LivePacketMetadataSensorResult captureMetadataOnce() override;

    private:
        MockPacketMetadataSensorConfig config_;

    private:
        LivePacketEndpoint makeEndpoint() const;
    };


    inline MockPacketMetadataSensor::MockPacketMetadataSensor(
        MockPacketMetadataSensorConfig config
    )
        : config_(config)
    {
    }


    inline std::string MockPacketMetadataSensor::name() const
    {
        return "Mock packet metadata sensor";
    }


    inline LivePacketMetadataSensorResult
        MockPacketMetadataSensor::captureMetadataOnce()
    {
        LivePacketMetadataSensorResult result;

        result.sensorName = name();

        if (!config_.enabled)
        {
            result.status =
                LivePacketMetadataSensorStatus::Unavailable;

            result.message =
                "Mock packet metadata sensor is disabled.";

            return result;
        }

        result.status =
            LivePacketMetadataSensorStatus::Ok;

        result.message =
            "Mock packet metadata generated for Stage 7 packet-evidence path testing.";

        const LivePacketEndpoint endpoint =
            makeEndpoint();

        // DNS query
        LivePacketMetadata dnsQuery;
        dnsQuery.type = LivePacketMetadataType::DnsQuery;
        dnsQuery.endpoint = endpoint;
        dnsQuery.name = config_.domain;
        dnsQuery.reason =
            "Mock DNS query metadata for packet evidence path test.";
        dnsQuery.confidence =
            netwolf::core::ConfidenceLevel::High;

        result.metadata.push_back(dnsQuery);

        // DNS answer
        LivePacketMetadata dnsAnswer;
        dnsAnswer.type = LivePacketMetadataType::DnsAnswer;
        dnsAnswer.endpoint = endpoint;
        dnsAnswer.name = config_.domain;
        dnsAnswer.resolvedIp = config_.remoteIp;
        dnsAnswer.reason =
            "Mock DNS answer metadata for packet evidence path test.";
        dnsAnswer.confidence =
            netwolf::core::ConfidenceLevel::High;

        result.metadata.push_back(dnsAnswer);

        // HTTP Host
        LivePacketMetadata httpHost;
        httpHost.type = LivePacketMetadataType::HttpHost;
        httpHost.endpoint = endpoint;
        httpHost.name = config_.httpHost;
        httpHost.reason =
            "Mock HTTP Host metadata for packet evidence path test.";
        httpHost.confidence =
            netwolf::core::ConfidenceLevel::High;

        result.metadata.push_back(httpHost);

        // TLS SNI
        LivePacketMetadata tlsSni;
        tlsSni.type = LivePacketMetadataType::TlsSni;
        tlsSni.endpoint = endpoint;
        tlsSni.name = config_.tlsSni;
        tlsSni.reason =
            "Mock TLS SNI metadata for packet evidence path test.";
        tlsSni.confidence =
            netwolf::core::ConfidenceLevel::High;

        result.metadata.push_back(tlsSni);

        // Endpoint observation
        LivePacketMetadata endpointObservation;
        endpointObservation.type =
            LivePacketMetadataType::EndpointObservation;
        endpointObservation.endpoint = endpoint;
        endpointObservation.reason =
            "Mock endpoint observation for packet evidence path test.";
        endpointObservation.confidence =
            netwolf::core::ConfidenceLevel::Medium;

        result.metadata.push_back(endpointObservation);

        return result;
    }


    inline LivePacketEndpoint MockPacketMetadataSensor::makeEndpoint() const
    {
        LivePacketEndpoint endpoint;

        endpoint.localIp = config_.localIp;
        endpoint.localPort = config_.localPort;

        endpoint.remoteIp = config_.remoteIp;
        endpoint.remotePort = config_.remotePort;

        endpoint.protocol =
            netwolf::core::TransportProtocol::TCP;

        return endpoint;
    }

} // namespace netwolf::live