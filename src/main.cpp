#include "../include/netwolf/core/engine.hpp"

#include <chrono>
#include <iostream>
#include <string>
#include <vector>

using namespace netwolf::core;


// ================================================================
// NetWolf v2 - Engine Test Main
//
// This file does NOT capture real network traffic yet.
// It creates simulated outbound connections to test the engine:
//
// 1. Normal device
// 2. Heavy device
// 3. Redflag device
//
// Goal:
// Verify that the core engine pipeline works before GUI/Sensor work.
// ================================================================


static Timestamp makeTimeOffsetSeconds(int seconds)
{
    return nowUtc() + std::chrono::seconds(seconds);
}


static ObservedConnection makeOutboundConnection(
    const std::string& deviceIp,
    const std::string& localIp,
    uint16_t localPort,
    const std::string& remoteIp,
    uint16_t remotePort,
    TransportProtocol protocol,
    uint64_t bytesSent,
    uint64_t bytesReceived,
    int timeOffsetSeconds
)
{
    ObservedConnection c;

    c.deviceIp = deviceIp;

    c.localIp = localIp;
    c.localPort = localPort;

    c.remoteIp = remoteIp;
    c.remotePort = remotePort;

    c.ipVersion = IpVersion::IPv4;
    c.protocol = protocol;
    c.direction = TrafficDirection::Outbound;

    c.firstSeen = makeTimeOffsetSeconds(timeOffsetSeconds);
    c.lastSeen = makeTimeOffsetSeconds(timeOffsetSeconds + 3);

    c.bytesSent = bytesSent;
    c.bytesReceived = bytesReceived;

    c.packetsSent = 10;
    c.packetsReceived = 20;

    c.interfaceName = "test-interface";

    return c;
}


static void attachSniEvidence(
    EngineEvidenceInput& evidence,
    const ObservedConnection& connection,
    const std::string& sni
)
{
    const std::string sessionId = makeSessionId(connection);

    EvidenceStore store;
    store.tlsSniCandidates.push_back(sni);

    evidence.evidenceBySessionId[sessionId] = store;
}


static void attachDnsEvidence(
    EngineEvidenceInput& evidence,
    const ObservedConnection& connection,
    const std::string& domain,
    bool fresh
)
{
    const std::string sessionId = makeSessionId(connection);

    DnsCandidate dns;
    dns.domain = domain;
    dns.resolvedIp = connection.remoteIp;
    dns.fresh = fresh;
    dns.observedAt = connection.firstSeen;

    evidence.evidenceBySessionId[sessionId].dnsCandidates.push_back(dns);
}


static void attachProcessEvidence(
    EngineEvidenceInput& evidence,
    const ObservedConnection& connection,
    uint32_t pid,
    const std::string& processName,
    const std::string& processPath
)
{
    const std::string sessionId = makeSessionId(connection);

    ProcessObservation process;
    process.pid = pid;
    process.processName = processName;
    process.processPath = processPath;

    evidence.processBySessionId[sessionId] = process;
}


static void addNormalDeviceTraffic(
    std::vector<ObservedConnection>& observed,
    EngineEvidenceInput& evidence
)
{
    const std::string deviceIp = "192.168.1.10";
    const std::string localIp = "192.168.1.10";

    std::vector<std::string> domains = {
        "google.com",
        "youtube.com",
        "github.com",
        "facebook.com",
        "cloudflare.com",
        "microsoft.com"
    };

    for (size_t i = 0; i < domains.size(); ++i)
    {
        ObservedConnection c = makeOutboundConnection(
            deviceIp,
            localIp,
            static_cast<uint16_t>(50000 + i),
            "142.250.0." + std::to_string(10 + i),
            443,
            TransportProtocol::TCP,
            2000,
            8000,
            static_cast<int>(i * 5)
        );

        attachSniEvidence(evidence, c, domains[i]);
        attachProcessEvidence(
            evidence,
            c,
            1200,
            "chrome.exe",
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
        );

        observed.push_back(c);
    }
}


static void addHeavyDeviceTraffic(
    std::vector<ObservedConnection>& observed,
    EngineEvidenceInput& evidence
)
{
    const std::string deviceIp = "192.168.1.20";
    const std::string localIp = "192.168.1.20";

    // Heavy but explainable:
    // many connections to one dominant service/entity, like video/download/update.
    for (int i = 0; i < 45; ++i)
    {
        ObservedConnection c = makeOutboundConnection(
            deviceIp,
            localIp,
            static_cast<uint16_t>(51000 + i),
            "172.217.10." + std::to_string((i % 40) + 1),
            443,
            TransportProtocol::TCP,
            1000000,
            4000000,
            i
        );

        attachSniEvidence(evidence, c, "youtube.com");
        attachProcessEvidence(
            evidence,
            c,
            1300,
            "chrome.exe",
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
        );

        observed.push_back(c);
    }
}


static void addRedflagDeviceTraffic(
    std::vector<ObservedConnection>& observed,
    EngineEvidenceInput& evidence
)
{
    const std::string deviceIp = "192.168.1.37";
    const std::string localIp = "192.168.1.37";

    // Multi-client-like behavior:
    // high connection count + many entities + diverse services + direct evidence.
    const std::vector<uint16_t> ports = {
        443, 80, 53, 853, 22, 3389, 3306, 5222, 3478, 8080
    };

    const std::vector<TransportProtocol> protocols = {
        TransportProtocol::TCP,
        TransportProtocol::TCP,
        TransportProtocol::UDP,
        TransportProtocol::TCP,
        TransportProtocol::TCP,
        TransportProtocol::TCP,
        TransportProtocol::TCP,
        TransportProtocol::TCP,
        TransportProtocol::UDP,
        TransportProtocol::TCP
    };

    for (int i = 0; i < 110; ++i)
    {
        const uint16_t port = ports[static_cast<size_t>(i) % ports.size()];
        const TransportProtocol protocol = protocols[static_cast<size_t>(i) % protocols.size()];

        ObservedConnection c = makeOutboundConnection(
            deviceIp,
            localIp,
            static_cast<uint16_t>(52000 + i),
            "203.0.113." + std::to_string((i % 200) + 1),
            port,
            protocol,
            50000,
            250000,
            i
        );

        const std::string domain =
            "service" + std::to_string(i % 35) + ".example-netwolf-test.com";

        if (port == 53)
        {
            attachDnsEvidence(evidence, c, domain, true);
        }
        else
        {
            attachSniEvidence(evidence, c, domain);
        }

        attachProcessEvidence(
            evidence,
            c,
            2000 + static_cast<uint32_t>(i % 8),
            "relay_like_process.exe",
            "C:\\NetWolfTest\\relay_like_process.exe"
        );

        observed.push_back(c);
    }
}


static void printConnectionReports(const std::vector<ConnectionReport>& reports)
{
    for (const auto& report : reports)
    {
        std::cout << "    - Main connection: " << report.entityName << "\n";
        std::cout << "      Category: " << report.category << "\n";
        std::cout << "      Type: " << report.connectionType << "\n";
        std::cout << "      Owner process: " << report.ownerProcess << "\n";
        std::cout << "      Sub-connections: " << report.subConnectionCount << "\n";
        std::cout << "      Bytes: " << report.bytes << "\n";
        std::cout << "      Confidence: " << toString(report.confidence) << "\n";
        std::cout << "      Evidence: " << report.evidenceUsed << "\n";
        std::cout << "      State: " << toString(report.classificationState) << "\n";
        std::cout << "\n";
    }
}


static void printDeviceSection(
    const std::string& title,
    const std::vector<DeviceReport>& devices
)
{
    std::cout << "\n============================================================\n";
    std::cout << title << "\n";
    std::cout << "Count: " << devices.size() << "\n";
    std::cout << "============================================================\n";

    for (const auto& device : devices)
    {
        std::cout << "\nDevice: " << device.deviceIp << "\n";
        std::cout << "State: " << toString(device.state) << "\n";
        std::cout << "MCS: " << device.score.mcs << "\n";
        std::cout << "Total connections: " << device.score.totalConnections << "\n";
        std::cout << "Groups: " << device.score.totalGroups << "\n";
        std::cout << "Unique entities: " << device.score.uniqueEntities << "\n";
        std::cout << "Unique services: " << device.score.uniqueServices << "\n";
        std::cout << "Traffic share: " << device.score.trafficSharePercent << "%\n";
        std::cout << "Attribution coverage: " << device.score.attributionCoveragePercent << "%\n";
        std::cout << "Dominant entity ratio: " << device.score.dominantEntityRatioPercent << "%\n";
        std::cout << "Reason: " << device.summaryReason << "\n";
        std::cout << "\nConnection reports:\n";

        printConnectionReports(device.connectionReports);
    }
}


int main()
{
    std::vector<ObservedConnection> observed;
    EngineEvidenceInput evidence;

    addNormalDeviceTraffic(observed, evidence);
    addHeavyDeviceTraffic(observed, evidence);
    addRedflagDeviceTraffic(observed, evidence);

    EngineInput input;
    input.observedConnections = observed;
    input.evidence = evidence;

    EngineConfig config;

    // Keep thresholds visible here for testing.
    // Later, we can move them to a config file or GUI settings.
    config.classifier.heavyMcsThreshold = 40.0;
    config.classifier.redflagMcsThreshold = 70.0;
    config.classifier.heavyConnectionCount = 35;
    config.classifier.redflagConnectionCount = 80;
    config.classifier.redflagUniqueEntities = 10;
    config.classifier.redflagUniqueServices = 6;
    config.classifier.redflagConcurrentConnections = 20;
    config.classifier.minimumAttributionCoverageForStrongRedflag = 30.0;

    NetWolfEngine engine(config);

    EngineRunResult result = engine.run(input);

    std::cout << "NetWolf v2 Core Engine Test\n";
    std::cout << "Pipeline: Analyze -> Origin -> Destination -> Group -> Classify\n";
    std::cout << "Observed outbound connections: " << observed.size() << "\n";
    std::cout << "Analyzed sessions: " << result.trace.analyzedSessions.size() << "\n";
    std::cout << "Attributed sessions: " << result.trace.attributedSessions.size() << "\n";
    std::cout << "Connection groups: " << result.trace.groups.size() << "\n";
    std::cout << "All connection reports: " << result.output.allConnectionReports.size() << "\n";

    printDeviceSection("NORMAL DEVICES", result.output.normalDevices);
    printDeviceSection("HEAVY DEVICES", result.output.heavyDevices);
    printDeviceSection("REDFLAG DEVICES", result.output.redflagDevices);

    std::cout << "\nDone.\n";

    return 0;
}