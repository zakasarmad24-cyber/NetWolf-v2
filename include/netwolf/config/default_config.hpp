#pragma once

#include <netwolf/core/engine.hpp>

#include <netwolf/sensors/outbound_sensor.hpp>
#include <netwolf/sensors/windows_tcp_table_sensor.hpp>
#include <netwolf/sensors/windows_udp_table_sensor.hpp>

#include <netwolf/live/live_engine_runner.hpp>

#include <netwolf/exporters/text_report_exporter.hpp>
#include <netwolf/exporters/csv_report_exporter.hpp>
#include <netwolf/exporters/report_pack_exporter.hpp>

#include <string>

namespace netwolf::config {

    // ================================================================
    // NetWolf v2 - Default Configuration
    // Layer: Configuration
    //
    // Purpose:
    // 1. Keep thresholds and behavior settings in one place.
    // 2. Avoid scattering magic numbers across engine, sensors, GUI, and tests.
    // 3. Preserve the PDF pipeline:
    //    Sensor -> Analyzer -> Destination Resolver -> Origin Resolver
    //    -> Grouper -> Classifier -> Report Builder
    // ================================================================


    // ------------------------------------------------
    // Main profile type
    // ------------------------------------------------

    enum class NetWolfProfile
    {
        Balanced,
        StrictResearch,
        LiveMonitoring
    };


    inline std::string toString(NetWolfProfile profile)
    {
        switch (profile)
        {
        case NetWolfProfile::Balanced:
            return "Balanced";

        case NetWolfProfile::StrictResearch:
            return "Strict Research";

        case NetWolfProfile::LiveMonitoring:
            return "Live Monitoring";

        default:
            return "Balanced";
        }
    }


    // ------------------------------------------------
    // Core engine config
    // ------------------------------------------------

    inline netwolf::core::EngineConfig makeBalancedEngineConfig()
    {
        netwolf::core::EngineConfig config;

        // -----------------------------
        // Analyzer
        // -----------------------------
        config.analyzer.treatPort443AsEncrypted = true;
        config.analyzer.treatUdp443AsQuic = true;
        config.analyzer.treatPort53AsDns = true;
        config.analyzer.treatPort80AsHttp = true;
        config.analyzer.treatPort853AsSecureDns = true;

        // -----------------------------
        // Origin Resolver
        // -----------------------------
        config.originResolver.classifyBrowsersAsUserApps = true;
        config.originResolver.classifyDeveloperTools = true;
        config.originResolver.classifyWindowsSystemProcesses = true;
        config.originResolver.classifySecurityTools = true;
        config.originResolver.allowExplainedUnavailableProcess = true;

        // -----------------------------
        // Destination Resolver
        // -----------------------------
        config.destinationResolver.preferTlsSniOverHttpHost = true;
        config.destinationResolver.preferHttpHostOverDns = true;
        config.destinationResolver.allowProviderLevelFallback = true;
        config.destinationResolver.allowProcessAssociatedFallback = true;
        config.destinationResolver.allowEncryptedIpOnlyFallback = true;
        config.destinationResolver.freshDnsWindowSeconds = 120;

        // -----------------------------
        // Grouper
        // -----------------------------
        config.grouper.groupingWindowSeconds = 60;
        config.grouper.groupByEntityName = true;
        config.grouper.includeOwnerProcessInGroupKey = true;
        config.grouper.includeCategoryInGroupKey = true;

        // -----------------------------
        // Device Classifier / MCS
        // -----------------------------
        config.classifier.heavyMcsThreshold = 40.0;
        config.classifier.redflagMcsThreshold = 70.0;

        config.classifier.heavyConnectionCount = 35;
        config.classifier.redflagConnectionCount = 80;

        config.classifier.redflagUniqueEntities = 10;
        config.classifier.redflagUniqueServices = 6;
        config.classifier.redflagConcurrentConnections = 20;

        config.classifier.heavyBytesThreshold = 100ull * 1024ull * 1024ull;

        config.classifier.minimumAttributionCoverageForStrongRedflag = 30.0;

        config.classifier.dominantEntityPenaltyStartPercent = 70.0;
        config.classifier.explainableHeavyDominantEntityPercent = 75.0;

        config.classifier.sustainedWindowSeconds = 120;
        config.classifier.sustainedMinimumConnections = 30;

        return config;
    }


    inline netwolf::core::EngineConfig makeStrictResearchEngineConfig()
    {
        netwolf::core::EngineConfig config = makeBalancedEngineConfig();

        // Stricter profile:
        // Useful for academic/research mode where we want fewer false Redflags.
        config.classifier.heavyMcsThreshold = 45.0;
        config.classifier.redflagMcsThreshold = 78.0;

        config.classifier.heavyConnectionCount = 45;
        config.classifier.redflagConnectionCount = 100;

        config.classifier.redflagUniqueEntities = 12;
        config.classifier.redflagUniqueServices = 7;
        config.classifier.redflagConcurrentConnections = 25;

        config.classifier.minimumAttributionCoverageForStrongRedflag = 45.0;

        config.classifier.dominantEntityPenaltyStartPercent = 65.0;
        config.classifier.explainableHeavyDominantEntityPercent = 70.0;

        return config;
    }


    inline netwolf::core::EngineConfig makeLiveMonitoringEngineConfig()
    {
        netwolf::core::EngineConfig config = makeBalancedEngineConfig();

        // Live profile:
        // Slightly more sensitive than strict research,
        // but still avoids Redflag from weak identity evidence alone.
        config.classifier.heavyMcsThreshold = 35.0;
        config.classifier.redflagMcsThreshold = 68.0;

        config.classifier.heavyConnectionCount = 30;
        config.classifier.redflagConnectionCount = 75;

        config.classifier.redflagUniqueEntities = 9;
        config.classifier.redflagUniqueServices = 6;
        config.classifier.redflagConcurrentConnections = 18;

        config.classifier.minimumAttributionCoverageForStrongRedflag = 30.0;

        return config;
    }


    inline netwolf::core::EngineConfig makeEngineConfig(
        NetWolfProfile profile
    )
    {
        switch (profile)
        {
        case NetWolfProfile::StrictResearch:
            return makeStrictResearchEngineConfig();

        case NetWolfProfile::LiveMonitoring:
            return makeLiveMonitoringEngineConfig();

        case NetWolfProfile::Balanced:
        default:
            return makeBalancedEngineConfig();
        }
    }


    // ------------------------------------------------
    // Sensor config
    // ------------------------------------------------

    inline netwolf::sensors::SensorConfig makeDefaultSensorConfig()
    {
        netwolf::sensors::SensorConfig config;

        config.captureOutboundOnly = true;
        config.includePrivateDestinations = true;
        config.includeLoopback = false;

        config.attachProcessEvidence = true;
        config.attachDnsEvidence = true;

        config.minimumTotalBytes = 0;
        config.snapshotLabel = "netwolf-live-snapshot";

        return config;
    }


    inline netwolf::sensors::WindowsTcpTableSensorConfig makeDefaultWindowsTcpSensorConfig()
    {
        netwolf::sensors::WindowsTcpTableSensorConfig config;

        config.includeEstablished = true;
        config.includeSynSent = false;
        config.includeCloseWait = false;

        config.skipZeroRemoteAddress = true;
        config.skipZeroRemotePort = true;

        config.resolveProcessName = true;

        return config;
    }


    inline netwolf::sensors::WindowsUdpTableSensorConfig makeDefaultWindowsUdpSensorConfig()
    {
        netwolf::sensors::WindowsUdpTableSensorConfig config;

        config.skipWildcardLocalAddress = true;
        config.skipZeroLocalPort = true;

        config.resolveProcessName = true;

        // Keep false because Windows UDP table has no remote IP/port.
        // Real UDP remote tracking will come from packet sensor later.
        config.emitEndpointOnlyLocalObservations = false;

        return config;
    }


    // ------------------------------------------------
    // Live runner config
    // ------------------------------------------------

    inline netwolf::live::LiveEngineRunnerConfig makeDefaultLiveRunnerConfig(
        NetWolfProfile profile = NetWolfProfile::Balanced
    )
    {
        netwolf::live::LiveEngineRunnerConfig config;

        config.sensorConfig = makeDefaultSensorConfig();
        config.engineConfig = makeEngineConfig(profile);

        config.allowPartialSensorResults = true;
        config.continueIfOneSensorFails = true;
        config.keepSensorMessages = true;
        config.allowEmptySnapshot = true;

        return config;
    }


    // ------------------------------------------------
    // Text report config
    // ------------------------------------------------

    inline netwolf::exporters::TextReportExporterConfig makeDefaultTextReportConfig()
    {
        netwolf::exporters::TextReportExporterConfig config;

        config.includeNormalDevices = true;
        config.includeHeavyDevices = true;
        config.includeRedflagDevices = true;

        config.includeConnectionReports = true;
        config.includeDeviceScoreDetails = true;
        config.includeLimitations = true;
        config.includeSummary = true;

        config.maxConnectionReportsPerDevice = 100;

        config.reportTitle = "NetWolf v2 Connection Engine Report";

        return config;
    }


    // ------------------------------------------------
    // CSV report config
    // ------------------------------------------------

    inline netwolf::exporters::CsvReportExporterConfig makeDefaultCsvReportConfig()
    {
        netwolf::exporters::CsvReportExporterConfig config;

        config.includeNormalDevices = true;
        config.includeHeavyDevices = true;
        config.includeRedflagDevices = true;

        config.includeConnectionReports = true;
        config.includeLimitations = true;

        config.delimiter = ',';

        return config;
    }


    // ------------------------------------------------
    // Report pack config
    // ------------------------------------------------

    inline netwolf::exporters::ReportPackExporterConfig makeDefaultReportPackConfig()
    {
        netwolf::exporters::ReportPackExporterConfig config;

        config.outputDirectory = "netwolf_reports";
        config.baseName = "netwolf_report";

        config.createTimestampedFolder = true;

        config.writeTextReport = true;
        config.writeDeviceSummaryCsv = true;
        config.writeDeviceScoresCsv = true;
        config.writeConnectionReportsCsv = true;

        config.overwriteExistingFiles = true;
        config.writeUtf8BomForCsv = true;

        config.textConfig = makeDefaultTextReportConfig();
        config.csvConfig = makeDefaultCsvReportConfig();

        return config;
    }


    // ------------------------------------------------
    // Full application config
    // ------------------------------------------------

    struct NetWolfAppConfig
    {
        NetWolfProfile profile = NetWolfProfile::Balanced;

        netwolf::core::EngineConfig engine;
        netwolf::sensors::SensorConfig sensor;

        netwolf::sensors::WindowsTcpTableSensorConfig windowsTcpSensor;
        netwolf::sensors::WindowsUdpTableSensorConfig windowsUdpSensor;

        netwolf::live::LiveEngineRunnerConfig liveRunner;

        netwolf::exporters::TextReportExporterConfig textReport;
        netwolf::exporters::CsvReportExporterConfig csvReport;
        netwolf::exporters::ReportPackExporterConfig reportPack;
    };


    inline NetWolfAppConfig makeDefaultAppConfig(
        NetWolfProfile profile = NetWolfProfile::Balanced
    )
    {
        NetWolfAppConfig config;

        config.profile = profile;

        config.engine = makeEngineConfig(profile);
        config.sensor = makeDefaultSensorConfig();

        config.windowsTcpSensor = makeDefaultWindowsTcpSensorConfig();
        config.windowsUdpSensor = makeDefaultWindowsUdpSensorConfig();

        config.liveRunner = makeDefaultLiveRunnerConfig(profile);

        config.textReport = makeDefaultTextReportConfig();
        config.csvReport = makeDefaultCsvReportConfig();
        config.reportPack = makeDefaultReportPackConfig();

        // Keep runner synchronized with app-level configs.
        config.liveRunner.sensorConfig = config.sensor;
        config.liveRunner.engineConfig = config.engine;

        return config;
    }

} // namespace netwolf::config