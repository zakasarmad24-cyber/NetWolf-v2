#pragma once

#include <netwolf/config/default_config.hpp>

#include <netwolf/core/engine.hpp>

#include <netwolf/sensors/outbound_sensor.hpp>
#include <netwolf/sensors/windows_tcp_table_sensor.hpp>
#include <netwolf/sensors/windows_udp_table_sensor.hpp>

#include <netwolf/live/live_engine_runner.hpp>

#include <netwolf/exporters/text_report_exporter.hpp>
#include <netwolf/exporters/csv_report_exporter.hpp>
#include <netwolf/exporters/report_pack_exporter.hpp>
#include <netwolf/exporters/experiment_log.hpp>
#include <netwolf/exporters/telecom_report.hpp>

#include <memory>
#include <string>
#include <vector>

namespace netwolf::app {

    // ================================================================
    // NetWolf v2 - Application Facade
    // Layer: High-level application API
    //
    // Purpose:
    // 1. Provide one clean entry point for GUI/CLI.
    // 2. Keep GUI away from low-level engine/sensor/exporter details.
    // 3. Run:
    //    - Core engine directly
    //    - Live Windows TCP snapshot
    //    - Optional UDP endpoint snapshot
    //    - Text/CSV/report pack export
    //
    // This file does NOT define GUI layout.
    // This file does NOT change engine logic.
    // ================================================================


    // ------------------------------------------------
    // Facade run mode
    // ------------------------------------------------

    enum class AppRunMode
    {
        CoreOnly,
        LiveWindowsTcp,
        LiveWindowsTcpAndUdpEndpoint
    };


    inline std::string toString(AppRunMode mode)
    {
        switch (mode)
        {
        case AppRunMode::CoreOnly:
            return "Core only";

        case AppRunMode::LiveWindowsTcp:
            return "Live Windows TCP";

        case AppRunMode::LiveWindowsTcpAndUdpEndpoint:
            return "Live Windows TCP + UDP endpoint";

        default:
            return "Core only";
        }
    }


    // ------------------------------------------------
    // Facade status
    // ------------------------------------------------

    enum class AppStatus
    {
        Ok,
        Partial,
        Failed
    };


    inline std::string toString(AppStatus status)
    {
        switch (status)
        {
        case AppStatus::Ok:
            return "OK";

        case AppStatus::Partial:
            return "Partial";

        case AppStatus::Failed:
            return "Failed";

        default:
            return "Failed";
        }
    }


    // ------------------------------------------------
    // Facade message
    // ------------------------------------------------

    struct AppMessage
    {
        AppStatus status = AppStatus::Ok;

        std::string code;
        std::string message;
        std::string details;
    };


    // ------------------------------------------------
    // Core-only run result
    // ------------------------------------------------

    struct AppEngineResult
    {
        AppStatus status = AppStatus::Ok;
        AppRunMode mode = AppRunMode::CoreOnly;

        netwolf::core::EngineInput input;
        netwolf::core::EngineRunResult engineRun;

        std::vector<AppMessage> messages;

        bool success() const
        {
            return status == AppStatus::Ok ||
                status == AppStatus::Partial;
        }
    };


    // ------------------------------------------------
    // Live run result
    // ------------------------------------------------

    struct AppLiveResult
    {
        AppStatus status = AppStatus::Ok;
        AppRunMode mode = AppRunMode::LiveWindowsTcp;

        netwolf::live::LiveRunResult liveRun;

        std::vector<AppMessage> messages;

        bool success() const
        {
            return status == AppStatus::Ok ||
                status == AppStatus::Partial;
        }
    };


    // ------------------------------------------------
    // Report export result wrapper
    // ------------------------------------------------

    struct AppReportExportResult
    {
        AppStatus status = AppStatus::Ok;

        netwolf::exporters::ReportPackExportResult reportPack;

        std::vector<AppMessage> messages;

        bool success() const
        {
            return status == AppStatus::Ok ||
                status == AppStatus::Partial;
        }
    };


    // ------------------------------------------------
    // Application Facade
    // ------------------------------------------------

    class NetWolfAppFacade
    {
    public:
        explicit NetWolfAppFacade(
            netwolf::config::NetWolfAppConfig config =
            netwolf::config::makeDefaultAppConfig()
        );

        static NetWolfAppFacade balanced();
        static NetWolfAppFacade strictResearch();
        static NetWolfAppFacade liveMonitoring();

        const netwolf::config::NetWolfAppConfig& config() const;
        void setConfig(const netwolf::config::NetWolfAppConfig& config);

        // Core-only run.
        AppEngineResult runEngine(
            const netwolf::core::EngineInput& input
        ) const;

        AppEngineResult runEngine(
            const std::vector<netwolf::core::ObservedConnection>& observedConnections
        ) const;

        // Live Windows run.
        AppLiveResult runLiveWindowsTcpOnce() const;

        AppLiveResult runLiveWindowsTcpAndUdpEndpointOnce() const;

        AppLiveResult runLiveWindowsTcpMockPacketDebugOnce() const;
        AppLiveResult runLiveWindowsTcpNpcapDebugOnce() const;
        AppLiveResult runLiveWindowsTcpNpcapLiveOnce() const;

        AppLiveResult runLiveWindowsTcpUdpMockPacketDebugOnce() const;

        // Export helpers.
        std::string exportTextReport(
            const netwolf::core::EngineRunResult& result
        ) const;

        std::string exportTextReport(
            const netwolf::live::LiveRunResult& result
        ) const;

        netwolf::exporters::CsvExportBundle exportCsvReports(
            const netwolf::core::EngineRunResult& result
        ) const;

        netwolf::exporters::CsvExportBundle exportCsvReports(
            const netwolf::live::LiveRunResult& result
        ) const;

        AppReportExportResult exportReportPack(
            const netwolf::core::EngineRunResult& result
        ) const;

        AppReportExportResult exportReportPack(
            const netwolf::live::LiveRunResult& result
        ) const;

    private:
        netwolf::config::NetWolfAppConfig config_;

        // The live engine runner used by the GUI Live Monitor. It is created
        // once and REUSED for every snapshot, so the engine keeps its memory
        // between snapshots (which devices were here, which vanished, which
        // appeared). Creating a fresh runner per snapshot erased that memory.
        // Shared so copies of this facade keep the same memory.
        mutable std::shared_ptr<netwolf::live::LiveEngineRunner> liveMonitorRunner_;

    private:
        AppLiveResult runLiveWithSensors(
            const std::vector<netwolf::sensors::IOutboundSensor*>& sensors,
            AppRunMode mode
        ) const;

        AppLiveResult runLiveWithSensors(
            netwolf::live::LiveEngineRunner& runner,
            const std::vector<netwolf::sensors::IOutboundSensor*>& sensors,
            AppRunMode mode
        ) const;

        void addMessage(
            AppEngineResult& result,
            AppStatus status,
            const std::string& code,
            const std::string& message,
            const std::string& details = {}
        ) const;

        void addMessage(
            AppLiveResult& result,
            AppStatus status,
            const std::string& code,
            const std::string& message,
            const std::string& details = {}
        ) const;

        void addMessage(
            AppReportExportResult& result,
            AppStatus status,
            const std::string& code,
            const std::string& message,
            const std::string& details = {}
        ) const;

        static AppStatus mapLiveStatus(
            netwolf::live::LiveRunStatus status
        );

        static AppStatus mapReportPackStatus(
            const netwolf::exporters::ReportPackExportResult& result
        );

        static AppMessage makeMessage(
            AppStatus status,
            const std::string& code,
            const std::string& message,
            const std::string& details
        );
    };


    // ------------------------------------------------
    // Inline implementation
    // ------------------------------------------------

    inline NetWolfAppFacade::NetWolfAppFacade(
        netwolf::config::NetWolfAppConfig config
    )
        : config_(config)
    {
    }


    inline NetWolfAppFacade NetWolfAppFacade::balanced()
    {
        return NetWolfAppFacade(
            netwolf::config::makeDefaultAppConfig(
                netwolf::config::NetWolfProfile::Balanced
            )
        );
    }


    inline NetWolfAppFacade NetWolfAppFacade::strictResearch()
    {
        return NetWolfAppFacade(
            netwolf::config::makeDefaultAppConfig(
                netwolf::config::NetWolfProfile::StrictResearch
            )
        );
    }


    inline NetWolfAppFacade NetWolfAppFacade::liveMonitoring()
    {
        return NetWolfAppFacade(
            netwolf::config::makeDefaultAppConfig(
                netwolf::config::NetWolfProfile::LiveMonitoring
            )
        );
    }


    inline const netwolf::config::NetWolfAppConfig&
        NetWolfAppFacade::config() const
    {
        return config_;
    }


    inline void NetWolfAppFacade::setConfig(
        const netwolf::config::NetWolfAppConfig& config
    )
    {
        config_ = config;

        // New configuration: start the live memory again with it.
        liveMonitorRunner_.reset();
    }


    inline AppEngineResult NetWolfAppFacade::runEngine(
        const netwolf::core::EngineInput& input
    ) const
    {
        AppEngineResult result;

        result.status = AppStatus::Ok;
        result.mode = AppRunMode::CoreOnly;
        result.input = input;

        netwolf::core::NetWolfEngine engine(config_.engine);
        result.engineRun = engine.run(input);

        if (input.observedConnections.empty())
        {
            addMessage(
                result,
                AppStatus::Partial,
                "empty_engine_input",
                "Engine input contains no observed connections.",
                "The engine ran successfully, but there was no traffic to analyze."
            );
        }

        if (result.engineRun.output.empty())
        {
            addMessage(
                result,
                AppStatus::Partial,
                "empty_engine_output",
                "Engine output is empty.",
                "No normal, heavy, or redflag devices were produced."
            );
        }

        return result;
    }


    inline AppEngineResult NetWolfAppFacade::runEngine(
        const std::vector<netwolf::core::ObservedConnection>& observedConnections
    ) const
    {
        netwolf::core::EngineInput input;
        input.observedConnections = observedConnections;

        return runEngine(input);
    }


    inline AppLiveResult NetWolfAppFacade::runLiveWindowsTcpOnce() const
    {
        netwolf::sensors::WindowsTcpTableSensor tcpSensor(
            config_.windowsTcpSensor
        );

        std::vector<netwolf::sensors::IOutboundSensor*> sensors;
        sensors.push_back(&tcpSensor);

        return runLiveWithSensors(
            sensors,
            AppRunMode::LiveWindowsTcp
        );
    }


    inline AppLiveResult NetWolfAppFacade::runLiveWindowsTcpAndUdpEndpointOnce() const
    {
        netwolf::sensors::WindowsTcpTableSensor tcpSensor(
            config_.windowsTcpSensor
        );

        netwolf::sensors::WindowsUdpTableSensor udpSensor(
            config_.windowsUdpSensor
        );

        std::vector<netwolf::sensors::IOutboundSensor*> sensors;
        sensors.push_back(&tcpSensor);
        sensors.push_back(&udpSensor);

        return runLiveWithSensors(
            sensors,
            AppRunMode::LiveWindowsTcpAndUdpEndpoint
        );
    }

    inline AppLiveResult NetWolfAppFacade::runLiveWindowsTcpMockPacketDebugOnce() const
    {
        netwolf::config::NetWolfAppConfig debugConfig = config_;

        debugConfig.liveRunner.enableMockPacketMetadataSensor = true;

        // Keep runner synchronized with app-level configs.
        debugConfig.liveRunner.sensorConfig = debugConfig.sensor;
        debugConfig.liveRunner.engineConfig = debugConfig.engine;

        NetWolfAppFacade debugFacade(debugConfig);

        return debugFacade.runLiveWindowsTcpOnce();
    }


    inline AppLiveResult NetWolfAppFacade::runLiveWindowsTcpUdpMockPacketDebugOnce() const
    {
        netwolf::config::NetWolfAppConfig debugConfig = config_;

        debugConfig.liveRunner.enableMockPacketMetadataSensor = true;

        // Keep runner synchronized with app-level configs.
        debugConfig.liveRunner.sensorConfig = debugConfig.sensor;
        debugConfig.liveRunner.engineConfig = debugConfig.engine;

        NetWolfAppFacade debugFacade(debugConfig);

        return debugFacade.runLiveWindowsTcpAndUdpEndpointOnce();
    }

    inline AppLiveResult NetWolfAppFacade::runLiveWindowsTcpNpcapDebugOnce() const
    {
        netwolf::config::NetWolfAppConfig debugConfig = config_;

        debugConfig.liveRunner.enableNpcapPacketMetadataSensor = true;

        debugConfig.liveRunner.npcapPacketMetadataSensor.captureFilter =
            "(udp port 53) or (tcp port 443)";

        debugConfig.liveRunner.npcapPacketMetadataSensor.maxPacketsToRead = 400;
        debugConfig.liveRunner.npcapPacketMetadataSensor.maxReadAttemptsPerAdapter = 1200;
        debugConfig.liveRunner.npcapPacketMetadataSensor.readTimeoutMs = 50;
        debugConfig.liveRunner.npcapPacketMetadataSensor.skipLikelyVirtualAdapters = true;

        // Keep runner synchronized with app-level configs.
        debugConfig.liveRunner.sensorConfig = debugConfig.sensor;
        debugConfig.liveRunner.engineConfig = debugConfig.engine;

        NetWolfAppFacade debugFacade(debugConfig);

        return debugFacade.runLiveWindowsTcpOnce();
    }

    inline AppLiveResult NetWolfAppFacade::runLiveWindowsTcpNpcapLiveOnce() const
    {
        netwolf::config::NetWolfAppConfig liveConfig = config_;

        liveConfig.liveRunner.enableNpcapPacketMetadataSensor = true;

        // --- Continuous hotspot capture ---
        // The adapter is opened ONCE and every IPv4 TCP/UDP packet is read
        // (not a small sample), so every device connected to the hotspot and
        // every one of its connections is seen.
        liveConfig.liveRunner.npcapPacketMetadataSensor.captureFilter =
            "ip and (tcp or udp)";

        liveConfig.liveRunner.continuousPacketCapture = true;
        liveConfig.liveRunner.useBackgroundPacketCaptureService = true;
        liveConfig.liveRunner.useHotspotFlowsAsConnections = true;
        liveConfig.liveRunner.hotspotFlowIdleSeconds = 45;

        // Identity metadata kept (DNS answers / TLS SNI only, not every packet).
        liveConfig.liveRunner.backgroundPacketEvidenceLimit = 3000;

        // --- Target the Windows Mobile Hotspot adapter ---
        // First choice: the adapter that owns the hotspot gateway address.
        // Fallback: an adapter whose name contains "Wi-Fi Direct Virtual"
        // (the Windows Mobile Hotspot is a Microsoft Wi-Fi Direct Virtual
        // Adapter). If nothing is captured, the status message lists the
        // adapters that were tried.
        liveConfig.liveRunner.npcapPacketMetadataSensor.preferredAdapterIpv4 =
            "192.168.137.1";
        liveConfig.liveRunner.npcapPacketMetadataSensor.preferredAdapterSubstring =
            "Wi-Fi Direct Virtual";
        liveConfig.liveRunner.npcapPacketMetadataSensor.promiscuousMode = true;
        liveConfig.liveRunner.npcapPacketMetadataSensor.skipLikelyVirtualAdapters = false;
        liveConfig.liveRunner.npcapPacketMetadataSensor.maxAdaptersToTry = 32;

        // --- The router is this PC ---
        // It is tracked for presence, but only the client devices are
        // classified as Normal / Heavy / Redflag.
        liveConfig.liveRunner.connectionTracker.routerDeviceIps = { "192.168.137.1" };
        liveConfig.liveRunner.classifyRouterDevice = false;

        // --- Destination grouping for client devices ---
        // One group per device and destination (Meta, Google, ...) for the
        // whole monitoring session: no per-minute split, and SNI-named and
        // ASN-named connections of the same entity stay in one group.
        liveConfig.engine.grouper.groupingWindowSeconds = 4294967295ull;
        liveConfig.engine.grouper.includeCategoryInGroupKey = false;

        // Keep runner synchronized with app-level configs.
        liveConfig.liveRunner.sensorConfig = liveConfig.sensor;
        liveConfig.liveRunner.engineConfig = liveConfig.engine;

        // Reuse ONE runner for every Live Monitor snapshot so the engine
        // remembers devices between snapshots (Evil Twin detection needs to
        // see devices vanish over time).
        if (!liveMonitorRunner_)
        {
            liveMonitorRunner_ =
                std::make_shared<netwolf::live::LiveEngineRunner>(
                    liveConfig.liveRunner
                );
        }

        netwolf::sensors::WindowsTcpTableSensor tcpSensor(
            liveConfig.windowsTcpSensor
        );

        std::vector<netwolf::sensors::IOutboundSensor*> sensors;
        sensors.push_back(&tcpSensor);

        AppLiveResult result = runLiveWithSensors(
            *liveMonitorRunner_,
            sensors,
            AppRunMode::LiveWindowsTcp
        );

        // Experiment log (Reports > Start Experiment Log): one record per snapshot.
        netwolf::exporters::ExperimentLog::instance().record(result.liveRun);

        // Telecommunications Information Reports (every 15 minutes while
        // Live Monitor runs, plus alert and final reports).
        netwolf::exporters::TelecomReports::instance().record(result.liveRun);

        return result;
    }

    inline std::string NetWolfAppFacade::exportTextReport(
        const netwolf::core::EngineRunResult& result
    ) const
    {
        netwolf::exporters::TextReportExporter exporter(
            config_.textReport
        );

        return exporter.exportEngineRun(result);
    }


    inline std::string NetWolfAppFacade::exportTextReport(
        const netwolf::live::LiveRunResult& result
    ) const
    {
        netwolf::exporters::TextReportExporter exporter(
            config_.textReport
        );

        return exporter.exportLiveRun(result);
    }


    inline netwolf::exporters::CsvExportBundle NetWolfAppFacade::exportCsvReports(
        const netwolf::core::EngineRunResult& result
    ) const
    {
        netwolf::exporters::CsvReportExporter exporter(
            config_.csvReport
        );

        return exporter.exportEngineRun(result);
    }


    inline netwolf::exporters::CsvExportBundle NetWolfAppFacade::exportCsvReports(
        const netwolf::live::LiveRunResult& result
    ) const
    {
        netwolf::exporters::CsvReportExporter exporter(
            config_.csvReport
        );

        return exporter.exportLiveRun(result);
    }


    inline AppReportExportResult NetWolfAppFacade::exportReportPack(
        const netwolf::core::EngineRunResult& result
    ) const
    {
        AppReportExportResult appResult;

        netwolf::exporters::ReportPackExporter exporter(
            config_.reportPack
        );

        appResult.reportPack = exporter.exportEngineRun(result);
        appResult.status = mapReportPackStatus(appResult.reportPack);

        if (!appResult.reportPack.ok)
        {
            addMessage(
                appResult,
                AppStatus::Failed,
                "report_pack_failed",
                "Report pack export failed.",
                appResult.reportPack.message
            );
        }

        return appResult;
    }


    inline AppReportExportResult NetWolfAppFacade::exportReportPack(
        const netwolf::live::LiveRunResult& result
    ) const
    {
        AppReportExportResult appResult;

        netwolf::exporters::ReportPackExporter exporter(
            config_.reportPack
        );

        appResult.reportPack = exporter.exportLiveRun(result);
        appResult.status = mapReportPackStatus(appResult.reportPack);

        if (!appResult.reportPack.ok)
        {
            addMessage(
                appResult,
                AppStatus::Failed,
                "report_pack_failed",
                "Report pack export failed.",
                appResult.reportPack.message
            );
        }

        return appResult;
    }


    inline AppLiveResult NetWolfAppFacade::runLiveWithSensors(
        const std::vector<netwolf::sensors::IOutboundSensor*>& sensors,
        AppRunMode mode
    ) const
    {
        // One-off runs (debug / UDP snapshot) keep their old behavior:
        // a fresh runner with no memory.
        netwolf::live::LiveEngineRunner runner(
            config_.liveRunner
        );

        return runLiveWithSensors(
            runner,
            sensors,
            mode
        );
    }


    inline AppLiveResult NetWolfAppFacade::runLiveWithSensors(
        netwolf::live::LiveEngineRunner& runner,
        const std::vector<netwolf::sensors::IOutboundSensor*>& sensors,
        AppRunMode mode
    ) const
    {
        AppLiveResult result;

        result.status = AppStatus::Ok;
        result.mode = mode;

        result.liveRun = runner.runOnce(sensors);
        result.status = mapLiveStatus(result.liveRun.status);

        if (!result.liveRun.success())
        {
            addMessage(
                result,
                AppStatus::Failed,
                "live_run_failed",
                "Live engine run failed.",
                result.liveRun.summary.summaryText
            );
        }
        else if (result.liveRun.status == netwolf::live::LiveRunStatus::Partial)
        {
            addMessage(
                result,
                AppStatus::Partial,
                "live_run_partial",
                "Live engine run completed with partial results.",
                result.liveRun.summary.summaryText
            );
        }

        return result;
    }


    inline void NetWolfAppFacade::addMessage(
        AppEngineResult& result,
        AppStatus status,
        const std::string& code,
        const std::string& message,
        const std::string& details
    ) const
    {
        result.messages.push_back(
            makeMessage(status, code, message, details)
        );

        if (status == AppStatus::Failed)
            result.status = AppStatus::Failed;
        else if (status == AppStatus::Partial &&
            result.status == AppStatus::Ok)
            result.status = AppStatus::Partial;
    }


    inline void NetWolfAppFacade::addMessage(
        AppLiveResult& result,
        AppStatus status,
        const std::string& code,
        const std::string& message,
        const std::string& details
    ) const
    {
        result.messages.push_back(
            makeMessage(status, code, message, details)
        );

        if (status == AppStatus::Failed)
            result.status = AppStatus::Failed;
        else if (status == AppStatus::Partial &&
            result.status == AppStatus::Ok)
            result.status = AppStatus::Partial;
    }


    inline void NetWolfAppFacade::addMessage(
        AppReportExportResult& result,
        AppStatus status,
        const std::string& code,
        const std::string& message,
        const std::string& details
    ) const
    {
        result.messages.push_back(
            makeMessage(status, code, message, details)
        );

        if (status == AppStatus::Failed)
            result.status = AppStatus::Failed;
        else if (status == AppStatus::Partial &&
            result.status == AppStatus::Ok)
            result.status = AppStatus::Partial;
    }


    inline AppStatus NetWolfAppFacade::mapLiveStatus(
        netwolf::live::LiveRunStatus status
    )
    {
        switch (status)
        {
        case netwolf::live::LiveRunStatus::Ok:
            return AppStatus::Ok;

        case netwolf::live::LiveRunStatus::Partial:
            return AppStatus::Partial;

        case netwolf::live::LiveRunStatus::Failed:
            return AppStatus::Failed;

        default:
            return AppStatus::Failed;
        }
    }


    inline AppStatus NetWolfAppFacade::mapReportPackStatus(
        const netwolf::exporters::ReportPackExportResult& result
    )
    {
        if (result.ok)
            return AppStatus::Ok;

        if (result.successCount > 0)
            return AppStatus::Partial;

        return AppStatus::Failed;
    }


    inline AppMessage NetWolfAppFacade::makeMessage(
        AppStatus status,
        const std::string& code,
        const std::string& message,
        const std::string& details
    )
    {
        AppMessage item;

        item.status = status;
        item.code = code;
        item.message = message;
        item.details = details;

        return item;
    }

} // namespace netwolf::app