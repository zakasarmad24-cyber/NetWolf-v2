#pragma once

#include <netwolf/app/app_facade.hpp>
#include <netwolf/app/app_types.hpp>

#include <optional>
#include <string>
#include <vector>

namespace netwolf::app {

    // ================================================================
    // NetWolf v2 - Application Controller
    // Layer: GUI/CLI Controller
    //
    // Purpose:
    // 1. Provide a simple controller for future GUI/CLI.
    // 2. Hide AppFacade, EngineRunResult, LiveRunResult details.
    // 3. Store the last dashboard snapshot.
    // 4. Allow exporting the last run without the GUI knowing internals.
    //
    // This file does NOT define GUI layout.
    // This file does NOT classify traffic.
    // This file does NOT capture packets directly.
    // ================================================================


    // ------------------------------------------------
    // Controller run result
    // ------------------------------------------------

    struct AppControllerRunResult
    {
        AppStatus status = AppStatus::Ok;
        AppRunMode mode = AppRunMode::CoreOnly;

        AppDashboardSnapshot dashboard;

        std::vector<AppMessage> messages;

        std::string summaryText;
        std::string stage7DebugSummary;

        bool success() const
        {
            return status == AppStatus::Ok ||
                status == AppStatus::Partial;
        }
    };


    // ------------------------------------------------
    // Controller state snapshot
    // ------------------------------------------------

    struct AppControllerState
    {
        bool hasLastEngineRun = false;
        bool hasLastLiveRun = false;
        bool hasDashboard = false;

        AppRunMode lastMode = AppRunMode::CoreOnly;
        AppStatus lastStatus = AppStatus::Ok;

        std::string lastSummary;
    };


    // ------------------------------------------------
    // Application Controller
    // ------------------------------------------------

    class NetWolfAppController
    {
    public:
        explicit NetWolfAppController(
            NetWolfAppFacade facade = NetWolfAppFacade::balanced()
        );

        const NetWolfAppFacade& facade() const;
        NetWolfAppFacade& facade();

        void setFacade(
            const NetWolfAppFacade& facade
        );

        void setConfig(
            const netwolf::config::NetWolfAppConfig& config
        );

        const netwolf::config::NetWolfAppConfig& config() const;

        // ------------------------------------------------------------
        // Core run
        // ------------------------------------------------------------

        AppControllerRunResult runEngine(
            const netwolf::core::EngineInput& input
        );

        AppControllerRunResult runEngine(
            const std::vector<netwolf::core::ObservedConnection>& observedConnections
        );

        // ------------------------------------------------------------
        // Live run
        // ------------------------------------------------------------

        AppControllerRunResult runLiveWindowsTcpOnce();

        AppControllerRunResult runLiveWindowsTcpAndUdpEndpointOnce();

        AppControllerRunResult runLiveWindowsTcpMockPacketDebugOnce();
        AppControllerRunResult runLiveWindowsTcpNpcapDebugOnce();
        AppControllerRunResult runLiveWindowsTcpNpcapLiveOnce();

        AppControllerRunResult runLiveWindowsTcpUdpMockPacketDebugOnce();

        // ------------------------------------------------------------
        // Dashboard / state
        // ------------------------------------------------------------

        bool hasDashboard() const;

        const AppDashboardSnapshot* lastDashboard() const;

        AppControllerState state() const;

        void clearLastRun();

        // ------------------------------------------------------------
        // Export last run
        // ------------------------------------------------------------

        AppReportExportResult exportLastReportPack() const;

    private:
        NetWolfAppFacade facade_;

        std::optional<netwolf::core::EngineRunResult> lastEngineRun_;
        std::optional<netwolf::live::LiveRunResult> lastLiveRun_;
        std::optional<AppDashboardSnapshot> lastDashboard_;

        AppRunMode lastMode_ = AppRunMode::CoreOnly;
        AppStatus lastStatus_ = AppStatus::Ok;
        std::string lastSummary_;

    private:
        AppControllerRunResult buildFromEngineResult(
            const AppEngineResult& result
        );

        AppControllerRunResult buildFromLiveResult(
            const AppLiveResult& result
        );

        void rememberEngineRun(
            const AppEngineResult& result,
            const AppDashboardSnapshot& dashboard
        );

        void rememberLiveRun(
            const AppLiveResult& result,
            const AppDashboardSnapshot& dashboard
        );

        static AppControllerRunResult makeFailedControllerResult(
            AppRunMode mode,
            const std::string& code,
            const std::string& message,
            const std::string& details = {}
        );

        static AppMessage makeMessage(
            AppStatus status,
            const std::string& code,
            const std::string& message,
            const std::string& details = {}
        );
    };


    // ------------------------------------------------
    // Inline implementation
    // ------------------------------------------------

    inline NetWolfAppController::NetWolfAppController(
        NetWolfAppFacade facade
    )
        : facade_(facade)
    {
    }


    inline const NetWolfAppFacade& NetWolfAppController::facade() const
    {
        return facade_;
    }


    inline NetWolfAppFacade& NetWolfAppController::facade()
    {
        return facade_;
    }


    inline void NetWolfAppController::setFacade(
        const NetWolfAppFacade& facade
    )
    {
        facade_ = facade;
        clearLastRun();
    }


    inline void NetWolfAppController::setConfig(
        const netwolf::config::NetWolfAppConfig& config
    )
    {
        facade_.setConfig(config);
        clearLastRun();
    }


    inline const netwolf::config::NetWolfAppConfig&
        NetWolfAppController::config() const
    {
        return facade_.config();
    }


    inline AppControllerRunResult NetWolfAppController::runEngine(
        const netwolf::core::EngineInput& input
    )
    {
        AppEngineResult result = facade_.runEngine(input);
        return buildFromEngineResult(result);
    }


    inline AppControllerRunResult NetWolfAppController::runEngine(
        const std::vector<netwolf::core::ObservedConnection>& observedConnections
    )
    {
        AppEngineResult result = facade_.runEngine(observedConnections);
        return buildFromEngineResult(result);
    }


    inline AppControllerRunResult NetWolfAppController::runLiveWindowsTcpOnce()
    {
        AppLiveResult result = facade_.runLiveWindowsTcpOnce();
        return buildFromLiveResult(result);
    }


    inline AppControllerRunResult
        NetWolfAppController::runLiveWindowsTcpAndUdpEndpointOnce()
    {
        AppLiveResult result =
            facade_.runLiveWindowsTcpAndUdpEndpointOnce();

        return buildFromLiveResult(result);
    }

    inline AppControllerRunResult
        NetWolfAppController::runLiveWindowsTcpMockPacketDebugOnce()
    {
        AppLiveResult result =
            facade_.runLiveWindowsTcpMockPacketDebugOnce();

        return buildFromLiveResult(result);
    }

    inline AppControllerRunResult
        NetWolfAppController::runLiveWindowsTcpNpcapDebugOnce()
    {
        AppLiveResult result =
            facade_.runLiveWindowsTcpNpcapDebugOnce();

        return buildFromLiveResult(result);
    }

    inline AppControllerRunResult
        NetWolfAppController::runLiveWindowsTcpNpcapLiveOnce()
    {
        AppLiveResult result =
            facade_.runLiveWindowsTcpNpcapLiveOnce();

        return buildFromLiveResult(result);
    }

    inline AppControllerRunResult
        NetWolfAppController::runLiveWindowsTcpUdpMockPacketDebugOnce()
    {
        AppLiveResult result =
            facade_.runLiveWindowsTcpUdpMockPacketDebugOnce();

        return buildFromLiveResult(result);
    }

    inline bool NetWolfAppController::hasDashboard() const
    {
        return lastDashboard_.has_value();
    }


    inline const AppDashboardSnapshot*
        NetWolfAppController::lastDashboard() const
    {
        if (!lastDashboard_.has_value())
            return nullptr;

        return &lastDashboard_.value();
    }


    inline AppControllerState NetWolfAppController::state() const
    {
        AppControllerState state;

        state.hasLastEngineRun = lastEngineRun_.has_value();
        state.hasLastLiveRun = lastLiveRun_.has_value();
        state.hasDashboard = lastDashboard_.has_value();

        state.lastMode = lastMode_;
        state.lastStatus = lastStatus_;
        state.lastSummary = lastSummary_;

        return state;
    }


    inline void NetWolfAppController::clearLastRun()
    {
        lastEngineRun_.reset();
        lastLiveRun_.reset();
        lastDashboard_.reset();

        lastMode_ = AppRunMode::CoreOnly;
        lastStatus_ = AppStatus::Ok;
        lastSummary_.clear();
    }


    inline AppReportExportResult NetWolfAppController::exportLastReportPack() const
    {
        if (lastLiveRun_.has_value())
        {
            return facade_.exportReportPack(
                lastLiveRun_.value()
            );
        }

        if (lastEngineRun_.has_value())
        {
            return facade_.exportReportPack(
                lastEngineRun_.value()
            );
        }

        AppReportExportResult result;

        result.status = AppStatus::Failed;

        result.messages.push_back(
            makeMessage(
                AppStatus::Failed,
                "no_last_run",
                "No previous engine or live run is available for export.",
                "Run the engine or live monitor before exporting a report pack."
            )
        );

        return result;
    }


    inline AppControllerRunResult NetWolfAppController::buildFromEngineResult(
        const AppEngineResult& result
    )
    {
        AppDashboardSnapshot dashboard =
            AppTypeMapper::fromEngineRun(
                result.engineRun,
                toString(result.status)
            );

        AppControllerRunResult controllerResult;

        controllerResult.status = result.status;
        controllerResult.mode = result.mode;
        controllerResult.dashboard = dashboard;
        controllerResult.messages = result.messages;
        controllerResult.summaryText = dashboard.summaryText;
        controllerResult.stage7DebugSummary.clear();

        rememberEngineRun(
            result,
            dashboard
        );

        return controllerResult;
    }


    inline AppControllerRunResult NetWolfAppController::buildFromLiveResult(
        const AppLiveResult& result
    )
    {
        AppDashboardSnapshot dashboard =
            AppTypeMapper::fromLiveRun(
                result.liveRun
            );

        AppControllerRunResult controllerResult;

        controllerResult.status = result.status;
        controllerResult.mode = result.mode;
        controllerResult.dashboard = dashboard;
        controllerResult.messages = result.messages;
        controllerResult.summaryText = dashboard.summaryText;

        controllerResult.stage7DebugSummary =
            result.liveRun.stage7DebugSummary;

        rememberLiveRun(
            result,
            dashboard
        );

        return controllerResult;
    }


    inline void NetWolfAppController::rememberEngineRun(
        const AppEngineResult& result,
        const AppDashboardSnapshot& dashboard
    )
    {
        lastEngineRun_ = result.engineRun;
        lastLiveRun_.reset();

        lastDashboard_ = dashboard;

        lastMode_ = result.mode;
        lastStatus_ = result.status;
        lastSummary_ = dashboard.summaryText;
    }


    inline void NetWolfAppController::rememberLiveRun(
        const AppLiveResult& result,
        const AppDashboardSnapshot& dashboard
    )
    {
        lastLiveRun_ = result.liveRun;
        lastEngineRun_.reset();

        lastDashboard_ = dashboard;

        lastMode_ = result.mode;
        lastStatus_ = result.status;
        lastSummary_ = dashboard.summaryText;
    }


    inline AppControllerRunResult
        NetWolfAppController::makeFailedControllerResult(
            AppRunMode mode,
            const std::string& code,
            const std::string& message,
            const std::string& details
        )
    {
        AppControllerRunResult result;

        result.status = AppStatus::Failed;
        result.mode = mode;
        result.dashboard.statusLabel = "Failed";
        result.dashboard.summaryText = message;
        result.summaryText = message;

        result.messages.push_back(
            makeMessage(
                AppStatus::Failed,
                code,
                message,
                details
            )
        );

        return result;
    }


    inline AppMessage NetWolfAppController::makeMessage(
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