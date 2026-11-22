#pragma once

#include <netwolf/app/app_controller.hpp>
#include <netwolf/gui/gui_models.hpp>

#include <optional>
#include <string>
#include <vector>

namespace netwolf::gui {

    // ================================================================
    // NetWolf v2 - GUI Controller
    // Layer: GUI bridge / Controller
    //
    // Purpose:
    // 1. Provide a clean controller for a future GUI.
    // 2. Convert AppController results into GuiDashboardModel.
    // 3. Store the last GUI dashboard model.
    // 4. Allow GUI to run live monitoring and export reports
    //    without knowing engine/sensor/exporter internals.
    //
    // This file does NOT draw windows.
    // This file does NOT define buttons.
    // This file does NOT classify traffic.
    // ================================================================


    // ------------------------------------------------
    // GUI controller status
    // ------------------------------------------------

    enum class GuiControllerStatus
    {
        Ok,
        Partial,
        Failed
    };


    inline std::string toString(GuiControllerStatus status)
    {
        switch (status)
        {
        case GuiControllerStatus::Ok:
            return "OK";

        case GuiControllerStatus::Partial:
            return "Partial";

        case GuiControllerStatus::Failed:
            return "Failed";

        default:
            return "Failed";
        }
    }


    // ------------------------------------------------
    // GUI message
    // ------------------------------------------------

    struct GuiControllerMessage
    {
        GuiControllerStatus status = GuiControllerStatus::Ok;

        std::string code;
        std::string message;
        std::string details;
    };


    // ------------------------------------------------
    // GUI run result
    // ------------------------------------------------

    struct GuiControllerRunResult
    {
        GuiControllerStatus status = GuiControllerStatus::Ok;

        std::string modeLabel;
        std::string statusLabel;
        std::string summaryText;

        GuiDashboardModel dashboard;

        std::vector<GuiControllerMessage> messages;

        bool success() const
        {
            return status == GuiControllerStatus::Ok ||
                status == GuiControllerStatus::Partial;
        }
    };


    // ------------------------------------------------
    // GUI report export result
    // ------------------------------------------------

    struct GuiReportExportResult
    {
        GuiControllerStatus status = GuiControllerStatus::Ok;

        bool ok = false;

        std::string message;
        std::string outputDirectory;

        size_t successCount = 0;
        size_t failureCount = 0;

        std::vector<std::string> writtenFiles;
        std::vector<std::string> failedFiles;

        std::vector<GuiControllerMessage> messages;

        bool success() const
        {
            return ok &&
                status != GuiControllerStatus::Failed &&
                failureCount == 0;
        }
    };


    // ------------------------------------------------
    // GUI controller state
    // ------------------------------------------------

    struct GuiControllerState
    {
        bool hasDashboard = false;
        bool hasLastRun = false;

        std::string lastModeLabel;
        std::string lastStatusLabel;
        std::string lastSummary;

        size_t normalDevices = 0;
        size_t heavyDevices = 0;
        size_t redflagDevices = 0;
    };


    // ------------------------------------------------
    // GUI Controller
    // ------------------------------------------------

    class NetWolfGuiController
    {
    public:
        explicit NetWolfGuiController(
            netwolf::app::NetWolfAppController controller =
            netwolf::app::NetWolfAppController()
        );

        netwolf::app::NetWolfAppController& appController();
        const netwolf::app::NetWolfAppController& appController() const;

        void setAppController(
            const netwolf::app::NetWolfAppController& controller
        );

        void setConfig(
            const netwolf::config::NetWolfAppConfig& config
        );

        const netwolf::config::NetWolfAppConfig& config() const;

        // ------------------------------------------------------------
        // Run operations
        // ------------------------------------------------------------

        GuiControllerRunResult runEngine(
            const netwolf::core::EngineInput& input
        );

        GuiControllerRunResult runEngine(
            const std::vector<netwolf::core::ObservedConnection>& observedConnections
        );

        GuiControllerRunResult runLiveWindowsTcpOnce();
        GuiControllerRunResult runLiveWindowsTcpNpcapLiveOnce();

        GuiControllerRunResult runLiveWindowsTcpAndUdpEndpointOnce();

        // ------------------------------------------------------------
        // Last dashboard
        // ------------------------------------------------------------

        bool hasDashboard() const;

        const GuiDashboardModel* lastDashboard() const;

        GuiControllerState state() const;

        void clearLastRun();

        // ------------------------------------------------------------
        // Export
        // ------------------------------------------------------------

        GuiReportExportResult exportLastReportPack() const;

    private:
        netwolf::app::NetWolfAppController controller_;

        std::optional<GuiDashboardModel> lastDashboard_;

        std::string lastModeLabel_;
        std::string lastStatusLabel_;
        std::string lastSummary_;

    private:
        GuiControllerRunResult buildRunResult(
            const netwolf::app::AppControllerRunResult& appResult
        );

        void rememberDashboard(
            const netwolf::app::AppControllerRunResult& appResult,
            const GuiDashboardModel& dashboard
        );

        static GuiControllerStatus mapStatus(
            netwolf::app::AppStatus status
        );

        static GuiControllerMessage mapMessage(
            const netwolf::app::AppMessage& message
        );

        static std::vector<GuiControllerMessage> mapMessages(
            const std::vector<netwolf::app::AppMessage>& messages
        );

        static GuiReportExportResult mapReportExportResult(
            const netwolf::app::AppReportExportResult& result
        );
    };


    // ------------------------------------------------
    // Inline implementation
    // ------------------------------------------------

    inline NetWolfGuiController::NetWolfGuiController(
        netwolf::app::NetWolfAppController controller
    )
        : controller_(std::move(controller))
    {
    }


    inline netwolf::app::NetWolfAppController&
        NetWolfGuiController::appController()
    {
        return controller_;
    }


    inline const netwolf::app::NetWolfAppController&
        NetWolfGuiController::appController() const
    {
        return controller_;
    }


    inline void NetWolfGuiController::setAppController(
        const netwolf::app::NetWolfAppController& controller
    )
    {
        controller_ = controller;
        clearLastRun();
    }


    inline void NetWolfGuiController::setConfig(
        const netwolf::config::NetWolfAppConfig& config
    )
    {
        controller_.setConfig(config);
        clearLastRun();
    }


    inline const netwolf::config::NetWolfAppConfig&
        NetWolfGuiController::config() const
    {
        return controller_.config();
    }


    inline GuiControllerRunResult NetWolfGuiController::runEngine(
        const netwolf::core::EngineInput& input
    )
    {
        netwolf::app::AppControllerRunResult appResult =
            controller_.runEngine(input);

        return buildRunResult(appResult);
    }


    inline GuiControllerRunResult NetWolfGuiController::runEngine(
        const std::vector<netwolf::core::ObservedConnection>& observedConnections
    )
    {
        netwolf::app::AppControllerRunResult appResult =
            controller_.runEngine(observedConnections);

        return buildRunResult(appResult);
    }

    inline GuiControllerRunResult NetWolfGuiController::runLiveWindowsTcpNpcapLiveOnce()
    {
        netwolf::app::AppControllerRunResult appResult =
            controller_.runLiveWindowsTcpNpcapLiveOnce();

        return buildRunResult(appResult);
    }

    inline GuiControllerRunResult
        NetWolfGuiController::runLiveWindowsTcpAndUdpEndpointOnce()
    {
        netwolf::app::AppControllerRunResult appResult =
            controller_.runLiveWindowsTcpAndUdpEndpointOnce();

        return buildRunResult(appResult);
    }


    inline bool NetWolfGuiController::hasDashboard() const
    {
        return lastDashboard_.has_value();
    }


    inline const GuiDashboardModel* NetWolfGuiController::lastDashboard() const
    {
        if (!lastDashboard_.has_value())
            return nullptr;

        return &lastDashboard_.value();
    }


    inline GuiControllerState NetWolfGuiController::state() const
    {
        GuiControllerState state;

        state.hasDashboard = lastDashboard_.has_value();

        const netwolf::app::AppControllerState appState =
            controller_.state();

        state.hasLastRun =
            appState.hasLastEngineRun ||
            appState.hasLastLiveRun;

        state.lastModeLabel = lastModeLabel_;
        state.lastStatusLabel = lastStatusLabel_;
        state.lastSummary = lastSummary_;

        if (lastDashboard_.has_value())
        {
            state.normalDevices =
                lastDashboard_->normalPanel.deviceCount;

            state.heavyDevices =
                lastDashboard_->heavyPanel.deviceCount;

            state.redflagDevices =
                lastDashboard_->redflagPanel.deviceCount;
        }

        return state;
    }


    inline void NetWolfGuiController::clearLastRun()
    {
        controller_.clearLastRun();

        lastDashboard_.reset();

        lastModeLabel_.clear();
        lastStatusLabel_.clear();
        lastSummary_.clear();
    }


    inline GuiReportExportResult
        NetWolfGuiController::exportLastReportPack() const
    {
        netwolf::app::AppReportExportResult appResult =
            controller_.exportLastReportPack();

        return mapReportExportResult(appResult);
    }


    inline GuiControllerRunResult NetWolfGuiController::buildRunResult(
        const netwolf::app::AppControllerRunResult& appResult
    )
    {
        GuiDashboardModel dashboard =
            GuiModelMapper::fromDashboard(
                appResult.dashboard
            );

        GuiControllerRunResult result;

        result.status = mapStatus(appResult.status);

        result.modeLabel =
            netwolf::app::toString(appResult.mode);

        result.statusLabel =
            netwolf::app::toString(appResult.status);

        result.summaryText = appResult.summaryText;
        result.dashboard = dashboard;
        result.messages = mapMessages(appResult.messages);

        rememberDashboard(
            appResult,
            dashboard
        );

        return result;
    }


    inline void NetWolfGuiController::rememberDashboard(
        const netwolf::app::AppControllerRunResult& appResult,
        const GuiDashboardModel& dashboard
    )
    {
        lastDashboard_ = dashboard;

        lastModeLabel_ =
            netwolf::app::toString(appResult.mode);

        lastStatusLabel_ =
            netwolf::app::toString(appResult.status);

        lastSummary_ = appResult.summaryText;
    }


    inline GuiControllerStatus NetWolfGuiController::mapStatus(
        netwolf::app::AppStatus status
    )
    {
        switch (status)
        {
        case netwolf::app::AppStatus::Ok:
            return GuiControllerStatus::Ok;

        case netwolf::app::AppStatus::Partial:
            return GuiControllerStatus::Partial;

        case netwolf::app::AppStatus::Failed:
            return GuiControllerStatus::Failed;

        default:
            return GuiControllerStatus::Failed;
        }
    }


    inline GuiControllerMessage NetWolfGuiController::mapMessage(
        const netwolf::app::AppMessage& message
    )
    {
        GuiControllerMessage mapped;

        mapped.status = mapStatus(message.status);
        mapped.code = message.code;
        mapped.message = message.message;
        mapped.details = message.details;

        return mapped;
    }


    inline std::vector<GuiControllerMessage>
        NetWolfGuiController::mapMessages(
            const std::vector<netwolf::app::AppMessage>& messages
        )
    {
        std::vector<GuiControllerMessage> mapped;
        mapped.reserve(messages.size());

        for (const auto& message : messages)
        {
            mapped.push_back(
                mapMessage(message)
            );
        }

        return mapped;
    }


    inline GuiReportExportResult
        NetWolfGuiController::mapReportExportResult(
            const netwolf::app::AppReportExportResult& result
        )
    {
        GuiReportExportResult mapped;

        mapped.status = mapStatus(result.status);
        mapped.ok = result.reportPack.ok;
        mapped.message = result.reportPack.message;
        mapped.outputDirectory = result.reportPack.paths.outputDirectory;
        mapped.successCount = result.reportPack.successCount;
        mapped.failureCount = result.reportPack.failureCount;
        mapped.messages = mapMessages(result.messages);

        for (const auto& fileResult : result.reportPack.fileResults)
        {
            if (fileResult.ok)
            {
                mapped.writtenFiles.push_back(
                    fileResult.path
                );
            }
            else
            {
                std::string failed =
                    fileResult.path;

                if (!fileResult.error.empty())
                {
                    failed += " | ";
                    failed += fileResult.error;
                }

                mapped.failedFiles.push_back(failed);
            }
        }

        return mapped;
    }

} // namespace netwolf::gui