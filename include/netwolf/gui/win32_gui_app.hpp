#pragma once

#include <netwolf/gui/gui_controller.hpp>

#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#endif

namespace netwolf::gui {

    // ================================================================
    // NetWolf v2 - Win32 GUI App Declaration
    // Layer: GUI / Win32 shell
    //
    // Purpose:
    // 1. Define a minimal Win32 GUI application shell.
    // 2. Keep GUI separate from:
    //    - Core engine
    //    - Sensors
    //    - Classifier
    //    - Exporters
    // 3. GUI consumes GuiController and GuiDashboardModel only.
    // 4. This file declares the GUI app; implementation comes next.
    //
    // This file does NOT change engine logic.
    // This file does NOT classify traffic.
    // This file does NOT capture packets directly.
    // ================================================================


    // ------------------------------------------------
    // GUI window command IDs
    // ------------------------------------------------

    enum class Win32GuiCommand : int
    {
        RunTcpOnce = 1001,
        RunTcpUdpOnce = 1002,
        ExportLastReport = 1003,
        ClearDashboard = 1004,
        ExitApp = 1005,
        About = 1006,
        StartLiveMonitor = 1007,
        StopLiveMonitor = 1008,
        StartExperimentLog = 1009,
        StopExperimentLog = 1010,
        ToggleReportMasking = 1011,
        OpenReportsFolder = 1012
    };


    // ------------------------------------------------
    // Basic GUI colors
    // Stored as RGB integers to keep model separate from GDI details.
    // Actual COLORREF conversion happens in implementation.
    // ------------------------------------------------

    struct Win32GuiColorTheme
    {
        int backgroundR = 12;
        int backgroundG = 18;
        int backgroundB = 28;

        int panelR = 22;
        int panelG = 31;
        int panelB = 45;

        int textR = 235;
        int textG = 240;
        int textB = 245;

        int mutedTextR = 150;
        int mutedTextG = 165;
        int mutedTextB = 180;

        int normalR = 80;
        int normalG = 190;
        int normalB = 130;

        int heavyR = 240;
        int heavyG = 180;
        int heavyB = 70;

        int redflagR = 240;
        int redflagG = 85;
        int redflagB = 90;

        int borderR = 50;
        int borderG = 65;
        int borderB = 85;
    };


    // ------------------------------------------------
    // GUI app configuration
    // ------------------------------------------------

    struct Win32GuiAppConfig
    {
        std::wstring windowTitle = L"NetWolf v2";

        int initialWidth = 1280;
        int initialHeight = 780;

        int minimumWidth = 980;
        int minimumHeight = 620;

        bool startMaximized = false;

        Win32GuiColorTheme theme;
    };


    // ------------------------------------------------
    // GUI text block
    // Used internally for drawing dashboard lines.
    // ------------------------------------------------

    struct Win32GuiTextBlock
    {
        std::wstring title;
        std::wstring subtitle;
        std::vector<std::wstring> lines;
    };


    // ------------------------------------------------
    // Win32 GUI App
    // ------------------------------------------------

    class Win32GuiApp
    {
    public:
        explicit Win32GuiApp(
            Win32GuiAppConfig config = {},
            NetWolfGuiController controller = NetWolfGuiController()
        );

        ~Win32GuiApp();

        Win32GuiApp(const Win32GuiApp&) = delete;
        Win32GuiApp& operator=(const Win32GuiApp&) = delete;

        Win32GuiApp(Win32GuiApp&&) = delete;
        Win32GuiApp& operator=(Win32GuiApp&&) = delete;

        int run(
            int nCmdShow
        );

        NetWolfGuiController& controller();
        const NetWolfGuiController& controller() const;

        const Win32GuiAppConfig& config() const;

    private:
        Win32GuiAppConfig config_;
        NetWolfGuiController controller_;

#ifdef _WIN32
        HWND hwnd_ = nullptr;

        HFONT titleFont_ = nullptr;
        HFONT headerFont_ = nullptr;
        HFONT normalFont_ = nullptr;
        HFONT smallFont_ = nullptr;

        HBRUSH backgroundBrush_ = nullptr;
        HBRUSH panelBrush_ = nullptr;

        bool initialized_ = false;
        bool liveTimerRunning_ = false;

        // Clock and session timer (top bar). The session starts with
        // Start Live Monitor and stops with Stop Live Monitor.
        bool sessionActive_ = false;
        bool sessionEverStarted_ = false;
        std::chrono::system_clock::time_point sessionStart_{};
        std::chrono::system_clock::time_point sessionStop_{};
        RECT clockRect_{};

        GuiDashboardModel currentDashboard_;
        std::wstring statusLine_;

        std::vector<RECT> connectionRowRects_;
        std::vector<std::string> connectionRowKeys_;
        std::set<std::string> expandedConnectionKeys_;

        // Device-first CONNECTIONS table: devices whose connections are
        // shown (by device IP), and the device shown in Evidence Inspector.
        std::set<std::string> expandedDeviceKeys_;
        std::string selectedDeviceIp_;

        RECT connectionsViewportRect_{};
        int connectionsScrollOffset_ = 0;
        int connectionsMaxScrollOffset_ = 0;

        RECT connectionsScrollBarRect_{};
        bool draggingConnectionsScrollBar_ = false;
        int draggingConnectionsScrollStartY_ = 0;
        int draggingConnectionsScrollStartOffset_ = 0;

        std::vector<RECT> expandedSubListRects_;
        std::vector<std::string> expandedSubListKeys_;

        std::map<std::string, int> subConnectionScrollOffsets_;
        std::map<std::string, int> subConnectionMaxScrollOffsets_;

        std::vector<RECT> subConnectionScrollBarRects_;
        std::vector<std::string> subConnectionScrollBarKeys_;

        bool draggingSubConnectionScrollBar_ = false;
        std::string draggingSubConnectionScrollKey_;
        int draggingSubConnectionScrollStartY_ = 0;
        int draggingSubConnectionScrollStartOffset_ = 0;

        // ------------------------------------------------------------
        // Background engine worker
        // The engine (TCP table + analysis + grouping + classification)
        // never runs on the UI thread. A single worker thread runs it and
        // posts the finished result back to the window, so painting,
        // scrolling and clicking stay responsive no matter how heavy a
        // snapshot is.
        // ------------------------------------------------------------

        std::thread engineThread_;

        // Serializes every call into controller_ (worker + UI export/clear).
        std::mutex engineMutex_;

        // Worker request state (protected by workerMutex_).
        std::mutex workerMutex_;
        std::condition_variable workerCv_;
        bool workerStop_ = false;
        bool liveMode_ = false;
        int pendingOneShot_ = 0;          // 0 = none, 1 = TCP, 2 = TCP + UDP
        bool pendingCaptureStop_ = false;

        // Finished result handed from worker to UI (protected by resultMutex_).
        std::mutex resultMutex_;
        bool hasPendingResult_ = false;
        GuiControllerRunResult pendingResult_;
        double pendingEngineMs_ = 0.0;

        // Previous dashboards waiting to be freed by the worker thread
        // (protected by resultMutex_). Freeing a large model takes real time,
        // so it is kept off the UI thread.
        std::vector<GuiDashboardModel> retiredDashboards_;

        // ------------------------------------------------------------
        // Live performance diagnostics (UI thread only).
        // Shown in the LIVE MONITOR box so slowness can be measured on the
        // real machine instead of guessed.
        // ------------------------------------------------------------
        double perfLastPaintMs_ = 0.0;
        double perfMaxPaintMs_ = 0.0;
        double perfLastApplyMs_ = 0.0;
        double perfLastEngineMs_ = 0.0;
        size_t perfRows_ = 0;
        size_t perfSubRows_ = 0;

    private:
        bool registerWindowClass(
            HINSTANCE instance
        );

        bool createMainWindow(
            HINSTANCE instance,
            int nCmdShow
        );

        void createGuiResources();
        void destroyGuiResources();

        void createMenuBar();

        void startExperimentLog();
        void stopExperimentLog();
        void toggleReportMasking();
        void openReportsFolder();

        void onCommand(
            int commandId
        );

        void onPaint();
        void onSize(
            int width,
            int height
        );

        void onLeftButtonDown(
            int x,
            int y
        );

        void onLeftButtonUp(
            int x,
            int y
        );

        void onMouseMove(
            int x,
            int y
        );

        void onMouseWheel(
            int delta,
            int screenX,
            int screenY
        );

        void onGetMinMaxInfo(
            MINMAXINFO* info
        );

        void runTcpOnce();
        void runTcpUdpOnce();

        void startLiveMonitor();
        void stopLiveMonitor();

        void exportLastReport();
        void clearDashboard();
        void showAbout();

        // Swaps the result's model into the dashboard (no copy). On return,
        // result.dashboard holds the PREVIOUS model, to be freed elsewhere.
        void updateDashboard(
            GuiControllerRunResult& result
        );

        // Background engine worker
        void startEngineWorker();
        void stopEngineWorker();
        void engineWorkerLoop();
        void requestOneShot(int kind);
        void applyPendingResult();

        void setStatusLine(
            const std::wstring& text
        );

        // ------------------------------------------------------------
        // Drawing helpers
        // ------------------------------------------------------------

        void drawDashboard(
            HDC hdc,
            const RECT& clientRect
        );

        void drawClockBox(
            HDC hdc,
            const RECT& rect
        );

        void drawTopBar(
            HDC hdc,
            const RECT& rect
        );

        void drawLiveMonitorBox(
            HDC hdc,
            const RECT& rect
        );

        void drawMetricCards(
            HDC hdc,
            const RECT& rect
        );

        void drawDevicePanels(
            HDC hdc,
            const RECT& rect
        );

        void drawDevicePanel(
            HDC hdc,
            const GuiDevicePanel& panel,
            const RECT& rect
        );

        void drawDeviceCard(
            HDC hdc,
            const GuiDeviceCard& device,
            const RECT& rect
        );

        void drawEmptyState(
            HDC hdc,
            const RECT& rect
        );

        void drawTextBlock(
            HDC hdc,
            const Win32GuiTextBlock& block,
            const RECT& rect
        );

        void drawRoundedPanel(
            HDC hdc,
            const RECT& rect,
            COLORREF fill,
            COLORREF border
        );

        COLORREF colorForSeverity(
            GuiSeverity severity
        ) const;

        COLORREF rgb(
            int r,
            int g,
            int b
        ) const;

        // ------------------------------------------------------------
        // String helpers
        // ------------------------------------------------------------

        static std::wstring widen(
            const std::string& value
        );

        static std::wstring shorten(
            const std::wstring& value,
            size_t maxLength
        );

        static std::wstring makeDeviceLine(
            const GuiDeviceCard& device
        );

        static std::wstring makePanelSummaryLine(
            const GuiDevicePanel& panel
        );

        // ------------------------------------------------------------
        // Win32 message handling
        // ------------------------------------------------------------

        static LRESULT CALLBACK windowProc(
            HWND hwnd,
            UINT message,
            WPARAM wParam,
            LPARAM lParam
        );

        LRESULT handleMessage(
            HWND hwnd,
            UINT message,
            WPARAM wParam,
            LPARAM lParam
        );

        static Win32GuiApp* appFromWindow(
            HWND hwnd
        );
#endif
    };


    // ------------------------------------------------
    // Non-Windows fallback declaration behavior
    // Implementation will return a clear failure code on non-Windows.
    // ------------------------------------------------

#ifndef _WIN32

    inline Win32GuiApp::Win32GuiApp(
        Win32GuiAppConfig config,
        NetWolfGuiController controller
    )
        : config_(std::move(config)),
        controller_(std::move(controller))
    {
    }

    inline Win32GuiApp::~Win32GuiApp() = default;

    inline int Win32GuiApp::run(
        int
    )
    {
        return 1;
    }

    inline NetWolfGuiController& Win32GuiApp::controller()
    {
        return controller_;
    }

    inline const NetWolfGuiController& Win32GuiApp::controller() const
    {
        return controller_;
    }

    inline const Win32GuiAppConfig& Win32GuiApp::config() const
    {
        return config_;
    }

#endif

} // namespace netwolf::gui