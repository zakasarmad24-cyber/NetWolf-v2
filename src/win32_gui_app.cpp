#include <netwolf/gui/win32_gui_app.hpp>
#include <netwolf/live/live_packet_capture_service.hpp>
#include <netwolf/exporters/experiment_log.hpp>
#include <netwolf/exporters/telecom_report.hpp>

#ifdef _WIN32

#include <shellapi.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <ctime>
#include <cwchar>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <utility>

namespace netwolf::gui {

    namespace {

        constexpr wchar_t kWindowClassName[] = L"NetWolfV2Win32GuiWindow";

        constexpr int kMargin = 18;
        constexpr int kGap = 14;

        constexpr int kTopBarHeight = 86;

        // Repaints the clock once per second, also when monitoring is stopped.
        constexpr UINT_PTR kClockTimerId = 77;
        constexpr int kClockWidth = 470;
        constexpr int kLiveBoxHeight = 116;
        constexpr int kMetricHeight = 102;

        constexpr int kPanelHeaderHeight = 54;
        constexpr int kDeviceCardHeight = 132;

        // Live Monitor refresh period. The engine runs on a background worker
        // thread, so this no longer affects UI smoothness.
        constexpr UINT kLiveMonitorIntervalMs = 1000;

        // Posted by the engine worker when a finished result is ready.
        constexpr UINT kEngineResultMessage = WM_APP + 1;

        // CONNECTIONS table: key prefix of a device header row.
        constexpr const char* kDeviceRowKeyPrefix = "dev|";

    } // namespace


    // ------------------------------------------------------------
    // Constructor / Destructor
    // ------------------------------------------------------------

    Win32GuiApp::Win32GuiApp(
        Win32GuiAppConfig config,
        NetWolfGuiController controller
    )
        : config_(std::move(config)),
        controller_(std::move(controller))
    {
        currentDashboard_.title = "NetWolf v2";
        currentDashboard_.statusLabel = "Ready";
        currentDashboard_.summaryText =
            "Ready. Use Run TCP Once to capture current Windows TCP connections.";

        currentDashboard_.normalPanel.severity = GuiSeverity::Normal;
        currentDashboard_.normalPanel.title = "Normal Devices";
        currentDashboard_.normalPanel.subtitle = "No data yet.";

        currentDashboard_.heavyPanel.severity = GuiSeverity::Heavy;
        currentDashboard_.heavyPanel.title = "Heavy Devices";
        currentDashboard_.heavyPanel.subtitle = "No data yet.";

        currentDashboard_.redflagPanel.severity = GuiSeverity::Redflag;
        currentDashboard_.redflagPanel.title = "Redflag Devices";
        currentDashboard_.redflagPanel.subtitle = "No data yet.";

        statusLine_ = L"Ready.";
    }


    Win32GuiApp::~Win32GuiApp()
    {
        // Normally already stopped in WM_DESTROY; safe to call twice.
        stopEngineWorker();
        destroyGuiResources();
    }


    // ------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------

    int Win32GuiApp::run(
        int nCmdShow
    )
    {
        HINSTANCE instance = GetModuleHandleW(nullptr);

        if (!registerWindowClass(instance))
            return 1;

        createGuiResources();

        if (!createMainWindow(instance, nCmdShow))
            return 1;

        // The window exists now, so the worker can post results to it.
        startEngineWorker();

        MSG message{};

        while (GetMessageW(&message, nullptr, 0, 0) > 0)
        {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }

        return static_cast<int>(message.wParam);
    }


    NetWolfGuiController& Win32GuiApp::controller()
    {
        return controller_;
    }


    const NetWolfGuiController& Win32GuiApp::controller() const
    {
        return controller_;
    }


    const Win32GuiAppConfig& Win32GuiApp::config() const
    {
        return config_;
    }


    // ------------------------------------------------------------
    // Window creation
    // ------------------------------------------------------------

    bool Win32GuiApp::registerWindowClass(
        HINSTANCE instance
    )
    {
        WNDCLASSEXW wc{};

        wc.cbSize = sizeof(WNDCLASSEXW);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = Win32GuiApp::windowProc;
        wc.cbClsExtra = 0;
        wc.cbWndExtra = 0;
        wc.hInstance = instance;
        wc.hIcon = LoadIconW(nullptr, MAKEINTRESOURCEW(32512));     // IDI_APPLICATION
        wc.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512)); // IDC_ARROW
        wc.hbrBackground = nullptr;
        wc.lpszMenuName = nullptr;
        wc.lpszClassName = kWindowClassName;
        wc.hIconSm = LoadIconW(nullptr, MAKEINTRESOURCEW(32512));   // IDI_APPLICATION

        const ATOM atom = RegisterClassExW(&wc);

        if (atom == 0)
        {
            const DWORD error = GetLastError();

            if (error == ERROR_CLASS_ALREADY_EXISTS)
                return true;

            return false;
        }

        return true;
    }


    bool Win32GuiApp::createMainWindow(
        HINSTANCE instance,
        int nCmdShow
    )
    {
        DWORD style =
            WS_OVERLAPPEDWINDOW |
            WS_CLIPCHILDREN |
            WS_CLIPSIBLINGS;

        RECT rect{
            0,
            0,
            config_.initialWidth,
            config_.initialHeight
        };

        AdjustWindowRect(
            &rect,
            style,
            TRUE
        );

        hwnd_ = CreateWindowExW(
            0,
            kWindowClassName,
            config_.windowTitle.c_str(),
            style,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            rect.right - rect.left,
            rect.bottom - rect.top,
            nullptr,
            nullptr,
            instance,
            this
        );

        if (!hwnd_)
            return false;

        createMenuBar();

        SetTimer(hwnd_, kClockTimerId, 1000, nullptr);

        if (config_.startMaximized)
            ShowWindow(hwnd_, SW_MAXIMIZE);
        else
            ShowWindow(hwnd_, nCmdShow);

        UpdateWindow(hwnd_);

        initialized_ = true;

        return true;
    }


    // ------------------------------------------------------------
    // Resources
    // ------------------------------------------------------------

    void Win32GuiApp::createGuiResources()
    {
        destroyGuiResources();

        titleFont_ = CreateFontW(
            28,
            0,
            0,
            0,
            FW_BOLD,
            FALSE,
            FALSE,
            FALSE,
            DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_SWISS,
            L"Segoe UI"
        );

        headerFont_ = CreateFontW(
            18,
            0,
            0,
            0,
            FW_SEMIBOLD,
            FALSE,
            FALSE,
            FALSE,
            DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_SWISS,
            L"Segoe UI"
        );

        normalFont_ = CreateFontW(
            15,
            0,
            0,
            0,
            FW_NORMAL,
            FALSE,
            FALSE,
            FALSE,
            DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_SWISS,
            L"Segoe UI"
        );

        smallFont_ = CreateFontW(
            13,
            0,
            0,
            0,
            FW_NORMAL,
            FALSE,
            FALSE,
            FALSE,
            DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_SWISS,
            L"Segoe UI"
        );

        backgroundBrush_ = CreateSolidBrush(
            rgb(
                config_.theme.backgroundR,
                config_.theme.backgroundG,
                config_.theme.backgroundB
            )
        );

        panelBrush_ = CreateSolidBrush(
            rgb(
                config_.theme.panelR,
                config_.theme.panelG,
                config_.theme.panelB
            )
        );
    }


    void Win32GuiApp::destroyGuiResources()
    {
        if (titleFont_)
        {
            DeleteObject(titleFont_);
            titleFont_ = nullptr;
        }

        if (headerFont_)
        {
            DeleteObject(headerFont_);
            headerFont_ = nullptr;
        }

        if (normalFont_)
        {
            DeleteObject(normalFont_);
            normalFont_ = nullptr;
        }

        if (smallFont_)
        {
            DeleteObject(smallFont_);
            smallFont_ = nullptr;
        }

        if (backgroundBrush_)
        {
            DeleteObject(backgroundBrush_);
            backgroundBrush_ = nullptr;
        }

        if (panelBrush_)
        {
            DeleteObject(panelBrush_);
            panelBrush_ = nullptr;
        }
    }


    // ------------------------------------------------------------
    // Menu
    // ------------------------------------------------------------

    void Win32GuiApp::createMenuBar()
    {
        HMENU menuBar = CreateMenu();
        HMENU runMenu = CreatePopupMenu();
        HMENU reportMenu = CreatePopupMenu();
        HMENU helpMenu = CreatePopupMenu();

        AppendMenuW(
            runMenu,
            MF_STRING,
            static_cast<UINT_PTR>(Win32GuiCommand::RunTcpOnce),
            L"Run TCP Once"
        );

        AppendMenuW(
            runMenu,
            MF_STRING,
            static_cast<UINT_PTR>(Win32GuiCommand::RunTcpUdpOnce),
            L"Run TCP + UDP Endpoint Once"
        );

        AppendMenuW(runMenu, MF_SEPARATOR, 0, nullptr);

        AppendMenuW(
            runMenu,
            MF_STRING,
            static_cast<UINT_PTR>(Win32GuiCommand::StartLiveMonitor),
            L"Start Live Monitor"
        );

        AppendMenuW(
            runMenu,
            MF_STRING,
            static_cast<UINT_PTR>(Win32GuiCommand::StopLiveMonitor),
            L"Stop Live Monitor"
        );

        AppendMenuW(runMenu, MF_SEPARATOR, 0, nullptr);

        AppendMenuW(
            runMenu,
            MF_STRING,
            static_cast<UINT_PTR>(Win32GuiCommand::ClearDashboard),
            L"Clear Dashboard"
        );

        AppendMenuW(runMenu, MF_SEPARATOR, 0, nullptr);

        AppendMenuW(
            runMenu,
            MF_STRING,
            static_cast<UINT_PTR>(Win32GuiCommand::ExitApp),
            L"Exit"
        );

        AppendMenuW(
            reportMenu,
            MF_STRING,
            static_cast<UINT_PTR>(Win32GuiCommand::ExportLastReport),
            L"Export Last Report Pack"
        );

        AppendMenuW(reportMenu, MF_SEPARATOR, 0, nullptr);

        AppendMenuW(
            reportMenu,
            MF_STRING,
            static_cast<UINT_PTR>(Win32GuiCommand::StartExperimentLog),
            L"Start Experiment Log"
        );

        AppendMenuW(
            reportMenu,
            MF_STRING,
            static_cast<UINT_PTR>(Win32GuiCommand::StopExperimentLog),
            L"Stop Experiment Log"
        );

        AppendMenuW(reportMenu, MF_SEPARATOR, 0, nullptr);

        AppendMenuW(
            reportMenu,
            MF_STRING | (netwolf::exporters::TelecomReports::instance().masking() ? MF_CHECKED : MF_UNCHECKED),
            static_cast<UINT_PTR>(Win32GuiCommand::ToggleReportMasking),
            L"Mask Identifiers in Reports"
        );

        AppendMenuW(
            reportMenu,
            MF_STRING,
            static_cast<UINT_PTR>(Win32GuiCommand::OpenReportsFolder),
            L"Open Reports Folder"
        );

        AppendMenuW(
            helpMenu,
            MF_STRING,
            static_cast<UINT_PTR>(Win32GuiCommand::About),
            L"About NetWolf v2"
        );

        AppendMenuW(menuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(runMenu), L"Run");
        AppendMenuW(menuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(reportMenu), L"Reports");
        AppendMenuW(menuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(helpMenu), L"Help");

        SetMenu(hwnd_, menuBar);
    }


    // ------------------------------------------------------------
    // Events
    // ------------------------------------------------------------

    void Win32GuiApp::onCommand(
        int commandId
    )
    {
        switch (static_cast<Win32GuiCommand>(commandId))
        {
        case Win32GuiCommand::StartLiveMonitor:
            startLiveMonitor();
            break;

        case Win32GuiCommand::StopLiveMonitor:
            stopLiveMonitor();
            break;

        case Win32GuiCommand::RunTcpOnce:
            runTcpOnce();
            break;

        case Win32GuiCommand::RunTcpUdpOnce:
            runTcpUdpOnce();
            break;

        case Win32GuiCommand::ExportLastReport:
            exportLastReport();
            break;

        case Win32GuiCommand::ClearDashboard:
            clearDashboard();
            break;

        case Win32GuiCommand::ExitApp:
            PostMessageW(hwnd_, WM_CLOSE, 0, 0);
            break;

        case Win32GuiCommand::About:
            showAbout();
            break;

        case Win32GuiCommand::StartExperimentLog:
            startExperimentLog();
            break;

        case Win32GuiCommand::StopExperimentLog:
            stopExperimentLog();
            break;

        case Win32GuiCommand::ToggleReportMasking:
            toggleReportMasking();
            break;

        case Win32GuiCommand::OpenReportsFolder:
            openReportsFolder();
            break;

        default:
            break;
        }
    }


    // Logs and reports go next to the .exe (an elevated Start-Process starts
    // in System32, so the working folder is not a safe place).
    static std::filesystem::path executableFolder()
    {
        wchar_t exePath[MAX_PATH]{};

        const DWORD length = GetModuleFileNameW(nullptr, exePath, MAX_PATH);

        return (length > 0 && length < MAX_PATH)
            ? std::filesystem::path(exePath).parent_path()
            : std::filesystem::current_path();
    }


    void Win32GuiApp::toggleReportMasking()
    {
        auto& reports = netwolf::exporters::TelecomReports::instance();
        const bool enabled = !reports.masking();

        reports.setMasking(enabled);

        CheckMenuItem(
            GetMenu(hwnd_),
            static_cast<UINT>(Win32GuiCommand::ToggleReportMasking),
            MF_BYCOMMAND | (enabled ? MF_CHECKED : MF_UNCHECKED)
        );

        setStatusLine(enabled
            ? L"Reports: identifiers masked (IP 192.168.137.xxx, MAC manufacturer part only)."
            : L"Reports: identifiers NOT masked. Keep new reports private.");
    }


    void Win32GuiApp::openReportsFolder()
    {
        const std::filesystem::path folder =
            netwolf::exporters::TelecomReports::rootFolder(executableFolder());

        std::error_code error;
        std::filesystem::create_directories(folder, error);

        ShellExecuteW(hwnd_, L"open", folder.wstring().c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    }


    void Win32GuiApp::startExperimentLog()
    {
        const std::filesystem::path baseFolder = executableFolder();

        std::string message;

        const bool started =
            netwolf::exporters::ExperimentLog::instance().start(baseFolder, message);

        statusLine_ = widen(message);

        MessageBoxW(
            hwnd_,
            (widen(message) + (started
                ? L"\n\nEvery Live Monitor snapshot is now written to devices.csv, summary.csv and events.csv. "
                  L"aliases.csv links D1, D2, ... to the real devices: keep it private."
                : L"")).c_str(),
            L"NetWolf v2 - Experiment Log",
            MB_OK | (started ? MB_ICONINFORMATION : MB_ICONERROR)
        );

        InvalidateRect(hwnd_, nullptr, FALSE);
    }


    void Win32GuiApp::stopExperimentLog()
    {
        const std::string folder = netwolf::exporters::ExperimentLog::instance().folder();

        netwolf::exporters::ExperimentLog::instance().stop();

        statusLine_ = folder.empty()
            ? L"Experiment log was not running."
            : L"Experiment log saved: " + widen(folder);

        InvalidateRect(hwnd_, nullptr, FALSE);
    }


    void Win32GuiApp::onPaint()
    {
        const auto paintStart = std::chrono::steady_clock::now();

        PAINTSTRUCT ps{};
        HDC hdc = BeginPaint(hwnd_, &ps);

        RECT client{};
        GetClientRect(hwnd_, &client);

        const int width = client.right - client.left;
        const int height = client.bottom - client.top;

        if (width <= 0 || height <= 0)
        {
            EndPaint(hwnd_, &ps);
            return;
        }

        // Double buffering:
        // Draw everything into an off-screen bitmap first,
        // then copy it to the real window in one operation.
        HDC memoryDc = CreateCompatibleDC(hdc);
        HBITMAP memoryBitmap = CreateCompatibleBitmap(hdc, width, height);

        HGDIOBJ oldBitmap = SelectObject(memoryDc, memoryBitmap);

        drawDashboard(memoryDc, client);

        BitBlt(
            hdc,
            0,
            0,
            width,
            height,
            memoryDc,
            0,
            0,
            SRCCOPY
        );

        SelectObject(memoryDc, oldBitmap);

        DeleteObject(memoryBitmap);
        DeleteDC(memoryDc);

        EndPaint(hwnd_, &ps);

        // Diagnostics: real paint time on this machine (shown next frame).
        perfLastPaintMs_ = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - paintStart
        ).count();

        if (perfLastPaintMs_ > perfMaxPaintMs_)
            perfMaxPaintMs_ = perfLastPaintMs_;
    }


    void Win32GuiApp::onSize(
        int,
        int
    )
    {
        if (hwnd_)
            InvalidateRect(hwnd_, nullptr, FALSE);
    }

    void Win32GuiApp::onLeftButtonDown(
        int x,
        int y
    )
    {
        POINT point{
    x,
    y
        };

        if (connectionsMaxScrollOffset_ > 0 &&
            PtInRect(
                &connectionsScrollBarRect_,
                point
            ))
        {
            draggingConnectionsScrollBar_ = true;
            draggingConnectionsScrollStartY_ = y;
            draggingConnectionsScrollStartOffset_ = connectionsScrollOffset_;

            SetCapture(hwnd_);
            return;
        }

        for (size_t i = 0; i < subConnectionScrollBarRects_.size(); ++i)
        {
            if (!PtInRect(
                &subConnectionScrollBarRects_[i],
                point
            ))
            {
                continue;
            }

            if (i >= subConnectionScrollBarKeys_.size())
                continue;

            const std::string key =
                subConnectionScrollBarKeys_[i];

            const int maxOffset =
                subConnectionMaxScrollOffsets_[key];

            if (maxOffset <= 0)
                continue;

            draggingSubConnectionScrollBar_ = true;
            draggingSubConnectionScrollKey_ = key;
            draggingSubConnectionScrollStartY_ = y;
            draggingSubConnectionScrollStartOffset_ =
                subConnectionScrollOffsets_[key];

            SetCapture(hwnd_);
            return;
        }

        for (size_t i = 0; i < connectionRowRects_.size(); ++i)
        {
            const RECT& rect = connectionRowRects_[i];

            const bool inside =
                x >= rect.left &&
                x <= rect.right &&
                y >= rect.top &&
                y <= rect.bottom;

            if (!inside)
                continue;

            if (i >= connectionRowKeys_.size())
                return;

            const std::string key = connectionRowKeys_[i];

            // Device header row: open / close the device and select it.
            if (key.rfind(kDeviceRowKeyPrefix, 0) == 0)
            {
                const std::string deviceIp =
                    key.substr(std::char_traits<char>::length(kDeviceRowKeyPrefix));

                if (expandedDeviceKeys_.find(deviceIp) != expandedDeviceKeys_.end())
                {
                    // Closing the device also returns Evidence Inspector to
                    // the snapshot overview.
                    expandedDeviceKeys_.erase(deviceIp);

                    if (selectedDeviceIp_ == deviceIp)
                        selectedDeviceIp_.clear();
                }
                else
                {
                    expandedDeviceKeys_.insert(deviceIp);
                    selectedDeviceIp_ = deviceIp;
                }

                InvalidateRect(hwnd_, nullptr, FALSE);
                return;
            }

            if (expandedConnectionKeys_.find(key) != expandedConnectionKeys_.end())
            {
                expandedConnectionKeys_.erase(key);
            }
            else
            {
                expandedConnectionKeys_.insert(key);
            }

            InvalidateRect(hwnd_, nullptr, FALSE);
            return;
        }
    }

    void Win32GuiApp::onLeftButtonUp(
        int,
        int
    )
    {
        if (!draggingSubConnectionScrollBar_ &&
            !draggingConnectionsScrollBar_)
        {
            return;
        }

        draggingSubConnectionScrollBar_ = false;
        draggingSubConnectionScrollKey_.clear();
        draggingSubConnectionScrollStartY_ = 0;
        draggingSubConnectionScrollStartOffset_ = 0;

        draggingConnectionsScrollBar_ = false;
        draggingConnectionsScrollStartY_ = 0;
        draggingConnectionsScrollStartOffset_ = 0;

        ReleaseCapture();

        if (hwnd_)
        {
            InvalidateRect(
                hwnd_,
                nullptr,
                FALSE
            );
        }
    }

    void Win32GuiApp::onMouseMove(
        int,
        int y
    )
    {
        if (draggingConnectionsScrollBar_)
        {
            if (connectionsMaxScrollOffset_ <= 0)
                return;

            const int trackHeight =
                connectionsScrollBarRect_.bottom - connectionsScrollBarRect_.top;

            if (trackHeight <= 24)
                return;

            const int contentHeight =
                trackHeight + connectionsMaxScrollOffset_;

            int thumbHeight =
                (trackHeight * trackHeight) / std::max(1, contentHeight);

            thumbHeight = std::max(24, thumbHeight);
            thumbHeight = std::min(trackHeight, thumbHeight);

            const int movableRange =
                std::max(1, trackHeight - thumbHeight);

            const int deltaY =
                y - draggingConnectionsScrollStartY_;

            int newOffset =
                draggingConnectionsScrollStartOffset_ +
                (deltaY * connectionsMaxScrollOffset_) / movableRange;

            connectionsScrollOffset_ =
                std::clamp(
                    newOffset,
                    0,
                    connectionsMaxScrollOffset_
                );

            if (hwnd_)
            {
                InvalidateRect(
                    hwnd_,
                    nullptr,
                    FALSE
                );
            }

            return;
        }

        if (!draggingSubConnectionScrollBar_)
            return;

        if (draggingSubConnectionScrollKey_.empty())
            return;

        const std::string key =
            draggingSubConnectionScrollKey_;

        const int maxOffset =
            subConnectionMaxScrollOffsets_[key];

        if (maxOffset <= 0)
            return;

        RECT trackRect{};
        bool foundTrack = false;

        for (size_t i = 0; i < subConnectionScrollBarKeys_.size(); ++i)
        {
            if (subConnectionScrollBarKeys_[i] == key &&
                i < subConnectionScrollBarRects_.size())
            {
                trackRect = subConnectionScrollBarRects_[i];
                foundTrack = true;
                break;
            }
        }

        if (!foundTrack)
            return;

        const int trackHeight =
            trackRect.bottom - trackRect.top;

        if (trackHeight <= 24)
            return;

        const int contentHeight =
            trackHeight + maxOffset;

        int thumbHeight =
            (trackHeight * trackHeight) / std::max(1, contentHeight);

        thumbHeight = std::max(24, thumbHeight);
        thumbHeight = std::min(trackHeight, thumbHeight);

        const int movableRange =
            std::max(1, trackHeight - thumbHeight);

        const int deltaY =
            y - draggingSubConnectionScrollStartY_;

        int newOffset =
            draggingSubConnectionScrollStartOffset_ +
            (deltaY * maxOffset) / movableRange;

        if (newOffset < 0)
            newOffset = 0;

        if (newOffset > maxOffset)
            newOffset = maxOffset;

        subConnectionScrollOffsets_[key] =
            newOffset;

        if (hwnd_)
        {
            InvalidateRect(
                hwnd_,
                nullptr,
                FALSE
            );
        }
    }

    void Win32GuiApp::onMouseWheel(
        int delta,
        int screenX,
        int screenY
    )
    {
        if (!hwnd_)
            return;

        POINT point{
            screenX,
            screenY
        };

        ScreenToClient(
            hwnd_,
            &point
        );

        // ------------------------------------------------------------
        // First priority:
        // if the mouse is inside an expanded sub-connection list,
        // scroll that sub-list instead of the whole CONNECTIONS table.
        // ------------------------------------------------------------

        for (size_t i = 0; i < expandedSubListRects_.size(); ++i)
        {
            const RECT& rect = expandedSubListRects_[i];

            const bool insideSubList =
                point.x >= rect.left &&
                point.x <= rect.right &&
                point.y >= rect.top &&
                point.y <= rect.bottom;

            if (!insideSubList)
                continue;

            if (i >= expandedSubListKeys_.size())
                return;

            const std::string key =
                expandedSubListKeys_[i];

            const int maxOffset =
                subConnectionMaxScrollOffsets_[key];

            if (maxOffset <= 0)
                return;

            const int scrollStep = 36;

            int& offset =
                subConnectionScrollOffsets_[key];

            if (delta > 0)
                offset -= scrollStep;
            else
                offset += scrollStep;

            offset =
                std::clamp(
                    offset,
                    0,
                    maxOffset
                );

            InvalidateRect(
                hwnd_,
                nullptr,
                FALSE
            );

            return;
        }

        // ------------------------------------------------------------
        // Second priority:
        // scroll the whole CONNECTIONS table.
        // ------------------------------------------------------------

        const bool insideConnections =
            (point.x >= connectionsViewportRect_.left &&
             point.x <= connectionsViewportRect_.right &&
             point.y >= connectionsViewportRect_.top &&
             point.y <= connectionsViewportRect_.bottom) ||
            (connectionsMaxScrollOffset_ > 0 &&
             PtInRect(&connectionsScrollBarRect_, point));

        if (!insideConnections)
            return;

        if (connectionsMaxScrollOffset_ <= 0)
            return;

        const int scrollStep = 72;

        if (delta > 0)
            connectionsScrollOffset_ -= scrollStep;
        else
            connectionsScrollOffset_ += scrollStep;

        connectionsScrollOffset_ =
            std::clamp(
                connectionsScrollOffset_,
                0,
                connectionsMaxScrollOffset_
            );

        InvalidateRect(
            hwnd_,
            nullptr,
            FALSE
        );
    }

    void Win32GuiApp::onGetMinMaxInfo(
        MINMAXINFO* info
    )
    {
        if (!info)
            return;

        info->ptMinTrackSize.x = config_.minimumWidth;
        info->ptMinTrackSize.y = config_.minimumHeight;
    }


    // ------------------------------------------------------------
    // Commands
    // ------------------------------------------------------------

    void Win32GuiApp::runTcpOnce()
    {
        // Non-blocking: the snapshot runs on the engine worker thread.
        setStatusLine(L"Running Windows TCP + background Npcap DNS/TLS snapshot in background...");
        requestOneShot(1);
    }


    void Win32GuiApp::runTcpUdpOnce()
    {
        // Non-blocking: the snapshot runs on the engine worker thread.
        setStatusLine(L"Running Windows TCP + UDP endpoint snapshot in background...");
        requestOneShot(2);
    }

    void Win32GuiApp::startLiveMonitor()
    {
        if (liveTimerRunning_)
        {
            setStatusLine(L"Live Monitor is already running.");
            return;
        }

        if (!hwnd_)
            return;

        {
            std::lock_guard<std::mutex> lock(workerMutex_);
            liveMode_ = true;
            pendingCaptureStop_ = false;
        }

        // Automatic reports for this monitoring session (every 15 minutes,
        // at an alert, and a final report when monitoring stops).
        std::string reportMessage;

        const bool reportsStarted =
            netwolf::exporters::TelecomReports::instance().begin(executableFolder(), reportMessage);

        // Wakes the worker; it runs the first snapshot immediately.
        workerCv_.notify_one();

        liveTimerRunning_ = true;

        sessionStart_ = std::chrono::system_clock::now();
        sessionActive_ = true;
        sessionEverStarted_ = true;

        setStatusLine(reportsStarted
            ? L"Live Monitor started. " + widen(reportMessage)
            : L"Live Monitor started, but reports are OFF: " + widen(reportMessage));
    }


    void Win32GuiApp::stopLiveMonitor()
    {
        if (!liveTimerRunning_)
        {
            setStatusLine(L"Live Monitor is not running.");
            return;
        }

        {
            std::lock_guard<std::mutex> lock(workerMutex_);
            liveMode_ = false;

            // The worker stops the capture service itself, after any snapshot
            // in progress finishes. Stopping it here could block the UI and
            // race with a snapshot that would restart it.
            pendingCaptureStop_ = true;
        }

        workerCv_.notify_one();

        liveTimerRunning_ = false;

        sessionStop_ = std::chrono::system_clock::now();
        sessionActive_ = false;

        // Final report of the session (the last snapshot, if one is still
        // running, waits for this and is then ignored).
        auto& reports = netwolf::exporters::TelecomReports::instance();
        const std::string folder = reports.folder();

        reports.end();

        setStatusLine(folder.empty()
            ? std::wstring(L"Live Monitor stopped.")
            : L"Live Monitor stopped. Final report saved in " + widen(folder));
    }


    // ------------------------------------------------------------
    // Background engine worker
    // ------------------------------------------------------------

    void Win32GuiApp::startEngineWorker()
    {
        if (engineThread_.joinable())
            return;

        {
            std::lock_guard<std::mutex> lock(workerMutex_);
            workerStop_ = false;
        }

        engineThread_ = std::thread(
            [this]()
            {
                engineWorkerLoop();
            }
        );
    }


    void Win32GuiApp::stopEngineWorker()
    {
        {
            std::lock_guard<std::mutex> lock(workerMutex_);
            workerStop_ = true;
            liveMode_ = false;
        }

        workerCv_.notify_one();

        // Waits for at most the snapshot currently in progress.
        if (engineThread_.joinable())
            engineThread_.join();
    }


    void Win32GuiApp::requestOneShot(int kind)
    {
        {
            std::lock_guard<std::mutex> lock(workerMutex_);
            pendingOneShot_ = kind;
        }

        workerCv_.notify_one();
    }


    void Win32GuiApp::engineWorkerLoop()
    {
        using Clock = std::chrono::steady_clock;

        Clock::time_point nextLiveRun = Clock::now();

        for (;;)
        {
            int job = 0;              // 1 = TCP (+ background Npcap), 2 = TCP + UDP
            bool stopCapture = false;

            {
                std::unique_lock<std::mutex> lock(workerMutex_);

                if (liveMode_)
                {
                    // Live: wake at the next refresh time, or earlier on a request.
                    workerCv_.wait_until(
                        lock,
                        nextLiveRun,
                        [this]()
                        {
                            return workerStop_ ||
                                pendingOneShot_ != 0 ||
                                pendingCaptureStop_ ||
                                !liveMode_;
                        }
                    );
                }
                else
                {
                    // Idle: sleep until there is something to do (no busy loop).
                    workerCv_.wait(
                        lock,
                        [this]()
                        {
                            return workerStop_ ||
                                pendingOneShot_ != 0 ||
                                pendingCaptureStop_ ||
                                liveMode_;
                        }
                    );
                }

                if (workerStop_)
                    return;

                if (pendingCaptureStop_)
                {
                    pendingCaptureStop_ = false;
                    stopCapture = !liveMode_;
                }

                if (pendingOneShot_ != 0)
                {
                    job = pendingOneShot_;
                    pendingOneShot_ = 0;
                }
                else if (liveMode_ && Clock::now() >= nextLiveRun)
                {
                    job = 1;
                }
            }

            if (stopCapture)
            {
                // Joins the capture thread here, on the worker, not on the UI.
                netwolf::live::LivePacketCaptureService::instance().stop();
            }

            if (job == 0)
                continue;

            GuiControllerRunResult result;

            const Clock::time_point engineStart = Clock::now();

            {
                std::lock_guard<std::mutex> engineLock(engineMutex_);

                if (job == 2)
                    result = controller_.runLiveWindowsTcpAndUdpEndpointOnce();
                else
                    result = controller_.runLiveWindowsTcpNpcapLiveOnce();
            }

            const double engineMs = std::chrono::duration<double, std::milli>(
                Clock::now() - engineStart
            ).count();

            // Anything to free is moved out under the lock and destroyed
            // after it, here on the worker thread, never on the UI thread.
            GuiControllerRunResult staleResult;
            std::vector<GuiDashboardModel> retired;

            {
                std::lock_guard<std::mutex> lock(resultMutex_);

                // A result the UI never picked up is replaced; free it below.
                if (hasPendingResult_)
                    staleResult = std::move(pendingResult_);

                pendingResult_ = std::move(result);
                pendingEngineMs_ = engineMs;
                hasPendingResult_ = true;

                retired.swap(retiredDashboards_);
            }

            retired.clear();
            staleResult = GuiControllerRunResult{};

            // Asynchronous: never blocks the worker on the UI thread.
            if (hwnd_)
                PostMessageW(hwnd_, kEngineResultMessage, 0, 0);

            nextLiveRun =
                Clock::now() + std::chrono::milliseconds(kLiveMonitorIntervalMs);
        }
    }


    void Win32GuiApp::applyPendingResult()
    {
        const auto applyStart = std::chrono::steady_clock::now();

        GuiControllerRunResult result;
        double engineMs = 0.0;

        {
            std::lock_guard<std::mutex> lock(resultMutex_);

            if (!hasPendingResult_)
                return;

            result = std::move(pendingResult_);
            engineMs = pendingEngineMs_;
            hasPendingResult_ = false;
        }

        // Runs on the UI thread: swaps in the finished model (no copy).
        updateDashboard(result);

        // result.dashboard now holds the PREVIOUS model. Freeing it can take
        // tens of milliseconds, so the worker thread frees it instead.
        {
            std::lock_guard<std::mutex> lock(resultMutex_);
            retiredDashboards_.push_back(std::move(result.dashboard));
        }

        // Diagnostics: size of what the UI now shows.
        size_t rows = 0;
        size_t subRows = 0;

        const GuiDevicePanel* panels[] = {
            &currentDashboard_.redflagPanel,
            &currentDashboard_.heavyPanel,
            &currentDashboard_.normalPanel
        };

        for (const GuiDevicePanel* panel : panels)
        {
            for (const auto& device : panel->devices)
            {
                rows += device.connections.size();

                for (const auto& connection : device.connections)
                    subRows += connection.subConnections.size();
            }
        }

        perfRows_ = rows;
        perfSubRows_ = subRows;
        perfLastEngineMs_ = engineMs;

        // Restart the "max paint" window for the new refresh period.
        perfMaxPaintMs_ = perfLastPaintMs_;

        perfLastApplyMs_ = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - applyStart
        ).count();
    }

    void Win32GuiApp::exportLastReport()
    {
        GuiReportExportResult result;

        {
            // The engine worker also uses controller_; never touch it concurrently.
            // Released before the MessageBox below so the worker is not held up.
            std::lock_guard<std::mutex> engineLock(engineMutex_);
            result = controller_.exportLastReportPack();
        }

        std::wostringstream message;

        message
            << L"Status: "
            << widen(toString(result.status))
            << L"\n\n"
            << L"Message: "
            << widen(result.message)
            << L"\n\n"
            << L"Output directory:\n"
            << widen(result.outputDirectory)
            << L"\n\n"
            << L"Files written: "
            << result.successCount
            << L"\nFailures: "
            << result.failureCount;

        MessageBoxW(
            hwnd_,
            message.str().c_str(),
            L"Report Export",
            result.success() ? MB_OK | MB_ICONINFORMATION : MB_OK | MB_ICONWARNING
        );

        setStatusLine(
            result.success()
            ? L"Report pack exported successfully."
            : L"Report export completed with warnings or errors."
        );

        InvalidateRect(hwnd_, nullptr, FALSE);
    }


    void Win32GuiApp::clearDashboard()
    {
        {
            std::lock_guard<std::mutex> engineLock(engineMutex_);
            controller_.clearLastRun();
        }

        // Drop a result that finished before the clear, so it does not
        // immediately repopulate the dashboard the user just cleared.
        {
            std::lock_guard<std::mutex> lock(resultMutex_);
            hasPendingResult_ = false;
        }

        currentDashboard_ = GuiDashboardModel{};
        currentDashboard_.title = "NetWolf v2";
        currentDashboard_.statusLabel = "Ready";
        currentDashboard_.summaryText = "Dashboard cleared. Run a snapshot to show data.";

        currentDashboard_.normalPanel.severity = GuiSeverity::Normal;
        currentDashboard_.normalPanel.title = "Normal Devices";
        currentDashboard_.normalPanel.subtitle = "No data yet.";

        currentDashboard_.heavyPanel.severity = GuiSeverity::Heavy;
        currentDashboard_.heavyPanel.title = "Heavy Devices";
        currentDashboard_.heavyPanel.subtitle = "No data yet.";

        currentDashboard_.redflagPanel.severity = GuiSeverity::Redflag;
        currentDashboard_.redflagPanel.title = "Redflag Devices";
        currentDashboard_.redflagPanel.subtitle = "No data yet.";

        setStatusLine(L"Dashboard cleared.");
    }


    void Win32GuiApp::showAbout()
    {
        MessageBoxW(
            hwnd_,
            L"NetWolf v2\n\n"
            L"Connection Attribution Engine\n\n"
            L"Pipeline:\n"
            L"Capture -> Analyze -> Attribute -> Group -> Classify\n\n"
            L"This GUI consumes GuiController output only.\n"
            L"The core engine remains separated from the interface.",
            L"About NetWolf v2",
            MB_OK | MB_ICONINFORMATION
        );
    }


    void Win32GuiApp::updateDashboard(
        GuiControllerRunResult& result
    )
    {
        // Performance: SWAP instead of deep-copying. A live dashboard holds
        // thousands of strings (every sub-connection carries reason/limitations
        // text); copying it on the UI thread every refresh froze scrolling.
        // After the swap, result.dashboard holds the previous model, which the
        // caller hands to the worker thread to free.
        std::swap(currentDashboard_, result.dashboard);

        std::wostringstream line;

        line
            << widen(result.statusLabel)
            << L" | "
            << widen(result.modeLabel)
            << L" | "
            << widen(result.summaryText);

        setStatusLine(line.str());
    }


    void Win32GuiApp::setStatusLine(
        const std::wstring& text
    )
    {
        statusLine_ = text;

        if (hwnd_)
            InvalidateRect(hwnd_, nullptr, FALSE);
    }


    // ------------------------------------------------------------
    // Drawing
    // ------------------------------------------------------------

    void Win32GuiApp::drawDashboard(
        HDC hdc,
        const RECT& clientRect
    )
    {
        FillRect(hdc, &clientRect, backgroundBrush_);

        SetBkMode(hdc, TRANSPARENT);

        RECT topBar{
            clientRect.left + kMargin,
            clientRect.top + kMargin,
            clientRect.right - kMargin,
            clientRect.top + kMargin + kTopBarHeight
        };

        RECT liveBox{
            clientRect.left + kMargin,
            topBar.bottom + kGap,
            clientRect.right - kMargin,
            topBar.bottom + kGap + kLiveBoxHeight
        };

        RECT metrics{
            clientRect.left + kMargin,
            liveBox.bottom + kGap,
            clientRect.right - kMargin,
            liveBox.bottom + kGap + kMetricHeight
        };

        RECT panels{
            clientRect.left + kMargin,
            metrics.bottom + kGap,
            clientRect.right - kMargin,
            clientRect.bottom - kMargin
        };

        drawTopBar(hdc, topBar);
        drawLiveMonitorBox(hdc, liveBox);
        drawMetricCards(hdc, metrics);

        drawDevicePanels(hdc, panels);
    }


    void Win32GuiApp::drawTopBar(
        HDC hdc,
        const RECT& rect
    )
    {
        drawRoundedPanel(
            hdc,
            rect,
            rgb(config_.theme.panelR, config_.theme.panelG, config_.theme.panelB),
            rgb(config_.theme.borderR, config_.theme.borderG, config_.theme.borderB)
        );

        // ---- Clock and session timer (right side) ----
        const bool clockFits = (rect.right - rect.left) > kClockWidth + 420;
        int textRight = rect.right - 20;

        if (clockFits)
        {
            clockRect_ = RECT{ rect.right - kClockWidth - 12, rect.top + 10, rect.right - 12, rect.bottom - 10 };
            drawClockBox(hdc, clockRect_);
            textRight = clockRect_.left - 16;
        }
        else
        {
            clockRect_ = RECT{};
        }

        RECT titleRect = rect;
        titleRect.left += 20;
        titleRect.top += 14;
        titleRect.right = textRight;
        titleRect.bottom = titleRect.top + 34;

        SelectObject(hdc, titleFont_);
        SetTextColor(
            hdc,
            rgb(config_.theme.textR, config_.theme.textG, config_.theme.textB)
        );

        const std::wstring title =
            widen(currentDashboard_.title.empty() ? "NetWolf v2" : currentDashboard_.title);

        DrawTextW(
            hdc,
            title.c_str(),
            -1,
            &titleRect,
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS
        );

        RECT summaryRect = rect;
        summaryRect.left += 20;
        summaryRect.top = titleRect.bottom + 8;
        summaryRect.right = textRight;
        summaryRect.bottom -= 10;

        SelectObject(hdc, smallFont_);
        SetTextColor(
            hdc,
            rgb(config_.theme.mutedTextR, config_.theme.mutedTextG, config_.theme.mutedTextB)
        );

        std::wstring summary = L"Status: ";

        summary += widen(
            currentDashboard_.statusLabel.empty()
            ? "Ready"
            : currentDashboard_.statusLabel
        );

        if (!statusLine_.empty())
        {
            summary += L" | ";
            summary += shorten(statusLine_, 130);
        }
        else
        {
            summary += L" | Waiting for snapshot.";
        }

        DrawTextW(
            hdc,
            summary.c_str(),
            -1,
            &summaryRect,
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS
        );
    }

    // Current date and time, and the Live Monitor session timer.
    void Win32GuiApp::drawClockBox(
        HDC hdc,
        const RECT& rect
    )
    {
        const bool running = sessionActive_;

        drawRoundedPanel(
            hdc,
            rect,
            rgb(config_.theme.backgroundR, config_.theme.backgroundG, config_.theme.backgroundB),
            running
                ? rgb(config_.theme.normalR, config_.theme.normalG, config_.theme.normalB)
                : rgb(config_.theme.borderR, config_.theme.borderG, config_.theme.borderB)
        );

        auto clockText = [](std::chrono::system_clock::time_point at, const wchar_t* pattern)
            {
                const std::time_t raw = std::chrono::system_clock::to_time_t(at);
                std::tm local{};
                localtime_s(&local, &raw);

                wchar_t buffer[64]{};
                std::wcsftime(buffer, 64, pattern, &local);
                return std::wstring(buffer);
            };

        auto durationText = [](std::chrono::system_clock::duration duration)
            {
                long long seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
                if (seconds < 0) seconds = 0;

                wchar_t buffer[32]{};
                swprintf(buffer, 32, L"%02lld:%02lld:%02lld", seconds / 3600, (seconds / 60) % 60, seconds % 60);
                return std::wstring(buffer);
            };

        const auto now = std::chrono::system_clock::now();

        // Line 1: date and time.
        RECT line1 = rect;
        line1.left += 14;
        line1.right -= 14;
        line1.top += 6;
        line1.bottom = line1.top + 32;

        SelectObject(hdc, titleFont_);
        SetTextColor(hdc, rgb(config_.theme.textR, config_.theme.textG, config_.theme.textB));

        const std::wstring dateTime = clockText(now, L"%Y-%m-%d   %H:%M:%S");
        DrawTextW(hdc, dateTime.c_str(), -1, &line1, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

        // Line 2: session.
        RECT line2 = rect;
        line2.left += 14;
        line2.right -= 14;
        line2.top = line1.bottom + 2;
        line2.bottom = rect.bottom - 4;

        std::wstring session;
        COLORREF color = rgb(config_.theme.mutedTextR, config_.theme.mutedTextG, config_.theme.mutedTextB);

        if (running)
        {
            session = L"Monitoring since " + clockText(sessionStart_, L"%H:%M:%S") +
                L"   |   " + durationText(now - sessionStart_);
            color = rgb(config_.theme.normalR, config_.theme.normalG, config_.theme.normalB);
        }
        else if (sessionEverStarted_)
        {
            session = L"Session: " + durationText(sessionStop_ - sessionStart_) + L" (stopped)  |  " +
                clockText(sessionStart_, L"%H:%M") + L"-" + clockText(sessionStop_, L"%H:%M");
            color = rgb(config_.theme.heavyR, config_.theme.heavyG, config_.theme.heavyB);
        }
        else
        {
            session = L"Live Monitor not started";
        }

        SelectObject(hdc, headerFont_);
        SetTextColor(hdc, color);
        DrawTextW(hdc, session.c_str(), -1, &line2, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    }


    void Win32GuiApp::drawLiveMonitorBox(
        HDC hdc,
        const RECT& rect
    )
    {
        GuiSeverity liveSeverity = GuiSeverity::Normal;

        if (currentDashboard_.redflagPanel.deviceCount > 0)
            liveSeverity = GuiSeverity::Redflag;
        else if (currentDashboard_.heavyPanel.deviceCount > 0)
            liveSeverity = GuiSeverity::Heavy;

        drawRoundedPanel(
            hdc,
            rect,
            rgb(
                std::min(255, config_.theme.panelR + 4),
                std::min(255, config_.theme.panelG + 4),
                std::min(255, config_.theme.panelB + 4)
            ),
            colorForSeverity(liveSeverity)
        );

        const size_t normalDevices =
            currentDashboard_.normalPanel.deviceCount;

        const size_t heavyDevices =
            currentDashboard_.heavyPanel.deviceCount;

        const size_t redflagDevices =
            currentDashboard_.redflagPanel.deviceCount;

        const size_t totalDevices =
            normalDevices + heavyDevices + redflagDevices;

        const size_t totalGroups =
            currentDashboard_.normalPanel.connectionCount +
            currentDashboard_.heavyPanel.connectionCount +
            currentDashboard_.redflagPanel.connectionCount;

        RECT titleRect = rect;
        titleRect.left += 18;
        titleRect.top += 12;
        titleRect.right -= 18;
        titleRect.bottom = titleRect.top + 24;

        SelectObject(hdc, headerFont_);
        SetTextColor(hdc, colorForSeverity(liveSeverity));

        DrawTextW(
            hdc,
            L"LIVE MONITOR",
            -1,
            &titleRect,
            DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS
        );

        RECT liveLampRect{
            rect.right - 42,
            titleRect.top + 3,
            rect.right - 24,
            titleRect.top + 21
        };

        HBRUSH liveLampBrush = CreateSolidBrush(
            liveTimerRunning_
                ? rgb(config_.theme.normalR, config_.theme.normalG, config_.theme.normalB)
                : rgb(config_.theme.redflagR, config_.theme.redflagG, config_.theme.redflagB)
        );

        HBRUSH oldLampBrush = static_cast<HBRUSH>(
            SelectObject(
                hdc,
                liveLampBrush
            )
        );

        HPEN liveLampPen = CreatePen(
            PS_SOLID,
            1,
            rgb(config_.theme.borderR, config_.theme.borderG, config_.theme.borderB)
        );

        HPEN oldLampPen = static_cast<HPEN>(
            SelectObject(
                hdc,
                liveLampPen
            )
        );

        Ellipse(
            hdc,
            liveLampRect.left,
            liveLampRect.top,
            liveLampRect.right,
            liveLampRect.bottom
        );

        SelectObject(hdc, oldLampPen);
        SelectObject(hdc, oldLampBrush);
        DeleteObject(liveLampPen);
        DeleteObject(liveLampBrush);

        RECT modeRect = rect;
        modeRect.left += 18;
        modeRect.top = titleRect.bottom + 8;
        modeRect.right = rect.left + ((rect.right - rect.left) / 3);
        modeRect.bottom = rect.bottom - 10;

        SelectObject(hdc, smallFont_);
        SetTextColor(
            hdc,
            rgb(config_.theme.textR, config_.theme.textG, config_.theme.textB)
        );

        std::wostringstream modeText;

        modeText
            << L"Mode: "
            << (liveTimerRunning_ ? L"Live Periodic" : L"Manual Snapshot")
            << L"\nSensor: Windows TCP Table + background Npcap DNS/TLS\n"
            << L"Refresh: "
            << (liveTimerRunning_ ? L"Every 1 second" : L"Manual")
            << L"\nExperiment log: "
            << (netwolf::exporters::ExperimentLog::instance().active() ? L"ON (recording)" : L"off")
            << L"\nReports: "
            << (netwolf::exporters::TelecomReports::instance().active()
                ? L"every 15 min (" + std::to_wstring(netwolf::exporters::TelecomReports::instance().reportsWritten()) + L" written)"
                : std::wstring(L"off"))
            << (netwolf::exporters::TelecomReports::instance().masking() ? L", masked" : L", NOT masked");

        DrawTextW(
            hdc,
            modeText.str().c_str(),
            -1,
            &modeRect,
            DT_LEFT | DT_TOP | DT_WORDBREAK | DT_END_ELLIPSIS
        );

        RECT stateRect = rect;
        stateRect.left = modeRect.right + 18;
        stateRect.top = titleRect.bottom + 8;
        stateRect.right = rect.left + ((rect.right - rect.left) * 2 / 3);
        stateRect.bottom = rect.bottom - 10;

        std::wostringstream stateText;

        stateText
            << L"Devices: "
            << totalDevices
            << L"\nNormal: "
            << normalDevices
            << L" | Heavy: "
            << heavyDevices
            << L" | Redflag: "
            << redflagDevices
            << L"\nGroups: "
            << totalGroups;

        DrawTextW(
            hdc,
            stateText.str().c_str(),
            -1,
            &stateRect,
            DT_LEFT | DT_TOP | DT_WORDBREAK | DT_END_ELLIPSIS
        );

        // Evil Twin algorithm state: red on ALERT, amber during a collapse.
        if (!currentDashboard_.evilTwinPhase.empty())
        {
            RECT evilTwinRect = stateRect;
            evilTwinRect.top = stateRect.top + 3 * 14;

            const std::string& phase = currentDashboard_.evilTwinPhase;

            COLORREF phaseColor =
                rgb(config_.theme.mutedTextR, config_.theme.mutedTextG, config_.theme.mutedTextB);

            if (phase == "ALERT")
                phaseColor = colorForSeverity(GuiSeverity::Redflag);
            else if (phase == "Collapse")
                phaseColor = colorForSeverity(GuiSeverity::Heavy);

            SetTextColor(hdc, phaseColor);

            const std::wstring evilTwinText =
                L"Evil Twin: " + widen(currentDashboard_.evilTwinSummary);

            DrawTextW(
                hdc,
                evilTwinText.c_str(),
                -1,
                &evilTwinRect,
                DT_LEFT | DT_TOP | DT_WORDBREAK | DT_END_ELLIPSIS
            );

            SetTextColor(
                hdc,
                rgb(config_.theme.mutedTextR, config_.theme.mutedTextG, config_.theme.mutedTextB)
            );
        }

        RECT summaryRect = rect;
        summaryRect.left = stateRect.right + 18;
        summaryRect.top = titleRect.bottom + 8;
        summaryRect.right = rect.right - 18;
        summaryRect.bottom = rect.bottom - 10;

        SetTextColor(
            hdc,
            rgb(config_.theme.mutedTextR, config_.theme.mutedTextG, config_.theme.mutedTextB)
        );

        std::wstring summary = L"Status: ";

        if (!currentDashboard_.statusLabel.empty())
            summary += widen(currentDashboard_.statusLabel);
        else
            summary += L"Ready";

        summary += L"\n";

        if (!currentDashboard_.hotspotLine.empty())
        {
            summary += shorten(widen(currentDashboard_.hotspotLine), 82);
            summary += L"\n";
        }
        else if (currentDashboard_.stage7LiveOutput)
        {
            summary += L"Stage 7: Live backend active | Groups: ";
            summary += std::to_wstring(currentDashboard_.stage7LiveGroups);
            summary += L" | Sub: ";
            summary += std::to_wstring(currentDashboard_.stage7LiveSubConnections);
            summary += L"\n";
        }
        else
        {
            summary += L"Stage 7: waiting for live backend output\n";
        }

        if (!statusLine_.empty())
            summary += shorten(statusLine_, 82);
        else
            summary += L"Waiting for snapshot.";

        // Live performance diagnostics, measured on this machine.
        // paint = UI time per frame, apply = UI time to take a new result,
        // engine = background snapshot time (does not block the UI).
        {
            std::wostringstream perf;

            perf
                << std::fixed
                << std::setprecision(1)
                << L"\nPerf: paint "
                << perfLastPaintMs_
                << L"ms (max "
                << perfMaxPaintMs_
                << L") | apply "
                << perfLastApplyMs_
                << L"ms | engine "
                << std::setprecision(0)
                << perfLastEngineMs_
                << L"ms | "
                << perfRows_
                << L" rows / "
                << perfSubRows_
                << L" subs";

            summary += perf.str();
        }

        DrawTextW(
            hdc,
            summary.c_str(),
            -1,
            &summaryRect,
            DT_LEFT | DT_TOP | DT_WORDBREAK | DT_END_ELLIPSIS
        );
    }

    void Win32GuiApp::drawMetricCards(
        HDC hdc,
        const RECT& rect
    )
    {
        std::vector<GuiMetricCard> metrics = currentDashboard_.topMetrics;

        if (metrics.empty())
        {
            metrics.push_back({ "Normal", "0", "Devices inside Normal box" });
            metrics.push_back({ "Heavy", "0", "Devices inside Heavy box" });
            metrics.push_back({ "Redflag", "0", "Devices inside Redflag box" });
            metrics.push_back({ "Groups", "0", "Grouped main connections" });
        }

        const int count = static_cast<int>(std::min<size_t>(metrics.size(), 6));

        if (count <= 0)
            return;

        const int totalGap = kGap * (count - 1);
        const int cardWidth = (rect.right - rect.left - totalGap) / count;

        for (int i = 0; i < count; ++i)
        {
            RECT card{
                rect.left + i * (cardWidth + kGap),
                rect.top,
                rect.left + i * (cardWidth + kGap) + cardWidth,
                rect.bottom
            };

            drawRoundedPanel(
                hdc,
                card,
                rgb(config_.theme.panelR, config_.theme.panelG, config_.theme.panelB),
                rgb(config_.theme.borderR, config_.theme.borderG, config_.theme.borderB)
            );

            RECT titleRect = card;
            titleRect.left += 14;
            titleRect.top += 10;
            titleRect.right -= 14;
            titleRect.bottom = titleRect.top + 20;

            SelectObject(hdc, smallFont_);
            SetTextColor(
                hdc,
                rgb(config_.theme.mutedTextR, config_.theme.mutedTextG, config_.theme.mutedTextB)
            );

            DrawTextW(
                hdc,
                widen(metrics[static_cast<size_t>(i)].title).c_str(),
                -1,
                &titleRect,
                DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS
            );

            RECT valueRect = card;
            valueRect.left += 14;
            valueRect.top = titleRect.bottom + 4;
            valueRect.right -= 14;
            valueRect.bottom = valueRect.top + 32;

            SelectObject(hdc, headerFont_);
            SetTextColor(
                hdc,
                rgb(config_.theme.textR, config_.theme.textG, config_.theme.textB)
            );

            DrawTextW(
                hdc,
                widen(metrics[static_cast<size_t>(i)].value).c_str(),
                -1,
                &valueRect,
                DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS
            );

            RECT hintRect = card;
            hintRect.left += 14;
            hintRect.top = valueRect.bottom + 2;
            hintRect.right -= 14;
            hintRect.bottom -= 8;

            SelectObject(hdc, smallFont_);
            SetTextColor(
                hdc,
                rgb(config_.theme.mutedTextR, config_.theme.mutedTextG, config_.theme.mutedTextB)
            );

            DrawTextW(
                hdc,
                widen(metrics[static_cast<size_t>(i)].hint).c_str(),
                -1,
                &hintRect,
                DT_LEFT | DT_TOP | DT_END_ELLIPSIS
            );
        }
    }


    void Win32GuiApp::drawDevicePanels(
        HDC hdc,
        const RECT& rect
    )
    {
        const int availableWidth = rect.right - rect.left;

        const int triageWidth =
            static_cast<int>(availableWidth * 0.25);

        const int inspectorWidth =
            static_cast<int>(availableWidth * 0.28);

        const int groupsWidth =
            availableWidth - triageWidth - inspectorWidth - (kGap * 2);

        RECT triageRect{
            rect.left,
            rect.top,
            rect.left + triageWidth,
            rect.bottom
        };

        RECT groupsRect{
            triageRect.right + kGap,
            rect.top,
            triageRect.right + kGap + groupsWidth,
            rect.bottom
        };

        RECT inspectorRect{
            groupsRect.right + kGap,
            rect.top,
            rect.right,
            rect.bottom
        };

        // ============================================================
        // LEFT PANEL: DEVICE TRIAGE
        // ============================================================

        drawRoundedPanel(
            hdc,
            triageRect,
            rgb(config_.theme.panelR, config_.theme.panelG, config_.theme.panelB),
            rgb(config_.theme.borderR, config_.theme.borderG, config_.theme.borderB)
        );

        RECT triageHeader = triageRect;
        triageHeader.left += 16;
        triageHeader.top += 14;
        triageHeader.right -= 16;
        triageHeader.bottom = triageHeader.top + 28;

        SelectObject(hdc, headerFont_);
        SetTextColor(
            hdc,
            rgb(config_.theme.textR, config_.theme.textG, config_.theme.textB)
        );

        DrawTextW(
            hdc,
            L"DEVICE TRIAGE",
            -1,
            &triageHeader,
            DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS
        );

        RECT triageSub = triageHeader;
        triageSub.top = triageHeader.bottom + 4;
        triageSub.bottom = triageSub.top + 34;

        SelectObject(hdc, smallFont_);
        SetTextColor(
            hdc,
            rgb(config_.theme.mutedTextR, config_.theme.mutedTextG, config_.theme.mutedTextB)
        );

        DrawTextW(
            hdc,
            L"Priority view: Redflag, Heavy, then Normal devices.",
            -1,
            &triageSub,
            DT_LEFT | DT_TOP | DT_WORDBREAK | DT_END_ELLIPSIS
        );

        auto drawBucket = [&](const GuiDevicePanel& panel, const wchar_t* title, const RECT& bucketRect)
            {
                drawRoundedPanel(
                    hdc,
                    bucketRect,
                    rgb(
                        std::min(255, config_.theme.panelR + 6),
                        std::min(255, config_.theme.panelG + 6),
                        std::min(255, config_.theme.panelB + 6)
                    ),
                    colorForSeverity(panel.severity)
                );

                RECT titleRect = bucketRect;
                titleRect.left += 12;
                titleRect.top += 10;
                titleRect.right -= 12;
                titleRect.bottom = titleRect.top + 22;

                SelectObject(hdc, headerFont_);
                SetTextColor(hdc, colorForSeverity(panel.severity));

                DrawTextW(
                    hdc,
                    title,
                    -1,
                    &titleRect,
                    DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS
                );

                RECT bodyRect = bucketRect;
                bodyRect.left += 12;
                bodyRect.top = titleRect.bottom + 6;
                bodyRect.right -= 12;
                bodyRect.bottom -= 8;

                SelectObject(hdc, smallFont_);
                SetTextColor(
                    hdc,
                    rgb(config_.theme.textR, config_.theme.textG, config_.theme.textB)
                );

                std::wostringstream body;

                body
                    << panel.deviceCount
                    << L" device";

                if (panel.deviceCount != 1)
                    body << L"s";

                body
                    << L" | "
                    << panel.connectionCount
                    << L" group";

                if (panel.connectionCount != 1)
                    body << L"s";

                if (!panel.devices.empty())
                {
                    // Up to two devices by name; the rest are counted.
                    const size_t shown = std::min<size_t>(panel.devices.size(), 2);

                    if (panel.devices.size() > shown)
                        body << L"  (+" << (panel.devices.size() - shown) << L" more)";

                    for (size_t index = 0; index < shown; ++index)
                    {
                        const GuiDeviceCard& device = panel.devices[index];

                        body
                            << L"\n"
                            << widen(device.hostName.empty() ? device.deviceIp : device.hostName)
                            << L"  |  "
                            << device.totalConnections
                            << L" conns";
                    }
                }
                else
                {
                    body << L"\nNo devices.";
                }

                DrawTextW(
                    hdc,
                    body.str().c_str(),
                    -1,
                    &bodyRect,
                    DT_LEFT | DT_TOP | DT_WORDBREAK | DT_END_ELLIPSIS
                );
            };

        const int bucketTop = triageSub.bottom + 12;
        const int bucketGap = 10;

        const int availableBucketHeight =
            triageRect.bottom - bucketTop - 14;

        const int bucketHeight =
            std::max<int>(
                88,
                (availableBucketHeight - (bucketGap * 2)) / 3
            );

        RECT redflagBucket{
            triageRect.left + 14,
            bucketTop,
            triageRect.right - 14,
            bucketTop + bucketHeight
        };

        RECT heavyBucket{
            triageRect.left + 14,
            redflagBucket.bottom + bucketGap,
            triageRect.right - 14,
            redflagBucket.bottom + bucketGap + bucketHeight
        };

        RECT normalBucket{
            triageRect.left + 14,
            heavyBucket.bottom + bucketGap,
            triageRect.right - 14,
            triageRect.bottom - 14
        };

        drawBucket(currentDashboard_.redflagPanel, L"REDFLAG", redflagBucket);
        drawBucket(currentDashboard_.heavyPanel, L"HEAVY", heavyBucket);
        drawBucket(currentDashboard_.normalPanel, L"NORMAL", normalBucket);

        // ============================================================
        // CENTER PANEL: CONNECTION GROUPS
        // ============================================================

        drawRoundedPanel(
            hdc,
            groupsRect,
            rgb(config_.theme.panelR, config_.theme.panelG, config_.theme.panelB),
            rgb(config_.theme.borderR, config_.theme.borderG, config_.theme.borderB)
        );

        RECT groupsHeader = groupsRect;
        groupsHeader.left += 16;
        groupsHeader.top += 14;
        groupsHeader.right -= 16;
        groupsHeader.bottom = groupsHeader.top + 28;

        SelectObject(hdc, headerFont_);
        SetTextColor(
            hdc,
            rgb(config_.theme.textR, config_.theme.textG, config_.theme.textB)
        );

        DrawTextW(
            hdc,
            L"CONNECTIONS",
            -1,
            &groupsHeader,
            DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS
        );

        RECT groupsSub = groupsHeader;
        groupsSub.top = groupsHeader.bottom + 4;
        groupsSub.bottom = groupsSub.top + 34;

        SelectObject(hdc, smallFont_);
        SetTextColor(
            hdc,
            rgb(config_.theme.mutedTextR, config_.theme.mutedTextG, config_.theme.mutedTextB)
        );

        DrawTextW(
            hdc,
            L"Destinations are shown as URL-style names when available; otherwise NetWolf shows the exact live remote endpoint URL.",
            -1,
            &groupsSub,
            DT_LEFT | DT_TOP | DT_WORDBREAK | DT_END_ELLIPSIS
        );

        // Device-first table:
        // every device is ONE header row; its destination groups appear under
        // it only while the device is open (click the device row to toggle).
        // Pointers only: rows live in currentDashboard_, unchanged during paint.
        struct TableDevice
        {
            const GuiDeviceCard* card = nullptr;
            std::vector<const GuiConnectionRow*> rows;
        };

        std::vector<TableDevice> tableDevices;

        auto rowOrder = [](const GuiConnectionRow* pa, const GuiConnectionRow* pb)
            {
                const GuiConnectionRow& a = *pa;
                const GuiConnectionRow& b = *pb;

                if (a.destinationKnown != b.destinationKnown)
                    return a.destinationKnown && !b.destinationKnown;

                if (a.directPacketDestination != b.directPacketDestination)
                    return a.directPacketDestination && !b.directPacketDestination;

                if (a.subConnectionCount != b.subConnectionCount)
                    return a.subConnectionCount > b.subConnectionCount;

                if (a.confidenceScore != b.confidenceScore)
                    return a.confidenceScore > b.confidenceScore;

                return a.destinationText < b.destinationText;
            };

        // Redflag first, then Heavy, then Normal; inside each state the
        // device with the most connections comes first.
        auto collectDevices = [&](const GuiDevicePanel& panel)
            {
                const size_t firstIndex = tableDevices.size();

                for (const auto& device : panel.devices)
                {
                    TableDevice tableDevice;
                    tableDevice.card = &device;

                    for (const auto& connection : device.connections)
                        tableDevice.rows.push_back(&connection);

                    std::stable_sort(
                        tableDevice.rows.begin(),
                        tableDevice.rows.end(),
                        rowOrder
                    );

                    tableDevices.push_back(std::move(tableDevice));
                }

                std::stable_sort(
                    tableDevices.begin() + static_cast<std::ptrdiff_t>(firstIndex),
                    tableDevices.end(),
                    [](const TableDevice& a, const TableDevice& b)
                    {
                        if (a.card->totalConnections != b.card->totalConnections)
                            return a.card->totalConnections > b.card->totalConnections;

                        return a.card->deviceIp < b.card->deviceIp;
                    }
                );
            };

        collectDevices(currentDashboard_.redflagPanel);
        collectDevices(currentDashboard_.heavyPanel);
        collectDevices(currentDashboard_.normalPanel);

        RECT tableRect = groupsRect;
        tableRect.left += 14;
        tableRect.top = groupsSub.bottom + 14;
        tableRect.right -= 14;
        tableRect.bottom -= 14;

        if (tableDevices.empty())
        {
            connectionRowRects_.clear();
            connectionRowKeys_.clear();

            expandedSubListRects_.clear();
            expandedSubListKeys_.clear();
            subConnectionMaxScrollOffsets_.clear();

            subConnectionScrollBarRects_.clear();
            subConnectionScrollBarKeys_.clear();

            connectionsScrollOffset_ = 0;
            connectionsMaxScrollOffset_ = 0;
            connectionsViewportRect_ = tableRect;

            SelectObject(hdc, normalFont_);
            SetTextColor(
                hdc,
                rgb(config_.theme.mutedTextR, config_.theme.mutedTextG, config_.theme.mutedTextB)
            );

            DrawTextW(
                hdc,
                L"No live connections yet.\nRun a TCP snapshot or start Live Monitor to populate this table.",
                -1,
                &tableRect,
                DT_LEFT | DT_TOP | DT_WORDBREAK
            );
        }
        else
        {
            const int tableWidth = tableRect.right - tableRect.left;

            // Names get all the width that is left after four small fixed
            // columns, so device and destination names are not cut.
            const int typeW = 54;
            const int subW = 50;
            const int trafficW = 76;
            const int confidenceW = 84;
            const int rightColumnsW = typeW + subW + trafficW + confidenceW;
            const int destW = std::max(140, tableWidth - rightColumnsW);

            const int headerHeight = 34;

            // Device row: 3 lines (name + state / details / top destinations).
            // Destination row: 2 lines (name / owner + exact host).
            const int deviceRowHeight = 66;
            const int childRowHeight = 46;

            RECT headerRect{
                tableRect.left,
                tableRect.top,
                tableRect.right,
                tableRect.top + headerHeight
            };

            drawRoundedPanel(
                hdc,
                headerRect,
                rgb(
                    std::min(255, config_.theme.panelR + 10),
                    std::min(255, config_.theme.panelG + 10),
                    std::min(255, config_.theme.panelB + 10)
                ),
                rgb(config_.theme.borderR, config_.theme.borderG, config_.theme.borderB)
            );

            auto drawCellText = [&](const std::wstring& text, const RECT& cell, COLORREF color, HFONT font)
                {
                    RECT textRect = cell;
                    textRect.left += 8;
                    textRect.right -= 8;

                    SelectObject(hdc, font);
                    SetTextColor(hdc, color);

                    DrawTextW(
                        hdc,
                        text.c_str(),
                        -1,
                        &textRect,
                        DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS
                    );
                };

            auto makeCell = [&](int left, int width, int top, int bottom) -> RECT
                {
                    return RECT{
                        left,
                        top,
                        left + width,
                        bottom
                    };
                };

            auto compactConnectionType = [&](const std::string& value) -> std::wstring
                {
                    if (value.find("HTTPS") != std::string::npos)
                        return L"HTTPS";

                    if (value.find("Encrypted HTTPS") != std::string::npos)
                        return L"HTTPS";

                    if (value.find("QUIC") != std::string::npos)
                        return L"QUIC";

                    if (value.find("DNS") != std::string::npos)
                        return L"DNS";

                    if (value.find("HTTP") != std::string::npos)
                        return L"HTTP";

                    if (value.find("TCP") != std::string::npos)
                        return L"TCP";

                    if (value.empty())
                        return L"Classified";

                    return shorten(widen(value), 18);
                };

            int x = tableRect.left;

            RECT destHeader = makeCell(x, destW, headerRect.top, headerRect.bottom);
            x += destW;

            RECT typeHeader = makeCell(x, typeW, headerRect.top, headerRect.bottom);
            x += typeW;

            RECT subHeader = makeCell(x, subW, headerRect.top, headerRect.bottom);
            x += subW;

            RECT trafficHeader = makeCell(x, trafficW, headerRect.top, headerRect.bottom);
            x += trafficW;

            RECT confidenceHeader = makeCell(x, confidenceW, headerRect.top, headerRect.bottom);

            const COLORREF headerColor =
                rgb(config_.theme.textR, config_.theme.textG, config_.theme.textB);

            drawCellText(L"Device  /  Destination", destHeader, headerColor, smallFont_);
            drawCellText(L"Type", typeHeader, headerColor, smallFont_);
            drawCellText(L"Conns", subHeader, headerColor, smallFont_);
            drawCellText(L"Traffic", trafficHeader, headerColor, smallFont_);
            drawCellText(L"Confidence", confidenceHeader, headerColor, smallFont_);

            HPEN gridPen = CreatePen(
                PS_SOLID,
                1,
                rgb(config_.theme.borderR, config_.theme.borderG, config_.theme.borderB)
            );

            HGDIOBJ oldPen = SelectObject(hdc, gridPen);

            int gridX = tableRect.left;

            for (const int columnWidth : { destW, typeW, subW, trafficW })
            {
                gridX += columnWidth;
                MoveToEx(hdc, gridX, headerRect.top, nullptr);
                LineTo(hdc, gridX, headerRect.bottom);
            }

            SelectObject(hdc, oldPen);
            DeleteObject(gridPen);

            connectionRowRects_.clear();
            connectionRowKeys_.clear();

            auto makeConnectionKey = [&](const GuiConnectionRow& row) -> std::string
                {
                    // Keep the UI expansion/scroll identity stable across live refreshes.
                    // Destination text, entity name, category, and confidence may change
                    // when background DNS/TLS evidence arrives. If those fields are part
                    // of the key, expanded rows collapse automatically every refresh.
                    // Use only the stable local grouping identity for GUI state.
                    std::string endpointKey;

                    if (!row.subConnections.empty())
                    {
                        const auto& sub = row.subConnections.front();

                        endpointKey =
                            sub.localIp + ":" + std::to_string(sub.localPort) + "->" +
                            sub.remoteIp + ":" + std::to_string(sub.remotePort);
                    }
                    else
                    {
                        endpointKey = "no-sub-endpoint";
                    }

                    return
                        row.sourceDeviceIp + "|" +
                        row.ownerProcess + "|" +
                        row.connectionType + "|" +
                        endpointKey;
                };

            // Flatten devices into visible table items. Each key is built
            // ONCE per paint. Group keys of closed devices still count as
            // current, so a group stays open when its device is reopened.
            struct TableItem
            {
                const GuiDeviceCard* device = nullptr;
                const GuiConnectionRow* row = nullptr;   // nullptr = device header
                size_t destinations = 0;
                std::string key;
            };

            std::vector<TableItem> items;
            std::set<std::string> currentKeys;

            for (const TableDevice& tableDevice : tableDevices)
            {
                TableItem header;
                header.device = tableDevice.card;
                header.destinations = tableDevice.rows.size();
                header.key = kDeviceRowKeyPrefix + tableDevice.card->deviceIp;
                items.push_back(std::move(header));

                const bool deviceOpen =
                    expandedDeviceKeys_.find(tableDevice.card->deviceIp) !=
                    expandedDeviceKeys_.end();

                for (const GuiConnectionRow* rowPtr : tableDevice.rows)
                {
                    std::string key = makeConnectionKey(*rowPtr);
                    currentKeys.insert(key);

                    if (deviceOpen)
                    {
                        TableItem child;
                        child.device = tableDevice.card;
                        child.row = rowPtr;
                        child.key = std::move(key);
                        items.push_back(std::move(child));
                    }
                }
            }

            for (auto it = expandedConnectionKeys_.begin();
                it != expandedConnectionKeys_.end(); )
            {
                if (currentKeys.find(*it) == currentKeys.end())
                    it = expandedConnectionKeys_.erase(it);
                else
                    ++it;
            }

            const int deviceGap = 6;
            const int childIndent = 18;

            const int firstRowTop = headerRect.bottom + 8;
            const int expandedHeight = 168;

            RECT scrollViewport{
                tableRect.left,
                firstRowTop,
                tableRect.right,
                tableRect.bottom
            };

            connectionsViewportRect_ = scrollViewport;

            const int viewportHeight =
                std::max<int>(
                    0,
                    scrollViewport.bottom - scrollViewport.top
                );

            int totalContentHeight = 0;

            for (size_t itemIndex = 0; itemIndex < items.size(); ++itemIndex)
            {
                const TableItem& item = items[itemIndex];

                if (item.row == nullptr)
                {
                    if (itemIndex > 0)
                        totalContentHeight += deviceGap;

                    totalContentHeight += deviceRowHeight;
                    continue;
                }

                totalContentHeight += childRowHeight;

                if (expandedConnectionKeys_.find(item.key) != expandedConnectionKeys_.end())
                {
                    totalContentHeight += 4;
                    totalContentHeight += expandedHeight;
                    totalContentHeight += 8;
                }
            }

            connectionsMaxScrollOffset_ =
                std::max<int>(
                    0,
                    totalContentHeight - viewportHeight
                );

            connectionsScrollOffset_ =
                std::clamp(
                    connectionsScrollOffset_,
                    0,
                    connectionsMaxScrollOffset_
                );

            HRGN clipRegion = CreateRectRgn(
                scrollViewport.left,
                scrollViewport.top,
                scrollViewport.right,
                scrollViewport.bottom
            );

            SelectClipRgn(
                hdc,
                clipRegion
            );

            int y = scrollViewport.top - connectionsScrollOffset_;
            int rowsDrawn = 0;

            const COLORREF tableTextColor =
                rgb(config_.theme.textR, config_.theme.textG, config_.theme.textB);

            const COLORREF tableMutedColor =
                rgb(config_.theme.mutedTextR, config_.theme.mutedTextG, config_.theme.mutedTextB);

            for (int i = 0; i < static_cast<int>(items.size()); ++i)
            {
                const TableItem& item = items[static_cast<size_t>(i)];

                // ---------------- Device header row ----------------
                if (item.row == nullptr)
                {
                    if (i > 0)
                        y += deviceGap;

                    const GuiDeviceCard& device = *item.device;

                    const bool deviceOpen =
                        expandedDeviceKeys_.find(device.deviceIp) != expandedDeviceKeys_.end();

                    const bool deviceSelected =
                        device.deviceIp == selectedDeviceIp_;

                    RECT deviceRect{
                        tableRect.left,
                        y,
                        tableRect.right,
                        y + deviceRowHeight
                    };

                    if (deviceRect.bottom >= scrollViewport.top &&
                        deviceRect.top <= scrollViewport.bottom)
                    {
                        connectionRowRects_.push_back(deviceRect);
                        connectionRowKeys_.push_back(item.key);

                        const int lift = deviceSelected ? 24 : 14;

                        drawRoundedPanel(
                            hdc,
                            deviceRect,
                            rgb(
                                std::min(255, config_.theme.panelR + lift),
                                std::min(255, config_.theme.panelG + lift),
                                std::min(255, config_.theme.panelB + lift)
                            ),
                            colorForSeverity(device.severity)
                        );

                        const COLORREF stateColor = colorForSeverity(device.severity);

                        // Open / closed marker.
                        RECT arrowCell{ deviceRect.left + 4, deviceRect.top + 4, deviceRect.left + 28, deviceRect.top + 26 };
                        drawCellText(deviceOpen ? L"\x25BC" : L"\x25BA", arrowCell, tableTextColor, smallFont_);

                        const int textLeft = deviceRect.left + 26;
                        const int stateWidth = 190;

                        // Line 1: device name (or IP) ........ STATE  |  MCS
                        RECT nameLine{ textLeft, deviceRect.top + 4, deviceRect.right - stateWidth, deviceRect.top + 26 };
                        drawCellText(
                            widen(device.hostName.empty() ? device.deviceIp : device.hostName),
                            nameLine,
                            tableTextColor,
                            normalFont_
                        );

                        std::string stateWord = toString(device.severity);

                        for (char& c : stateWord)
                            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

                        RECT stateLine{ deviceRect.right - stateWidth, deviceRect.top + 4, deviceRect.right - 10, deviceRect.top + 26 };
                        {
                            RECT textRect = stateLine;
                            SelectObject(hdc, smallFont_);
                            SetTextColor(hdc, stateColor);

                            const std::wstring stateText =
                                widen(stateWord) + L"   |   MCS " +
                                widen(device.mcsText.empty() ? "0" : device.mcsText);

                            DrawTextW(hdc, stateText.c_str(), -1, &textRect,
                                DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
                        }

                        // Line 2: IP | type | connections | destinations | traffic
                        std::wostringstream details;
                        details
                            << widen(device.deviceIp)
                            << L"   |   "
                            << widen(device.deviceType.empty() ? "Detecting..." : device.deviceType)
                            << L"   |   "
                            << device.totalConnections
                            << (device.totalConnections == 1 ? L" connection" : L" connections")
                            << L"   |   "
                            << item.destinations
                            << (item.destinations == 1 ? L" destination" : L" destinations")
                            << L"   |   "
                            << widen(device.totalBytesHuman.empty() ? "0 B" : device.totalBytesHuman);

                        RECT detailsLine{ textLeft, deviceRect.top + 25, deviceRect.right - 10, deviceRect.top + 44 };
                        drawCellText(details.str(), detailsLine, tableMutedColor, smallFont_);

                        // Line 3: forwarding warning, or where the device connects most.
                        RECT thirdLine{ textLeft, deviceRect.top + 43, deviceRect.right - 10, deviceRect.top + 62 };

                        if (device.forwarding)
                        {
                            std::wstring warning =
                                L"FORWARDS traffic of other devices (" +
                                std::to_wstring(device.forwardedSyns) + L" connections)";

                            if (!device.platformsBehind.empty())
                            {
                                warning += L":  ";

                                for (size_t index = 0; index < device.platformsBehind.size(); ++index)
                                {
                                    if (index > 0)
                                        warning += L", ";

                                    warning += widen(device.platformsBehind[index]);
                                }
                            }

                            drawCellText(warning, thirdLine, colorForSeverity(GuiSeverity::Redflag), smallFont_);
                        }
                        else
                        {
                            std::vector<const GuiConnectionRow*> top;

                            for (const auto& connection : device.connections)
                                top.push_back(&connection);

                            std::stable_sort(
                                top.begin(),
                                top.end(),
                                [](const GuiConnectionRow* a, const GuiConnectionRow* b)
                                {
                                    return a->subConnectionCount > b->subConnectionCount;
                                }
                            );

                            std::wstring topText = L"Top:  ";

                            for (size_t index = 0; index < top.size() && index < 4; ++index)
                            {
                                if (index > 0)
                                    topText += L",   ";

                                topText +=
                                    widen(top[index]->entityName.empty()
                                        ? top[index]->destinationText
                                        : top[index]->entityName) +
                                    L" (" + std::to_wstring(top[index]->subConnectionCount) + L")";
                            }

                            if (top.empty())
                                topText += L"no connections yet";

                            drawCellText(topText, thirdLine, tableMutedColor, smallFont_);
                        }

                        rowsDrawn++;
                    }

                    y += deviceRowHeight;
                    continue;
                }

                // ---------------- Destination group row (inside an open device) ----------------
                const GuiConnectionRow& row = *item.row;

                const std::string& rowKey = item.key;

                const bool expanded =
                    expandedConnectionKeys_.find(rowKey) != expandedConnectionKeys_.end();

                RECT rowRect{
                    tableRect.left + childIndent,
                    y,
                    tableRect.right,
                    y + childRowHeight
                };

                // Guide line in the indent, in the device's state color.
                {
                    RECT guide{
                        tableRect.left + 6,
                        y - 2,
                        tableRect.left + 9,
                        y + childRowHeight + 2
                    };

                    HBRUSH guideBrush = CreateSolidBrush(colorForSeverity(item.device->severity));
                    FillRect(hdc, &guide, guideBrush);
                    DeleteObject(guideBrush);
                }

                const bool rowVisible =
                    rowRect.bottom >= scrollViewport.top &&
                    rowRect.top <= scrollViewport.bottom;

                if (rowVisible)
                {
                    connectionRowRects_.push_back(rowRect);
                    connectionRowKeys_.push_back(rowKey);

                    COLORREF rowFill =
                        expanded
                        ? rgb(
                            std::min(255, config_.theme.panelR + 16),
                            std::min(255, config_.theme.panelG + 16),
                            std::min(255, config_.theme.panelB + 16)
                        )
                        : ((i % 2 == 0)
                            ? rgb(
                                std::min(255, config_.theme.panelR + 4),
                                std::min(255, config_.theme.panelG + 4),
                                std::min(255, config_.theme.panelB + 4)
                            )
                            : rgb(
                                std::min(255, config_.theme.panelR + 8),
                                std::min(255, config_.theme.panelG + 8),
                                std::min(255, config_.theme.panelB + 8)
                            ));

                    drawRoundedPanel(
                        hdc,
                        rowRect,
                        rowFill,
                        expanded
                        ? colorForSeverity(GuiSeverity::Normal)
                        : rgb(config_.theme.borderR, config_.theme.borderG, config_.theme.borderB)
                    );

                    // The small columns sit on line 1; line 2 uses the full row width.
                    const int lineOneBottom = rowRect.top + 24;

                    int colX = tableRect.left + destW;

                    RECT typeCell = makeCell(colX, typeW, rowRect.top + 3, lineOneBottom);
                    colX += typeW;

                    RECT subCell = makeCell(colX, subW, rowRect.top + 3, lineOneBottom);
                    colX += subW;

                    RECT trafficCell = makeCell(colX, trafficW, rowRect.top + 3, lineOneBottom);
                    colX += trafficW;

                    RECT confidenceCell = makeCell(colX, confidenceW, rowRect.top + 3, lineOneBottom);

                    const COLORREF textColor =
                        rgb(config_.theme.textR, config_.theme.textG, config_.theme.textB);

                    const COLORREF mutedColor =
                        rgb(config_.theme.mutedTextR, config_.theme.mutedTextG, config_.theme.mutedTextB);

                    // Line 1: the destination (registrable domain or network owner).
                    std::wstring destination =
                        widen(row.entityName.empty()
                            ? row.destinationText
                            : row.entityName);

                    if (row.expandable)
                        destination = (expanded ? L"-  " : L"+  ") + destination;

                    RECT nameLine{ rowRect.left + 2, rowRect.top + 3, tableRect.left + destW, rowRect.top + 24 };
                    drawCellText(destination, nameLine, row.destinationKnown ? textColor : mutedColor, normalFont_);

                    // Line 2: who owns the server network + the exact host seen.
                    std::wstring detail;

                    if (!row.category.empty() &&
                        row.category != "Internet service" &&
                        row.category != "Classified traffic")
                    {
                        detail = widen(row.category) + L"   |   ";
                    }

                    detail += widen(row.destinationText.empty() ? row.destinationDomain : row.destinationText);

                    RECT detailLine{ rowRect.left + 2, rowRect.top + 23, rowRect.right - 10, rowRect.top + 42 };
                    drawCellText(detail, detailLine, mutedColor, smallFont_);

                    drawCellText(compactConnectionType(row.connectionType), typeCell, mutedColor, smallFont_);
                    drawCellText(std::to_wstring(row.subConnectionCount), subCell, textColor, smallFont_);
                    drawCellText(widen(row.bytesHuman.empty() ? "0 B" : row.bytesHuman), trafficCell, mutedColor, smallFont_);
                    drawCellText(widen(row.confidenceLabel), confidenceCell, textColor, smallFont_);

                    rowsDrawn++;
                }

                y += childRowHeight;

                if (!expanded)
                    continue;

                RECT expandedRect{
                    tableRect.left + 18,
                    y + 4,
                    tableRect.right - 18,
                    y + 4 + expandedHeight
                };

                const bool expandedVisible =
                    expandedRect.bottom >= scrollViewport.top &&
                    expandedRect.top <= scrollViewport.bottom;

                if (expandedVisible)
                {
                    drawRoundedPanel(
                        hdc,
                        expandedRect,
                        rgb(
                            std::min(255, config_.theme.panelR + 12),
                            std::min(255, config_.theme.panelG + 12),
                            std::min(255, config_.theme.panelB + 12)
                        ),
                        colorForSeverity(GuiSeverity::Normal)
                    );

                    RECT expandedText = expandedRect;
                    expandedText.left += 12;
                    expandedText.top += 10;
                    expandedText.right -= 12;
                    expandedText.bottom -= 10;

                    SelectObject(hdc, smallFont_);
                    SetTextColor(
                        hdc,
                        rgb(config_.theme.textR, config_.theme.textG, config_.theme.textB)
                    );

                    RECT expandedTitle = expandedRect;
                    expandedTitle.left += 12;
                    expandedTitle.top += 8;
                    expandedTitle.right -= 12;
                    expandedTitle.bottom = expandedTitle.top + 38;

                    SelectObject(hdc, smallFont_);
                    SetTextColor(
                        hdc,
                        rgb(config_.theme.textR, config_.theme.textG, config_.theme.textB)
                    );

                    std::wostringstream titleText;

                    titleText
                        << L"Expanded linked sub-connections"
                        << L" | Sub-connections: "
                        << row.subConnections.size()
                        << L"\n"
                        << L"Identity: "
                        << widen(row.destinationStateText.empty()
                            ? (row.destinationKnown ? "Known destination" : "Pending destination")
                            : row.destinationStateText)
                        << L"\n"
                        << L"Main: "
                        << shorten(
                            widen(
                                row.destinationText.empty()
                                ? row.entityName
                                : row.destinationText
                            ),
                            64
                        );

                    DrawTextW(
                        hdc,
                        titleText.str().c_str(),
                        -1,
                        &expandedTitle,
                        DT_LEFT | DT_TOP | DT_WORDBREAK | DT_END_ELLIPSIS
                    );

                    RECT subViewport{
                        expandedRect.left + 12,
                        expandedTitle.bottom + 6,
                        expandedRect.right - 12,
                        expandedRect.bottom - 10
                    };

                    RECT clippedSubViewport{
                        std::max(subViewport.left, scrollViewport.left),
                        std::max(subViewport.top, scrollViewport.top),
                        std::min(subViewport.right, scrollViewport.right),
                        std::min(subViewport.bottom, scrollViewport.bottom)
                    };

                    const bool subViewportHasVisibleArea =
                        clippedSubViewport.right > clippedSubViewport.left &&
                        clippedSubViewport.bottom > clippedSubViewport.top;

                    if (subViewportHasVisibleArea)
                    {

                    expandedSubListRects_.push_back(subViewport);
                    expandedSubListKeys_.push_back(rowKey);

                    const int subRowHeight = 18;

                    const int subContentHeight =
                        static_cast<int>(row.subConnections.size()) * subRowHeight;

                    const int subViewportHeight =
                        std::max<int>(
                            0,
                            subViewport.bottom - subViewport.top
                        );

                    subConnectionMaxScrollOffsets_[rowKey] =
                        std::max<int>(
                            0,
                            subContentHeight - subViewportHeight
                        );

                    subConnectionScrollOffsets_[rowKey] =
                        std::clamp(
                            subConnectionScrollOffsets_[rowKey],
                            0,
                            subConnectionMaxScrollOffsets_[rowKey]
                        );

                    HRGN subClip = CreateRectRgn(
                        clippedSubViewport.left,
                        clippedSubViewport.top,
                        clippedSubViewport.right,
                        clippedSubViewport.bottom
                    );

                    SelectClipRgn(
                        hdc,
                        subClip
                    );

                    if (row.subConnections.empty())
                    {
                        DrawTextW(
                            hdc,
                            L"No sub-connection records were passed to the GUI.",
                            -1,
                            &subViewport,
                            DT_LEFT | DT_TOP | DT_WORDBREAK | DT_END_ELLIPSIS
                        );
                    }
                    else
                    {
                        int subY =
                            subViewport.top -
                            subConnectionScrollOffsets_[rowKey];

                        for (size_t subIndex = 0; subIndex < row.subConnections.size(); ++subIndex)
                        {
                            const GuiSubConnectionRow& sub =
                                row.subConnections[subIndex];

                            RECT subLineRect{
                                subViewport.left,
                                subY,
                                subViewport.right,
                                subY + subRowHeight
                            };

                            const bool visible =
                                subLineRect.bottom >= subViewport.top &&
                                subLineRect.top <= subViewport.bottom;

                            if (visible)
                            {
                                std::wstring process =
                                    !sub.processName.empty()
                                    ? widen(sub.processName)
                                    : L"process unavailable";

                                std::wstring local =
                                    widen(sub.localIp.empty() ? sub.deviceIp : sub.localIp);

                                if (sub.localPort > 0)
                                {
                                    local += L":";
                                    local += std::to_wstring(sub.localPort);
                                }

                                std::wstring remote =
                                    widen(sub.remoteIp.empty() ? "remote unavailable" : sub.remoteIp);

                                if (sub.remotePort > 0)
                                {
                                    remote += L":";
                                    remote += std::to_wstring(sub.remotePort);
                                }

                                std::wstring state =
                                    !sub.transportState.empty()
                                    ? widen(sub.transportState)
                                    : L"state unavailable";

                                std::wstring destinationLabel;

                                if (!sub.destinationDomain.empty())
                                {
                                    destinationLabel = widen(sub.destinationDomain);
                                }
                                else if (!sub.entityName.empty())
                                {
                                    destinationLabel = widen(sub.entityName);
                                }
                                else if (!sub.remoteIp.empty())
                                {
                                    destinationLabel = widen(sub.remoteIp);

                                    if (sub.remotePort > 0)
                                    {
                                        destinationLabel += L":";
                                        destinationLabel += std::to_wstring(sub.remotePort);
                                    }
                                }
                                else
                                {
                                    destinationLabel = L"observed endpoint";
                                }

                                std::wostringstream line;

                                line
                                    << L"- "
                                    << shorten(local, 22)
                                    << L" -> "
                                    << shorten(destinationLabel, 32)
                                    << L" ["
                                    << shorten(remote, 24)
                                    << L"] | "
                                    << shorten(process, 20)
                                    << L" | "
                                    << shorten(state, 12)
                                    << L" | "
                                    << compactConnectionType(sub.connectionType);

                                DrawTextW(
                                    hdc,
                                    line.str().c_str(),
                                    -1,
                                    &subLineRect,
                                    DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS
                                );
                            }

                            subY += subRowHeight;
                        }
                    }

                    SelectClipRgn(
                        hdc,
                        clipRegion
                    );

                    DeleteObject(
                        subClip
                    );

                    if (subConnectionMaxScrollOffsets_[rowKey] > 0)
                    {
                        RECT hintRect{
                            subViewport.left,
                            subViewport.bottom - 16,
                            subViewport.right,
                            subViewport.bottom
                        };

                        std::wostringstream hint;

                        RECT scrollBarTrack{
    expandedRect.right - 12,
    subViewport.top,
    expandedRect.right - 6,
    subViewport.bottom
                        };

                        subConnectionScrollBarRects_.push_back(scrollBarTrack);
                        subConnectionScrollBarKeys_.push_back(rowKey);

                        const int trackHeight =
                            scrollBarTrack.bottom - scrollBarTrack.top;

                        const int maxOffset =
                            subConnectionMaxScrollOffsets_[rowKey];

                        const int currentOffset =
                            subConnectionScrollOffsets_[rowKey];

                        if (trackHeight > 24 && maxOffset > 0)
                        {
                            const int contentHeight =
                                trackHeight + maxOffset;

                            int thumbHeight =
                                (trackHeight * trackHeight) / std::max(1, contentHeight);

                            thumbHeight = std::max(24, thumbHeight);
                            thumbHeight = std::min(trackHeight, thumbHeight);

                            const int movableRange =
                                std::max(1, trackHeight - thumbHeight);

                            const int thumbTop =
                                scrollBarTrack.top +
                                (currentOffset * movableRange) / maxOffset;

                            RECT thumbRect{
                                scrollBarTrack.left,
                                thumbTop,
                                scrollBarTrack.right,
                                thumbTop + thumbHeight
                            };

                            HBRUSH trackBrush = CreateSolidBrush(
                                rgb(
                                    std::min(255, config_.theme.panelR + 18),
                                    std::min(255, config_.theme.panelG + 18),
                                    std::min(255, config_.theme.panelB + 18)
                                )
                            );

                            FillRect(
                                hdc,
                                &scrollBarTrack,
                                trackBrush
                            );

                            DeleteObject(trackBrush);

                            HBRUSH thumbBrush = CreateSolidBrush(
                                rgb(
                                    config_.theme.normalR,
                                    config_.theme.normalG,
                                    config_.theme.normalB
                                )
                            );

                            FillRect(
                                hdc,
                                &thumbRect,
                                thumbBrush
                            );

                            DeleteObject(thumbBrush);
                        }

                        hint
                            << L"Sub-scroll "
                            << subConnectionScrollOffsets_[rowKey]
                            << L" / "
                            << subConnectionMaxScrollOffsets_[rowKey];

                        SetTextColor(
                            hdc,
                            rgb(config_.theme.mutedTextR, config_.theme.mutedTextG, config_.theme.mutedTextB)
                        );

                        DrawTextW(
                            hdc,
                            hint.str().c_str(),
                            -1,
                            &hintRect,
                            DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS
                        );
                    }
                } // end subViewportHasVisibleArea
            }

                y = expandedRect.bottom + 8;
            }

            SelectClipRgn(
                hdc,
                nullptr
            );

            DeleteObject(
                clipRegion
            );

            if (connectionsMaxScrollOffset_ > 0)
            {
                connectionsScrollBarRect_ = RECT{
                    tableRect.right - 10,
                    scrollViewport.top,
                    tableRect.right - 4,
                    scrollViewport.bottom
                };

                const int trackHeight =
                    connectionsScrollBarRect_.bottom - connectionsScrollBarRect_.top;

                const int contentHeight =
                    trackHeight + connectionsMaxScrollOffset_;

                int thumbHeight =
                    (trackHeight * trackHeight) / std::max(1, contentHeight);

                thumbHeight = std::max(28, thumbHeight);
                thumbHeight = std::min(trackHeight, thumbHeight);

                const int movableRange =
                    std::max(1, trackHeight - thumbHeight);

                const int thumbTop =
                    connectionsScrollBarRect_.top +
                    (connectionsScrollOffset_ * movableRange) / connectionsMaxScrollOffset_;

                RECT thumbRect{
                    connectionsScrollBarRect_.left,
                    thumbTop,
                    connectionsScrollBarRect_.right,
                    thumbTop + thumbHeight
                };

                HBRUSH trackBrush = CreateSolidBrush(
                    rgb(
                        std::min(255, config_.theme.panelR + 16),
                        std::min(255, config_.theme.panelG + 16),
                        std::min(255, config_.theme.panelB + 16)
                    )
                );

                FillRect(
                    hdc,
                    &connectionsScrollBarRect_,
                    trackBrush
                );

                DeleteObject(trackBrush);

                HBRUSH thumbBrush = CreateSolidBrush(
                    rgb(config_.theme.normalR, config_.theme.normalG, config_.theme.normalB)
                );

                FillRect(
                    hdc,
                    &thumbRect,
                    thumbBrush
                );

                DeleteObject(thumbBrush);

                RECT scrollHintRect{
                    tableRect.left,
                    tableRect.bottom - 22,
                    tableRect.right - 16,
                    tableRect.bottom
                };

                std::wostringstream hint;

                hint
                    << L"Scroll: "
                    << connectionsScrollOffset_
                    << L" / "
                    << connectionsMaxScrollOffset_
                    << L"  |  wheel or drag green bar";

                SelectObject(hdc, smallFont_);
                SetTextColor(
                    hdc,
                    rgb(config_.theme.mutedTextR, config_.theme.mutedTextG, config_.theme.mutedTextB)
                );

                DrawTextW(
                    hdc,
                    hint.str().c_str(),
                    -1,
                    &scrollHintRect,
                    DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS
                );
            }
            else
            {
                connectionsScrollBarRect_ = RECT{};
            }
        }

        // ============================================================
        // RIGHT PANEL: EVIDENCE INSPECTOR
        // ============================================================

        drawRoundedPanel(
            hdc,
            inspectorRect,
            rgb(config_.theme.panelR, config_.theme.panelG, config_.theme.panelB),
            rgb(config_.theme.borderR, config_.theme.borderG, config_.theme.borderB)
        );

        RECT inspectorHeader = inspectorRect;
        inspectorHeader.left += 16;
        inspectorHeader.top += 14;
        inspectorHeader.right -= 16;
        inspectorHeader.bottom = inspectorHeader.top + 28;

        SelectObject(hdc, headerFont_);
        SetTextColor(
            hdc,
            rgb(config_.theme.textR, config_.theme.textG, config_.theme.textB)
        );

        DrawTextW(
            hdc,
            L"EVIDENCE INSPECTOR",
            -1,
            &inspectorHeader,
            DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS
        );

        RECT inspectorBody = inspectorRect;
        inspectorBody.left += 16;
        inspectorBody.top = inspectorHeader.bottom + 12;
        inspectorBody.right -= 16;
        inspectorBody.bottom -= 16;

        SelectObject(hdc, smallFont_);
        SetTextColor(
            hdc,
            rgb(config_.theme.textR, config_.theme.textG, config_.theme.textB)
        );

        std::wostringstream inspector;

        // A device selected in the CONNECTIONS table is explained here.
        const GuiDeviceCard* selectedDevice = nullptr;

        if (!selectedDeviceIp_.empty())
        {
            for (const GuiDevicePanel* panel : {
                    &currentDashboard_.redflagPanel,
                    &currentDashboard_.heavyPanel,
                    &currentDashboard_.normalPanel })
            {
                for (const auto& device : panel->devices)
                {
                    if (device.deviceIp == selectedDeviceIp_)
                        selectedDevice = &device;
                }
            }
        }

        if (selectedDevice != nullptr)
        {
            const GuiDeviceCard& device = *selectedDevice;

            inspector
                << L"Selected device: "
                << widen(device.deviceIp);

            if (!device.hostName.empty())
            {
                inspector
                    << L"\nName: "
                    << widen(device.hostName)
                    << L" ("
                    << widen(device.nameSource)
                    << L")";
            }

            inspector
                << L"\nType: "
                << widen(device.deviceType.empty() ? "Detecting..." : device.deviceType)
                << L"\nType evidence: "
                << widen(device.typeEvidence.empty() ? "none yet" : device.typeEvidence);

            if (!device.mac.empty())
                inspector << L"\nMAC: " << widen(device.mac);

            inspector << L"\nForwards other devices: ";

            if (device.forwarding)
            {
                inspector
                    << L"YES, "
                    << device.forwardedSyns
                    << L" connection(s) passed through it";

                if (!device.platformsBehind.empty())
                {
                    inspector << L"; systems behind it: ";

                    for (size_t index = 0; index < device.platformsBehind.size(); ++index)
                    {
                        if (index > 0)
                            inspector << L", ";

                        inspector << widen(device.platformsBehind[index]);
                    }
                }
            }
            else
            {
                inspector << L"No";
            }

            inspector
                << L"\n\nState: "
                << widen(device.stateLabel.empty() ? toString(device.severity) : device.stateLabel)
                << L"\n\nConnections: "
                << device.totalConnections
                << L"\nDestinations: "
                << device.connections.size()
                << L"\nTraffic: "
                << widen(device.totalBytesHuman.empty() ? "0 B" : device.totalBytesHuman)
                << L"\nMCS: "
                << widen(device.mcsText.empty() ? "0" : device.mcsText)
                << L"\n\nTop destinations:\n";

            std::vector<const GuiConnectionRow*> top;

            for (const auto& connection : device.connections)
                top.push_back(&connection);

            std::stable_sort(
                top.begin(),
                top.end(),
                [](const GuiConnectionRow* a, const GuiConnectionRow* b)
                {
                    return a->subConnectionCount > b->subConnectionCount;
                }
            );

            const size_t shown = std::min<size_t>(top.size(), 6);

            for (size_t index = 0; index < shown; ++index)
            {
                inspector
                    << L"- "
                    << shorten(widen(top[index]->entityName.empty()
                        ? top[index]->destinationText
                        : top[index]->entityName), 28)
                    << L" x"
                    << top[index]->subConnectionCount
                    << L"\n";
            }

            if (top.size() > shown)
                inspector << L"- ... " << (top.size() - shown) << L" more\n";

            inspector
                << L"\nWhy this state:\n"
                << widen(device.summaryReason.empty()
                    ? "No classification reason was provided."
                    : device.summaryReason);
        }
        else
        {
            inspector
                << L"Selected: Current snapshot overview\n\n"
                << L"Status:\n"
                << widen(
                    currentDashboard_.statusLabel.empty()
                    ? "Ready"
                    : currentDashboard_.statusLabel
                )
                << L"\n\n"
                << L"Devices:\n"
                << L"Normal: "
                << currentDashboard_.normalPanel.deviceCount
                << L"\nHeavy: "
                << currentDashboard_.heavyPanel.deviceCount
                << L"\nRedflag: "
                << currentDashboard_.redflagPanel.deviceCount
                << L"\n\n"
                << L"Groups:\n"
                << (
                    currentDashboard_.normalPanel.connectionCount +
                    currentDashboard_.heavyPanel.connectionCount +
                    currentDashboard_.redflagPanel.connectionCount
                    )
                << L"\n\n"
                << L"Evidence mode:\n"
                << L"TCP table + process metadata + background Npcap DNS/TLS\n\n"
                << L"Limitations:\n"
                << L"TLS SNI appears only when ClientHello is captured.\n"
                << L"DNS depends on visible UDP/53 traffic.\n"
                << L"Encrypted DNS/QUIC may hide destination names.";
        }

        DrawTextW(
            hdc,
            inspector.str().c_str(),
            -1,
            &inspectorBody,
            DT_LEFT | DT_TOP | DT_WORDBREAK | DT_END_ELLIPSIS
        );
    }


    void Win32GuiApp::drawDeviceCard(
        HDC hdc,
        const GuiDeviceCard& device,
        const RECT& rect
    )
    {
        drawRoundedPanel(
            hdc,
            rect,
            rgb(
                std::min(255, config_.theme.panelR + 8),
                std::min(255, config_.theme.panelG + 8),
                std::min(255, config_.theme.panelB + 8)
            ),
            colorForSeverity(device.severity)
        );

        RECT titleRect = rect;
        titleRect.left += 12;
        titleRect.top += 10;
        titleRect.right -= 12;
        titleRect.bottom = titleRect.top + 22;

        SelectObject(hdc, headerFont_);
        SetTextColor(
            hdc,
            rgb(config_.theme.textR, config_.theme.textG, config_.theme.textB)
        );

        DrawTextW(
            hdc,
            shorten(widen(device.title), 52).c_str(),
            -1,
            &titleRect,
            DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS
        );

        RECT subRect = rect;
        subRect.left += 12;
        subRect.top = titleRect.bottom + 4;
        subRect.right -= 12;
        subRect.bottom = subRect.top + 36;

        SelectObject(hdc, smallFont_);
        SetTextColor(
            hdc,
            rgb(config_.theme.mutedTextR, config_.theme.mutedTextG, config_.theme.mutedTextB)
        );

        DrawTextW(
            hdc,
            widen(device.subtitle).c_str(),
            -1,
            &subRect,
            DT_LEFT | DT_TOP | DT_WORDBREAK | DT_END_ELLIPSIS
        );

        RECT detailRect = rect;
        detailRect.left += 12;
        detailRect.top = subRect.bottom + 6;
        detailRect.right -= 12;
        detailRect.bottom -= 8;

        std::wostringstream detail;

        detail
            << L"Entities: "
            << device.uniqueEntities
            << L" | Services: "
            << device.uniqueServices
            << L" | Coverage: "
            << widen(GuiModelMapper::fromDashboard(
                netwolf::app::AppDashboardSnapshot{}
            ).statusLabel);

        const std::wstring line =
            L"Entities: " + std::to_wstring(device.uniqueEntities) +
            L" | Services: " + std::to_wstring(device.uniqueServices) +
            L" | Coverage: " + widen(std::to_string(static_cast<int>(device.attributionCoveragePercent))) + L"%";

        DrawTextW(
            hdc,
            line.c_str(),
            -1,
            &detailRect,
            DT_LEFT | DT_TOP | DT_END_ELLIPSIS
        );
    }


    void Win32GuiApp::drawEmptyState(
        HDC hdc,
        const RECT& rect
    )
    {
        drawRoundedPanel(
            hdc,
            rect,
            rgb(config_.theme.panelR, config_.theme.panelG, config_.theme.panelB),
            rgb(config_.theme.borderR, config_.theme.borderG, config_.theme.borderB)
        );

        RECT textRect = rect;
        textRect.left += 28;
        textRect.top += 28;
        textRect.right -= 28;
        textRect.bottom -= 28;

        SelectObject(hdc, headerFont_);
        SetTextColor(
            hdc,
            rgb(config_.theme.textR, config_.theme.textG, config_.theme.textB)
        );

        const std::wstring title =
            L"No dashboard data yet.\n\n";

        DrawTextW(
            hdc,
            title.c_str(),
            -1,
            &textRect,
            DT_LEFT | DT_TOP | DT_WORDBREAK
        );

        textRect.top += 70;

        SelectObject(hdc, normalFont_);
        SetTextColor(
            hdc,
            rgb(config_.theme.mutedTextR, config_.theme.mutedTextG, config_.theme.mutedTextB)
        );

        const std::wstring body =
            L"Choose Run > Run TCP Once to capture active TCP connections from the Windows TCP table.\n\n"
            L"The GUI will display devices in Normal, Heavy, and Redflag panels based on the engine output.";

        DrawTextW(
            hdc,
            body.c_str(),
            -1,
            &textRect,
            DT_LEFT | DT_TOP | DT_WORDBREAK
        );
    }


    void Win32GuiApp::drawTextBlock(
        HDC hdc,
        const Win32GuiTextBlock& block,
        const RECT& rect
    )
    {
        RECT current = rect;

        SelectObject(hdc, headerFont_);
        SetTextColor(
            hdc,
            rgb(config_.theme.textR, config_.theme.textG, config_.theme.textB)
        );

        DrawTextW(
            hdc,
            block.title.c_str(),
            -1,
            &current,
            DT_LEFT | DT_TOP | DT_SINGLELINE | DT_END_ELLIPSIS
        );

        current.top += 28;

        SelectObject(hdc, smallFont_);
        SetTextColor(
            hdc,
            rgb(config_.theme.mutedTextR, config_.theme.mutedTextG, config_.theme.mutedTextB)
        );

        DrawTextW(
            hdc,
            block.subtitle.c_str(),
            -1,
            &current,
            DT_LEFT | DT_TOP | DT_WORDBREAK | DT_END_ELLIPSIS
        );

        current.top += 38;

        for (const auto& line : block.lines)
        {
            DrawTextW(
                hdc,
                line.c_str(),
                -1,
                &current,
                DT_LEFT | DT_TOP | DT_SINGLELINE | DT_END_ELLIPSIS
            );

            current.top += 20;

            if (current.top >= rect.bottom)
                break;
        }
    }


    void Win32GuiApp::drawRoundedPanel(
        HDC hdc,
        const RECT& rect,
        COLORREF fill,
        COLORREF border
    )
    {
        HBRUSH fillBrush = CreateSolidBrush(fill);
        HPEN borderPen = CreatePen(PS_SOLID, 1, border);

        HGDIOBJ oldBrush = SelectObject(hdc, fillBrush);
        HGDIOBJ oldPen = SelectObject(hdc, borderPen);

        RoundRect(
            hdc,
            rect.left,
            rect.top,
            rect.right,
            rect.bottom,
            18,
            18
        );

        SelectObject(hdc, oldPen);
        SelectObject(hdc, oldBrush);

        DeleteObject(borderPen);
        DeleteObject(fillBrush);
    }


    COLORREF Win32GuiApp::colorForSeverity(
        GuiSeverity severity
    ) const
    {
        switch (severity)
        {
        case GuiSeverity::Normal:
            return rgb(
                config_.theme.normalR,
                config_.theme.normalG,
                config_.theme.normalB
            );

        case GuiSeverity::Heavy:
            return rgb(
                config_.theme.heavyR,
                config_.theme.heavyG,
                config_.theme.heavyB
            );

        case GuiSeverity::Redflag:
            return rgb(
                config_.theme.redflagR,
                config_.theme.redflagG,
                config_.theme.redflagB
            );

        default:
            return rgb(
                config_.theme.borderR,
                config_.theme.borderG,
                config_.theme.borderB
            );
        }
    }


    COLORREF Win32GuiApp::rgb(
        int r,
        int g,
        int b
    ) const
    {
        return RGB(
            static_cast<BYTE>(std::clamp(r, 0, 255)),
            static_cast<BYTE>(std::clamp(g, 0, 255)),
            static_cast<BYTE>(std::clamp(b, 0, 255))
        );
    }


    // ------------------------------------------------------------
    // String helpers
    // ------------------------------------------------------------

    std::wstring Win32GuiApp::widen(
        const std::string& value
    )
    {
        if (value.empty())
            return L"";

        const int sizeNeeded = MultiByteToWideChar(
            CP_UTF8,
            0,
            value.c_str(),
            static_cast<int>(value.size()),
            nullptr,
            0
        );

        if (sizeNeeded <= 0)
        {
            std::wstring fallback;
            fallback.reserve(value.size());

            for (unsigned char ch : value)
                fallback.push_back(static_cast<wchar_t>(ch));

            return fallback;
        }

        std::wstring result(
            static_cast<size_t>(sizeNeeded),
            L'\0'
        );

        MultiByteToWideChar(
            CP_UTF8,
            0,
            value.c_str(),
            static_cast<int>(value.size()),
            result.data(),
            sizeNeeded
        );

        return result;
    }


    std::wstring Win32GuiApp::shorten(
        const std::wstring& value,
        size_t maxLength
    )
    {
        if (value.size() <= maxLength)
            return value;

        if (maxLength <= 3)
            return value.substr(0, maxLength);

        return value.substr(0, maxLength - 3) + L"...";
    }


    std::wstring Win32GuiApp::makeDeviceLine(
        const GuiDeviceCard& device
    )
    {
        std::wostringstream out;

        out
            << widen(device.deviceIp)
            << L" | MCS "
            << widen(device.mcsText)
            << L" | "
            << device.totalConnections
            << L" connections";

        return out.str();
    }


    std::wstring Win32GuiApp::makePanelSummaryLine(
        const GuiDevicePanel& panel
    )
    {
        std::wostringstream out;

        out
            << panel.deviceCount
            << L" devices, "
            << panel.connectionCount
            << L" groups";

        return out.str();
    }


    // ------------------------------------------------------------
    // Message handling
    // ------------------------------------------------------------

    LRESULT CALLBACK Win32GuiApp::windowProc(
        HWND hwnd,
        UINT message,
        WPARAM wParam,
        LPARAM lParam
    )
    {
        if (message == WM_NCCREATE)
        {
            auto* createStruct =
                reinterpret_cast<CREATESTRUCTW*>(lParam);

            auto* app =
                reinterpret_cast<Win32GuiApp*>(createStruct->lpCreateParams);

            SetWindowLongPtrW(
                hwnd,
                GWLP_USERDATA,
                reinterpret_cast<LONG_PTR>(app)
            );

            return TRUE;
        }

        Win32GuiApp* app = appFromWindow(hwnd);

        if (app)
        {
            return app->handleMessage(
                hwnd,
                message,
                wParam,
                lParam
            );
        }

        return DefWindowProcW(
            hwnd,
            message,
            wParam,
            lParam
        );
    }


    LRESULT Win32GuiApp::handleMessage(
        HWND hwnd,
        UINT message,
        WPARAM wParam,
        LPARAM lParam
    )
    {
        switch (message)
        {
        case WM_COMMAND:
            onCommand(LOWORD(wParam));
            return 0;

        case WM_PAINT:
            onPaint();
            return 0;

        case WM_SIZE:
            onSize(
                LOWORD(lParam),
                HIWORD(lParam)
            );
            return 0;

        case WM_LBUTTONDOWN:
            onLeftButtonDown(
                static_cast<int>(static_cast<short>(LOWORD(lParam))),
                static_cast<int>(static_cast<short>(HIWORD(lParam)))
            );
            return 0;

        case WM_LBUTTONUP:
            onLeftButtonUp(
                static_cast<int>(static_cast<short>(LOWORD(lParam))),
                static_cast<int>(static_cast<short>(HIWORD(lParam)))
            );
            return 0;

        case WM_MOUSEMOVE:
            if (draggingSubConnectionScrollBar_ ||
                draggingConnectionsScrollBar_)
            {
                onMouseMove(
                    static_cast<int>(static_cast<short>(LOWORD(lParam))),
                    static_cast<int>(static_cast<short>(HIWORD(lParam)))
                );
                return 0;
            }

            return DefWindowProcW(
                hwnd,
                message,
                wParam,
                lParam
            );

        case WM_MOUSEWHEEL:
            onMouseWheel(
                static_cast<int>(static_cast<short>(HIWORD(wParam))),
                static_cast<int>(static_cast<short>(LOWORD(lParam))),
                static_cast<int>(static_cast<short>(HIWORD(lParam)))
            );
            return 0;

        case kEngineResultMessage:
            // A background snapshot finished: apply it (cheap) and repaint.
            applyPendingResult();
            return 0;

        case WM_GETMINMAXINFO:
            onGetMinMaxInfo(
                reinterpret_cast<MINMAXINFO*>(lParam)
            );
            return 0;

        case WM_ERASEBKGND:
            return 1;

        case WM_TIMER:
            if (wParam == kClockTimerId)
            {
                // Only the clock box is repainted between engine snapshots.
                if (clockRect_.right > clockRect_.left)
                    InvalidateRect(hwnd, &clockRect_, FALSE);
                return 0;
            }
            break;

        case WM_DESTROY:
            KillTimer(hwnd, kClockTimerId);
            liveTimerRunning_ = false;

            // Stop the engine worker first (waits for a snapshot in progress),
            // then the capture service, so nothing restarts it afterwards.
            stopEngineWorker();

            // Final report if the window is closed while monitoring.
            netwolf::exporters::TelecomReports::instance().end();

            netwolf::live::LivePacketCaptureService::instance().stop();

            PostQuitMessage(0);
            return 0;

        default:
            return DefWindowProcW(
                hwnd,
                message,
                wParam,
                lParam
            );
        }
    }

    Win32GuiApp* Win32GuiApp::appFromWindow(
        HWND hwnd
    )
    {
        return reinterpret_cast<Win32GuiApp*>(
            GetWindowLongPtrW(
                hwnd,
                GWLP_USERDATA
            )
            );
    }

} // namespace netwolf::gui

#endif // _WIN32