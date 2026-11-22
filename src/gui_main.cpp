#include <netwolf/gui/win32_gui_app.hpp>

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

// ================================================================
// NetWolf v2 - GUI Main
//
// Purpose:
// 1. Start the Win32 GUI application.
// 2. Keep GUI entry point separate from:
//    - Core engine
//    - CLI
//    - Sensors
//    - Exporters
//
// This file does NOT contain engine logic.
// This file does NOT classify traffic.
// It only launches netwolf::gui::Win32GuiApp.
// ================================================================


int WINAPI wWinMain(
    HINSTANCE,
    HINSTANCE,
    PWSTR,
    int nCmdShow
)
{
    netwolf::gui::Win32GuiAppConfig config;

    config.windowTitle = L"NetWolf v2 - Connection Attribution Engine";

    config.initialWidth = 1280;
    config.initialHeight = 780;

    config.minimumWidth = 980;
    config.minimumHeight = 620;

    config.startMaximized = false;

    netwolf::gui::Win32GuiApp app(config);

    return app.run(nCmdShow);
}

#else

#include <iostream>

int main()
{
    std::cerr << "NetWolf v2 GUI is only available on Windows.\n";
    return 1;
}

#endif