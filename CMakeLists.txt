cmake_minimum_required(VERSION 3.20)

project(NetWolfV2
    VERSION 0.1.0
    LANGUAGES CXX
)

# ================================================================
# NetWolf v2 - Build File
#
# Targets:
# 1. NetWolfV2Gui   (the application)
#    - src/gui_main.cpp
#    - src/win32_gui_app.cpp
#    - resources/netwolf.rc   (application icon)
#    - Win32 GUI shell consuming GuiController / GuiDashboardModel
#
# 2. NetWolfV2Core  (engine test bench)
#    - src/main.cpp
#    - Runs the real engine on simulated devices; no capture, no Windows
#      APIs, so engine changes can be tested on any platform.
#
# Architecture:
# Core Engine remains separate.
# The GUI consumes the engine through app/controller layers.
# ================================================================

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ------------------------------------------------
# Header-only interface target
# ------------------------------------------------

add_library(NetWolfV2Headers INTERFACE)

target_include_directories(NetWolfV2Headers
    INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# ------------------------------------------------
# Optional Npcap SDK interface target
# Used by Stage 8 real packet metadata capture.
# ------------------------------------------------

add_library(NetWolfV2Npcap INTERFACE)

if (WIN32)
    set(NPCAP_SDK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/npcap-sdk")
    set(NPCAP_INCLUDE_DIR "${NPCAP_SDK_DIR}/Include")

    if (CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(NPCAP_LIB_DIR "${NPCAP_SDK_DIR}/Lib/x64")
    else()
        set(NPCAP_LIB_DIR "${NPCAP_SDK_DIR}/Lib")
    endif()

    if (EXISTS "${NPCAP_INCLUDE_DIR}/pcap.h"
        AND EXISTS "${NPCAP_LIB_DIR}/wpcap.lib"
        AND EXISTS "${NPCAP_LIB_DIR}/Packet.lib")

        message(STATUS "Npcap SDK enabled: ${NPCAP_SDK_DIR}")

        target_include_directories(NetWolfV2Npcap
            INTERFACE
                "${NPCAP_INCLUDE_DIR}"
        )

        target_link_libraries(NetWolfV2Npcap
            INTERFACE
                "${NPCAP_LIB_DIR}/wpcap.lib"
                "${NPCAP_LIB_DIR}/Packet.lib"
        )

        target_compile_definitions(NetWolfV2Npcap
            INTERFACE
                NETWOLF_HAS_NPCAP=1
        )
    else()
        message(WARNING "Npcap SDK not found. Real packet capture will be disabled.")

        target_compile_definitions(NetWolfV2Npcap
            INTERFACE
                NETWOLF_HAS_NPCAP=0
        )
    endif()
else()
    target_compile_definitions(NetWolfV2Npcap
        INTERFACE
            NETWOLF_HAS_NPCAP=0
    )
endif()

# ------------------------------------------------
# Core executable
# ------------------------------------------------

add_executable(NetWolfV2Core
    src/main.cpp
)

target_link_libraries(NetWolfV2Core
    PRIVATE
        NetWolfV2Headers
        NetWolfV2Npcap
)

# ------------------------------------------------
# GUI executable
# ------------------------------------------------

if (WIN32)
    add_executable(NetWolfV2Gui WIN32
        src/gui_main.cpp
        src/win32_gui_app.cpp
        resources/netwolf.rc          # <-- application icon resource
    )
else()
    add_executable(NetWolfV2Gui
        src/gui_main.cpp
        src/win32_gui_app.cpp
    )
endif()

target_link_libraries(NetWolfV2Gui
    PRIVATE
        NetWolfV2Headers
        NetWolfV2Npcap
)

# Launch with Administrator rights (required by Npcap packet capture).
# This sets the UAC level inside the manifest the MSVC linker generates,
# so double-clicking the icon prompts for elevation automatically.
if (MSVC)
    target_link_options(NetWolfV2Gui
        PRIVATE
            "/MANIFESTUAC:level='requireAdministrator'"
    )
endif()

# ------------------------------------------------
# Windows system libraries
# Needed by:
# - Windows TCP/UDP table sensors
# - Win32 GUI / GDI drawing
# ------------------------------------------------

if (WIN32)
    target_link_libraries(NetWolfV2Gui
        PRIVATE
            iphlpapi
            ws2_32
            user32
            gdi32
            comdlg32
            shell32
    )
endif()

# ------------------------------------------------
# Compiler warnings
# ------------------------------------------------

if (MSVC)
    target_compile_options(NetWolfV2Core
        PRIVATE
            /W4
            /permissive-
    )

    target_compile_options(NetWolfV2Gui
        PRIVATE
            /W4
            /permissive-
    )
else()
    target_compile_options(NetWolfV2Core
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
    )

    target_compile_options(NetWolfV2Gui
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
    )
endif()

# ------------------------------------------------
# Output folders
# ------------------------------------------------

set_target_properties(NetWolfV2Core PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

set_target_properties(NetWolfV2Gui PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# ------------------------------------------------
# Visual Studio convenience
# ------------------------------------------------

set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    PROPERTY VS_STARTUP_PROJECT NetWolfV2Gui
)
