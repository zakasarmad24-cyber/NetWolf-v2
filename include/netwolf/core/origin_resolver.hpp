#pragma once

#include "models.hpp"
#include "session_id.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace netwolf::core {

    // ================================================================
    // NetWolf v2 - Origin Resolver
    // Layer 4: Origin Resolver
    //
    // Purpose:
    // 1. Identify who/what created the connection.
    // 2. Classify process origin:
    //    - User/Application
    //    - Developer/Work tool
    //    - Background/System
    //    - Security tool
    //    - Unknown but explained
    // 3. Avoid raw Unknown by always producing an explained origin state.
    // ================================================================


    // ------------------------------------------------
    // Raw process observation
    // This can come later from Windows APIs, OS tables,
    // packet metadata, or manual test injection.
    // ------------------------------------------------

    struct ProcessObservation
    {
        uint32_t pid = 0;
        std::string processName;
        std::string processPath;
    };


    // ------------------------------------------------
    // Origin resolution result
    // ------------------------------------------------

    struct OriginResolutionResult
    {
        ProcessCandidate process;

        bool processVisible = false;

        ConfidenceLevel confidence = ConfidenceLevel::None;

        std::string reason;
        std::string limitations;
    };


    // ------------------------------------------------
    // Origin resolver configuration
    // ------------------------------------------------

    struct OriginResolverConfig
    {
        bool classifyBrowsersAsUserApps = true;
        bool classifyDeveloperTools = true;
        bool classifyWindowsSystemProcesses = true;
        bool classifySecurityTools = true;

        // If no process evidence exists, return an explained fallback.
        bool allowExplainedUnavailableProcess = true;
    };


    // ------------------------------------------------
    // Origin Resolver
    // ------------------------------------------------

    class OriginResolver
    {
    public:
        explicit OriginResolver(OriginResolverConfig config = {});

        OriginResolutionResult resolve(
            const ConnectionSession& session
        ) const;

        OriginResolutionResult resolveFromObservation(
            const ProcessObservation& observation
        ) const;

        ConnectionSession attachOriginEvidence(
            ConnectionSession session,
            const OriginResolutionResult& origin
        ) const;

    private:
        OriginResolverConfig config_;

    private:
        OriginClass classifyProcess(
            const std::string& processName,
            const std::string& processPath
        ) const;

        OriginResolutionResult buildVisibleProcessResult(
            const ProcessObservation& observation,
            OriginClass originClass
        ) const;

        OriginResolutionResult buildFallbackProcessResult(
            const ConnectionSession& session
        ) const;

        static bool containsAny(
            const std::string& text,
            const std::vector<std::string>& tokens
        );

        static bool isBrowserProcess(const std::string& processName);
        static bool isDeveloperToolProcess(const std::string& processName);
        static bool isWindowsSystemProcess(const std::string& processName);
        static bool isSecurityToolProcess(const std::string& processName);
    };


    // ------------------------------------------------
    // Inline implementation
    // ------------------------------------------------

    inline OriginResolver::OriginResolver(OriginResolverConfig config)
        : config_(config)
    {
    }


    inline OriginResolutionResult OriginResolver::resolve(
        const ConnectionSession& session
    ) const
    {
        if (!session.evidence.processCandidates.empty())
        {
            const ProcessCandidate& existing = session.evidence.processCandidates.front();

            ProcessObservation observation;
            observation.pid = existing.pid;
            observation.processName = existing.processName;
            observation.processPath = existing.processPath;

            return resolveFromObservation(observation);
        }

        return buildFallbackProcessResult(session);
    }


    inline OriginResolutionResult OriginResolver::resolveFromObservation(
        const ProcessObservation& observation
    ) const
    {
        const OriginClass originClass = classifyProcess(
            observation.processName,
            observation.processPath
        );

        return buildVisibleProcessResult(observation, originClass);
    }


    inline ConnectionSession OriginResolver::attachOriginEvidence(
        ConnectionSession session,
        const OriginResolutionResult& origin
    ) const
    {
        // Avoid duplicating the same visible process if it already exists.
        if (!session.evidence.processCandidates.empty())
        {
            session.evidence.processCandidates.front() = origin.process;
            return session;
        }

        session.evidence.processCandidates.push_back(origin.process);
        return session;
    }


    inline OriginClass OriginResolver::classifyProcess(
        const std::string& processName,
        const std::string& processPath
    ) const
    {
        const std::string name = lowerCopy(processName);
        const std::string path = lowerCopy(processPath);
        const std::string merged = name + " " + path;

        if (config_.classifyBrowsersAsUserApps && isBrowserProcess(merged))
            return OriginClass::UserApplication;

        if (config_.classifyDeveloperTools && isDeveloperToolProcess(merged))
            return OriginClass::DeveloperTool;

        if (config_.classifyWindowsSystemProcesses && isWindowsSystemProcess(merged))
            return OriginClass::BackgroundSystem;

        if (config_.classifySecurityTools && isSecurityToolProcess(merged))
            return OriginClass::SecurityTool;

        if (!trimCopy(processName).empty())
            return OriginClass::UserApplication;

        return OriginClass::UnknownButExplained;
    }


    inline OriginResolutionResult OriginResolver::buildVisibleProcessResult(
        const ProcessObservation& observation,
        OriginClass originClass
    ) const
    {
        OriginResolutionResult result;

        result.process.pid = observation.pid;
        result.process.processName = trimCopy(observation.processName);
        result.process.processPath = trimCopy(observation.processPath);
        result.process.originClass = originClass;
        result.process.observedAt = nowUtc();

        result.processVisible = !result.process.processName.empty() || observation.pid != 0;

        switch (originClass)
        {
        case OriginClass::UserApplication:
            result.confidence = ConfidenceLevel::MediumHigh;
            result.reason =
                "The connection is associated with a visible user/application process.";
            result.limitations =
                "Process ownership identifies the local origin, but does not by itself prove the exact remote service.";
            break;

        case OriginClass::DeveloperTool:
            result.confidence = ConfidenceLevel::MediumHigh;
            result.reason =
                "The connection is associated with a developer/work tool process.";
            result.limitations =
                "Developer tools may create multiple background connections for repositories, extensions, containers, or package services.";
            break;

        case OriginClass::BackgroundSystem:
            result.confidence = ConfidenceLevel::MediumHigh;
            result.reason =
                "The connection is associated with a background/system process.";
            result.limitations =
                "System processes can host multiple Windows services, so destination evidence is still needed for exact attribution.";
            break;

        case OriginClass::SecurityTool:
            result.confidence = ConfidenceLevel::MediumHigh;
            result.reason =
                "The connection is associated with a security or protection tool.";
            result.limitations =
                "Security tools may contact update, reputation, scanning, or telemetry endpoints.";
            break;

        case OriginClass::UnknownButExplained:
        default:
            result.confidence = ConfidenceLevel::Low;
            result.reason =
                "The local process could not be identified clearly, so the engine keeps an explained origin classification.";
            result.limitations =
                "No reliable process identity was available. This is not a raw Unknown result.";
            break;
        }

        if (result.process.processName.empty())
        {
            result.process.processName = "Process context unavailable";
            result.process.originClass = OriginClass::UnknownButExplained;
            result.processVisible = false;
            result.confidence = ConfidenceLevel::Low;
            result.reason =
                "No visible process name was available for this connection.";
            result.limitations =
                "The engine preserves an explained origin instead of raw Unknown.";
        }

        return result;
    }


    inline OriginResolutionResult OriginResolver::buildFallbackProcessResult(
        const ConnectionSession& session
    ) const
    {
        OriginResolutionResult result;

        result.process.pid = 0;
        result.process.processName = "Process context unavailable";
        result.process.processPath.clear();
        result.process.originClass = OriginClass::UnknownButExplained;
        result.process.observedAt = nowUtc();

        result.processVisible = false;
        result.confidence = ConfidenceLevel::Low;

        if (session.dnsLikely)
        {
            result.reason =
                "No process metadata was available, but the connection behavior indicates DNS/name-resolution traffic.";
            result.limitations =
                "Origin process is unavailable; classification is based on connection analysis only.";
            return result;
        }

        if (session.encryptedLikely)
        {
            result.reason =
                "No process metadata was available, but the connection appears to be encrypted outbound traffic.";
            result.limitations =
                "Origin process is unavailable; encrypted traffic is explained without claiming exact process identity.";
            return result;
        }

        result.reason =
            "No process metadata was available for this connection.";
        result.limitations =
            "The engine reports an explained origin state instead of raw Unknown.";

        return result;
    }


    inline bool OriginResolver::containsAny(
        const std::string& text,
        const std::vector<std::string>& tokens
    )
    {
        const std::string loweredText = lowerCopy(text);

        for (const auto& token : tokens)
        {
            if (loweredText.find(lowerCopy(token)) != std::string::npos)
                return true;
        }

        return false;
    }


    inline bool OriginResolver::isBrowserProcess(const std::string& processName)
    {
        return containsAny(
            processName,
            {
                "chrome.exe",
                "msedge.exe",
                "firefox.exe",
                "brave.exe",
                "opera.exe",
                "vivaldi.exe",
                "browser"
            }
        );
    }


    inline bool OriginResolver::isDeveloperToolProcess(const std::string& processName)
    {
        return containsAny(
            processName,
            {
                "code.exe",
                "devenv.exe",
                "git.exe",
                "docker.exe",
                "docker desktop.exe",
                "node.exe",
                "npm.exe",
                "python.exe",
                "py.exe",
                "cmake.exe",
                "cl.exe",
                "msbuild.exe",
                "powershell.exe",
                "terminal",
                "wsl.exe"
            }
        );
    }


    inline bool OriginResolver::isWindowsSystemProcess(const std::string& processName)
    {
        return containsAny(
            processName,
            {
                "svchost.exe",
                "system",
                "searchhost.exe",
                "runtimebroker.exe",
                "sihost.exe",
                "backgroundtaskhost.exe",
                "windows update",
                "wuauclt.exe",
                "usoclient.exe",
                "services.exe",
                "lsass.exe",
                "wininit.exe",
                "spoolsv.exe",
                "taskhostw.exe",
                "fontdrvhost.exe"
            }
        );
    }


    inline bool OriginResolver::isSecurityToolProcess(const std::string& processName)
    {
        return containsAny(
            processName,
            {
                "msmpeng.exe",
                "securityhealthservice.exe",
                "windefend",
                "defender",
                "avast",
                "avg",
                "kaspersky",
                "bitdefender",
                "eset",
                "norton",
                "malwarebytes",
                "sentinel",
                "crowdstrike",
                "carbonblack",
                "sophos"
            }
        );
    }

} // namespace netwolf::core