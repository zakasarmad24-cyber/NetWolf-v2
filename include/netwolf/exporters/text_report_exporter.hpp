#pragma once

#include <netwolf/core/engine.hpp>
#include <netwolf/live/live_engine_runner.hpp>

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace netwolf::exporters {

    // ================================================================
    // NetWolf v2 - Text Report Exporter
    // Layer: Exporter / Human-readable report
    //
    // Purpose:
    // 1. Convert EngineOutput / LiveRunResult into readable text.
    // 2. Preserve the engine structure:
    //    - Normal devices
    //    - Heavy devices
    //    - Redflag devices
    //    - Grouped main connections
    //    - Sub-connection count
    //    - Identity + Classification + Explanation
    //
    // This file does NOT define GUI layout.
    // This file does NOT classify traffic.
    // It only exports what the engine already produced.
    // ================================================================


    // ------------------------------------------------
    // Exporter configuration
    // ------------------------------------------------

    struct TextReportExporterConfig
    {
        bool includeNormalDevices = true;
        bool includeHeavyDevices = true;
        bool includeRedflagDevices = true;

        bool includeConnectionReports = true;
        bool includeDeviceScoreDetails = true;
        bool includeLimitations = true;
        bool includeSummary = true;

        size_t maxConnectionReportsPerDevice = 100;

        std::string reportTitle = "NetWolf v2 Connection Engine Report";
    };


    // ------------------------------------------------
    // Text Report Exporter
    // ------------------------------------------------

    class TextReportExporter
    {
    public:
        explicit TextReportExporter(
            TextReportExporterConfig config = {}
        );

        std::string exportEngineRun(
            const netwolf::core::EngineRunResult& result
        ) const;

        std::string exportLiveRun(
            const netwolf::live::LiveRunResult& result
        ) const;

        std::string exportOutput(
            const netwolf::core::EngineOutput& output
        ) const;

    private:
        TextReportExporterConfig config_;

    private:
        void writeHeader(
            std::ostringstream& out
        ) const;

        void writeLiveSummary(
            std::ostringstream& out,
            const netwolf::live::LiveRunResult& result
        ) const;

        void writeEngineTraceSummary(
            std::ostringstream& out,
            const netwolf::core::EngineRunResult& result
        ) const;

        void writeOutput(
            std::ostringstream& out,
            const netwolf::core::EngineOutput& output
        ) const;

        void writeDeviceSection(
            std::ostringstream& out,
            const std::string& title,
            const std::vector<netwolf::core::DeviceReport>& devices
        ) const;

        void writeDeviceReport(
            std::ostringstream& out,
            const netwolf::core::DeviceReport& device
        ) const;

        void writeDeviceScore(
            std::ostringstream& out,
            const netwolf::core::DeviceScore& score
        ) const;

        void writeConnectionReport(
            std::ostringstream& out,
            const netwolf::core::ConnectionReport& report,
            size_t index
        ) const;

        void writeMessages(
            std::ostringstream& out,
            const std::vector<netwolf::live::LiveRunMessage>& messages
        ) const;

        static std::string timeToString(
            const std::chrono::system_clock::time_point& time
        );

        static std::string bytesToHuman(
            uint64_t bytes
        );

        static std::string separator(
            char ch = '=',
            size_t count = 72
        );
    };


    // ------------------------------------------------
    // Inline implementation
    // ------------------------------------------------

    inline TextReportExporter::TextReportExporter(
        TextReportExporterConfig config
    )
        : config_(config)
    {
    }


    inline std::string TextReportExporter::exportEngineRun(
        const netwolf::core::EngineRunResult& result
    ) const
    {
        std::ostringstream out;

        writeHeader(out);
        writeEngineTraceSummary(out, result);
        writeOutput(out, result.output);

        return out.str();
    }


    inline std::string TextReportExporter::exportLiveRun(
        const netwolf::live::LiveRunResult& result
    ) const
    {
        std::ostringstream out;

        writeHeader(out);
        writeLiveSummary(out, result);
        writeMessages(out, result.messages);
        writeEngineTraceSummary(out, result.engineRun);
        writeOutput(out, result.engineRun.output);

        return out.str();
    }


    inline std::string TextReportExporter::exportOutput(
        const netwolf::core::EngineOutput& output
    ) const
    {
        std::ostringstream out;

        writeHeader(out);
        writeOutput(out, output);

        return out.str();
    }


    inline void TextReportExporter::writeHeader(
        std::ostringstream& out
    ) const
    {
        out << separator('=') << "\n";
        out << config_.reportTitle << "\n";
        out << "Generated at: " << timeToString(std::chrono::system_clock::now()) << "\n";
        out << separator('=') << "\n\n";
    }


    inline void TextReportExporter::writeLiveSummary(
        std::ostringstream& out,
        const netwolf::live::LiveRunResult& result
    ) const
    {
        if (!config_.includeSummary)
            return;

        out << "LIVE RUN SUMMARY\n";
        out << separator('-') << "\n";

        out << "Status: " << netwolf::live::toString(result.status) << "\n";
        out << "Started: " << timeToString(result.startedAt) << "\n";
        out << "Finished: " << timeToString(result.finishedAt) << "\n";
        out << "Summary: " << result.summary.summaryText << "\n";

        out << "Sensors: " << result.summary.sensorCount << "\n";
        out << "Successful sensors: " << result.summary.successfulSensors << "\n";
        out << "Partial sensors: " << result.summary.partialSensors << "\n";
        out << "Failed sensors: " << result.summary.failedSensors << "\n";

        out << "Observed connections: " << result.summary.observedConnections << "\n";
        out << "Analyzed sessions: " << result.summary.analyzedSessions << "\n";
        out << "Attributed sessions: " << result.summary.attributedSessions << "\n";
        out << "Connection groups: " << result.summary.connectionGroups << "\n";

        out << "Normal devices: " << result.summary.normalDevices << "\n";
        out << "Heavy devices: " << result.summary.heavyDevices << "\n";
        out << "Redflag devices: " << result.summary.redflagDevices << "\n\n";
    }


    inline void TextReportExporter::writeEngineTraceSummary(
        std::ostringstream& out,
        const netwolf::core::EngineRunResult& result
    ) const
    {
        if (!config_.includeSummary)
            return;

        out << "ENGINE TRACE SUMMARY\n";
        out << separator('-') << "\n";

        out << "Analyzed sessions: " << result.trace.analyzedSessions.size() << "\n";
        out << "Attributed sessions: " << result.trace.attributedSessions.size() << "\n";
        out << "Connection groups: " << result.trace.groups.size() << "\n";
        out << "All connection reports: " << result.output.allConnectionReports.size() << "\n";

        out << "Normal devices: " << result.output.normalDevices.size() << "\n";
        out << "Heavy devices: " << result.output.heavyDevices.size() << "\n";
        out << "Redflag devices: " << result.output.redflagDevices.size() << "\n\n";
    }


    inline void TextReportExporter::writeOutput(
        std::ostringstream& out,
        const netwolf::core::EngineOutput& output
    ) const
    {
        if (config_.includeRedflagDevices)
        {
            writeDeviceSection(
                out,
                "REDFLAG DEVICES",
                output.redflagDevices
            );
        }

        if (config_.includeHeavyDevices)
        {
            writeDeviceSection(
                out,
                "HEAVY DEVICES",
                output.heavyDevices
            );
        }

        if (config_.includeNormalDevices)
        {
            writeDeviceSection(
                out,
                "NORMAL DEVICES",
                output.normalDevices
            );
        }
    }


    inline void TextReportExporter::writeDeviceSection(
        std::ostringstream& out,
        const std::string& title,
        const std::vector<netwolf::core::DeviceReport>& devices
    ) const
    {
        out << title << "\n";
        out << separator('=') << "\n";
        out << "Count: " << devices.size() << "\n\n";

        if (devices.empty())
        {
            out << "No devices in this state.\n\n";
            return;
        }

        for (const auto& device : devices)
        {
            writeDeviceReport(out, device);
            out << "\n";
        }
    }


    inline void TextReportExporter::writeDeviceReport(
        std::ostringstream& out,
        const netwolf::core::DeviceReport& device
    ) const
    {
        out << "Device: " << device.deviceIp << "\n";
        out << "State: " << netwolf::core::toString(device.state) << "\n";
        out << "Total bytes: " << bytesToHuman(device.totalBytes)
            << " (" << device.totalBytes << " bytes)\n";
        out << "Summary reason: " << device.summaryReason << "\n";

        if (config_.includeDeviceScoreDetails)
        {
            writeDeviceScore(out, device.score);
        }

        if (!config_.includeConnectionReports)
            return;

        out << "\nConnection groups / reports:\n";
        out << separator('-', 48) << "\n";

        size_t index = 0;

        for (const auto& report : device.connectionReports)
        {
            if (index >= config_.maxConnectionReportsPerDevice)
            {
                out << "... more connection reports omitted by exporter limit.\n";
                break;
            }

            writeConnectionReport(out, report, index + 1);
            index++;
        }
    }


    inline void TextReportExporter::writeDeviceScore(
        std::ostringstream& out,
        const netwolf::core::DeviceScore& score
    ) const
    {
        out << "\nDevice score:\n";

        out << "  MCS: " << score.mcs << "\n";
        out << "  Total connections: " << score.totalConnections << "\n";
        out << "  Total groups: " << score.totalGroups << "\n";
        out << "  Unique entities: " << score.uniqueEntities << "\n";
        out << "  Unique categories: " << score.uniqueCategories << "\n";
        out << "  Unique services: " << score.uniqueServices << "\n";
        out << "  Concurrent connections estimate: " << score.concurrentConnections << "\n";
        out << "  Traffic share: " << score.trafficSharePercent << "%\n";
        out << "  Attribution coverage: " << score.attributionCoveragePercent << "%\n";
        out << "  Dominant entity ratio: " << score.dominantEntityRatioPercent << "%\n";

        out << "  Connection intensity score: " << score.connectionIntensityScore << "\n";
        out << "  Entity diversity score: " << score.entityDiversityScore << "\n";
        out << "  Service diversity score: " << score.serviceDiversityScore << "\n";
        out << "  Concurrency score: " << score.concurrencyScore << "\n";
        out << "  Traffic share score: " << score.trafficShareScore << "\n";
        out << "  Sustained activity score: " << score.sustainedActivityScore << "\n";

        out << "  Dominant entity penalty: " << score.dominantEntityPenalty << "\n";
        out << "  Explainable heavy usage penalty: " << score.explainableHeavyUsagePenalty << "\n";
        out << "  Weak attribution penalty: " << score.weakAttributionPenalty << "\n";
    }


    inline void TextReportExporter::writeConnectionReport(
        std::ostringstream& out,
        const netwolf::core::ConnectionReport& report,
        size_t index
    ) const
    {
        out << "[" << index << "] "
            << report.entityName
            << "\n";

        out << "  Identity:\n";
        out << "    Entity: " << report.entityName << "\n";
        out << "    Destination domain: " << report.destinationDomain << "\n";
        out << "    Category: " << report.category << "\n";
        out << "    Source: " << report.source << "\n";
        out << "    Confidence: " << netwolf::core::toString(report.confidence) << "\n";

        out << "  Connection:\n";
        out << "    Type: " << report.connectionType << "\n";
        out << "    Device IP: " << report.deviceIp << "\n";
        out << "    Owner process: " << report.ownerProcess << "\n";
        out << "    Sub-connections: " << report.subConnectionCount << "\n";
        out << "    Bytes: " << bytesToHuman(report.bytes)
            << " (" << report.bytes << " bytes)\n";

        out << "  Explanation:\n";
        out << "    Evidence used: " << report.evidenceUsed << "\n";
        out << "    Reason: " << report.reason << "\n";

        if (config_.includeLimitations)
        {
            out << "    Limitations: " << report.limitations << "\n";
        }

        out << "    Classification state: "
            << netwolf::core::toString(report.classificationState)
            << "\n\n";
    }


    inline void TextReportExporter::writeMessages(
        std::ostringstream& out,
        const std::vector<netwolf::live::LiveRunMessage>& messages
    ) const
    {
        if (messages.empty())
            return;

        out << "RUN MESSAGES\n";
        out << separator('-') << "\n";

        for (const auto& message : messages)
        {
            out << "- [" << netwolf::live::toString(message.status) << "] "
                << message.code << ": "
                << message.message;

            if (!message.details.empty())
                out << " | " << message.details;

            out << "\n";
        }

        out << "\n";
    }


    inline std::string TextReportExporter::timeToString(
        const std::chrono::system_clock::time_point& time
    )
    {
        const std::time_t t = std::chrono::system_clock::to_time_t(time);

        std::tm tmValue{};

#ifdef _WIN32
        localtime_s(&tmValue, &t);
#else
        localtime_r(&t, &tmValue);
#endif

        std::ostringstream out;
        out << std::put_time(&tmValue, "%Y-%m-%d %H:%M:%S");

        return out.str();
    }


    inline std::string TextReportExporter::bytesToHuman(
        uint64_t bytes
    )
    {
        const double kb = 1024.0;
        const double mb = kb * 1024.0;
        const double gb = mb * 1024.0;

        std::ostringstream out;
        out << std::fixed << std::setprecision(2);

        if (bytes >= static_cast<uint64_t>(gb))
        {
            out << static_cast<double>(bytes) / gb << " GB";
        }
        else if (bytes >= static_cast<uint64_t>(mb))
        {
            out << static_cast<double>(bytes) / mb << " MB";
        }
        else if (bytes >= static_cast<uint64_t>(kb))
        {
            out << static_cast<double>(bytes) / kb << " KB";
        }
        else
        {
            out << bytes << " B";
        }

        return out.str();
    }


    inline std::string TextReportExporter::separator(
        char ch,
        size_t count
    )
    {
        return std::string(count, ch);
    }

} // namespace netwolf::exporters