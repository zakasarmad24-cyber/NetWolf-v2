#pragma once

#include <netwolf/core/engine.hpp>
#include <netwolf/live/live_engine_runner.hpp>

#include <netwolf/exporters/text_report_exporter.hpp>
#include <netwolf/exporters/csv_report_exporter.hpp>

#include <netwolf/utils/file_writer.hpp>

#include <chrono>
#include <ctime>
#include <filesystem>
#include <sstream>
#include <string>
#include <vector>

namespace netwolf::exporters {

    // ================================================================
    // NetWolf v2 - Report Pack Exporter
    // Layer: Exporter / Report package
    //
    // Purpose:
    // 1. Export a full report pack into one directory.
    // 2. Write:
    //    - TXT report
    //    - device_summary.csv
    //    - device_scores.csv
    //    - connection_reports.csv
    // 3. Keep report packaging separate from:
    //    - Core engine
    //    - Sensors
    //    - GUI
    // ================================================================


    // ------------------------------------------------
    // Report pack paths
    // ------------------------------------------------

    struct ReportPackPaths
    {
        std::string outputDirectory;

        std::string textReportPath;
        std::string deviceSummaryCsvPath;
        std::string deviceScoresCsvPath;
        std::string connectionReportsCsvPath;
    };


    // ------------------------------------------------
    // Report pack export result
    // ------------------------------------------------

    struct ReportPackExportResult
    {
        bool ok = false;

        ReportPackPaths paths;

        std::vector<netwolf::utils::FileWriteResult> fileResults;

        size_t successCount = 0;
        size_t failureCount = 0;

        std::string message;

        bool allFilesWritten() const
        {
            return ok && failureCount == 0;
        }
    };


    // ------------------------------------------------
    // Report pack exporter configuration
    // ------------------------------------------------

    struct ReportPackExporterConfig
    {
        std::string outputDirectory = "netwolf_reports";

        // Base name used for file names.
        std::string baseName = "netwolf_report";

        // If true, create a timestamped subdirectory for each export.
        bool createTimestampedFolder = true;

        bool writeTextReport = true;
        bool writeDeviceSummaryCsv = true;
        bool writeDeviceScoresCsv = true;
        bool writeConnectionReportsCsv = true;

        bool overwriteExistingFiles = true;

        // Helpful for opening CSV files in Excel.
        bool writeUtf8BomForCsv = true;

        TextReportExporterConfig textConfig;
        CsvReportExporterConfig csvConfig;
    };


    // ------------------------------------------------
    // Report Pack Exporter
    // ------------------------------------------------

    class ReportPackExporter
    {
    public:
        explicit ReportPackExporter(
            ReportPackExporterConfig config = {}
        );

        ReportPackExportResult exportEngineRun(
            const netwolf::core::EngineRunResult& result
        ) const;

        ReportPackExportResult exportLiveRun(
            const netwolf::live::LiveRunResult& result
        ) const;

        ReportPackExportResult exportOutput(
            const netwolf::core::EngineOutput& output
        ) const;

    private:
        ReportPackExporterConfig config_;

    private:
        ReportPackExportResult exportTexts(
            const std::string& textReport,
            const CsvExportBundle& csvBundle
        ) const;

        ReportPackPaths buildPaths() const;

        void addWriteResult(
            ReportPackExportResult& result,
            const netwolf::utils::FileWriteResult& writeResult
        ) const;

        static std::string makeTimestampFolderName();

        static std::string sanitizeFilePart(
            const std::string& value
        );

        static std::string joinPath(
            const std::string& a,
            const std::string& b
        );

        static std::string buildFinalMessage(
            const ReportPackExportResult& result
        );
    };


    // ------------------------------------------------
    // Inline implementation
    // ------------------------------------------------

    inline ReportPackExporter::ReportPackExporter(
        ReportPackExporterConfig config
    )
        : config_(config)
    {
    }


    inline ReportPackExportResult ReportPackExporter::exportEngineRun(
        const netwolf::core::EngineRunResult& result
    ) const
    {
        TextReportExporter textExporter(config_.textConfig);
        CsvReportExporter csvExporter(config_.csvConfig);

        const std::string textReport =
            textExporter.exportEngineRun(result);

        const CsvExportBundle csvBundle =
            csvExporter.exportEngineRun(result);

        return exportTexts(
            textReport,
            csvBundle
        );
    }


    inline ReportPackExportResult ReportPackExporter::exportLiveRun(
        const netwolf::live::LiveRunResult& result
    ) const
    {
        TextReportExporter textExporter(config_.textConfig);
        CsvReportExporter csvExporter(config_.csvConfig);

        const std::string textReport =
            textExporter.exportLiveRun(result);

        const CsvExportBundle csvBundle =
            csvExporter.exportLiveRun(result);

        return exportTexts(
            textReport,
            csvBundle
        );
    }


    inline ReportPackExportResult ReportPackExporter::exportOutput(
        const netwolf::core::EngineOutput& output
    ) const
    {
        TextReportExporter textExporter(config_.textConfig);
        CsvReportExporter csvExporter(config_.csvConfig);

        const std::string textReport =
            textExporter.exportOutput(output);

        const CsvExportBundle csvBundle =
            csvExporter.exportOutput(output);

        return exportTexts(
            textReport,
            csvBundle
        );
    }


    inline ReportPackExportResult ReportPackExporter::exportTexts(
        const std::string& textReport,
        const CsvExportBundle& csvBundle
    ) const
    {
        ReportPackExportResult result;
        result.paths = buildPaths();

        netwolf::utils::FileWriterConfig textWriterConfig;
        textWriterConfig.createParentDirectories = true;
        textWriterConfig.overwriteExistingFiles = config_.overwriteExistingFiles;
        textWriterConfig.writeUtf8Bom = false;

        netwolf::utils::FileWriter textWriter(textWriterConfig);

        netwolf::utils::FileWriterConfig csvWriterConfig;
        csvWriterConfig.createParentDirectories = true;
        csvWriterConfig.overwriteExistingFiles = config_.overwriteExistingFiles;
        csvWriterConfig.writeUtf8Bom = config_.writeUtf8BomForCsv;

        netwolf::utils::FileWriter csvWriter(csvWriterConfig);

        if (config_.writeTextReport)
        {
            addWriteResult(
                result,
                textWriter.writeTextFile(
                    result.paths.textReportPath,
                    textReport
                )
            );
        }

        if (config_.writeDeviceSummaryCsv)
        {
            addWriteResult(
                result,
                csvWriter.writeTextFile(
                    result.paths.deviceSummaryCsvPath,
                    csvBundle.deviceSummaryCsv
                )
            );
        }

        if (config_.writeDeviceScoresCsv)
        {
            addWriteResult(
                result,
                csvWriter.writeTextFile(
                    result.paths.deviceScoresCsvPath,
                    csvBundle.deviceScoresCsv
                )
            );
        }

        if (config_.writeConnectionReportsCsv)
        {
            addWriteResult(
                result,
                csvWriter.writeTextFile(
                    result.paths.connectionReportsCsvPath,
                    csvBundle.connectionReportsCsv
                )
            );
        }

        result.ok = result.failureCount == 0;
        result.message = buildFinalMessage(result);

        return result;
    }


    inline ReportPackPaths ReportPackExporter::buildPaths() const
    {
        ReportPackPaths paths;

        std::string directory = config_.outputDirectory.empty()
            ? "netwolf_reports"
            : config_.outputDirectory;

        if (config_.createTimestampedFolder)
        {
            directory = joinPath(
                directory,
                makeTimestampFolderName()
            );
        }

        const std::string baseName = sanitizeFilePart(
            config_.baseName.empty()
            ? "netwolf_report"
            : config_.baseName
        );

        paths.outputDirectory = directory;

        paths.textReportPath = joinPath(
            directory,
            baseName + ".txt"
        );

        paths.deviceSummaryCsvPath = joinPath(
            directory,
            "device_summary.csv"
        );

        paths.deviceScoresCsvPath = joinPath(
            directory,
            "device_scores.csv"
        );

        paths.connectionReportsCsvPath = joinPath(
            directory,
            "connection_reports.csv"
        );

        return paths;
    }


    inline void ReportPackExporter::addWriteResult(
        ReportPackExportResult& result,
        const netwolf::utils::FileWriteResult& writeResult
    ) const
    {
        result.fileResults.push_back(writeResult);

        if (writeResult.ok)
            result.successCount++;
        else
            result.failureCount++;
    }


    inline std::string ReportPackExporter::makeTimestampFolderName()
    {
        const auto now = std::chrono::system_clock::now();
        const std::time_t t = std::chrono::system_clock::to_time_t(now);

        std::tm tmValue{};

#ifdef _WIN32
        localtime_s(&tmValue, &t);
#else
        localtime_r(&t, &tmValue);
#endif

        std::ostringstream out;

        out
            << "run_"
            << (tmValue.tm_year + 1900)
            << "_";

        if ((tmValue.tm_mon + 1) < 10)
            out << "0";
        out << (tmValue.tm_mon + 1) << "_";

        if (tmValue.tm_mday < 10)
            out << "0";
        out << tmValue.tm_mday << "_";

        if (tmValue.tm_hour < 10)
            out << "0";
        out << tmValue.tm_hour;

        if (tmValue.tm_min < 10)
            out << "0";
        out << tmValue.tm_min;

        if (tmValue.tm_sec < 10)
            out << "0";
        out << tmValue.tm_sec;

        return out.str();
    }


    inline std::string ReportPackExporter::sanitizeFilePart(
        const std::string& value
    )
    {
        std::string result;

        result.reserve(value.size());

        for (char ch : value)
        {
            const bool safe =
                (ch >= 'a' && ch <= 'z') ||
                (ch >= 'A' && ch <= 'Z') ||
                (ch >= '0' && ch <= '9') ||
                ch == '_' ||
                ch == '-' ||
                ch == '.';

            if (safe)
                result.push_back(ch);
            else
                result.push_back('_');
        }

        if (result.empty())
            return "netwolf_report";

        return result;
    }


    inline std::string ReportPackExporter::joinPath(
        const std::string& a,
        const std::string& b
    )
    {
        std::filesystem::path path(a);
        path /= b;

        return path.string();
    }


    inline std::string ReportPackExporter::buildFinalMessage(
        const ReportPackExportResult& result
    )
    {
        std::ostringstream out;

        if (result.ok)
        {
            out
                << "Report pack exported successfully. "
                << "Files written: "
                << result.successCount
                << ". Output directory: "
                << result.paths.outputDirectory
                << ".";
        }
        else
        {
            out
                << "Report pack export completed with errors. "
                << "Files written: "
                << result.successCount
                << ", failures: "
                << result.failureCount
                << ". Output directory: "
                << result.paths.outputDirectory
                << ".";
        }

        return out.str();
    }

} // namespace netwolf::exporters