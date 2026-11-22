#pragma once

#include <netwolf/core/engine.hpp>
#include <netwolf/live/live_engine_runner.hpp>

#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>

namespace netwolf::exporters {

    // ================================================================
    // NetWolf v2 - CSV Report Exporter
    // Layer: Exporter / CSV reports
    //
    // Purpose:
    // 1. Export structured engine results to CSV.
    // 2. Keep reports independent from GUI.
    // 3. Provide machine-readable outputs:
    //    - Device summary
    //    - Device scores
    //    - Connection reports
    //
    // This file does NOT classify.
    // This file does NOT capture traffic.
    // It only exports the already-produced engine output.
    // ================================================================


    // ------------------------------------------------
    // CSV export bundle
    // ------------------------------------------------

    struct CsvExportBundle
    {
        std::string deviceSummaryCsv;
        std::string deviceScoresCsv;
        std::string connectionReportsCsv;
    };


    // ------------------------------------------------
    // CSV exporter configuration
    // ------------------------------------------------

    struct CsvReportExporterConfig
    {
        bool includeNormalDevices = true;
        bool includeHeavyDevices = true;
        bool includeRedflagDevices = true;

        bool includeConnectionReports = true;
        bool includeLimitations = true;

        char delimiter = ',';
    };


    // ------------------------------------------------
    // CSV Report Exporter
    // ------------------------------------------------

    class CsvReportExporter
    {
    public:
        explicit CsvReportExporter(
            CsvReportExporterConfig config = {}
        );

        CsvExportBundle exportEngineRun(
            const netwolf::core::EngineRunResult& result
        ) const;

        CsvExportBundle exportLiveRun(
            const netwolf::live::LiveRunResult& result
        ) const;

        CsvExportBundle exportOutput(
            const netwolf::core::EngineOutput& output
        ) const;

        std::string exportDeviceSummaryCsv(
            const netwolf::core::EngineOutput& output
        ) const;

        std::string exportDeviceScoresCsv(
            const netwolf::core::EngineOutput& output
        ) const;

        std::string exportConnectionReportsCsv(
            const netwolf::core::EngineOutput& output
        ) const;

        bool writeCsvFile(
            const std::string& path,
            const std::string& csvText
        ) const;

    private:
        CsvReportExporterConfig config_;

    private:
        void writeDeviceSummaryRows(
            std::ostringstream& out,
            const std::vector<netwolf::core::DeviceReport>& devices,
            const std::string& stateLabel
        ) const;

        void writeDeviceScoreRows(
            std::ostringstream& out,
            const std::vector<netwolf::core::DeviceReport>& devices,
            const std::string& stateLabel
        ) const;

        void writeConnectionReportRows(
            std::ostringstream& out,
            const std::vector<netwolf::core::DeviceReport>& devices,
            const std::string& stateLabel
        ) const;

        void writeConnectionReportRow(
            std::ostringstream& out,
            const netwolf::core::DeviceReport& device,
            const netwolf::core::ConnectionReport& report,
            const std::string& stateLabel,
            size_t index
        ) const;

        void collectSelectedDevices(
            const netwolf::core::EngineOutput& output,
            std::vector<std::pair<std::string, const std::vector<netwolf::core::DeviceReport>*>>& sections
        ) const;

        std::string cell(const std::string& value) const;
        std::string cell(const char* value) const;

        // Accept ANY integer type (size_t, uint64_t, ...) with an exact match,
        // so the call is never ambiguous with cell(double) on 32-bit builds
        // where size_t and uint64_t are different widths.
        template <typename T,
            typename std::enable_if<std::is_integral<T>::value, int>::type = 0>
        std::string cell(T value) const
        {
            return std::to_string(value);
        }

        std::string cell(double value) const;

        void endRow(std::ostringstream& out) const;

        static std::string escapeCsv(
            const std::string& value,
            char delimiter
        );
    };


    // ------------------------------------------------
    // Inline implementation
    // ------------------------------------------------

    inline CsvReportExporter::CsvReportExporter(
        CsvReportExporterConfig config
    )
        : config_(config)
    {
    }


    inline CsvExportBundle CsvReportExporter::exportEngineRun(
        const netwolf::core::EngineRunResult& result
    ) const
    {
        return exportOutput(result.output);
    }


    inline CsvExportBundle CsvReportExporter::exportLiveRun(
        const netwolf::live::LiveRunResult& result
    ) const
    {
        return exportOutput(result.engineRun.output);
    }


    inline CsvExportBundle CsvReportExporter::exportOutput(
        const netwolf::core::EngineOutput& output
    ) const
    {
        CsvExportBundle bundle;

        bundle.deviceSummaryCsv = exportDeviceSummaryCsv(output);
        bundle.deviceScoresCsv = exportDeviceScoresCsv(output);
        bundle.connectionReportsCsv = exportConnectionReportsCsv(output);

        return bundle;
    }


    inline std::string CsvReportExporter::exportDeviceSummaryCsv(
        const netwolf::core::EngineOutput& output
    ) const
    {
        std::ostringstream out;

        out
            << cell("state")
            << config_.delimiter
            << cell("device_ip")
            << config_.delimiter
            << cell("mcs")
            << config_.delimiter
            << cell("total_connections")
            << config_.delimiter
            << cell("total_groups")
            << config_.delimiter
            << cell("total_bytes")
            << config_.delimiter
            << cell("unique_entities")
            << config_.delimiter
            << cell("unique_services")
            << config_.delimiter
            << cell("traffic_share_percent")
            << config_.delimiter
            << cell("attribution_coverage_percent")
            << config_.delimiter
            << cell("dominant_entity_ratio_percent")
            << config_.delimiter
            << cell("summary_reason");

        endRow(out);

        std::vector<std::pair<std::string, const std::vector<netwolf::core::DeviceReport>*>> sections;
        collectSelectedDevices(output, sections);

        for (const auto& section : sections)
        {
            writeDeviceSummaryRows(
                out,
                *section.second,
                section.first
            );
        }

        return out.str();
    }


    inline std::string CsvReportExporter::exportDeviceScoresCsv(
        const netwolf::core::EngineOutput& output
    ) const
    {
        std::ostringstream out;

        out
            << cell("state")
            << config_.delimiter
            << cell("device_ip")
            << config_.delimiter
            << cell("mcs")
            << config_.delimiter
            << cell("connection_intensity_score")
            << config_.delimiter
            << cell("entity_diversity_score")
            << config_.delimiter
            << cell("service_diversity_score")
            << config_.delimiter
            << cell("concurrency_score")
            << config_.delimiter
            << cell("traffic_share_score")
            << config_.delimiter
            << cell("sustained_activity_score")
            << config_.delimiter
            << cell("dominant_entity_penalty")
            << config_.delimiter
            << cell("explainable_heavy_usage_penalty")
            << config_.delimiter
            << cell("weak_attribution_penalty")
            << config_.delimiter
            << cell("total_connections")
            << config_.delimiter
            << cell("unique_entities")
            << config_.delimiter
            << cell("unique_categories")
            << config_.delimiter
            << cell("unique_services")
            << config_.delimiter
            << cell("concurrent_connections_estimate")
            << config_.delimiter
            << cell("total_bytes");

        endRow(out);

        std::vector<std::pair<std::string, const std::vector<netwolf::core::DeviceReport>*>> sections;
        collectSelectedDevices(output, sections);

        for (const auto& section : sections)
        {
            writeDeviceScoreRows(
                out,
                *section.second,
                section.first
            );
        }

        return out.str();
    }


    inline std::string CsvReportExporter::exportConnectionReportsCsv(
        const netwolf::core::EngineOutput& output
    ) const
    {
        std::ostringstream out;

        out
            << cell("state")
            << config_.delimiter
            << cell("device_ip")
            << config_.delimiter
            << cell("connection_index")
            << config_.delimiter
            << cell("entity_name")
            << config_.delimiter
            << cell("destination_domain")
            << config_.delimiter
            << cell("category")
            << config_.delimiter
            << cell("source")
            << config_.delimiter
            << cell("confidence")
            << config_.delimiter
            << cell("connection_type")
            << config_.delimiter
            << cell("owner_process")
            << config_.delimiter
            << cell("sub_connection_count")
            << config_.delimiter
            << cell("bytes")
            << config_.delimiter
            << cell("evidence_used")
            << config_.delimiter
            << cell("reason");

        if (config_.includeLimitations)
        {
            out << config_.delimiter << cell("limitations");
        }

        endRow(out);

        std::vector<std::pair<std::string, const std::vector<netwolf::core::DeviceReport>*>> sections;
        collectSelectedDevices(output, sections);

        for (const auto& section : sections)
        {
            writeConnectionReportRows(
                out,
                *section.second,
                section.first
            );
        }

        return out.str();
    }


    inline bool CsvReportExporter::writeCsvFile(
        const std::string& path,
        const std::string& csvText
    ) const
    {
        std::ofstream file(path, std::ios::binary);

        if (!file)
            return false;

        file << csvText;

        return static_cast<bool>(file);
    }


    inline void CsvReportExporter::writeDeviceSummaryRows(
        std::ostringstream& out,
        const std::vector<netwolf::core::DeviceReport>& devices,
        const std::string& stateLabel
    ) const
    {
        for (const auto& device : devices)
        {
            const auto& score = device.score;

            out
                << cell(stateLabel)
                << config_.delimiter
                << cell(device.deviceIp)
                << config_.delimiter
                << cell(score.mcs)
                << config_.delimiter
                << cell(score.totalConnections)
                << config_.delimiter
                << cell(score.totalGroups)
                << config_.delimiter
                << cell(score.totalBytes)
                << config_.delimiter
                << cell(score.uniqueEntities)
                << config_.delimiter
                << cell(score.uniqueServices)
                << config_.delimiter
                << cell(score.trafficSharePercent)
                << config_.delimiter
                << cell(score.attributionCoveragePercent)
                << config_.delimiter
                << cell(score.dominantEntityRatioPercent)
                << config_.delimiter
                << cell(device.summaryReason);

            endRow(out);
        }
    }


    inline void CsvReportExporter::writeDeviceScoreRows(
        std::ostringstream& out,
        const std::vector<netwolf::core::DeviceReport>& devices,
        const std::string& stateLabel
    ) const
    {
        for (const auto& device : devices)
        {
            const auto& score = device.score;

            out
                << cell(stateLabel)
                << config_.delimiter
                << cell(device.deviceIp)
                << config_.delimiter
                << cell(score.mcs)
                << config_.delimiter
                << cell(score.connectionIntensityScore)
                << config_.delimiter
                << cell(score.entityDiversityScore)
                << config_.delimiter
                << cell(score.serviceDiversityScore)
                << config_.delimiter
                << cell(score.concurrencyScore)
                << config_.delimiter
                << cell(score.trafficShareScore)
                << config_.delimiter
                << cell(score.sustainedActivityScore)
                << config_.delimiter
                << cell(score.dominantEntityPenalty)
                << config_.delimiter
                << cell(score.explainableHeavyUsagePenalty)
                << config_.delimiter
                << cell(score.weakAttributionPenalty)
                << config_.delimiter
                << cell(score.totalConnections)
                << config_.delimiter
                << cell(score.uniqueEntities)
                << config_.delimiter
                << cell(score.uniqueCategories)
                << config_.delimiter
                << cell(score.uniqueServices)
                << config_.delimiter
                << cell(score.concurrentConnections)
                << config_.delimiter
                << cell(score.totalBytes);

            endRow(out);
        }
    }


    inline void CsvReportExporter::writeConnectionReportRows(
        std::ostringstream& out,
        const std::vector<netwolf::core::DeviceReport>& devices,
        const std::string& stateLabel
    ) const
    {
        for (const auto& device : devices)
        {
            size_t index = 1;

            for (const auto& report : device.connectionReports)
            {
                writeConnectionReportRow(
                    out,
                    device,
                    report,
                    stateLabel,
                    index
                );

                index++;
            }
        }
    }


    inline void CsvReportExporter::writeConnectionReportRow(
        std::ostringstream& out,
        const netwolf::core::DeviceReport& device,
        const netwolf::core::ConnectionReport& report,
        const std::string& stateLabel,
        size_t index
    ) const
    {
        out
            << cell(stateLabel)
            << config_.delimiter
            << cell(device.deviceIp)
            << config_.delimiter
            << cell(index)
            << config_.delimiter
            << cell(report.entityName)
            << config_.delimiter
            << cell(report.destinationDomain)
            << config_.delimiter
            << cell(report.category)
            << config_.delimiter
            << cell(report.source)
            << config_.delimiter
            << cell(netwolf::core::toString(report.confidence))
            << config_.delimiter
            << cell(report.connectionType)
            << config_.delimiter
            << cell(report.ownerProcess)
            << config_.delimiter
            << cell(report.subConnectionCount)
            << config_.delimiter
            << cell(report.bytes)
            << config_.delimiter
            << cell(report.evidenceUsed)
            << config_.delimiter
            << cell(report.reason);

        if (config_.includeLimitations)
        {
            out << config_.delimiter << cell(report.limitations);
        }

        endRow(out);
    }


    inline void CsvReportExporter::collectSelectedDevices(
        const netwolf::core::EngineOutput& output,
        std::vector<std::pair<std::string, const std::vector<netwolf::core::DeviceReport>*>>& sections
    ) const
    {
        if (config_.includeRedflagDevices)
        {
            sections.push_back({
                "Redflag State",
                &output.redflagDevices
                });
        }

        if (config_.includeHeavyDevices)
        {
            sections.push_back({
                "Heavy State",
                &output.heavyDevices
                });
        }

        if (config_.includeNormalDevices)
        {
            sections.push_back({
                "Normal State",
                &output.normalDevices
                });
        }
    }


    inline std::string CsvReportExporter::cell(
        const std::string& value
    ) const
    {
        return escapeCsv(value, config_.delimiter);
    }


    inline std::string CsvReportExporter::cell(
        const char* value
    ) const
    {
        if (value == nullptr)
            return escapeCsv("", config_.delimiter);

        return escapeCsv(std::string(value), config_.delimiter);
    }


    inline std::string CsvReportExporter::cell(
        double value
    ) const
    {
        std::ostringstream out;
        out << std::fixed << std::setprecision(4) << value;
        return out.str();
    }


    inline void CsvReportExporter::endRow(
        std::ostringstream& out
    ) const
    {
        out << "\r\n";
    }


    inline std::string CsvReportExporter::escapeCsv(
        const std::string& value,
        char delimiter
    )
    {
        bool needsQuotes = false;

        for (char ch : value)
        {
            if (ch == delimiter || ch == '"' || ch == '\n' || ch == '\r')
            {
                needsQuotes = true;
                break;
            }
        }

        if (!needsQuotes)
            return value;

        std::string escaped;
        escaped.reserve(value.size() + 2);

        escaped.push_back('"');

        for (char ch : value)
        {
            if (ch == '"')
                escaped.push_back('"');

            escaped.push_back(ch);
        }

        escaped.push_back('"');

        return escaped;
    }

} // namespace netwolf::exporters