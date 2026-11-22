#pragma once

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace netwolf::utils {

    // ================================================================
    // NetWolf v2 - File Writer Utility
    // Layer: Utilities
    //
    // Purpose:
    // 1. Write TXT/CSV reports to disk.
    // 2. Keep file writing separate from exporters.
    // 3. Create parent directories automatically when needed.
    // 4. Return clear success/failure information.
    // ================================================================


    // ------------------------------------------------
    // File write result
    // ------------------------------------------------

    struct FileWriteResult
    {
        bool ok = false;

        std::string path;
        std::string message;
        std::string error;

        static FileWriteResult success(
            const std::string& filePath,
            const std::string& successMessage = "File written successfully."
        )
        {
            FileWriteResult result;

            result.ok = true;
            result.path = filePath;
            result.message = successMessage;

            return result;
        }

        static FileWriteResult failure(
            const std::string& filePath,
            const std::string& errorMessage
        )
        {
            FileWriteResult result;

            result.ok = false;
            result.path = filePath;
            result.message = "File write failed.";
            result.error = errorMessage;

            return result;
        }
    };


    // ------------------------------------------------
    // File writer configuration
    // ------------------------------------------------

    struct FileWriterConfig
    {
        bool createParentDirectories = true;
        bool overwriteExistingFiles = true;

        // UTF-8 BOM can help Excel recognize UTF-8 CSV files.
        bool writeUtf8Bom = false;
    };


    // ------------------------------------------------
    // File Writer
    // ------------------------------------------------

    class FileWriter
    {
    public:
        explicit FileWriter(
            FileWriterConfig config = {}
        );

        FileWriteResult writeTextFile(
            const std::string& path,
            const std::string& content
        ) const;

        FileWriteResult writeLinesFile(
            const std::string& path,
            const std::vector<std::string>& lines
        ) const;

        FileWriteResult writeBinaryFile(
            const std::string& path,
            const std::vector<unsigned char>& bytes
        ) const;

        bool exists(
            const std::string& path
        ) const;

    private:
        FileWriterConfig config_;

    private:
        FileWriteResult preparePath(
            const std::string& path
        ) const;

        static std::string normalizePathForMessage(
            const std::filesystem::path& path
        );
    };


    // ------------------------------------------------
    // Inline implementation
    // ------------------------------------------------

    inline FileWriter::FileWriter(
        FileWriterConfig config
    )
        : config_(config)
    {
    }


    inline FileWriteResult FileWriter::writeTextFile(
        const std::string& path,
        const std::string& content
    ) const
    {
        FileWriteResult prepared = preparePath(path);

        if (!prepared.ok)
            return prepared;

        std::ofstream file(
            path,
            std::ios::binary | std::ios::out | std::ios::trunc
        );

        if (!file)
        {
            return FileWriteResult::failure(
                path,
                "Could not open file for writing."
            );
        }

        if (config_.writeUtf8Bom)
        {
            const unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
            file.write(
                reinterpret_cast<const char*>(bom),
                static_cast<std::streamsize>(sizeof(bom))
            );
        }

        file << content;

        if (!file)
        {
            return FileWriteResult::failure(
                path,
                "Failed while writing text content."
            );
        }

        return FileWriteResult::success(path);
    }


    inline FileWriteResult FileWriter::writeLinesFile(
        const std::string& path,
        const std::vector<std::string>& lines
    ) const
    {
        std::ostringstream content;

        for (const auto& line : lines)
        {
            content << line << "\n";
        }

        return writeTextFile(
            path,
            content.str()
        );
    }


    inline FileWriteResult FileWriter::writeBinaryFile(
        const std::string& path,
        const std::vector<unsigned char>& bytes
    ) const
    {
        FileWriteResult prepared = preparePath(path);

        if (!prepared.ok)
            return prepared;

        std::ofstream file(
            path,
            std::ios::binary | std::ios::out | std::ios::trunc
        );

        if (!file)
        {
            return FileWriteResult::failure(
                path,
                "Could not open binary file for writing."
            );
        }

        if (!bytes.empty())
        {
            file.write(
                reinterpret_cast<const char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size())
            );
        }

        if (!file)
        {
            return FileWriteResult::failure(
                path,
                "Failed while writing binary content."
            );
        }

        return FileWriteResult::success(path);
    }


    inline bool FileWriter::exists(
        const std::string& path
    ) const
    {
        if (path.empty())
            return false;

        std::error_code ec;
        return std::filesystem::exists(
            std::filesystem::path(path),
            ec
        );
    }


    inline FileWriteResult FileWriter::preparePath(
        const std::string& path
    ) const
    {
        if (path.empty())
        {
            return FileWriteResult::failure(
                path,
                "File path is empty."
            );
        }

        std::filesystem::path fsPath(path);

        if (std::filesystem::exists(fsPath) &&
            !config_.overwriteExistingFiles)
        {
            return FileWriteResult::failure(
                path,
                "File already exists and overwriteExistingFiles is false."
            );
        }

        if (config_.createParentDirectories)
        {
            const std::filesystem::path parent = fsPath.parent_path();

            if (!parent.empty())
            {
                std::error_code ec;

                std::filesystem::create_directories(
                    parent,
                    ec
                );

                if (ec)
                {
                    return FileWriteResult::failure(
                        path,
                        "Could not create parent directories: " + ec.message()
                    );
                }
            }
        }

        return FileWriteResult::success(
            normalizePathForMessage(fsPath),
            "File path prepared successfully."
        );
    }


    inline std::string FileWriter::normalizePathForMessage(
        const std::filesystem::path& path
    )
    {
        return path.u8string();
    }

} // namespace netwolf::utils