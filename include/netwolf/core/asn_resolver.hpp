#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
// winsock2.h must come before windows.h (same order as the socket sensors),
// otherwise windows.h pulls in the old winsock.h and the two conflict.
#include <winsock2.h>
#include <windows.h>
#endif

namespace netwolf::core {

    // ================================================================
    // NetWolf v2 - Offline ASN / Owner Resolver
    // Layer 3b: IP -> owning organization (no network, no DNS needed)
    //
    // Purpose:
    // Name the OWNER of every public destination IP automatically, even
    // when no DNS answer and no TLS SNI were observed. There is no list
    // of apps or companies in the code: the owner comes from the full
    // public IP-to-ASN dataset (iptoasn.com, ip2asn-v4), converted to a
    // compact binary (resources/ip2asn.bin) and EMBEDDED in the .exe as
    // an RCDATA resource. Fully offline.
    //
    // Database lookup order:
    //   1. RCDATA resource IDR_NETWOLF_ASN (201) inside the running .exe
    //   2. file named by the NETWOLF_ASN_DB environment variable
    //   3. resources/ip2asn.bin or ip2asn.bin in the working directory
    //
    // Binary format (little-endian), made by tools/make_asn_bin.py:
    //   char[8] "NWASN1\0\0" | u32 rangeCount | u32 ownerCount |
    //   u32 namesBytes | u32 sourceRows
    //   rangeCount x { u32 startIp, u32 ownerIndex }  (0xFFFFFFFF = not routed;
    //                                                  a range ends where the next starts)
    //   ownerCount x { u32 asn, u32 nameOffset, u16 nameLength, char country[2] }
    //   names (UTF-8)
    // ================================================================

    // Must match resources/resource.h
    constexpr int kNetWolfAsnResourceId = 201;

    // Environment variable as std::string ("" if missing). Uses _dupenv_s on
    // MSVC, where getenv is flagged as unsafe (warning C4996).
    inline std::string readEnvironmentVariable(const char* name)
    {
#if defined(_MSC_VER)
        char* buffer = nullptr;
        size_t length = 0;

        if (_dupenv_s(&buffer, &length, name) != 0 || buffer == nullptr)
            return {};

        std::string value(buffer);
        std::free(buffer);
        return value;
#else
        const char* value = std::getenv(name);
        return value != nullptr ? std::string(value) : std::string();
#endif
    }


    struct AsnInfo
    {
        bool        found = false;   // false => private / not routed / no database
        std::string org;             // "Akamai Technologies, Inc."
        std::string asn;             // "AS20940"
        std::string country;         // "US"
        std::string category;        // "Network owner AS20940 (US)"
    };


    class AsnDatabase
    {
    public:
        // Loaded once per process; shared by every resolver instance.
        static const AsnDatabase& instance()
        {
            static const AsnDatabase database;
            return database;
        }

        bool loaded() const { return rangeCount_ > 0; }
        uint32_t rangeCount() const { return rangeCount_; }
        uint32_t ownerCount() const { return ownerCount_; }
        const std::string& source() const { return source_; }

        AsnInfo lookup(uint32_t ip) const
        {
            AsnInfo info;

            if (!loaded())
                return info;

            // Last range whose start <= ip.
            uint32_t low = 0;
            uint32_t high = rangeCount_;

            while (low < high)
            {
                const uint32_t mid = low + (high - low) / 2;

                if (readU32(ranges_ + static_cast<size_t>(mid) * 8) <= ip)
                    low = mid + 1;
                else
                    high = mid;
            }

            if (low == 0)
                return info;

            const uint32_t ownerIndex =
                readU32(ranges_ + static_cast<size_t>(low - 1) * 8 + 4);

            if (ownerIndex == 0xFFFFFFFFu || ownerIndex >= ownerCount_)
                return info;

            const unsigned char* owner = owners_ + static_cast<size_t>(ownerIndex) * 12;

            const uint32_t asn = readU32(owner);
            const uint32_t nameOffset = readU32(owner + 4);
            const uint16_t nameLength =
                static_cast<uint16_t>(owner[8] | (owner[9] << 8));

            if (static_cast<uint64_t>(nameOffset) + nameLength > namesBytes_)
                return info;

            info.found = true;
            info.org.assign(reinterpret_cast<const char*>(names_ + nameOffset), nameLength);
            info.asn = "AS" + std::to_string(asn);

            const char country[2] = {
                static_cast<char>(owner[10]),
                static_cast<char>(owner[11])
            };

            if (country[0] != '-' && country[0] != ' ' && country[0] != '\0')
                info.country.assign(country, 2);

            info.category = "Network owner " + info.asn +
                (info.country.empty() ? "" : " (" + info.country + ")");

            return info;
        }

    private:
        AsnDatabase()
        {
#if defined(_WIN32)
            if (tryResource())
                return;
#endif
            const std::string overridePath = readEnvironmentVariable("NETWOLF_ASN_DB");

            if (!overridePath.empty() && tryFile(overridePath))
                return;

            if (tryFile("resources/ip2asn.bin"))
                return;

            tryFile("ip2asn.bin");
        }

#if defined(_WIN32)
        bool tryResource()
        {
            HRSRC resource = FindResourceW(
                nullptr,
                MAKEINTRESOURCEW(kNetWolfAsnResourceId),
                MAKEINTRESOURCEW(10)    // RT_RCDATA (wide form: the project does not define UNICODE)
            );

            if (!resource)
                return false;

            HGLOBAL handle = LoadResource(nullptr, resource);

            if (!handle)
                return false;

            const void* data = LockResource(handle);
            const DWORD size = SizeofResource(nullptr, resource);

            // Resource memory stays valid for the life of the process.
            return data != nullptr &&
                attach(static_cast<const unsigned char*>(data), size, "embedded resource");
        }
#endif

        bool tryFile(const std::string& path)
        {
            std::ifstream in(path, std::ios::binary);

            if (!in)
                return false;

            std::vector<unsigned char> bytes(
                (std::istreambuf_iterator<char>(in)),
                std::istreambuf_iterator<char>()
            );

            if (bytes.empty())
                return false;

            owned_ = std::move(bytes);

            if (!attach(owned_.data(), owned_.size(), path))
            {
                owned_.clear();
                return false;
            }

            return true;
        }

        bool attach(const unsigned char* data, size_t size, const std::string& source)
        {
            if (data == nullptr || size < 24 || std::memcmp(data, "NWASN1", 6) != 0)
                return false;

            const uint32_t rangeCount = readU32(data + 8);
            const uint32_t ownerCount = readU32(data + 12);
            const uint32_t namesBytes = readU32(data + 16);

            const uint64_t needed =
                24ull + 8ull * rangeCount + 12ull * ownerCount + namesBytes;

            if (needed > size || rangeCount == 0)
                return false;

            ranges_ = data + 24;
            owners_ = ranges_ + 8ull * rangeCount;
            names_ = owners_ + 12ull * ownerCount;

            rangeCount_ = rangeCount;
            ownerCount_ = ownerCount;
            namesBytes_ = namesBytes;
            source_ = source;

            return true;
        }

        static uint32_t readU32(const unsigned char* p)
        {
            return static_cast<uint32_t>(p[0]) |
                (static_cast<uint32_t>(p[1]) << 8) |
                (static_cast<uint32_t>(p[2]) << 16) |
                (static_cast<uint32_t>(p[3]) << 24);
        }

    private:
        std::vector<unsigned char> owned_;

        const unsigned char* ranges_ = nullptr;
        const unsigned char* owners_ = nullptr;
        const unsigned char* names_ = nullptr;

        uint32_t rangeCount_ = 0;
        uint32_t ownerCount_ = 0;
        uint32_t namesBytes_ = 0;

        std::string source_ = "not loaded";
    };


    class AsnResolver
    {
    public:
        // Look up a dotted IPv4 string, e.g. "157.240.1.35".
        AsnInfo lookup(const std::string& ipv4) const
        {
            uint32_t ip = 0;

            if (!parseIpv4(ipv4, ip))
                return AsnInfo{};

            return lookup(ip);
        }

        // Look up a 32-bit host-order IPv4 address.
        AsnInfo lookup(uint32_t ip) const
        {
            if (isPrivateOrReserved(ip))
                return AsnInfo{};

            return AsnDatabase::instance().lookup(ip);
        }

        bool databaseLoaded() const
        {
            return AsnDatabase::instance().loaded();
        }

        static bool parseIpv4(const std::string& ip, uint32_t& out)
        {
            uint32_t parts[4] = { 0, 0, 0, 0 };
            int partIndex = 0;
            int digits = 0;
            uint32_t value = 0;

            for (char c : ip)
            {
                if (c >= '0' && c <= '9')
                {
                    value = value * 10 + static_cast<uint32_t>(c - '0');

                    if (value > 255 || ++digits > 3)
                        return false;
                }
                else if (c == '.')
                {
                    if (digits == 0 || partIndex >= 3)
                        return false;

                    parts[partIndex++] = value;
                    value = 0;
                    digits = 0;
                }
                else
                {
                    return false; // not a plain IPv4 (IPv6, hostname...)
                }
            }

            if (digits == 0 || partIndex != 3)
                return false;

            parts[3] = value;

            out = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
            return true;
        }

    private:
        // RFC private / special-use ranges never have a public owner.
        static bool isPrivateOrReserved(uint32_t ip)
        {
            const uint32_t a = ip >> 24;
            const uint32_t b = (ip >> 16) & 0xFF;

            return a == 0 || a == 10 || a == 127 || a >= 224 ||
                (a == 100 && b >= 64 && b <= 127) ||
                (a == 169 && b == 254) ||
                (a == 172 && b >= 16 && b <= 31) ||
                (a == 192 && b == 168);
        }
    };

} // namespace netwolf::core
