// ================================================================
// NetWolf v2 - Evaluation program (NetWolfV2Eval)
//
// Turns the experiment logs into the numbers of the paper:
//
//   1. Real experiments: detection delay, alerts, false alarms per
//      device-hour, crowd and collapse statistics (Table 4).
//   2. Trace-driven controlled evaluation: hundreds of scenarios built
//      from the REAL per-device traces of the experiments (crowds of
//      3..30 devices, Evil Twin relays and hard benign cases). Every
//      scenario is replayed through NetWolf's OWN decision code
//      (LiveConnectionTracker::evaluateEvilTwin) and through five
//      baselines: TPR, FPR, precision, F1, AUC, delay (Table 5, Fig. 5a).
//   3. Sensitivity of the result to alpha, rho, W_c and the flow idle
//      time (Fig. 5b), and the calibration statistics used to justify
//      the thresholds.
//
// Usage (PowerShell, in the project folder):
//   .\build-x64\bin\NetWolfV2Eval.exe "D:\NetWolf Experiments"
//   options: --out <folder> --scale <0.2..5> --seed <n> --no-sensitivity
//
// Input: a folder that contains the experiment folders (Exp-01, ...).
// Each experiment folder holds data\devices.csv, data\summary.csv,
// data\events.csv (written by NetWolf v2) and experiment.txt:
//
//   type = attack            (or: normal)
//   relay = D4               (attack only: alias of the Evil Twin device)
//   attack_start = 2026-11-21 16:05:00
//   last_victim_moved = 2026-11-21 16:07:10
//   exclude = D7             (optional: devices to leave out)
//
// Everything is deterministic: the same data and seed give the same
// numbers on every computer.
// ================================================================

#if defined(_WIN32) && !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <netwolf/live/live_connection_tracker.hpp>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

namespace ev {

    constexpr double kNaN = std::numeric_limits<double>::quiet_NaN();
    constexpr double kNever = 1e18;

    // ------------------------------------------------------------ random
    // Own generator and distributions: identical results on MSVC and GCC.
    struct Rng
    {
        uint64_t state;

        explicit Rng(uint64_t seed) : state(seed * 0x9E3779B97F4A7C15ull + 0x1234567ull) {}

        uint64_t next()
        {
            uint64_t z = (state += 0x9E3779B97F4A7C15ull);
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
            return z ^ (z >> 31);
        }

        double uni() { return static_cast<double>(next() >> 11) * (1.0 / 9007199254740992.0); }
        double uni(double a, double b) { return a + (b - a) * uni(); }
        int below(int n) { return n <= 0 ? 0 : static_cast<int>(uni() * n) % n; }
        double expo(double mean) { return -mean * std::log(1.0 - uni()); }
    };

    // ------------------------------------------------------------ text helpers
    std::string trim(const std::string& s)
    {
        const size_t a = s.find_first_not_of(" \t\r\n");
        if (a == std::string::npos) return std::string();
        const size_t b = s.find_last_not_of(" \t\r\n");
        return s.substr(a, b - a + 1);
    }

    std::string lower(std::string s)
    {
        for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return s;
    }

    std::vector<std::string> splitCsv(const std::string& line)
    {
        std::vector<std::string> out;
        std::string cur;
        bool quoted = false;

        for (size_t i = 0; i < line.size(); ++i)
        {
            const char c = line[i];

            if (quoted)
            {
                if (c == '"' && i + 1 < line.size() && line[i + 1] == '"') { cur += '"'; ++i; }
                else if (c == '"') quoted = false;
                else cur += c;
            }
            else if (c == '"') quoted = true;
            else if (c == ',') { out.push_back(cur); cur.clear(); }
            else if (c != '\r' && c != '\n') cur += c;
        }

        out.push_back(cur);
        return out;
    }

    struct CsvTable
    {
        std::map<std::string, size_t> column;
        std::vector<std::vector<std::string>> rows;

        std::string get(const std::vector<std::string>& row, const std::string& name) const
        {
            const auto it = column.find(name);
            if (it == column.end() || it->second >= row.size()) return std::string();
            return row[it->second];
        }

        bool has(const std::string& name) const { return column.count(name) != 0; }
    };

    bool readCsv(const fs::path& file, CsvTable& table)
    {
        std::ifstream in(file, std::ios::binary);
        if (!in) return false;

        std::string line;
        if (!std::getline(in, line)) return false;

        if (line.size() >= 3 && static_cast<unsigned char>(line[0]) == 0xEF) line = line.substr(3);

        const auto header = splitCsv(line);
        for (size_t i = 0; i < header.size(); ++i) table.column[trim(header[i])] = i;

        while (std::getline(in, line))
        {
            if (trim(line).empty()) continue;
            table.rows.push_back(splitCsv(line));
        }

        return true;
    }

    // "YYYY-MM-DD HH:MM:SS(.mmm)" -> seconds (local clock, consistent between files)
    bool parseTime(const std::string& text, double& out)
    {
        int y = 0, mo = 0, d = 0, h = 0, mi = 0;
        double s = 0.0;

        const std::string t = trim(text);
        if (std::sscanf(t.c_str(), "%d-%d-%d %d:%d:%lf", &y, &mo, &d, &h, &mi, &s) < 5) return false;

        // days from civil (Howard Hinnant)
        y -= mo <= 2 ? 1 : 0;
        const long era = (y >= 0 ? y : y - 399) / 400;
        const long yoe = static_cast<long>(y - era * 400);
        const long doy = (153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5 + d - 1;
        const long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        const long days = era * 146097 + doe - 719468;

        out = static_cast<double>(days) * 86400.0 + h * 3600.0 + mi * 60.0 + s;
        return true;
    }

    std::string family(const std::string& type)
    {
        const std::string t = lower(type);
        if (t.find("windows") != std::string::npos) return "Windows";
        if (t.find("apple") != std::string::npos || t.find("ios") != std::string::npos ||
            t.find("mac") != std::string::npos || t.find("iphone") != std::string::npos) return "Apple";
        if (t.find("android") != std::string::npos || t.find("linux") != std::string::npos) return "Android/Linux";
        return std::string();
    }

    std::string fmt(double v, int digits = 3)
    {
        if (std::isnan(v)) return "";
        std::ostringstream o;
        o << std::fixed << std::setprecision(digits) << v;
        return o.str();
    }

    double median(std::vector<double> v)
    {
        v.erase(std::remove_if(v.begin(), v.end(), [](double x) { return std::isnan(x); }), v.end());
        if (v.empty()) return kNaN;
        std::sort(v.begin(), v.end());
        const size_t m = v.size() / 2;
        return v.size() % 2 ? v[m] : 0.5 * (v[m - 1] + v[m]);
    }

    double quantile(std::vector<double> v, double q)
    {
        v.erase(std::remove_if(v.begin(), v.end(), [](double x) { return std::isnan(x); }), v.end());
        if (v.empty()) return kNaN;
        std::sort(v.begin(), v.end());
        const double pos = q * (v.size() - 1);
        const size_t i = static_cast<size_t>(pos);
        const double f = pos - i;
        return i + 1 < v.size() ? v[i] * (1 - f) + v[i + 1] * f : v[i];
    }

    std::string htmlEscape(const std::string& s)
    {
        std::string o;
        for (char c : s)
        {
            if (c == '&') o += "&amp;";
            else if (c == '<') o += "&lt;";
            else if (c == '>') o += "&gt;";
            else o += c;
        }
        return o;
    }

    // ------------------------------------------------------------ destination names
    struct Names
    {
        std::map<std::string, int> id;
        std::vector<std::string> name;

        int get(const std::string& s)
        {
            const auto it = id.find(s);
            if (it != id.end()) return it->second;
            const int k = static_cast<int>(name.size());
            id[s] = k;
            name.push_back(s);
            return k;
        }
    };

    Names g_names;

    // ------------------------------------------------------------ one device snapshot
    struct Snap
    {
        int conns = 0;
        std::vector<std::pair<int, int>> dests;   // name id, connections
        bool fwd = false;
        int syns = 0;                              // cumulative forwarded connection starts
        std::vector<std::string> behind;
        double people = 0.0;
        std::string state;
    };

    // "a.com (3); b.net (2)"
    std::vector<std::pair<int, int>> parseDestinations(const std::string& text)
    {
        std::vector<std::pair<int, int>> out;
        size_t start = 0;

        while (start < text.size())
        {
            size_t end = text.find("; ", start);
            if (end == std::string::npos) end = text.size();

            std::string item = trim(text.substr(start, end - start));
            int count = 1;

            const size_t open = item.rfind(" (");
            if (open != std::string::npos && !item.empty() && item.back() == ')')
            {
                count = std::max(1, std::atoi(item.substr(open + 2).c_str()));
                item = item.substr(0, open);
            }

            if (!item.empty()) out.emplace_back(g_names.get(item), count);
            start = end + 2;
        }

        return out;
    }

    // ------------------------------------------------------------ experiments
    struct Label
    {
        bool present = false;
        std::string type;        // attack / normal
        std::string relay;
        double attackStart = kNaN;
        double lastMoved = kNaN;
        std::set<std::string> exclude;
    };

    struct DeviceRows
    {
        std::string type;
        std::vector<std::pair<double, Snap>> rows;   // time, snapshot
        double firstRedflag = kNaN;
        double peopleAtAlert = kNaN;
    };

    struct Experiment
    {
        fs::path folder;
        std::string name;
        Label label;
        std::map<std::string, DeviceRows> devices;
        double tStart = kNaN;
        double tEnd = kNaN;
        size_t crowdPeak = 0;
        size_t collapses = 0;
        size_t rows = 0;
        bool hasAllDestinations = false;
        bool derivedAttackStart = false;
        bool derivedLastMoved = false;
    };

    Label readLabel(const fs::path& folder)
    {
        Label label;

        for (const fs::path& candidate : { folder / "experiment.txt", folder / "data" / "experiment.txt" })
        {
            std::ifstream in(candidate);
            if (!in) continue;

            label.present = true;
            std::string line;

            while (std::getline(in, line))
            {
                const size_t hash = line.find('#');
                if (hash != std::string::npos) line = line.substr(0, hash);

                const size_t eq = line.find('=');
                if (eq == std::string::npos) continue;

                const std::string key = lower(trim(line.substr(0, eq)));
                const std::string value = trim(line.substr(eq + 1));

                if (key == "type") label.type = lower(value);
                else if (key == "relay") label.relay = value;
                else if (key == "attack_start") parseTime(value, label.attackStart);
                else if (key == "last_victim_moved") parseTime(value, label.lastMoved);
                else if (key == "exclude")
                {
                    std::stringstream ss(value);
                    std::string item;
                    while (std::getline(ss, item, ',')) if (!trim(item).empty()) label.exclude.insert(trim(item));
                }
            }

            break;
        }

        return label;
    }

    bool loadExperiment(const fs::path& devicesCsv, Experiment& exp, std::string& warning)
    {
        const fs::path dataFolder = devicesCsv.parent_path();
        exp.folder = lower(dataFolder.filename().u8string()) == "data" ? dataFolder.parent_path() : dataFolder;
        exp.name = exp.folder.filename().u8string();
        exp.label = readLabel(exp.folder);

        CsvTable devices;
        if (!readCsv(devicesCsv, devices)) { warning = "cannot read " + devicesCsv.u8string(); return false; }

        exp.hasAllDestinations = devices.has("all_destinations");

        for (const auto& row : devices.rows)
        {
            double t = 0.0;
            if (!parseTime(devices.get(row, "time"), t)) continue;

            const std::string alias = devices.get(row, "device");
            if (alias.empty()) continue;

            DeviceRows& dev = exp.devices[alias];
            if (dev.type.empty()) dev.type = devices.get(row, "type");

            Snap s;
            s.conns = std::atoi(devices.get(row, "connections").c_str());
            s.dests = parseDestinations(exp.hasAllDestinations
                ? devices.get(row, "all_destinations") : devices.get(row, "top_destinations"));
            s.fwd = devices.get(row, "forwarding") == "yes";
            s.syns = std::atoi(devices.get(row, "forwarded_connections").c_str());
            s.people = std::atof(devices.get(row, "estimated_people").c_str());
            s.state = devices.get(row, "state");

            const std::string behind = devices.get(row, "systems_behind");
            std::stringstream ss(behind);
            std::string item;
            while (std::getline(ss, item, '+')) if (!trim(item).empty()) s.behind.push_back(trim(item));

            if (s.state == "Redflag" && std::isnan(dev.firstRedflag))
            {
                dev.firstRedflag = t;
                dev.peopleAtAlert = s.people;
            }

            if (s.conns <= 0) continue;

            if (std::isnan(exp.tStart) || t < exp.tStart) exp.tStart = t;
            if (std::isnan(exp.tEnd) || t > exp.tEnd) exp.tEnd = t;

            dev.rows.emplace_back(t, std::move(s));
            ++exp.rows;
        }

        CsvTable summary;
        if (readCsv(dataFolder / "summary.csv", summary))
        {
            for (const auto& row : summary.rows)
                exp.crowdPeak = std::max<size_t>(exp.crowdPeak, std::atoi(summary.get(row, "crowd_peak").c_str()));
        }

        CsvTable events;
        std::vector<std::pair<double, std::string>> forwardingOfRelay;   // time
        std::vector<std::pair<double, std::string>> departures;          // time, alias
        if (readCsv(dataFolder / "events.csv", events))
        {
            for (const auto& row : events.rows)
            {
                const std::string details = events.get(row, "details");
                const std::string event = events.get(row, "event");
                if (details.rfind("COLLAPSE:", 0) == 0) ++exp.collapses;

                double t = 0.0;
                if (!parseTime(events.get(row, "time"), t)) continue;
                const std::string alias = details.substr(0, details.find(' '));

                if (event == "forwarding_detected" && alias == exp.label.relay) forwardingOfRelay.emplace_back(t, alias);
                if (event == "device_left") departures.emplace_back(t, alias);
            }
        }

        // Attack times not written in experiment.txt are taken from the log:
        //   attack start      = the relay's first forwarding after its alert-free period
        //                       (the last "forwarding_detected" before the alert, or the first one)
        //   last victim moved = the latest departure of another device around the
        //                       attack minus the flow idle time (45 s), i.e. the last
        //                       packet that victim sent to the legitimate access point.
        if (exp.label.type == "attack" && !exp.label.relay.empty())
        {
            double alert = kNaN;
            const auto relayRows = exp.devices.find(exp.label.relay);
            if (relayRows != exp.devices.end()) alert = relayRows->second.firstRedflag;

            if (std::isnan(exp.label.attackStart) && !forwardingOfRelay.empty())
            {
                double chosen = forwardingOfRelay.front().first;
                for (const auto& f : forwardingOfRelay)
                    if (std::isnan(alert) || f.first <= alert) chosen = f.first;
                exp.label.attackStart = chosen;
                exp.derivedAttackStart = true;
            }

            if (std::isnan(exp.label.lastMoved) && !std::isnan(exp.label.attackStart))
            {
                double latest = kNaN;
                for (const auto& [t, alias] : departures)
                {
                    if (alias == exp.label.relay) continue;
                    if (t < exp.label.attackStart - 60.0 || t > exp.label.attackStart + 300.0) continue;
                    if (!std::isnan(alert) && t > alert + 5.0) continue;
                    latest = std::isnan(latest) ? t : std::max(latest, t);
                }
                if (!std::isnan(latest))
                {
                    exp.label.lastMoved = latest - 45.0;
                    exp.derivedLastMoved = true;
                }
            }
        }

        if (exp.rows == 0) { warning = "no device rows in " + devicesCsv.u8string(); return false; }
        return true;
    }

    // ------------------------------------------------------------ traces
    struct Trace
    {
        std::string source;
        std::string type;
        std::string fam;
        int span = 0;
        std::vector<int> at;       // second -> snapshot index or -1
        std::vector<Snap> snaps;
        double meanConns = 0.0;

        const Snap* get(long t) const
        {
            if (span <= 0) return nullptr;
            long k = t % span;
            if (k < 0) k += span;
            const int i = at[static_cast<size_t>(k)];
            return i < 0 ? nullptr : &snaps[static_cast<size_t>(i)];
        }
    };

    Trace makeTrace(const std::string& source, const std::string& type,
        const std::vector<std::pair<double, Snap>>& rows, size_t from, size_t to)
    {
        Trace tr;
        tr.source = source;
        tr.type = type;
        tr.fam = family(type);

        const double t0 = rows[from].first;
        tr.span = static_cast<int>(std::lround(rows[to - 1].first - t0)) + 1;
        tr.at.assign(static_cast<size_t>(tr.span), -1);

        double sum = 0.0;

        for (size_t i = from; i < to; ++i)
        {
            const long k = std::lround(rows[i].first - t0);
            if (k < 0 || k >= tr.span) continue;
            tr.at[static_cast<size_t>(k)] = static_cast<int>(tr.snaps.size());
            tr.snaps.push_back(rows[i].second);
            sum += rows[i].second.conns;
        }

        // Snapshot syns are cumulative in the log; keep per-trace increments only.
        int base = tr.snaps.empty() ? 0 : tr.snaps.front().syns;
        for (auto& s : tr.snaps) { const int v = s.syns; s.syns = std::max(0, v - base); }

        tr.meanConns = tr.snaps.empty() ? 0.0 : sum / static_cast<double>(tr.span);
        return tr;
    }

    // ------------------------------------------------------------ isolation forest (baseline B5)
    struct IsolationForest
    {
        struct Node { int feature = -1; double split = 0.0; int left = -1, right = -1; int size = 0; };
        std::vector<std::vector<Node>> trees;
        int psi = 256;

        static double c(double n)
        {
            if (n <= 1.0) return 0.0;
            if (n <= 2.0) return 1.0;
            return 2.0 * (std::log(n - 1.0) + 0.5772156649) - 2.0 * (n - 1.0) / n;
        }

        int build(std::vector<Node>& tree, std::vector<const std::vector<double>*>& data, size_t a, size_t b,
            int depth, int maxDepth, Rng& rng)
        {
            const int index = static_cast<int>(tree.size());
            tree.push_back(Node{});
            tree[index].size = static_cast<int>(b - a);

            if (depth >= maxDepth || b - a <= 1) return index;

            const int dims = static_cast<int>(data[a]->size());
            for (int attempt = 0; attempt < dims * 2; ++attempt)
            {
                const int f = rng.below(dims);
                double lo = (*data[a])[f], hi = lo;
                for (size_t i = a; i < b; ++i) { lo = std::min(lo, (*data[i])[f]); hi = std::max(hi, (*data[i])[f]); }
                if (hi <= lo) continue;

                const double split = rng.uni(lo, hi);
                const auto mid = std::partition(data.begin() + static_cast<long>(a), data.begin() + static_cast<long>(b),
                    [&](const std::vector<double>* x) { return (*x)[f] < split; });
                const size_t m = static_cast<size_t>(mid - data.begin());

                tree[index].feature = f;
                tree[index].split = split;
                const int l = build(tree, data, a, m, depth + 1, maxDepth, rng);
                const int r = build(tree, data, m, b, depth + 1, maxDepth, rng);
                tree[index].left = l;
                tree[index].right = r;
                return index;
            }

            return index;
        }

        void fit(const std::vector<std::vector<double>>& samples, Rng& rng, int count = 100)
        {
            trees.clear();
            if (samples.empty()) return;
            psi = static_cast<int>(std::min<size_t>(256, samples.size()));
            const int maxDepth = static_cast<int>(std::ceil(std::log2(std::max(2, psi))));

            for (int t = 0; t < count; ++t)
            {
                std::vector<const std::vector<double>*> sub;
                for (int i = 0; i < psi; ++i) sub.push_back(&samples[static_cast<size_t>(rng.below(static_cast<int>(samples.size())))]);
                std::vector<Node> tree;
                build(tree, sub, 0, sub.size(), 0, maxDepth, rng);
                trees.push_back(std::move(tree));
            }
        }

        double score(const std::vector<double>& x) const
        {
            if (trees.empty()) return 0.0;
            double total = 0.0;

            for (const auto& tree : trees)
            {
                int node = 0;
                int depth = 0;
                while (tree[static_cast<size_t>(node)].feature >= 0)
                {
                    const Node& n = tree[static_cast<size_t>(node)];
                    node = x[static_cast<size_t>(n.feature)] < n.split ? n.left : n.right;
                    ++depth;
                }
                total += depth + c(tree[static_cast<size_t>(node)].size);
            }

            return std::pow(2.0, -(total / trees.size()) / c(psi));
        }
    };

    std::vector<double> features(int conns, size_t dests, int gmax, int syns, size_t behind)
    {
        return { std::log1p(static_cast<double>(conns)), std::log1p(static_cast<double>(dests)),
                 std::log1p(static_cast<double>(gmax)), std::log1p(static_cast<double>(syns)),
                 static_cast<double>(behind) };
    }

    // ------------------------------------------------------------ scenarios
    enum class Kind { PosMember, PosNew, PosMemberTtl, PosNewTtl, NegChurn, NegDeparture, NegHeavy, NegTether, NegTunnel };

    const char* kindName(Kind k)
    {
        switch (k)
        {
        case Kind::PosMember: return "attack_relay_in_crowd";
        case Kind::PosNew: return "attack_relay_new_device";
        case Kind::PosMemberTtl: return "attack_ttl_normalized_in_crowd";
        case Kind::PosNewTtl: return "attack_ttl_normalized_new_device";
        case Kind::NegChurn: return "benign_natural_churn";
        case Kind::NegDeparture: return "benign_mass_departure";
        case Kind::NegHeavy: return "benign_heavy_user_remains";
        case Kind::NegTether: return "benign_tethering_remains";
        case Kind::NegTunnel: return "benign_tunnel_device_remains";
        }
        return "?";
    }

    bool isPositive(Kind k) { return k == Kind::PosMember || k == Kind::PosNew || k == Kind::PosMemberTtl || k == Kind::PosNewTtl; }
    bool isTtlNormalized(Kind k) { return k == Kind::PosMemberTtl || k == Kind::PosNewTtl; }

    struct Actor
    {
        int trace = -1;
        long offset = 0;
        double join = 0.0;
        double leave = kNever;      // own presence ends (includes flow idle linger)
        int role = 0;               // 0 normal, 1 relay, 2 tether, 3 tunnel
        int companion = -1;         // tether: the device behind it
        long companionOffset = 0;
        double migrate = -1.0;      // victim: time it moves to the relay
        double reconnect = 0.0;
        int tunnelSyns = 0;
    };

    struct Scenario
    {
        int id = 0;
        Kind kind = Kind::NegChurn;
        int n = 0;
        bool positive = false;
        bool ttlNormalized = false;
        int relay = -1;
        double t0 = 0.0;
        double tLast = kNaN;
        double end = 0.0;
        double churnMean = kNaN;
        std::vector<Actor> actors;
    };

    struct GenSettings
    {
        double idleSeconds = 45.0;   // hotspot flow idle time (vanish delay)
        double maxMigration = 120.0; // victims move within [0, maxMigration] s
    };

    struct Pool
    {
        std::vector<Trace> traces;
        std::vector<int> windowsTraces;
        std::vector<int> byHeaviness;     // indices, heaviest first
    };

    struct ScenarioFactory
    {
        const Pool& pool;
        GenSettings gen;

        int pick(Rng& rng) const { return rng.below(static_cast<int>(pool.traces.size())); }

        Actor crowdActor(Rng& rng) const
        {
            Actor a;
            a.trace = pick(rng);
            a.offset = static_cast<long>(rng.uni() * pool.traces[static_cast<size_t>(a.trace)].span);
            a.join = rng.uni(0.0, 30.0);
            return a;
        }

        double linger(Rng& rng) const { return rng.uni(std::max(1.0, gen.idleSeconds - 15.0), gen.idleSeconds); }

        Scenario make(Kind kind, int n, int id, Rng& rng) const
        {
            Scenario sc;
            sc.id = id;
            sc.kind = kind;
            sc.n = n;
            sc.positive = isPositive(kind);
            sc.ttlNormalized = isTtlNormalized(kind);
            sc.t0 = rng.uni(300.0, 600.0);

            const double migration = rng.uni(10.0, gen.maxMigration);
            sc.end = sc.t0 + migration + gen.idleSeconds + 300.0;

            for (int i = 0; i < n; ++i) sc.actors.push_back(crowdActor(rng));

            auto leaveAll = [&](int keep)
                {
                    for (int i = 0; i < n; ++i)
                    {
                        if (i == keep) continue;
                        sc.actors[static_cast<size_t>(i)].leave = sc.t0 + rng.uni(0.0, migration) + linger(rng);
                    }
                };

            switch (kind)
            {
            case Kind::PosMember:
            case Kind::PosMemberTtl:
            case Kind::PosNew:
            case Kind::PosNewTtl:
            {
                const bool member = kind == Kind::PosMember || kind == Kind::PosMemberTtl;

                if (member)
                {
                    sc.relay = rng.below(n);
                }
                else
                {
                    Actor attacker = crowdActor(rng);
                    attacker.join = sc.t0 - rng.uni(0.0, 60.0);
                    sc.actors.push_back(attacker);
                    sc.relay = n;
                }

                sc.actors[static_cast<size_t>(sc.relay)].role = 1;
                sc.tLast = sc.t0;

                for (int i = 0; i < n; ++i)
                {
                    if (i == sc.relay) continue;
                    Actor& v = sc.actors[static_cast<size_t>(i)];
                    v.migrate = sc.t0 + rng.uni(0.0, migration);
                    v.reconnect = rng.uni(2.0, 20.0);
                    v.leave = v.migrate + linger(rng);
                    sc.tLast = std::max(sc.tLast, v.migrate);
                }
                break;
            }

            case Kind::NegChurn:
            {
                const double means[] = { 20.0, 45.0, 90.0 };
                sc.churnMean = means[rng.below(3)] * 60.0;
                sc.end = sc.t0 + 900.0;

                for (auto& a : sc.actors) a.leave = a.join + rng.expo(sc.churnMean) + linger(rng);

                // Poisson arrivals keep the mean crowd size.
                const double rate = n / sc.churnMean;
                double t = rng.expo(1.0 / rate);
                while (t < sc.end)
                {
                    Actor a = crowdActor(rng);
                    a.join = t;
                    a.leave = t + rng.expo(sc.churnMean) + linger(rng);
                    sc.actors.push_back(a);
                    t += rng.expo(1.0 / rate);
                }
                break;
            }

            case Kind::NegDeparture:
            {
                const double share = rng.uni(0.8, 1.0);
                const int leaving = std::min(n, static_cast<int>(std::ceil(share * n)));
                std::vector<int> order(static_cast<size_t>(n));
                for (int i = 0; i < n; ++i) order[static_cast<size_t>(i)] = i;
                for (int i = n - 1; i > 0; --i) std::swap(order[static_cast<size_t>(i)], order[static_cast<size_t>(rng.below(i + 1))]);
                for (int k = 0; k < leaving; ++k)
                    sc.actors[static_cast<size_t>(order[static_cast<size_t>(k)])].leave = sc.t0 + rng.uni(0.0, migration) + linger(rng);
                break;
            }

            case Kind::NegHeavy:
            {
                // The remaining device is one of the heaviest real traces.
                const size_t top = std::max<size_t>(1, pool.byHeaviness.size() / 4);
                sc.actors[0].trace = pool.byHeaviness[static_cast<size_t>(rng.below(static_cast<int>(top)))];
                sc.actors[0].offset = static_cast<long>(rng.uni() * pool.traces[static_cast<size_t>(sc.actors[0].trace)].span);
                leaveAll(0);
                break;
            }

            case Kind::NegTether:
            {
                Actor& phone = sc.actors[0];
                phone.role = 2;
                phone.companion = pool.windowsTraces.empty()
                    ? pick(rng) : pool.windowsTraces[static_cast<size_t>(rng.below(static_cast<int>(pool.windowsTraces.size())))];
                phone.companionOffset = static_cast<long>(rng.uni() * pool.traces[static_cast<size_t>(phone.companion)].span);
                leaveAll(0);
                break;
            }

            case Kind::NegTunnel:
            {
                sc.actors[0].role = 3;
                sc.actors[0].tunnelSyns = 2 + rng.below(9);
                leaveAll(0);
                break;
            }
            }

            return sc;
        }
    };

    // ------------------------------------------------------------ per-step profile
    struct Profile
    {
        std::string id;
        int actor = -1;
        std::string type;
        int conns = 0;
        std::map<int, int> dests;
        bool fwd = false;
        int syns = 0;
        std::set<std::string> behind;
        std::map<std::string, int> fwdBy;      // OS family -> forwarded connection starts

        int gmax() const { int g = 0; for (const auto& d : dests) g = std::max(g, d.second); return g; }
    };

    void addSnap(Profile& p, const Snap& s)
    {
        p.conns += s.conns;
        for (const auto& d : s.dests) p.dests[d.first] += d.second;
    }

    struct ScenarioState
    {
        std::map<int, int> lastConns;      // victim/companion -> conns at previous step
        std::map<int, bool> contributed;
        int relaySyns = 0;
        int tetherSyns = 0;
        std::set<std::string> relayBehind;
        std::map<std::string, int> relayBy;
        std::map<size_t, int> ownSynsBase;  // actor -> forwarded starts already counted when it appeared
        std::map<size_t, int> ownSynsLast;
    };

    std::vector<Profile> profilesAt(const Scenario& sc, const Pool& pool, double t, ScenarioState& st)
    {
        std::vector<Profile> out;
        const long sec = static_cast<long>(std::floor(t));

        auto ownSnap = [&](const Actor& a) -> const Snap*
            {
                if (t < a.join || t >= a.leave) return nullptr;
                return pool.traces[static_cast<size_t>(a.trace)].get(a.offset + sec);
            };

        for (size_t i = 0; i < sc.actors.size(); ++i)
        {
            const Actor& a = sc.actors[i];
            const Trace& tr = pool.traces[static_cast<size_t>(a.trace)];

            Profile p;
            p.id = "S" + std::to_string(i + 1);
            p.actor = static_cast<int>(i);
            p.type = tr.type;

            const Snap* own = ownSnap(a);

            if (own != nullptr)
            {
                addSnap(p, *own);

                // The tool counts forwarded connection starts from the moment
                // it first sees a device: rebase the trace's counter at the
                // actor's first appearance (and when the trace wraps around).
                auto base = st.ownSynsBase.find(i);
                auto last = st.ownSynsLast.find(i);
                if (base == st.ownSynsBase.end() || (last != st.ownSynsLast.end() && own->syns < last->second))
                {
                    const int carried = base == st.ownSynsBase.end() ? 0 : (last->second - base->second);
                    st.ownSynsBase[i] = own->syns - carried;
                }
                st.ownSynsLast[i] = own->syns;

                const int ownSyns = std::max(0, own->syns - st.ownSynsBase[i]);
                p.fwd = own->fwd && ownSyns > 0;
                p.syns = ownSyns;
                for (const auto& b : own->behind) { p.behind.insert(b); p.fwdBy[b] = std::max(p.fwdBy[b], ownSyns); }
            }

            if (a.role == 1)
            {
                for (size_t v = 0; v < sc.actors.size(); ++v)
                {
                    const Actor& victim = sc.actors[v];
                    if (victim.migrate < 0.0 || t < victim.migrate + victim.reconnect) continue;

                    const Snap* s = pool.traces[static_cast<size_t>(victim.trace)].get(victim.offset + sec);
                    const int now = s != nullptr ? s->conns : 0;
                    const int before = st.lastConns.count(static_cast<int>(v)) ? st.lastConns[static_cast<int>(v)] : 0;

                    if (s != nullptr)
                    {
                        addSnap(p, *s);
                        const int started = std::max(0, now - before);
                        st.relaySyns += started;
                        if (started > 0)
                        {
                            const std::string f = family(pool.traces[static_cast<size_t>(victim.trace)].type);
                            if (!f.empty()) { st.relayBehind.insert(f); st.relayBy[f] += started; }
                        }
                    }

                    st.lastConns[static_cast<int>(v)] = now;
                }

                if (!sc.ttlNormalized && st.relaySyns > 0)
                {
                    p.fwd = true;
                    p.syns += st.relaySyns;
                    for (const auto& b : st.relayBehind) p.behind.insert(b);
                    for (const auto& [f, n] : st.relayBy) p.fwdBy[f] += n;
                }
            }
            else if (a.role == 2 && own != nullptr)
            {
                const Trace& ct = pool.traces[static_cast<size_t>(a.companion)];
                const Snap* s = ct.get(a.companionOffset + sec);
                const int now = s != nullptr ? s->conns : 0;
                const int before = st.lastConns.count(-1) ? st.lastConns[-1] : 0;

                if (s != nullptr)
                {
                    addSnap(p, *s);
                    st.tetherSyns += std::max(0, now - before);
                }

                st.lastConns[-1] = now;

                if (st.tetherSyns > 0)
                {
                    p.fwd = true;
                    p.syns += st.tetherSyns;
                    if (!ct.fam.empty()) { p.behind.insert(ct.fam); p.fwdBy[ct.fam] += st.tetherSyns; }
                }
            }
            else if (a.role == 3 && own != nullptr)
            {
                // A phone with a tunnel/VPN-like service: a few forwarded
                // connection starts from the beginning, slowly growing (as
                // the S24 in the real experiments).
                const int tunnel = a.tunnelSyns + static_cast<int>((t - a.join) / 60.0);
                p.fwd = true;
                p.syns += tunnel;
                if (!tr.fam.empty()) { p.behind.insert(tr.fam); p.fwdBy[tr.fam] += tunnel; }
            }

            if (p.conns > 0) out.push_back(std::move(p));
        }

        return out;
    }

    // ------------------------------------------------------------ methods
    enum Method { NetWolf = 0, B1Connections, B2Destinations, B3Forwarding, B4Concentration, B5IsolationForest, MethodCount };

    const char* methodName(int m)
    {
        switch (m)
        {
        case NetWolf: return "NetWolf v2";
        case B1Connections: return "B1 connection count";
        case B2Destinations: return "B2 destination count";
        case B3Forwarding: return "B3 TTL forwarding only";
        case B4Concentration: return "B4 concentration ratio (previous NetWolf)";
        case B5IsolationForest: return "B5 isolation forest";
        }
        return "?";
    }

    // Running maximum of a score: (time, value) at every increase.
    struct Curve
    {
        std::vector<std::pair<double, double>> steps;

        void add(double t, double v)
        {
            if (steps.empty() || v > steps.back().second + 1e-12) steps.emplace_back(t, v);
        }

        double max() const { return steps.empty() ? 0.0 : steps.back().second; }

        double firstAtLeast(double threshold) const
        {
            for (const auto& s : steps) if (s.second + 1e-12 >= threshold) return s.first;
            return kNaN;
        }
    };

    struct Outcome
    {
        // NetWolf's own decision.
        double alertRelay = kNaN;     // first verdict on the relay
        double alertOther = kNaN;     // first verdict on any other device
        double peopleAtAlert = kNaN;
        size_t collapses = 0;

        Curve relay[MethodCount];
        Curve other[MethodCount];

        double deviceHours = 0.0;
    };

    struct NetWolfSettings
    {
        netwolf::live::LiveEvilTwinConfig evilTwin;
    };

    Outcome runScenario(const Scenario& sc, const Pool& pool, const NetWolfSettings& nw,
        const IsolationForest* forest, std::vector<double>* benignE)
    {
        Outcome out;

        netwolf::live::LiveConnectionTrackerConfig cfg;
        cfg.evilTwin = nw.evilTwin;
        netwolf::live::LiveConnectionTracker tracker(cfg);

        const auto base = std::chrono::system_clock::time_point(std::chrono::seconds(1700000000));
        ScenarioState st;


        const std::string relayId = sc.relay >= 0 ? "S" + std::to_string(sc.relay + 1) : std::string();

        for (double t = 0.0; t <= sc.end; t += 1.0)
        {
            const std::vector<Profile> profiles = profilesAt(sc, pool, t, st);

            // NetWolf: the tool's own tracker and decision code.
            std::vector<netwolf::core::ObservedConnection> seen;
            std::vector<netwolf::live::LiveDeviceProfile> input;
            std::set<std::string> activeNow;

            for (const auto& p : profiles)
            {
                netwolf::core::ObservedConnection c;
                c.deviceIp = p.id;
                c.remoteIp = "0.0.0.0";
                seen.push_back(c);

                netwolf::live::LiveDeviceProfile lp;
                lp.deviceIp = p.id;
                lp.displayName = p.id;
                lp.deviceType = p.type;
                lp.connections = static_cast<size_t>(p.conns);
                for (const auto& d : p.dests) lp.destinations.insert(g_names.name[static_cast<size_t>(d.first)]);
                lp.forwarding = p.fwd;
                lp.forwardedConnections = static_cast<size_t>(p.syns);
                lp.platformsBehind.assign(p.behind.begin(), p.behind.end());
                for (const auto& [f, n] : p.fwdBy) if (n > 0) lp.forwardedByPlatform[f] = static_cast<size_t>(n);
                input.push_back(std::move(lp));

                activeNow.insert(p.id);
            }

            tracker.update(seen, std::set<std::string>());
            const auto status = tracker.evaluateEvilTwin(input, 1,
                base + std::chrono::seconds(static_cast<long long>(t)));

            for (const auto& e : status.events) if (e.rfind("COLLAPSE:", 0) == 0) ++out.collapses;

            for (const auto& [ip, evidence] : status.verdicts)
            {
                (void)evidence;
                // Before the attack starts, any alert (even on the future relay) is false.
                if (ip == relayId && t >= sc.t0)
                {
                    if (std::isnan(out.alertRelay))
                    {
                        out.alertRelay = t;
                        const auto e = status.estimatedUsers.find(ip);
                        if (e != status.estimatedUsers.end()) out.peopleAtAlert = e->second;
                    }
                }
                else if (std::isnan(out.alertOther))
                {
                    out.alertOther = t;
                }
            }

            for (const auto& p : profiles)
            {
                const bool isRelay = sc.positive && t >= sc.t0 && p.id == relayId;

                // NetWolf continuous score: the tool's own decision statistic
                // (an alert is raised at 1.0 or more).
                const auto scoreIt = status.decisionScore.find(p.id);
                const double score = scoreIt != status.decisionScore.end() ? scoreIt->second : 0.0;

                const int gmax = p.gmax();
                const double values[MethodCount] = {
                    score,
                    static_cast<double>(p.conns),
                    static_cast<double>(p.dests.size()),
                    static_cast<double>(p.syns),
                    p.conns >= 35 ? static_cast<double>(gmax) / p.conns : 0.0,
                    forest != nullptr ? forest->score(features(p.conns, p.dests.size(), gmax, p.syns, p.behind.size())) : 0.0
                };

                for (int m = 0; m < MethodCount; ++m)
                    (isRelay ? out.relay[m] : out.other[m]).add(t, values[m]);

                if (benignE != nullptr && !sc.positive && !status.collapseActive &&
                    profiles.size() >= cfg.evilTwin.minimumCrowdDevices && static_cast<long>(t) % 5 == 0)
                {
                    const auto e = status.estimatedUsers.find(p.id);
                    if (e != status.estimatedUsers.end()) benignE->push_back(e->second);
                }

            }

            out.deviceHours += profiles.size() / 3600.0;
        }

        return out;
    }

    // ------------------------------------------------------------ metrics
    struct Metrics
    {
        size_t positives = 0, negatives = 0, tp = 0, fp = 0, wrongDevice = 0;
        double tpr = kNaN, fpr = kNaN, precision = kNaN, f1 = kNaN, auc = kNaN;
        double delayFromLastMove = kNaN, delayFromStart = kNaN, delayP90 = kNaN;
        double threshold = kNaN;
        double falseAlarmsPerDeviceHour = kNaN;
    };

    struct Decision
    {
        bool detected = false;   // positive: relay flagged
        bool flagged = false;    // any device flagged
        double time = kNaN;
    };

    Decision decide(const Scenario& sc, const Outcome& o, int method, double threshold)
    {
        Decision d;

        if (method == NetWolf && std::isnan(threshold))
        {
            d.detected = sc.positive && !std::isnan(o.alertRelay);
            d.flagged = !std::isnan(o.alertRelay) || !std::isnan(o.alertOther);
            d.time = o.alertRelay;
            return d;
        }

        const double tr = o.relay[method].firstAtLeast(threshold);
        const double to = o.other[method].firstAtLeast(threshold);
        d.detected = sc.positive && !std::isnan(tr);
        d.flagged = !std::isnan(tr) || !std::isnan(to);
        d.time = tr;
        return d;
    }

    double scenarioScore(const Scenario& sc, const Outcome& o, int method)
    {
        return sc.positive ? o.relay[method].max() : std::max(o.relay[method].max(), o.other[method].max());
    }

    double aucOf(const std::vector<double>& pos, const std::vector<double>& neg)
    {
        if (pos.empty() || neg.empty()) return kNaN;

        // Mann-Whitney U with ties counted as one half.
        std::vector<std::pair<double, int>> all;
        for (double v : pos) all.emplace_back(v, 1);
        for (double v : neg) all.emplace_back(v, 0);
        std::sort(all.begin(), all.end(), [](const auto& a, const auto& b) { return a.first < b.first; });

        double rankSumPos = 0.0;
        size_t i = 0;
        while (i < all.size())
        {
            size_t j = i;
            while (j + 1 < all.size() && all[j + 1].first == all[i].first) ++j;
            const double rank = 0.5 * (static_cast<double>(i) + static_cast<double>(j)) + 1.0;
            for (size_t k = i; k <= j; ++k) if (all[k].second) rankSumPos += rank;
            i = j + 1;
        }

        const double np = static_cast<double>(pos.size()), nn = static_cast<double>(neg.size());
        return (rankSumPos - np * (np + 1.0) / 2.0) / (np * nn);
    }

    Metrics evaluate(const std::vector<Scenario>& scs, const std::vector<Outcome>& outs, int method, double threshold,
        bool (*include)(const Scenario&))
    {
        Metrics m;
        m.threshold = threshold;
        std::vector<double> delaysLast, delaysStart, pos, neg;
        double negHours = 0.0;

        for (size_t i = 0; i < scs.size(); ++i)
        {
            const Scenario& sc = scs[i];
            if (!include(sc)) continue;
            const Decision d = decide(sc, outs[i], method, threshold);

            if (sc.positive)
            {
                ++m.positives;
                pos.push_back(scenarioScore(sc, outs[i], method));
                if (d.detected)
                {
                    ++m.tp;
                    delaysLast.push_back(d.time - sc.tLast);
                    delaysStart.push_back(d.time - sc.t0);
                }
                else if (d.flagged) ++m.wrongDevice;
            }
            else
            {
                ++m.negatives;
                neg.push_back(scenarioScore(sc, outs[i], method));
                negHours += outs[i].deviceHours;
                if (d.flagged) ++m.fp;
            }
        }

        if (m.positives) m.tpr = static_cast<double>(m.tp) / m.positives;
        if (m.negatives) m.fpr = static_cast<double>(m.fp) / m.negatives;
        if (m.tp + m.fp) m.precision = static_cast<double>(m.tp) / (m.tp + m.fp);
        if (!std::isnan(m.precision) && !std::isnan(m.tpr) && m.precision + m.tpr > 0)
            m.f1 = 2 * m.precision * m.tpr / (m.precision + m.tpr);
        else if (m.positives) m.f1 = 0.0;
        m.auc = aucOf(pos, neg);
        m.delayFromLastMove = median(delaysLast);
        m.delayFromStart = median(delaysStart);
        m.delayP90 = quantile(delaysLast, 0.9);
        if (negHours > 0) m.falseAlarmsPerDeviceHour = m.fp / negHours;
        return m;
    }

    bool includeMain(const Scenario& sc) { return !sc.ttlNormalized; }
    bool includeAll(const Scenario&) { return true; }

    // Best-F1 threshold on the calibration scenarios (baselines only).
    double calibrate(const std::vector<Scenario>& scs, const std::vector<Outcome>& outs, int method)
    {
        std::vector<double> candidates;
        for (size_t i = 0; i < scs.size(); ++i)
            if (includeMain(scs[i])) candidates.push_back(scenarioScore(scs[i], outs[i], method));
        std::sort(candidates.begin(), candidates.end());
        candidates.erase(std::unique(candidates.begin(), candidates.end()), candidates.end());

        double best = candidates.empty() ? 1.0 : candidates.back() + 1.0;
        double bestF1 = -1.0, bestFpr = 2.0;

        for (double c : candidates)
        {
            if (c <= 0.0) continue;
            const Metrics m = evaluate(scs, outs, method, c, includeMain);
            const double f1 = std::isnan(m.f1) ? 0.0 : m.f1;
            const double fpr = std::isnan(m.fpr) ? 0.0 : m.fpr;
            if (f1 > bestF1 + 1e-12 || (std::fabs(f1 - bestF1) <= 1e-12 && fpr < bestFpr))
            {
                bestF1 = f1; bestFpr = fpr; best = c;
            }
        }

        return best;
    }

    std::vector<std::pair<double, double>> rocPoints(const std::vector<Scenario>& scs, const std::vector<Outcome>& outs, int method)
    {
        std::vector<double> pos, neg;
        for (size_t i = 0; i < scs.size(); ++i)
        {
            if (!includeMain(scs[i])) continue;
            (scs[i].positive ? pos : neg).push_back(scenarioScore(scs[i], outs[i], method));
        }

        std::vector<double> th = pos;
        th.insert(th.end(), neg.begin(), neg.end());
        std::sort(th.begin(), th.end());
        th.erase(std::unique(th.begin(), th.end()), th.end());

        std::vector<std::pair<double, double>> pts;
        pts.emplace_back(1.0, 1.0);
        for (double t : th)
        {
            double tp = 0, fp = 0;
            for (double v : pos) if (v >= t && v > 0.0) ++tp;
            for (double v : neg) if (v >= t && v > 0.0) ++fp;
            pts.emplace_back(neg.empty() ? 0.0 : fp / neg.size(), pos.empty() ? 0.0 : tp / pos.size());
        }
        pts.emplace_back(0.0, 0.0);
        std::sort(pts.begin(), pts.end());
        pts.erase(std::unique(pts.begin(), pts.end()), pts.end());
        return pts;
    }

    // ------------------------------------------------------------ SVG charts
    std::string svgRoc(const std::vector<std::pair<std::string, std::vector<std::pair<double, double>>>>& curves)
    {
        const char* colors[] = { "#c62828", "#1565c0", "#2e7d32", "#6a1b9a", "#ef6c00", "#455a64" };
        std::ostringstream s;
        const int W = 460, H = 380, L = 55, B = 45, T = 15, R = 15;
        const double pw = W - L - R, ph = H - T - B;

        s << "<svg xmlns='http://www.w3.org/2000/svg' width='" << W + 260 << "' height='" << H << "' font-family='Arial' font-size='12'>";
        s << "<rect x='" << L << "' y='" << T << "' width='" << pw << "' height='" << ph << "' fill='white' stroke='#888'/>";
        for (int k = 0; k <= 5; ++k)
        {
            const double v = k / 5.0;
            s << "<line x1='" << L + v * pw << "' y1='" << T << "' x2='" << L + v * pw << "' y2='" << T + ph << "' stroke='#eee'/>";
            s << "<line x1='" << L << "' y1='" << T + ph - v * ph << "' x2='" << L + pw << "' y2='" << T + ph - v * ph << "' stroke='#eee'/>";
            s << "<text x='" << L + v * pw << "' y='" << T + ph + 16 << "' text-anchor='middle'>" << fmt(v, 1) << "</text>";
            s << "<text x='" << L - 6 << "' y='" << T + ph - v * ph + 4 << "' text-anchor='end'>" << fmt(v, 1) << "</text>";
        }
        s << "<line x1='" << L << "' y1='" << T + ph << "' x2='" << L + pw << "' y2='" << T << "' stroke='#bbb' stroke-dasharray='4 4'/>";
        s << "<text x='" << L + pw / 2 << "' y='" << H - 8 << "' text-anchor='middle'>False positive rate</text>";
        s << "<text transform='translate(14," << T + ph / 2 << ") rotate(-90)' text-anchor='middle'>True positive rate</text>";

        for (size_t c = 0; c < curves.size(); ++c)
        {
            s << "<polyline fill='none' stroke='" << colors[c % 6] << "' stroke-width='" << (c == 0 ? 3 : 1.8) << "' points='";
            for (const auto& p : curves[c].second) s << L + p.first * pw << ',' << T + ph - p.second * ph << ' ';
            s << "'/>";
            s << "<rect x='" << W + 5 << "' y='" << T + 10 + c * 22 << "' width='14' height='4' fill='" << colors[c % 6] << "'/>";
            s << "<text x='" << W + 25 << "' y='" << T + 16 + c * 22 << "'>" << htmlEscape(curves[c].first) << "</text>";
        }

        s << "</svg>";
        return s.str();
    }

    struct SensRow { std::string param; double value; Metrics m; bool isDefault; };

    std::string svgSensitivity(const std::vector<SensRow>& rows, const std::string& param)
    {
        std::vector<SensRow> r;
        for (const auto& x : rows) if (x.param == param) r.push_back(x);
        if (r.empty()) return std::string();

        const int W = 300, H = 200, L = 40, B = 35, T = 20, R = 10;
        const double pw = W - L - R, ph = H - T - B;
        const double lo = r.front().value, hi = r.back().value;
        auto X = [&](double v) { return L + (hi > lo ? (v - lo) / (hi - lo) : 0.5) * pw; };
        auto Y = [&](double v) { return T + ph - (std::isnan(v) ? 0.0 : v) * ph; };

        std::ostringstream s;
        s << "<svg xmlns='http://www.w3.org/2000/svg' width='" << W << "' height='" << H << "' font-family='Arial' font-size='11'>";
        s << "<rect x='" << L << "' y='" << T << "' width='" << pw << "' height='" << ph << "' fill='white' stroke='#888'/>";
        s << "<text x='" << L + pw / 2 << "' y='12' text-anchor='middle' font-weight='bold'>" << htmlEscape(param) << "</text>";
        for (int k = 0; k <= 4; ++k)
            s << "<text x='" << L - 5 << "' y='" << Y(k / 4.0) + 4 << "' text-anchor='end'>" << fmt(k / 4.0, 2) << "</text>";
        for (const auto& x : r)
            s << "<text x='" << X(x.value) << "' y='" << T + ph + 14 << "' text-anchor='middle'" << (x.isDefault ? " font-weight='bold'" : "") << ">" << fmt(x.value, x.value < 2 ? 2 : 0) << "</text>";

        for (int series = 0; series < 2; ++series)
        {
            s << "<polyline fill='none' stroke='" << (series == 0 ? "#2e7d32" : "#c62828") << "' stroke-width='2' points='";
            for (const auto& x : r) s << X(x.value) << ',' << Y(series == 0 ? x.m.tpr : x.m.fpr) << ' ';
            s << "'/>";
        }
        s << "<text x='" << L + 5 << "' y='" << H - 3 << "' fill='#2e7d32'>TPR</text><text x='" << L + 40 << "' y='" << H - 3 << "' fill='#c62828'>FPR</text>";
        s << "</svg>";
        return s.str();
    }

} // namespace ev


static int run(const std::vector<fs::path>& args)
{
    using namespace ev;

    const int argc = static_cast<int>(args.size());
    std::vector<std::string> argText;
    for (const auto& a : args) argText.push_back(a.u8string());
    auto argv = [&](int i) { return argText[static_cast<size_t>(i)].c_str(); };

    if (argc < 2)
    {
        std::cout << "NetWolf v2 - evaluation program\n\n"
                  << "Usage: NetWolfV2Eval <experiments folder> [--out <folder>] [--scale <x>] [--seed <n>] [--no-sensitivity]\n";
        return 1;
    }

    fs::path root = args[1];
    fs::path outFolder;
    double scale = 1.0;
    uint64_t seed = 2026;
    bool sensitivity = true;

    for (int i = 2; i < argc; ++i)
    {
        const std::string a = argv(i);
        if (a == "--out" && i + 1 < argc) outFolder = args[static_cast<size_t>(++i)];
        else if (a == "--scale" && i + 1 < argc) scale = std::max(0.05, std::atof(argv(++i)));
        else if (a == "--seed" && i + 1 < argc) seed = std::strtoull(argv(++i), nullptr, 10);
        else if (a == "--no-sensitivity") sensitivity = false;
    }

    if (outFolder.empty()) outFolder = root / "evaluation_results";
    std::error_code ec;
    fs::create_directories(outFolder, ec);

    const auto clockStart = std::chrono::steady_clock::now();

    // ================================================================ 1. load experiments
    std::vector<Experiment> experiments;

    for (auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied, ec);
        it != fs::recursive_directory_iterator(); it.increment(ec))
    {
        if (ec) break;
        if (!it->is_regular_file() || it->path().filename() != "devices.csv") continue;
        if (it->path().u8string().find("evaluation_results") != std::string::npos) continue;

        Experiment exp;
        std::string warning;
        if (loadExperiment(it->path(), exp, warning)) experiments.push_back(std::move(exp));
        else std::cout << "  skipped: " << warning << "\n";
    }

    std::sort(experiments.begin(), experiments.end(), [](const Experiment& a, const Experiment& b) { return a.name < b.name; });

    std::cout << "NetWolf v2 evaluation\n"
              << "  experiments found: " << experiments.size() << " in " << root.u8string() << "\n";

    if (experiments.empty())
    {
        std::cout << "No devices.csv files were found. Point the program to the folder that contains Exp-01, Exp-02, ...\n";
        return 2;
    }

    // ================================================================ 2. real experiments
    std::ofstream realCsv(outFolder / "real_experiments.csv");
    realCsv << "experiment,type,duration_min,devices,device_hours,crowd_peak,collapses,alerts,alerted_devices,"
               "relay,relay_detected,delay_from_attack_start_s,delay_from_last_victim_s,people_at_alert,"
               "wrong_device_alerts,false_alarms_per_device_hour,full_destinations_logged,label_file,attack_times\n";

    std::ostringstream realHtml;
    double totalNormalHours = 0.0;
    size_t totalNormalAlarms = 0;

    for (const auto& exp : experiments)
    {
        double deviceHours = 0.0;
        std::vector<std::pair<double, std::string>> alerts;

        for (const auto& [alias, dev] : exp.devices)
        {
            deviceHours += dev.rows.size() / 3600.0;
            if (!std::isnan(dev.firstRedflag)) alerts.emplace_back(dev.firstRedflag, alias);
        }
        std::sort(alerts.begin(), alerts.end());

        const bool attack = exp.label.type == "attack";
        bool detected = false;
        double delayStart = kNaN, delayLast = kNaN, people = kNaN;
        size_t wrong = 0;
        std::string alerted;

        for (const auto& [t, alias] : alerts)
        {
            alerted += (alerted.empty() ? "" : " ") + alias;
            if (attack && alias == exp.label.relay)
            {
                detected = true;
                if (!std::isnan(exp.label.attackStart)) delayStart = t - exp.label.attackStart;
                if (!std::isnan(exp.label.lastMoved)) delayLast = t - exp.label.lastMoved;
                people = exp.devices.at(alias).peopleAtAlert;
            }
            else ++wrong;
        }

        double faPerHour = kNaN;
        if (exp.label.type == "normal" && deviceHours > 0)
        {
            faPerHour = alerts.size() / deviceHours;
            totalNormalHours += deviceHours;
            totalNormalAlarms += alerts.size();
        }

        const double minutes = (exp.tEnd - exp.tStart) / 60.0;

        realCsv << exp.name << ',' << (exp.label.type.empty() ? "unlabelled" : exp.label.type) << ',' << fmt(minutes, 1) << ','
                << exp.devices.size() << ',' << fmt(deviceHours, 2) << ',' << exp.crowdPeak << ',' << exp.collapses << ','
                << alerts.size() << ",\"" << alerted << "\"," << exp.label.relay << ',' << (attack ? (detected ? "yes" : "no") : "") << ','
                << fmt(delayStart, 1) << ',' << fmt(delayLast, 1) << ',' << fmt(people, 2) << ',' << wrong << ','
                << fmt(faPerHour, 3) << ',' << (exp.hasAllDestinations ? "yes" : "no (top 5 only)") << ','
                << (exp.label.present ? "yes" : "MISSING") << ','
                << (attack ? ((exp.derivedAttackStart || exp.derivedLastMoved) ? "derived from the log" : "from experiment.txt") : "") << '\n';

        realHtml << "<tr><td>" << htmlEscape(exp.name) << "</td><td>" << htmlEscape(exp.label.type.empty() ? "unlabelled" : exp.label.type)
                 << "</td><td>" << fmt(minutes, 1) << "</td><td>" << exp.devices.size() << "</td><td>" << fmt(deviceHours, 2)
                 << "</td><td>" << exp.crowdPeak << "</td><td>" << exp.collapses << "</td><td>" << htmlEscape(alerted.empty() ? "-" : alerted)
                 << "</td><td>" << (attack ? (detected ? "yes" : "<b>no</b>") : "-") << "</td><td>" << fmt(delayLast, 1)
                 << "</td><td>" << fmt(delayStart, 1) << "</td><td>" << wrong << "</td></tr>\n";

        std::cout << "  " << exp.name << ": " << (exp.label.type.empty() ? "UNLABELLED (add experiment.txt)" : exp.label.type)
                  << ", " << exp.devices.size() << " devices, " << fmt(minutes, 1) << " min, alerts: " << (alerted.empty() ? "none" : alerted) << "\n";
    }
    realCsv.close();

    // ================================================================ 3. trace pools (benign behaviour only)
    Pool calibrationPool, testPool;
    size_t excludedExperiments = 0;

    for (const auto& exp : experiments)
    {
        double cutoff = kNever;

        if (exp.label.type == "attack")
        {
            if (std::isnan(exp.label.attackStart)) { ++excludedExperiments; continue; }
            cutoff = exp.label.attackStart - 30.0;
        }
        else if (exp.label.type != "normal")
        {
            bool anyAlert = false;
            for (const auto& [alias, dev] : exp.devices) if (!std::isnan(dev.firstRedflag)) anyAlert = true;
            if (anyAlert) { ++excludedExperiments; continue; }   // unlabelled attack: unsafe as benign data
        }

        for (const auto& [alias, dev] : exp.devices)
        {
            if (exp.label.exclude.count(alias)) continue;

            std::vector<std::pair<double, Snap>> rows;
            for (const auto& r : dev.rows) if (r.first < cutoff) rows.push_back(r);
            if (rows.size() < 60) continue;

            const double span = rows.back().first - rows.front().first;
            if (span < 120.0) continue;

            const std::string source = exp.name + "/" + alias;

            if (span >= 600.0)
            {
                const double mid = rows.front().first + span / 2.0;
                size_t split = 0;
                while (split < rows.size() && rows[split].first < mid) ++split;
                if (split >= 30 && rows.size() - split >= 30)
                {
                    calibrationPool.traces.push_back(makeTrace(source + "#1", dev.type, rows, 0, split));
                    testPool.traces.push_back(makeTrace(source + "#2", dev.type, rows, split, rows.size()));
                    continue;
                }
            }

            testPool.traces.push_back(makeTrace(source, dev.type, rows, 0, rows.size()));
        }
    }

    bool sharedPool = false;
    if (calibrationPool.traces.size() < 3)
    {
        calibrationPool = testPool;
        sharedPool = true;
    }

    for (Pool* pool : { &calibrationPool, &testPool })
    {
        for (size_t i = 0; i < pool->traces.size(); ++i)
        {
            pool->byHeaviness.push_back(static_cast<int>(i));
            if (pool->traces[i].fam == "Windows") pool->windowsTraces.push_back(static_cast<int>(i));
        }
        std::sort(pool->byHeaviness.begin(), pool->byHeaviness.end(), [&](int a, int b)
            {
                const double ma = pool->traces[static_cast<size_t>(a)].meanConns, mb = pool->traces[static_cast<size_t>(b)].meanConns;
                return ma != mb ? ma > mb : a < b;
            });
    }

    std::cout << "  benign traces: " << testPool.traces.size() << " (test), " << calibrationPool.traces.size()
              << (sharedPool ? " (calibration = test, not enough data to split)" : " (calibration)") << "\n";

    if (testPool.traces.size() < 2)
    {
        std::cout << "Not enough benign traces for the scenario evaluation (need at least 2 devices with 2+ minutes of activity).\n";
        return 3;
    }

    // ================================================================ 4. scenarios
    const int crowdSizes[] = { 2, 3, 5, 8, 15, 30 };
    const std::pair<Kind, int> plan[] = {
        { Kind::PosMember, 30 }, { Kind::PosNew, 30 }, { Kind::PosMemberTtl, 10 }, { Kind::PosNewTtl, 10 },
        { Kind::NegChurn, 30 }, { Kind::NegDeparture, 20 }, { Kind::NegHeavy, 15 }, { Kind::NegTether, 15 }, { Kind::NegTunnel, 15 } };

    auto buildScenarios = [&](const Pool& pool, double factor, uint64_t s, const GenSettings& gen)
        {
            Rng rng(s);
            ScenarioFactory factory{ pool, gen };
            std::vector<Scenario> list;
            int id = 0;
            for (int n : crowdSizes)
                for (const auto& [kind, count] : plan)
                {
                    const int k = std::max(1, static_cast<int>(std::lround(count * factor)));
                    for (int i = 0; i < k; ++i) list.push_back(factory.make(kind, n, ++id, rng));
                }
            return list;
        };

    auto runAll = [&](const std::vector<Scenario>& list, const Pool& pool, const NetWolfSettings& nw,
        const IsolationForest* forest, std::vector<double>* benignE, const char* label)
        {
            std::vector<Outcome> outs;
            outs.reserve(list.size());
            for (size_t i = 0; i < list.size(); ++i)
            {
                outs.push_back(runScenario(list[i], pool, nw, forest, benignE));
                if ((i + 1) % 50 == 0 || i + 1 == list.size())
                    std::cout << "\r  " << label << ": " << (i + 1) << " / " << list.size() << " scenarios" << std::flush;
            }
            std::cout << "\n";
            return outs;
        };

    NetWolfSettings defaults;
    const GenSettings defaultGen;

    // Isolation forest trained on benign single-device snapshots (calibration traces).
    IsolationForest forest;
    {
        std::vector<std::vector<double>> samples;
        Rng rng(seed + 7);
        for (const auto& tr : calibrationPool.traces)
            for (const auto& s : tr.snaps)
            {
                int gmax = 0;
                for (const auto& d : s.dests) gmax = std::max(gmax, d.second);
                samples.push_back(features(s.conns, s.dests.size(), gmax, s.syns, s.behind.size()));
            }
        if (samples.size() > 20000)
        {
            for (size_t i = samples.size() - 1; i > 0; --i) std::swap(samples[i], samples[static_cast<size_t>(rng.below(static_cast<int>(i + 1)))]);
            samples.resize(20000);
        }
        forest.fit(samples, rng);
    }

    std::vector<double> benignE;

    const auto calScenarios = buildScenarios(calibrationPool, 0.4 * scale, seed + 1, defaultGen);
    const auto calOutcomes = runAll(calScenarios, calibrationPool, defaults, &forest, nullptr, "calibration");

    const auto scenarios = buildScenarios(testPool, scale, seed, defaultGen);
    const auto outcomes = runAll(scenarios, testPool, defaults, &forest, &benignE, "test");

    // ================================================================ 5. metrics
    double thresholds[MethodCount];
    thresholds[NetWolf] = kNaN;   // NetWolf: its own fixed rule, nothing tuned
    for (int m = 1; m < MethodCount; ++m) thresholds[m] = calibrate(calScenarios, calOutcomes, m);

    Metrics main[MethodCount];
    for (int m = 0; m < MethodCount; ++m) main[m] = evaluate(scenarios, outcomes, m, thresholds[m], includeMain);

    // AUC of NetWolf from its continuous score (decision rule == score >= 1).
    {
        const Metrics s = evaluate(scenarios, outcomes, NetWolf, 1.0, includeMain);
        main[NetWolf].auc = s.auc;
    }

    // Agreement between the continuous score and the real decision.
    size_t agree = 0, total = 0;
    for (size_t i = 0; i < scenarios.size(); ++i)
    {
        const Decision real = decide(scenarios[i], outcomes[i], NetWolf, kNaN);
        const Decision byScore = decide(scenarios[i], outcomes[i], NetWolf, 1.0);
        ++total;
        if (real.flagged == byScore.flagged && real.detected == byScore.detected) ++agree;
    }

    std::ofstream summaryCsv(outFolder / "table5_detection_results.csv");
    summaryCsv << "method,TPR,FPR,precision,F1,AUC,median_delay_after_last_victim_s,p90_delay_s,median_delay_after_attack_start_s,"
                  "false_alarms_per_device_hour,positives,negatives,TP,FP,wrong_device,threshold\n";
    for (int m = 0; m < MethodCount; ++m)
    {
        const Metrics& x = main[m];
        summaryCsv << '"' << methodName(m) << "\"," << fmt(x.tpr) << ',' << fmt(x.fpr) << ',' << fmt(x.precision) << ',' << fmt(x.f1) << ','
                   << fmt(x.auc) << ',' << fmt(x.delayFromLastMove, 1) << ',' << fmt(x.delayP90, 1) << ',' << fmt(x.delayFromStart, 1) << ','
                   << fmt(x.falseAlarmsPerDeviceHour, 4) << ',' << x.positives << ',' << x.negatives << ',' << x.tp << ',' << x.fp << ','
                   << x.wrongDevice << ',' << (m == NetWolf ? std::string("fixed rule") : fmt(x.threshold, 4)) << '\n';
    }
    summaryCsv.close();

    // By crowd size and by scenario type.
    std::ofstream bySizeCsv(outFolder / "results_by_crowd_size.csv");
    bySizeCsv << "method,crowd_size,TPR,FPR,F1,median_delay_s\n";
    std::ostringstream bySizeHtml;
    for (int m = 0; m < MethodCount; ++m)
        for (int n : crowdSizes)
        {
            std::vector<Scenario> s;
            std::vector<Outcome> o;
            for (size_t i = 0; i < scenarios.size(); ++i) if (scenarios[i].n == n) { s.push_back(scenarios[i]); o.push_back(outcomes[i]); }
            const Metrics x = evaluate(s, o, m, thresholds[m], includeMain);
            bySizeCsv << '"' << methodName(m) << "\"," << n << ',' << fmt(x.tpr) << ',' << fmt(x.fpr) << ',' << fmt(x.f1) << ',' << fmt(x.delayFromLastMove, 1) << '\n';
            if (m == NetWolf)
                bySizeHtml << "<tr><td>" << n << "</td><td>" << fmt(x.tpr) << "</td><td>" << fmt(x.fpr) << "</td><td>" << fmt(x.f1) << "</td><td>" << fmt(x.delayFromLastMove, 1) << "</td></tr>\n";
        }
    bySizeCsv.close();

    std::ofstream byTypeCsv(outFolder / "results_by_scenario_type.csv");
    byTypeCsv << "scenario_type,label,scenarios";
    for (int m = 0; m < MethodCount; ++m) byTypeCsv << ",\"" << methodName(m) << " (detected or flagged share)\"";
    byTypeCsv << '\n';
    std::ostringstream byTypeHtml;
    for (const auto& [kind, count] : plan)
    {
        (void)count;
        size_t n = 0;
        size_t hits[MethodCount] = {};
        for (size_t i = 0; i < scenarios.size(); ++i)
        {
            if (scenarios[i].kind != kind) continue;
            ++n;
            for (int m = 0; m < MethodCount; ++m)
            {
                const Decision d = decide(scenarios[i], outcomes[i], m, thresholds[m]);
                if (scenarios[i].positive ? d.detected : d.flagged) ++hits[m];
            }
        }
        byTypeCsv << kindName(kind) << ',' << (isPositive(kind) ? "attack" : "benign") << ',' << n;
        byTypeHtml << "<tr><td>" << kindName(kind) << "</td><td>" << (isPositive(kind) ? "attack (detection rate)" : "benign (false alarm rate)") << "</td><td>" << n << "</td>";
        for (int m = 0; m < MethodCount; ++m)
        {
            const double share = n ? static_cast<double>(hits[m]) / n : kNaN;
            byTypeCsv << ',' << fmt(share);
            byTypeHtml << "<td>" << fmt(share, 2) << "</td>";
        }
        byTypeCsv << '\n';
        byTypeHtml << "</tr>\n";
    }
    byTypeCsv.close();

    // ROC.
    std::vector<std::pair<std::string, std::vector<std::pair<double, double>>>> rocs;
    std::ofstream rocCsv(outFolder / "fig5a_roc_points.csv");
    rocCsv << "method,FPR,TPR\n";
    for (int m = 0; m < MethodCount; ++m)
    {
        auto pts = rocPoints(scenarios, outcomes, m);
        for (const auto& p : pts) rocCsv << '"' << methodName(m) << "\"," << fmt(p.first, 4) << ',' << fmt(p.second, 4) << '\n';
        rocs.emplace_back(std::string(methodName(m)) + " (AUC " + fmt(main[m].auc, 3) + ")", std::move(pts));
    }
    rocCsv.close();

    // Per-scenario record.
    std::ofstream scCsv(outFolder / "scenarios.csv");
    scCsv << "id,type,crowd_size,label,ttl_normalized,attack_start_s,last_victim_s,end_s,churn_mean_min,netwolf_alert_on_relay_s,"
             "netwolf_alert_on_other_s,netwolf_delay_after_last_victim_s,people_at_alert,collapses,netwolf_score";
    for (int m = 1; m < MethodCount; ++m) scCsv << ",\"" << methodName(m) << " score\"";
    scCsv << '\n';
    for (size_t i = 0; i < scenarios.size(); ++i)
    {
        const Scenario& s = scenarios[i];
        const Outcome& o = outcomes[i];
        scCsv << s.id << ',' << kindName(s.kind) << ',' << s.n << ',' << (s.positive ? "attack" : "benign") << ','
              << (s.ttlNormalized ? "yes" : "no") << ',' << fmt(s.t0, 0) << ',' << fmt(s.tLast, 0) << ',' << fmt(s.end, 0) << ','
              << fmt(s.churnMean / 60.0, 0) << ',' << fmt(o.alertRelay, 0) << ',' << fmt(o.alertOther, 0) << ','
              << fmt(o.alertRelay - s.tLast, 0) << ',' << fmt(o.peopleAtAlert, 2) << ',' << o.collapses;
        for (int m = 0; m < MethodCount; ++m) scCsv << ',' << fmt(scenarioScore(s, o, m), 4);
        scCsv << '\n';
    }
    scCsv.close();

    // Calibration statistics (threshold justification).
    std::ofstream calCsv(outFolder / "calibration_statistics.csv");
    calCsv << "statistic,value\n"
           << "benign E_j samples," << benignE.size() << '\n'
           << "benign E_j median," << fmt(median(benignE)) << '\n'
           << "benign E_j 95th percentile," << fmt(quantile(benignE, 0.95)) << '\n'
           << "benign E_j 99th percentile," << fmt(quantile(benignE, 0.99)) << '\n'
           << "benign E_j 99.9th percentile," << fmt(quantile(benignE, 0.999)) << '\n'
           << "benign E_j maximum," << fmt(quantile(benignE, 1.0)) << '\n'
           << "share of benign E_j >= 2," << fmt(benignE.empty() ? kNaN
                : static_cast<double>(std::count_if(benignE.begin(), benignE.end(), [](double e) { return e >= 2.0; })) / benignE.size(), 5) << '\n'
           << "real normal experiments: device-hours," << fmt(totalNormalHours, 2) << '\n'
           << "real normal experiments: alerts," << totalNormalAlarms << '\n'
           << "decision agreement (score>=1 vs NetWolf decision)," << fmt(total ? static_cast<double>(agree) / total : kNaN, 4) << '\n'
           << "benign traces (test / calibration)," << testPool.traces.size() << " / " << calibrationPool.traces.size() << '\n'
           << "calibration pool shared with test," << (sharedPool ? "yes" : "no") << '\n'
           << "excluded experiments (attack without attack_start or unlabelled with alerts)," << excludedExperiments << '\n'
           << "seed," << seed << '\n'
           << "scale," << scale << '\n';
    calCsv.close();

    // ================================================================ 6. sensitivity
    std::vector<SensRow> sens;

    if (sensitivity)
    {
        const double sensScale = 0.35 * scale;
        const auto base = buildScenarios(testPool, sensScale, seed + 100, defaultGen);

        auto runSetting = [&](const std::string& param, double value, bool isDefault, const NetWolfSettings& nw, const GenSettings& gen)
            {
                const auto list = (gen.idleSeconds == defaultGen.idleSeconds) ? base : buildScenarios(testPool, sensScale, seed + 100, gen);
                std::string label = "sensitivity " + param + "=" + fmt(value, value < 2 ? 2 : 0);
                const auto outs = runAll(list, testPool, nw, nullptr, nullptr, label.c_str());
                sens.push_back(SensRow{ param, value, evaluate(list, outs, NetWolf, kNaN, includeMain), isDefault });
            };

        for (double v : { 0.3, 0.4, 0.5, 0.6, 0.8, 1.0 })
        {
            NetWolfSettings nw = defaults; nw.evilTwin.aggregationFraction = v;
            runSetting("alpha (aggregation share)", v, v == 0.5, nw, defaultGen);
        }
        for (double v : { 0.6, 0.7, 0.8, 0.9 })
        {
            NetWolfSettings nw = defaults; nw.evilTwin.collapseFraction = v;
            runSetting("rho (vanished share)", v, v == 0.8, nw, defaultGen);
        }
        for (double v : { 90.0, 150.0, 240.0 })
        {
            NetWolfSettings nw = defaults; nw.evilTwin.collapseWindowSeconds = static_cast<int>(v);
            runSetting("W_c (crowd window, s)", v, v == 150.0, nw, defaultGen);
        }
        for (double v : { 20.0, 45.0, 90.0 })
        {
            GenSettings gen = defaultGen; gen.idleSeconds = v;
            runSetting("flow idle time (s)", v, v == 45.0, defaults, gen);
        }

        std::ofstream sensCsv(outFolder / "fig5b_sensitivity.csv");
        sensCsv << "parameter,value,default,TPR,FPR,F1,median_delay_s\n";
        for (const auto& r : sens)
            sensCsv << '"' << r.param << "\"," << r.value << ',' << (r.isDefault ? "yes" : "") << ',' << fmt(r.m.tpr) << ','
                    << fmt(r.m.fpr) << ',' << fmt(r.m.f1) << ',' << fmt(r.m.delayFromLastMove, 1) << '\n';
    }

    // ================================================================ 7. HTML report
    const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - clockStart).count();

    std::ofstream html(outFolder / "evaluation_report.html");
    html << "<!DOCTYPE html><html><head><meta charset='utf-8'><title>NetWolf v2 - Evaluation</title><style>"
         << "body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1d2433}h1{font-size:22px}h2{font-size:17px;margin-top:28px;border-bottom:2px solid #e3e7ef}"
         << "table{border-collapse:collapse;font-size:13px;margin:8px 0}th,td{border:1px solid #d5dbe6;padding:4px 8px;text-align:left}th{background:#eef1f6}"
         << ".muted{color:#5a6478;font-size:12px}.best td{background:#e3f4e8;font-weight:bold}</style></head><body>"
         << "<h1>NetWolf v2 &mdash; Evaluation results</h1><p class='muted'>Experiments: " << htmlEscape(root.u8string())
         << " &middot; seed " << seed << " &middot; scale " << scale << " &middot; " << fmt(seconds, 0) << " s</p>";

    html << "<h2>Real experiments (Table 4)</h2><table><tr><th>Experiment</th><th>Type</th><th>Minutes</th><th>Devices</th><th>Device-hours</th>"
         << "<th>Crowd peak</th><th>Collapses</th><th>Alerted devices</th><th>Relay detected</th><th>Delay after last victim, s</th>"
         << "<th>Delay after attack start, s</th><th>Wrong-device alerts</th></tr>" << realHtml.str() << "</table>";

    html << "<h2>Trace-driven evaluation (Table 5)</h2><p class='muted'>" << scenarios.size() << " scenarios built from "
         << testPool.traces.size() << " real benign device traces; TTL-normalizing relays are reported separately below. "
         << "Baseline thresholds were chosen for the best F1 on separate calibration scenarios; NetWolf uses its fixed rule.</p>"
         << "<table><tr><th>Method</th><th>TPR</th><th>FPR</th><th>Precision</th><th>F1</th><th>AUC</th><th>Median delay, s</th><th>False alarms / device-hour</th><th>Threshold</th></tr>";
    for (int m = 0; m < MethodCount; ++m)
    {
        const Metrics& x = main[m];
        html << "<tr" << (m == NetWolf ? " class='best'" : "") << "><td>" << methodName(m) << "</td><td>" << fmt(x.tpr) << "</td><td>" << fmt(x.fpr)
             << "</td><td>" << fmt(x.precision) << "</td><td>" << fmt(x.f1) << "</td><td>" << fmt(x.auc) << "</td><td>" << fmt(x.delayFromLastMove, 1)
             << "</td><td>" << fmt(x.falseAlarmsPerDeviceHour, 4) << "</td><td>" << (m == NetWolf ? std::string("fixed rule") : fmt(x.threshold, 3)) << "</td></tr>";
    }
    html << "</table>";

    html << "<h2>ROC curves (Fig. 5a)</h2>" << svgRoc(rocs);

    html << "<h2>NetWolf v2 by crowd size</h2><table><tr><th>Crowd size</th><th>TPR</th><th>FPR</th><th>F1</th><th>Median delay, s</th></tr>"
         << bySizeHtml.str() << "</table>";

    html << "<h2>By scenario type</h2><table><tr><th>Scenario</th><th>Meaning of the value</th><th>Scenarios</th>";
    for (int m = 0; m < MethodCount; ++m) html << "<th>" << methodName(m) << "</th>";
    html << "</tr>" << byTypeHtml.str() << "</table>";

    if (!sens.empty())
    {
        html << "<h2>Sensitivity (Fig. 5b)</h2><div>";
        for (const char* p : { "alpha (aggregation share)", "rho (vanished share)", "W_c (crowd window, s)", "flow idle time (s)" })
            html << svgSensitivity(sens, p) << ' ';
        html << "</div><table><tr><th>Parameter</th><th>Value</th><th>TPR</th><th>FPR</th><th>F1</th><th>Median delay, s</th></tr>";
        for (const auto& r : sens)
            html << "<tr" << (r.isDefault ? " class='best'" : "") << "><td>" << htmlEscape(r.param) << "</td><td>" << r.value << "</td><td>"
                 << fmt(r.m.tpr) << "</td><td>" << fmt(r.m.fpr) << "</td><td>" << fmt(r.m.f1) << "</td><td>" << fmt(r.m.delayFromLastMove, 1) << "</td></tr>";
        html << "</table>";
    }

    html << "<h2>Calibration statistics</h2><table>"
         << "<tr><td>Benign estimated-people values E_j (single devices in crowds)</td><td>" << benignE.size() << " samples</td></tr>"
         << "<tr><td>Median / 99th percentile / maximum</td><td>" << fmt(median(benignE), 2) << " / " << fmt(quantile(benignE, 0.99), 2)
         << " / " << fmt(quantile(benignE, 1.0), 2) << "</td></tr>"
         << "<tr><td>Agreement of the continuous score with the real decision</td><td>" << fmt(total ? 100.0 * agree / total : kNaN, 1) << "%</td></tr>"
         << "<tr><td>Real normal experiments</td><td>" << totalNormalAlarms << " alerts in " << fmt(totalNormalHours, 2) << " device-hours</td></tr>"
         << "</table><p class='muted'>All CSV files in this folder contain the same numbers for the paper.</p></body></html>";
    html.close();

    std::cout << "\nNetWolf v2: TPR " << fmt(main[NetWolf].tpr) << ", FPR " << fmt(main[NetWolf].fpr) << ", AUC " << fmt(main[NetWolf].auc)
              << ", median delay " << fmt(main[NetWolf].delayFromLastMove, 1) << " s\n"
              << "Results: " << outFolder.u8string() << "\n"
              << "Open evaluation_report.html to see everything.\n";

    return 0;
}


#if defined(_WIN32)
int wmain(int argc, wchar_t** argv)
{
    std::vector<fs::path> args;
    for (int i = 0; i < argc; ++i) args.emplace_back(argv[i]);
    return run(args);
}
#else
int main(int argc, char** argv)
{
    std::vector<fs::path> args;
    for (int i = 0; i < argc; ++i) args.emplace_back(argv[i]);
    return run(args);
}
#endif
