#pragma once

#include "models.hpp"
#include "session_id.hpp"
#include "connection_analyzer.hpp"
#include "destination_resolver.hpp"
#include "origin_resolver.hpp"
#include "connection_grouper.hpp"
#include "report_builder.hpp"
#include "device_classifier.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace netwolf::core {

    // ================================================================
    // NetWolf v2 - Main Engine
    // Layer: Orchestrator
    //
    // Purpose:
    // 1. Run all engine layers in the correct PDF order.
    // 2. Keep the GUI independent from the engine.
    // 3. Return structured output:
    //    - Normal devices
    //    - Heavy devices
    //    - Redflag devices
    //    - Connection reports
    //
    // Pipeline:
    // ObservedConnection
    // -> ConnectionAnalyzer
    // -> OriginResolver
    // -> DestinationResolver
    // -> ConnectionGrouper
    // -> DeviceClassifier
    // -> EngineOutput
    // ================================================================


    // ------------------------------------------------
    // Engine configuration
    // ------------------------------------------------

    struct EngineConfig
    {
        ConnectionAnalyzerConfig analyzer;
        OriginResolverConfig originResolver;
        DestinationResolverConfig destinationResolver;
        ConnectionGrouperConfig grouper;
        DeviceClassifierConfig classifier;
    };


    // ------------------------------------------------
    // Optional external evidence input
    //
    // Later, the live sensor can fill these maps using:
    // - Windows TCP table
    // - Process/PID table
    // - DNS cache / DNS packet observations
    // - TLS SNI / HTTP Host extraction if available
    // ------------------------------------------------

    struct EngineEvidenceInput
    {
        std::map<std::string, EvidenceStore> evidenceBySessionId;
        std::map<std::string, ProcessObservation> processBySessionId;
    };


    // ------------------------------------------------
    // Full engine input
    // ------------------------------------------------

    struct EngineInput
    {
        std::vector<ObservedConnection> observedConnections;
        EngineEvidenceInput evidence;
    };


    // ------------------------------------------------
    // Internal pipeline trace
    // Useful during testing before GUI integration.
    // ------------------------------------------------

    struct EngineTrace
    {
        std::vector<ConnectionSession> analyzedSessions;
        std::vector<AttributedSession> attributedSessions;
        std::vector<ConnectionGroup> groups;
    };


    // ------------------------------------------------
    // Engine run result
    // ------------------------------------------------

    struct EngineRunResult
    {
        EngineOutput output;
        EngineTrace trace;
    };


    // ------------------------------------------------
    // Main Engine
    // ------------------------------------------------

    class NetWolfEngine
    {
    public:
        explicit NetWolfEngine(EngineConfig config = {});

        EngineRunResult run(const EngineInput& input) const;

        EngineRunResult run(
            const std::vector<ObservedConnection>& observedConnections
        ) const;

    private:
        EngineConfig config_;

        ConnectionAnalyzer analyzer_;
        OriginResolver originResolver_;
        DestinationResolver destinationResolver_;
        ConnectionGrouper grouper_;
        DeviceClassifier classifier_;

    private:
        ConnectionSession applyExternalEvidence(
            ConnectionSession session,
            const EngineEvidenceInput& evidenceInput
        ) const;

        AttributedSession attributeSession(
            ConnectionSession session
        ) const;

        static EvidenceStore mergeEvidence(
            EvidenceStore base,
            const EvidenceStore& external
        );

        static void appendUniqueString(
            std::vector<std::string>& target,
            const std::vector<std::string>& source
        );

        static bool processIsVisibleEnough(
            const OriginResolutionResult& origin
        );
    };


    // ------------------------------------------------
    // Inline implementation
    // ------------------------------------------------

    inline NetWolfEngine::NetWolfEngine(EngineConfig config)
        : config_(config),
        analyzer_(config_.analyzer),
        originResolver_(config_.originResolver),
        destinationResolver_(config_.destinationResolver),
        grouper_(config_.grouper),
        classifier_(config_.classifier)
    {
    }


    inline EngineRunResult NetWolfEngine::run(
        const std::vector<ObservedConnection>& observedConnections
    ) const
    {
        EngineInput input;
        input.observedConnections = observedConnections;

        return run(input);
    }


    inline EngineRunResult NetWolfEngine::run(const EngineInput& input) const
    {
        EngineRunResult result;

        // ------------------------------------------------------------
        // Layer 1 + 2:
        // Outbound detection model input -> analyzed ConnectionSession
        // ------------------------------------------------------------

        std::vector<ConnectionSession> sessions =
            analyzer_.analyzeBatch(input.observedConnections);

        result.trace.analyzedSessions.reserve(sessions.size());
        result.trace.attributedSessions.reserve(sessions.size());

        // ------------------------------------------------------------
        // Layer 3 + 4:
        // Attach external evidence, resolve origin, resolve destination
        // ------------------------------------------------------------

        for (auto& session : sessions)
        {
            session = applyExternalEvidence(
                std::move(session),
                input.evidence
            );

            result.trace.analyzedSessions.push_back(session);

            AttributedSession attributed = attributeSession(std::move(session));
            result.trace.attributedSessions.push_back(std::move(attributed));
        }

        // ------------------------------------------------------------
        // Layer 5:
        // Group similar sub-connections under main connection groups
        // ------------------------------------------------------------

        result.trace.groups = grouper_.group(result.trace.attributedSessions);

        // ------------------------------------------------------------
        // Layer 7/8/9:
        // Classify devices into Normal / Heavy / Redflag
        // ------------------------------------------------------------

        result.output = classifier_.classify(result.trace.groups);

        return result;
    }


    inline ConnectionSession NetWolfEngine::applyExternalEvidence(
        ConnectionSession session,
        const EngineEvidenceInput& evidenceInput
    ) const
    {
        // External evidence can be attached by session ID.
        const auto evidenceIt = evidenceInput.evidenceBySessionId.find(session.sessionId);

        if (evidenceIt != evidenceInput.evidenceBySessionId.end())
        {
            session.evidence = mergeEvidence(
                session.evidence,
                evidenceIt->second
            );
        }

        // External process observation can also be attached by session ID.
        const auto processIt = evidenceInput.processBySessionId.find(session.sessionId);

        if (processIt != evidenceInput.processBySessionId.end())
        {
            OriginResolutionResult origin =
                originResolver_.resolveFromObservation(processIt->second);

            session = originResolver_.attachOriginEvidence(
                std::move(session),
                origin
            );
        }

        return session;
    }


    inline AttributedSession NetWolfEngine::attributeSession(
        ConnectionSession session
    ) const
    {
        // ------------------------------------------------------------
        // Origin resolver:
        // Determine who/what created the connection.
        // ------------------------------------------------------------

        OriginResolutionResult origin = originResolver_.resolve(session);

        // Important:
        // If we have a real visible process, attach it before destination
        // resolution so DestinationResolver can use process context.
        //
        // If process is unavailable, do NOT force it into evidence before
        // destination resolution, otherwise every IP-only connection would
        // become "Process-associated" too early.
        // We attach fallback origin after destination resolution.
        if (processIsVisibleEnough(origin))
        {
            session = originResolver_.attachOriginEvidence(
                std::move(session),
                origin
            );
        }

        // ------------------------------------------------------------
        // Destination resolver:
        // Identify destination using strongest evidence.
        // Enforces no raw Unknown.
        // ------------------------------------------------------------

        AttributionResult attribution =
            destinationResolver_.resolve(session);

        // Attach origin fallback to the final attribution if destination
        // resolver did not already attach a process.
        if (!attribution.ownerProcess.has_value())
        {
            attribution.ownerProcess = origin.process;
        }

        AttributedSession result;
        result.session = std::move(session);
        result.attribution = std::move(attribution);

        return result;
    }


    inline EvidenceStore NetWolfEngine::mergeEvidence(
        EvidenceStore base,
        const EvidenceStore& external
    )
    {
        base.dnsCandidates.insert(
            base.dnsCandidates.end(),
            external.dnsCandidates.begin(),
            external.dnsCandidates.end()
        );

        appendUniqueString(
            base.tlsSniCandidates,
            external.tlsSniCandidates
        );

        appendUniqueString(
            base.httpHostCandidates,
            external.httpHostCandidates
        );

        base.processCandidates.insert(
            base.processCandidates.end(),
            external.processCandidates.begin(),
            external.processCandidates.end()
        );

        base.providerHints.insert(
            base.providerHints.end(),
            external.providerHints.begin(),
            external.providerHints.end()
        );

        return base;
    }


    inline void NetWolfEngine::appendUniqueString(
        std::vector<std::string>& target,
        const std::vector<std::string>& source
    )
    {
        std::set<std::string> existing;

        for (const auto& item : target)
            existing.insert(normalizeKeyPart(item));

        for (const auto& item : source)
        {
            const std::string key = normalizeKeyPart(item);

            if (key == "-")
                continue;

            if (existing.insert(key).second)
                target.push_back(item);
        }
    }


    inline bool NetWolfEngine::processIsVisibleEnough(
        const OriginResolutionResult& origin
    )
    {
        if (!origin.processVisible)
            return false;

        const std::string name = trimCopy(origin.process.processName);

        if (name.empty())
            return false;

        if (lowerCopy(name) == "process context unavailable")
            return false;

        return true;
    }

} // namespace netwolf::core