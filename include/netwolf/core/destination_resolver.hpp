#pragma once

#include "models.hpp"
#include "session_id.hpp"
#include "asn_resolver.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace netwolf::core {

    // ================================================================
    // NetWolf v2 - Destination Resolver
    // Layer 3: Destination Resolver
    //
    // Purpose:
    // 1. Identify destination using strongest available evidence.
    // 2. Apply evidence priority:
    //    TLS SNI / HTTP Host / DNS Answer / Fresh DNS / Process / Provider / IP-only
    // 3. Enforce "No raw Unknown" policy.
    // ================================================================


    // ------------------------------------------------
    // Helper conversion
    // ------------------------------------------------

    inline std::string toString(EvidenceSource source)
    {
        switch (source)
        {
        case EvidenceSource::None:
            return "None";

        case EvidenceSource::TlsSni:
            return "TLS SNI";

        case EvidenceSource::HttpHost:
            return "HTTP Host";

        case EvidenceSource::DnsAnswer:
            return "DNS Answer";

        case EvidenceSource::FreshDnsCorrelation:
            return "Fresh DNS correlation";

        case EvidenceSource::ProcessContext:
            return "Process context";

        case EvidenceSource::ProviderHint:
            return "Provider/CDN hint";

        case EvidenceSource::PortProtocolHint:
            return "Port/protocol hint";

        case EvidenceSource::IpOnly:
            return "IP-only";

        default:
            return "None";
        }
    }


    // ------------------------------------------------
    // Resolver configuration
    // ------------------------------------------------

    struct DestinationResolverConfig
    {
        bool preferTlsSniOverHttpHost = true;
        bool preferHttpHostOverDns = true;
        bool allowProviderLevelFallback = true;
        bool allowProcessAssociatedFallback = true;
        bool allowEncryptedIpOnlyFallback = true;

        // Later, when we add DNS timeline, this can become stricter.
        uint64_t freshDnsWindowSeconds = 120;
    };


    // ------------------------------------------------
    // Domain/provider classification
    // ------------------------------------------------

    struct ProviderClassification
    {
        std::string entityName;
        std::string category;
        std::string trafficClass;
        std::string reason;
        ConfidenceLevel confidence = ConfidenceLevel::Low;
    };

    class DestinationResolver
    {
    public:
        explicit DestinationResolver(DestinationResolverConfig config = {});

        AttributionResult resolve(const ConnectionSession& session) const;

    private:
        DestinationResolverConfig config_;
        AsnResolver asnResolver_;

    private:
        AttributionResult fromTlsSni(const ConnectionSession& session) const;
        AttributionResult fromHttpHost(const ConnectionSession& session) const;
        AttributionResult fromDnsAnswer(const ConnectionSession& session) const;
        AttributionResult fromFreshDnsCorrelation(const ConnectionSession& session) const;
        AttributionResult fromProviderHint(const ConnectionSession& session) const;
        AttributionResult fromProcessContext(const ConnectionSession& session) const;
        AttributionResult fromIpOnlyFallback(const ConnectionSession& session) const;

        std::optional<ProcessCandidate> selectBestProcess(
            const EvidenceStore& evidence
        ) const;

        std::optional<ProviderHint> selectBestProviderHint(
            const EvidenceStore& evidence
        ) const;

        std::optional<DnsCandidate> selectBestDnsCandidate(
            const EvidenceStore& evidence
        ) const;

        std::optional<DnsCandidate> selectFreshDnsCandidate(
            const EvidenceStore& evidence
        ) const;

        ProviderClassification classifyDomainOrHost(
            const std::string& hostOrDomain,
            const std::string& remoteIp = {}
        ) const;

        ProviderClassification classifyIpAndPort(
            const ConnectionSession& session
        ) const;

        ProviderClassification classifyProcess(
            const ProcessCandidate& process,
            const ConnectionSession& session
        ) const;

        static std::string cleanHost(std::string host);

    public:
        // "sf16-teko.tiktokcdn.com" -> "tiktokcdn.com",
        // "www.bbc.co.uk" -> "bbc.co.uk". Automatic, no list of services.
        static std::string registrableDomain(const std::string& host);

    private:
        static bool containsToken(const std::string& text, const std::string& token);
        static bool endsWithToken(const std::string& text, const std::string& token);
        static bool isPrivateOrLocalIp(const std::string& ip);
    };


    // ------------------------------------------------
    // Inline implementation
    // ------------------------------------------------

    inline DestinationResolver::DestinationResolver(DestinationResolverConfig config)
        : config_(config)
    {
    }


    inline AttributionResult DestinationResolver::resolve(const ConnectionSession& session) const
    {
        // 1. TLS SNI: strongest direct evidence
        if (session.evidence.hasTlsSni())
            return fromTlsSni(session);

        // 2. HTTP Host: strongest direct evidence for plain HTTP
        if (session.evidence.hasHttpHost())
            return fromHttpHost(session);

        // 3. DNS answer: strong direct evidence
        if (session.evidence.hasDns())
            return fromDnsAnswer(session);

        // 4. Fresh DNS correlation: medium/high correlated evidence
        if (session.evidence.hasFreshDns())
            return fromFreshDnsCorrelation(session);

        // 5. Provider/CDN hint
        if (session.evidence.hasProviderHint() && config_.allowProviderLevelFallback)
            return fromProviderHint(session);

        // 6. Process-associated explanation
        if (session.evidence.hasProcessContext() && config_.allowProcessAssociatedFallback)
            return fromProcessContext(session);

        // 7. Final explained IP-only fallback
        return fromIpOnlyFallback(session);
    }


    inline AttributionResult DestinationResolver::fromTlsSni(
        const ConnectionSession& session
    ) const
    {
        const std::string host = cleanHost(session.evidence.tlsSniCandidates.front());
        const ProviderClassification classification = classifyDomainOrHost(host, session.observed.remoteIp);

        AttributionResult result;
        result.type = AttributionType::ExactDestination;
        result.destinationDomain = host;
        result.entityName = classification.entityName;
        result.category = classification.category;
        result.trafficClass = classification.trafficClass;
        result.source = EvidenceSource::TlsSni;
        result.confidence = ConfidenceLevel::High;
        result.ownerProcess = selectBestProcess(session.evidence);
        result.reason = "Destination was identified from TLS SNI, which is direct evidence observed in the connection metadata.";
        result.limitations = "Encrypted payload content is not inspected; only metadata attribution is used.";

        return result;
    }


    inline AttributionResult DestinationResolver::fromHttpHost(
        const ConnectionSession& session
    ) const
    {
        const std::string host = cleanHost(session.evidence.httpHostCandidates.front());
        const ProviderClassification classification = classifyDomainOrHost(host, session.observed.remoteIp);

        AttributionResult result;
        result.type = AttributionType::ExactDestination;
        result.destinationDomain = host;
        result.entityName = classification.entityName;
        result.category = classification.category;
        result.trafficClass = classification.trafficClass;
        result.source = EvidenceSource::HttpHost;
        result.confidence = ConfidenceLevel::High;
        result.ownerProcess = selectBestProcess(session.evidence);
        result.reason = "Destination was identified from HTTP Host header, which is direct application-layer evidence.";
        result.limitations = "Only visible HTTP metadata is used; encrypted content is not inspected.";

        return result;
    }


    inline AttributionResult DestinationResolver::fromDnsAnswer(
        const ConnectionSession& session
    ) const
    {
        const auto candidate = selectBestDnsCandidate(session.evidence);
        const std::string domain = candidate.has_value()
            ? cleanHost(candidate->domain)
            : std::string{};

        const ProviderClassification classification =
            classifyDomainOrHost(domain, session.observed.remoteIp);

        AttributionResult result;
        result.type = candidate.has_value() && candidate->fresh
            ? AttributionType::CorrelatedDestination
            : AttributionType::ExactDestination;

        result.destinationDomain = domain;
        result.entityName = classification.entityName;
        result.category = classification.category;
        result.trafficClass = classification.trafficClass;
        result.source = candidate.has_value() && candidate->fresh
            ? EvidenceSource::FreshDnsCorrelation
            : EvidenceSource::DnsAnswer;

        result.confidence = candidate.has_value() && candidate->fresh
            ? ConfidenceLevel::MediumHigh
            : ConfidenceLevel::High;

        result.ownerProcess = selectBestProcess(session.evidence);

        result.reason = candidate.has_value() && candidate->fresh
            ? "Destination was linked using fresh DNS correlation within the observation window."
            : "Destination was identified from DNS answer evidence.";

        result.limitations = "DNS attribution can be affected by shared CDN infrastructure, caching, and reused IP addresses.";

        return result;
    }


    inline AttributionResult DestinationResolver::fromFreshDnsCorrelation(
        const ConnectionSession& session
    ) const
    {
        const auto candidate = selectFreshDnsCandidate(session.evidence);
        const std::string domain = candidate.has_value()
            ? cleanHost(candidate->domain)
            : std::string{};

        const ProviderClassification classification =
            classifyDomainOrHost(domain, session.observed.remoteIp);

        AttributionResult result;
        result.type = AttributionType::CorrelatedDestination;
        result.destinationDomain = domain;
        result.entityName = classification.entityName;
        result.category = classification.category;
        result.trafficClass = classification.trafficClass;
        result.source = EvidenceSource::FreshDnsCorrelation;
        result.confidence = ConfidenceLevel::MediumHigh;
        result.ownerProcess = selectBestProcess(session.evidence);
        result.reason = "Destination was correlated using fresh DNS evidence near the connection time.";
        result.limitations = "This is correlated evidence, not direct SNI/Host evidence.";

        return result;
    }


    inline AttributionResult DestinationResolver::fromProviderHint(
        const ConnectionSession& session
    ) const
    {
        const auto hint = selectBestProviderHint(session.evidence);
        const ProviderClassification fallbackClassification = classifyIpAndPort(session);

        AttributionResult result;
        result.type = AttributionType::ProviderLevel;

        if (hint.has_value())
        {
            result.entityName = hint->providerName.empty()
                ? fallbackClassification.entityName
                : hint->providerName;

            result.category = hint->category.empty()
                ? fallbackClassification.category
                : hint->category;

            result.reason = hint->reason.empty()
                ? "Destination was classified at provider level using infrastructure/provider hints."
                : hint->reason;

            result.confidence = hint->confidence;
        }
        else
        {
            result.entityName = fallbackClassification.entityName;
            result.category = fallbackClassification.category;
            result.reason = fallbackClassification.reason;
            result.confidence = fallbackClassification.confidence;
        }

        result.destinationDomain.clear();
        result.trafficClass = fallbackClassification.trafficClass;
        result.source = EvidenceSource::ProviderHint;
        result.ownerProcess = selectBestProcess(session.evidence);
        result.limitations = "Provider-level attribution identifies infrastructure/category, not an exact website or application endpoint.";

        return result;
    }


    inline AttributionResult DestinationResolver::fromProcessContext(
        const ConnectionSession& session
    ) const
    {
        const auto process = selectBestProcess(session.evidence);

        AttributionResult result;
        result.type = AttributionType::ProcessAssociated;
        result.source = EvidenceSource::ProcessContext;
        result.confidence = ConfidenceLevel::Medium;
        result.ownerProcess = process;

        if (process.has_value())
        {
            const ProviderClassification classification = classifyProcess(process.value(), session);

            result.entityName = classification.entityName;
            result.category = classification.category;
            result.trafficClass = classification.trafficClass;
            result.reason = classification.reason;
            result.limitations = "Process context explains the likely origin/type of traffic, but it does not prove the exact remote service name.";
        }
        else
        {
            const ProviderClassification classification = classifyIpAndPort(session);

            result.entityName = classification.entityName;
            result.category = classification.category;
            result.trafficClass = classification.trafficClass;
            result.reason = "No domain evidence was available; destination was explained using protocol and port classification.";
            result.limitations = "No process context was available despite process fallback path.";
        }

        return result;
    }


    inline AttributionResult DestinationResolver::fromIpOnlyFallback(
        const ConnectionSession& session
    ) const
    {
        const ProviderClassification classification = classifyIpAndPort(session);

        AttributionResult result;

        if (session.encryptedLikely && config_.allowEncryptedIpOnlyFallback)
            result.type = AttributionType::EncryptedIpOnly;
        else
            result.type = AttributionType::ClassifiedIpOnly;

        result.destinationDomain.clear();
        result.entityName = classification.entityName;
        result.category = classification.category;
        result.trafficClass = classification.trafficClass;
        result.source = EvidenceSource::IpOnly;
        result.confidence = classification.confidence;
        result.ownerProcess = selectBestProcess(session.evidence);

        result.reason = classification.reason;
        result.limitations =
            "No DNS/SNI/HTTP Host evidence was available. The engine reports an explained IP-only classification instead of raw Unknown.";

        return result;
    }


    inline std::optional<ProcessCandidate> DestinationResolver::selectBestProcess(
        const EvidenceStore& evidence
    ) const
    {
        if (evidence.processCandidates.empty())
            return std::nullopt;

        // For now, select the first process candidate.
        // Later, we can rank by timestamp closeness and PID reliability.
        return evidence.processCandidates.front();
    }


    inline std::optional<ProviderHint> DestinationResolver::selectBestProviderHint(
        const EvidenceStore& evidence
    ) const
    {
        if (evidence.providerHints.empty())
            return std::nullopt;

        return *std::max_element(
            evidence.providerHints.begin(),
            evidence.providerHints.end(),
            [](const ProviderHint& a, const ProviderHint& b)
            {
                return confidenceScore(a.confidence) < confidenceScore(b.confidence);
            }
        );
    }


    inline std::optional<DnsCandidate> DestinationResolver::selectBestDnsCandidate(
        const EvidenceStore& evidence
    ) const
    {
        if (evidence.dnsCandidates.empty())
            return std::nullopt;

        auto fresh = selectFreshDnsCandidate(evidence);
        if (fresh.has_value())
            return fresh;

        return evidence.dnsCandidates.front();
    }


    inline std::optional<DnsCandidate> DestinationResolver::selectFreshDnsCandidate(
        const EvidenceStore& evidence
    ) const
    {
        auto it = std::find_if(
            evidence.dnsCandidates.begin(),
            evidence.dnsCandidates.end(),
            [](const DnsCandidate& candidate)
            {
                return candidate.fresh;
            }
        );

        if (it == evidence.dnsCandidates.end())
            return std::nullopt;

        return *it;
    }


    inline ProviderClassification DestinationResolver::classifyDomainOrHost(
        const std::string& hostOrDomain,
        const std::string& remoteIp
    ) const
    {
        // Fully automatic naming, no list of apps or companies:
        // - entity  = registrable domain of the observed name (SNI / Host / DNS),
        //             so every sub-host of one service forms one group;
        // - category = owner of the server IP from the offline ASN database.
        const std::string host = cleanHost(hostOrDomain);

        ProviderClassification result;
        result.trafficClass = "Application traffic";
        result.confidence = ConfidenceLevel::MediumHigh;

        if (host.empty())
        {
            result.entityName = "Domain evidence unavailable";
            result.category = "Explained destination";
            result.trafficClass = "Classified traffic";
            result.reason = "Domain evidence field was empty; resolver preserved an explained classification.";
            result.confidence = ConfidenceLevel::Low;
            return result;
        }

        result.entityName = registrableDomain(host);

        const AsnInfo owner = asnResolver_.lookup(remoteIp);

        result.category = owner.found
            ? owner.org + " (" + owner.asn + ")"
            : "Internet service";

        result.reason =
            "Destination named automatically from the observed name " + host +
            " (registrable domain " + result.entityName + ")" +
            (owner.found
                ? "; the server network belongs to " + owner.org + " (" + owner.asn + ")."
                : ".");

        return result;
    }


    inline std::string DestinationResolver::registrableDomain(const std::string& rawHost)
    {
        std::string host = cleanHost(rawHost);

        while (!host.empty() && host.back() == '.')
            host.pop_back();

        if (host.empty())
            return host;

        // IP literals stay as they are.
        uint32_t ipValue = 0;

        if (AsnResolver::parseIpv4(host, ipValue) || host.find(':') != std::string::npos)
            return host;

        std::vector<std::string> labels;
        size_t start = 0;

        while (start <= host.size())
        {
            const size_t dot = host.find('.', start);
            const size_t end = dot == std::string::npos ? host.size() : dot;

            if (end > start)
                labels.push_back(host.substr(start, end - start));

            if (dot == std::string::npos)
                break;

            start = dot + 1;
        }

        if (labels.size() <= 2)
            return host;

        // Country-code second-level registrations: example.co.uk,
        // example.com.au, example.gov.iq, ... take three labels.
        const std::string& top = labels[labels.size() - 1];
        const std::string& second = labels[labels.size() - 2];

        const bool countryCodeTop = top.size() == 2;

        const bool genericSecondLevel =
            second == "co" || second == "com" || second == "net" || second == "org" ||
            second == "gov" || second == "edu" || second == "ac" || second == "mil" ||
            second == "gob" || second == "or" || second == "ne" || second == "go" ||
            second == "nic" || second == "sch" || second == "info" || second == "biz";

        const size_t keep = (countryCodeTop && genericSecondLevel) ? 3 : 2;

        std::string result;

        for (size_t index = labels.size() - keep; index < labels.size(); ++index)
        {
            if (!result.empty())
                result += '.';

            result += labels[index];
        }

        return result;
    }


    inline ProviderClassification DestinationResolver::classifyIpAndPort(
        const ConnectionSession& session
    ) const
    {
        ProviderClassification result;

        const auto& observed = session.observed;
        const bool localIp = isPrivateOrLocalIp(observed.remoteIp);

        if (localIp)
        {
            result.entityName = "Local/private network endpoint";
            result.category = "Local network";
            result.trafficClass = "LAN/Internal traffic";
            result.reason = "Remote IP is private/local; no exact domain evidence was available.";
            result.confidence = ConfidenceLevel::Medium;
            return result;
        }

        {
            const AsnInfo asn = asnResolver_.lookup(observed.remoteIp);

            if (asn.found)
            {
                result.entityName = asn.org;        // owner of the server network
                result.category = asn.category;     // "Network owner AS20940 (US)"

                if (session.quicLikely)
                    result.trafficClass = "Encrypted QUIC traffic";
                else if (session.httpsLikely || session.encryptedLikely)
                    result.trafficClass = "Encrypted HTTPS traffic";
                else if (session.httpLikely)
                    result.trafficClass = "Web traffic";
                else
                    result.trafficClass = session.connectionType.empty()
                    ? "IP traffic" : session.connectionType;

                result.reason =
                    "Destination IP belongs to " + asn.org + " (" + asn.asn +
                    "), identified from the offline IP-to-ASN owner table; "
                    "no DNS/SNI/Host evidence was available.";

                result.confidence = ConfidenceLevel::Medium;
                return result;
            }
        }

        if (session.dnsLikely)
        {
            result.entityName = "DNS resolver";
            result.category = "Name resolution";
            result.trafficClass = "Infrastructure traffic";
            result.reason = "Connection matches DNS-related port/protocol behavior.";
            result.confidence = ConfidenceLevel::Medium;
            return result;
        }

        if (session.quicLikely)
        {
            result.entityName = "Encrypted QUIC IP endpoint";
            result.category = "Encrypted web traffic";
            result.trafficClass = "Encrypted IP-only";
            result.reason = "UDP/443 suggests QUIC/HTTP3, but no SNI/Host/DNS identity was available.";
            result.confidence = ConfidenceLevel::Low;
            return result;
        }

        if (session.httpsLikely || session.encryptedLikely)
        {
            result.entityName = "Encrypted HTTPS IP endpoint";
            result.category = "Encrypted web traffic";
            result.trafficClass = "Encrypted IP-only";
            result.reason = "Encrypted remote connection was detected without visible destination name.";
            result.confidence = ConfidenceLevel::Low;
            return result;
        }

        if (session.httpLikely)
        {
            result.entityName = "HTTP IP endpoint";
            result.category = "Web traffic";
            result.trafficClass = "Classified IP-only";
            result.reason = "HTTP-like traffic was detected, but no Host evidence was available.";
            result.confidence = ConfidenceLevel::Low;
            return result;
        }

        result.entityName = "Classified IP-only endpoint";
        result.category = "General IP traffic";
        result.trafficClass = session.connectionType.empty()
            ? "Classified IP-only"
            : session.connectionType;

        result.reason = "No exact destination evidence was available; protocol and remote port were preserved as an explained classification.";
        result.confidence = ConfidenceLevel::Low;

        return result;
    }


    inline ProviderClassification DestinationResolver::classifyProcess(
        const ProcessCandidate& process,
        const ConnectionSession& session
    ) const
    {
        ProviderClassification result;

        const std::string name = lowerCopy(process.processName);

        result.entityName = process.processName.empty()
            ? "Process-associated traffic"
            : process.processName;

        result.category = toString(process.originClass);
        result.trafficClass = "Process-associated traffic";
        result.reason = "No destination identity evidence was available; owner process context explains likely traffic origin.";
        result.confidence = ConfidenceLevel::Medium;

        if (name.find("chrome") != std::string::npos ||
            name.find("msedge") != std::string::npos ||
            name.find("firefox") != std::string::npos ||
            name.find("brave") != std::string::npos ||
            name.find("opera") != std::string::npos)
        {
            result.entityName = "Browser-associated traffic";
            result.category = "User/Application";
            result.trafficClass = session.encryptedLikely
                ? "Encrypted browser traffic"
                : "Browser traffic";

            result.reason = "Traffic is associated with a browser process, but no exact destination name was visible.";
            result.confidence = ConfidenceLevel::Medium;
            return result;
        }

        if (name.find("svchost") != std::string::npos ||
            name.find("searchhost") != std::string::npos ||
            name.find("system") != std::string::npos ||
            name.find("windows") != std::string::npos)
        {
            result.entityName = "Windows background/system traffic";
            result.category = "Background/System";
            result.trafficClass = "Background/System infrastructure traffic";
            result.reason = "Traffic is associated with a Windows background/system process.";
            result.confidence = ConfidenceLevel::Medium;
            return result;
        }

        if (name.find("code") != std::string::npos ||
            name.find("devenv") != std::string::npos ||
            name.find("git") != std::string::npos ||
            name.find("docker") != std::string::npos)
        {
            result.entityName = "Developer/work tool traffic";
            result.category = "Developer/Work tool";
            result.trafficClass = "Developer/Work traffic";
            result.reason = "Traffic is associated with a developer/work tool process.";
            result.confidence = ConfidenceLevel::Medium;
            return result;
        }

        if (name.find("discord") != std::string::npos ||
            name.find("steam") != std::string::npos)
        {
            result.entityName = process.processName;
            result.category = "User/Application";
            result.trafficClass = "Real-time application traffic";
            result.reason = "Traffic is associated with a known user application process.";
            result.confidence = ConfidenceLevel::Medium;
            return result;
        }

        return result;
    }


    inline std::string DestinationResolver::cleanHost(std::string host)
    {
        host = trimCopy(host);
        host = lowerCopy(host);

        while (!host.empty() && host.back() == '.')
            host.pop_back();

        if (host.rfind("www.", 0) == 0)
            host.erase(0, 4);

        return host;
    }


    inline bool DestinationResolver::containsToken(
        const std::string& text,
        const std::string& token
    )
    {
        return lowerCopy(text).find(lowerCopy(token)) != std::string::npos;
    }


    inline bool DestinationResolver::endsWithToken(
        const std::string& text,
        const std::string& token
    )
    {
        const std::string a = lowerCopy(text);
        const std::string b = lowerCopy(token);

        if (b.size() > a.size())
            return false;

        return std::equal(b.rbegin(), b.rend(), a.rbegin());
    }


    inline bool DestinationResolver::isPrivateOrLocalIp(const std::string& ip)
    {
        return ip.rfind("10.", 0) == 0 ||
            ip.rfind("192.168.", 0) == 0 ||
            ip.rfind("172.16.", 0) == 0 ||
            ip.rfind("172.17.", 0) == 0 ||
            ip.rfind("172.18.", 0) == 0 ||
            ip.rfind("172.19.", 0) == 0 ||
            ip.rfind("172.20.", 0) == 0 ||
            ip.rfind("172.21.", 0) == 0 ||
            ip.rfind("172.22.", 0) == 0 ||
            ip.rfind("172.23.", 0) == 0 ||
            ip.rfind("172.24.", 0) == 0 ||
            ip.rfind("172.25.", 0) == 0 ||
            ip.rfind("172.26.", 0) == 0 ||
            ip.rfind("172.27.", 0) == 0 ||
            ip.rfind("172.28.", 0) == 0 ||
            ip.rfind("172.29.", 0) == 0 ||
            ip.rfind("172.30.", 0) == 0 ||
            ip.rfind("172.31.", 0) == 0 ||
            ip.rfind("127.", 0) == 0 ||
            ip == "::1";
    }

} // namespace netwolf::core