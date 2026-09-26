package com.websec.scanner.engine;

import com.websec.scanner.model.Finding;
import com.websec.scanner.model.ScanReport;
import com.websec.scanner.scanner.*;
import com.websec.scanner.scope.ScopeChecker;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class ScanEngine {

    private static final int HOST_CONCURRENCY = 5;

    private final SubdomainScanner subdomainScanner;
    private final HeaderScanner headerScanner;
    private final HttpScanner httpScanner;
    private final PortScanner portScanner;
    private final EndpointScanner endpointScanner;
    private final FingerprintScanner fingerprintScanner;
    private final CorsScanner corsScanner;
    private final JwtScanner jwtScanner;
    private final RedirectScanner redirectScanner;
    private final ScopeChecker scopeChecker;

    public ScanReport run(String domain) {
        log.info("========================================");
        log.info("  WebSec Scanner - Iniciando scan");
        log.info("  Alvo: {}", domain);
        log.info("========================================");

        long startTime = Instant.now().toEpochMilli();
        String startedAt = ScanReport.now();
        List<Finding> allFindings = new ArrayList<>();

        log.info("[Engine] FASE 1 — Descoberta de subdomínios");
        List<String> activeHosts = subdomainScanner
                .discoverHostsWithFindings(domain, allFindings);

        int beforeScopeFilter = activeHosts.size();
        activeHosts = activeHosts.stream().filter(scopeChecker::isInScope).toList();
        if (activeHosts.size() != beforeScopeFilter) {
            log.warn("[Engine] {} host(s) fora do escopo configurado foram ignorados",
                    beforeScopeFilter - activeHosts.size());
        }

        log.info("[Engine] {} hosts ativos para análise", activeHosts.size());

        log.info("[Engine] FASE 2 — Análise de cada host (concorrente)");
        allFindings.addAll(scanHosts(activeHosts));

        log.info("[Engine] FASE 3 — Scan de portas em: {}", domain);
        allFindings.addAll(portScanner.scan(domain).block());

        long duration = Instant.now().toEpochMilli() - startTime;

        ScanReport report = ScanReport.builder()
                .domain(domain)
                .scannedAt(startedAt)
                .scanDuration(duration / 1000.0 + "s")
                .totalFindings(allFindings.size())
                .findings(allFindings)
                .build();

        log.info("========================================");
        log.info("[Engine] Scan concluído em {}s | {} findings",
                duration / 1000.0, allFindings.size());
        log.info("========================================");

        return report;
    }

    private List<Finding> scanHosts(List<String> activeHosts) {
        return Flux.fromIterable(activeHosts)
                .flatMap(this::scanSingleHost, HOST_CONCURRENCY)
                .collectList()
                .map(perHostFindings -> perHostFindings.stream()
                        .flatMap(List::stream)
                        .toList())
                .block();
    }

    private Mono<List<Finding>> scanSingleHost(String host) {
        log.info("[Engine] ▶ Analisando: {}", host);

        return Mono.zip(
                httpScanner.scan(host),
                headerScanner.scan(host),
                endpointScanner.scan(host),
                fingerprintScanner.scan(host),
                corsScanner.scan(host),
                jwtScanner.scan(host),
                redirectScanner.scan(host)
        ).map(results -> {
            List<Finding> merged = new ArrayList<>();
            merged.addAll(results.getT1());
            merged.addAll(results.getT2());
            merged.addAll(results.getT3());
            merged.addAll(results.getT4());
            merged.addAll(results.getT5());
            merged.addAll(results.getT6());
            merged.addAll(results.getT7());
            return merged;
        });
    }
}
