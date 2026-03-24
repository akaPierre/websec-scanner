package com.websec.scanner.engine;

import com.websec.scanner.model.Finding;
import com.websec.scanner.model.ScanReport;
import com.websec.scanner.scanner.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class ScanEngine {

    private final SubdomainScanner subdomainScanner;
    private final HeaderScanner headerScanner;
    private final HttpScanner httpScanner;
    private final PortScanner portScanner;
    private final EndpointScanner endpointScanner;
    private final FingerprintScanner fingerprintScanner;

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

        log.info("[Engine] {} hosts ativos para análise", activeHosts.size());

        log.info("[Engine] FASE 2 — Análise de cada host");
        for (String host : activeHosts) {
            log.info("[Engine] ▶ Analisando: {}", host);
            allFindings.addAll(httpScanner.scan(host));
            allFindings.addAll(headerScanner.scan(host));
            allFindings.addAll(endpointScanner.scan(host));
            allFindings.addAll(fingerprintScanner.scan(host));
        }

        log.info("[Engine] FASE 3 — Scan de portas em: {}", domain);
        allFindings.addAll(portScanner.scan(domain));

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
}