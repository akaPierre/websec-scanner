package com.websec.scanner.scanner;

import com.websec.scanner.model.Finding;
import com.websec.scanner.model.FindingType;
import com.websec.scanner.model.Severity;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class HeaderScanner implements Scanner {
    
    private final WebClient webClient;

    private static final Map<String, Severity> SECURITY_HEADERS = Map.of(
        "Content-Security-Policy",   Severity.HIGH,
            "X-Frame-Options",           Severity.MEDIUM,
            "X-Content-Type-Options",    Severity.MEDIUM,
            "Strict-Transport-Security", Severity.HIGH,
            "Referrer-Policy",           Severity.LOW,
            "Permissions-Policy",        Severity.LOW
    );

    @Override
    public String getName() {
        return "Header Scanner";
    }

    @Override
    public List<Finding> scan(String target) {
        List<Finding> findings = new ArrayList<>();
        log.info("[{}] Analisando headers de: {}", getName(), target);

        try {
            HttpHeaders headers = webClient
                    .method(HttpMethod.GET)
                    .uri(target)
                    .retrieve()
                    .toBodilessEntity()
                    .map(response -> response.getHeaders())
                    .onErrorReturn(HttpHeaders.EMPTY)
                    .block();

            if (headers == null || headers.isEmpty()) {
                log.warn("[{}] Não foi possível obter headers de: {}", getName(), target);
                return findings;
            }

            SECURITY_HEADERS.forEach((headerName, severity) -> {
                if (!headers.containsKey(headerName)) {
                    findings.add(Finding.builder()
                            .type(FindingType.HEADER)
                            .severity(severity)
                            .title("Header de segurança ausente: " + headerName)
                            .description("O header '" + headerName + "' não está presente na resposta HTTP.")
                            .evidence("Header não encontrado na resposta de: " + target)
                            .recommendation(getRecommendation(headerName))
                            .target(target)
                            .build());
                }
            });

            checkExposedHeaders(headers, target, findings);
        } catch (WebClientException e) {
            log.warn("[{}] Erro ao conectar em {}: {}", getName(), target, e.getMessage());
        }

        return findings;
    }

    private void checkExposedHeaders(HttpHeaders headers, String target, List<Finding> findings) {
        List<String> serverHeader = headers.get("Server");
        if (serverHeader != null && !serverHeader.isEmpty()) {
            String value = serverHeader.get(0);

            if (value.matches(".*[0-9]+.*")) {
                findings.add(Finding.builder()
                        .type(FindingType.FINGERPRINT)
                        .severity(Severity.LOW)
                        .title("Versão do servidor exposta no header 'Server'")
                        .description("O header 'Server' revela a versão do software, facilitando ataques direcionados.")
                        .evidence("Server: " + value)
                        .recommendation("Configure o servidor para omitir ou generalizar o header 'Server'.")
                        .target(target)
                        .build());
            }
        }

        List<String> poweredBy = headers.get("X-Powered-By");
        if (poweredBy != null && !poweredBy.isEmpty()) {
            findings.add(Finding.builder()
                    .type(FindingType.FINGERPRINT)
                    .severity(Severity.LOW)
                    .title("Tecnologia exposta no header 'X-Powered-By'")
                    .description("O header 'X-Powered-By' revela a tecnologia utilizada no backend.")
                    .evidence("X-Powered-By: " + poweredBy.get(0))
                    .recommendation("Remova o header 'X-Powered-By' da configuração do servidor/framework.")
                    .target(target)
                    .build());
        }
    }

    private String getRecommendation(String headerName) {
        return switch (headerName) {
            case "Content-Security-Policy" ->
                    "Adicione o header CSP para restringir fontes de conteúdo. Ex: Content-Security-Policy: default-src 'self'";
            case "X-Frame-Options" ->
                    "Adicione: X-Frame-Options: DENY ou SAMEORIGIN para prevenir clickjacking.";
            case "X-Content-Type-Options" ->
                    "Adicione: X-Content-Type-Options: nosniff para prevenir MIME-type sniffing.";
            case "Strict-Transport-Security" ->
                    "Adicione: Strict-Transport-Security: max-age=31536000; includeSubDomains para forçar HTTPS.";
            case "Referrer-Policy" ->
                    "Adicione: Referrer-Policy: strict-origin-when-cross-origin para controlar informações de referência.";
            case "Permissions-Policy" ->
                    "Adicione Permissions-Policy para restringir acesso a APIs do navegador (câmera, microfone, etc).";
            default -> "Consulte as diretrizes OWASP Secure Headers Project.";
        };
    }
}