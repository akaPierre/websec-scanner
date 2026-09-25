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
import reactor.core.publisher.Mono;

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
    public Mono<List<Finding>> scan(String target) {
        log.info("[{}] Analisando headers de: {}", getName(), target);

        return webClient
                .method(HttpMethod.GET)
                .uri(target)
                // exchangeToMono (not retrieve()) is required here: retrieve()
                // throws for any 4xx/5xx status by default, which would skip
                // header analysis entirely on WAF blocks or error pages.
                .exchangeToMono(response -> {
                    List<Finding> findings = buildFindings(response.headers().asHttpHeaders(), target);
                    return response.releaseBody().thenReturn(findings);
                })
                .onErrorResume(e -> {
                    log.warn("[{}] Erro ao conectar em {}: {}", getName(), target, e.getMessage());
                    return Mono.just(List.of());
                });
    }

    private List<Finding> buildFindings(HttpHeaders headers, String target) {
        List<Finding> findings = new ArrayList<>();

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
        checkCookieFlags(headers, target, findings);
        return findings;
    }

    // Package-private so tests can exercise the Secure-flag branch directly
    // against an "https://" target without needing a real TLS handshake.
    void checkCookieFlags(HttpHeaders headers, String target, List<Finding> findings) {
        List<String> cookies = headers.get(HttpHeaders.SET_COOKIE);
        if (cookies == null) return;

        boolean isHttps = target.startsWith("https://");

        for (String cookie : cookies) {
            String cookieName = cookie.split("=", 2)[0].trim();
            String lower = cookie.toLowerCase();

            if (isHttps && !lower.contains("secure")) {
                findings.add(cookieFinding(target, cookieName, "Secure", Severity.MEDIUM,
                        "O cookie '" + cookieName + "' não possui o atributo Secure, podendo ser " +
                                "transmitido em uma conexão HTTP não criptografada.",
                        "Adicione o atributo 'Secure' para garantir que o cookie só seja enviado via HTTPS."));
            }

            if (!lower.contains("httponly")) {
                findings.add(cookieFinding(target, cookieName, "HttpOnly", Severity.MEDIUM,
                        "O cookie '" + cookieName + "' não possui o atributo HttpOnly, podendo ser " +
                                "acessado via JavaScript (risco de roubo em ataques XSS).",
                        "Adicione o atributo 'HttpOnly' para impedir acesso ao cookie via JavaScript."));
            }

            if (!lower.contains("samesite")) {
                findings.add(cookieFinding(target, cookieName, "SameSite", Severity.LOW,
                        "O cookie '" + cookieName + "' não possui o atributo SameSite, ficando mais " +
                                "exposto a ataques CSRF.",
                        "Adicione o atributo 'SameSite=Strict' ou 'SameSite=Lax' ao cookie."));
            }
        }
    }

    private Finding cookieFinding(String target, String cookieName, String missingAttribute,
                                   Severity severity, String description, String recommendation) {
        return Finding.builder()
                .type(FindingType.COOKIE)
                .severity(severity)
                .title("Cookie sem atributo " + missingAttribute + ": " + cookieName)
                .description(description)
                .evidence("Set-Cookie: " + cookieName + " (sem " + missingAttribute + ")")
                .recommendation(recommendation)
                .target(target)
                .build();
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
