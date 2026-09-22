package com.websec.scanner.scanner;

import com.websec.scanner.model.Finding;
import com.websec.scanner.model.FindingType;
import com.websec.scanner.model.Severity;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class FingerprintScanner implements Scanner {

    private final WebClient webClient;

    private static final Map<String, String> COOKIE_FINGERPRINTS = Map.of(
            "PHPSESSID",   "PHP",
            "JSESSIONID",  "Java EE / Spring",
            "ASP.NET_SessionId", "ASP.NET",
            "laravel_session", "Laravel (PHP)",
            "connect.sid", "Node.js / Express",
            "django_session", "Django (Python)",
            "rack.session", "Ruby on Rails"
    );

    private static final Map<String, String> HEADER_FINGERPRINTS = Map.of(
            "X-AspNet-Version",    "ASP.NET",
            "X-AspNetMvc-Version", "ASP.NET MVC",
            "X-Generator",         "CMS detectado via X-Generator",
            "X-Drupal-Cache",      "Drupal CMS",
            "X-Joomla-Version",    "Joomla CMS"
    );

    @Override
    public String getName() {
        return "Fingerprint Scanner";
    }

    @Override
    public Mono<List<Finding>> scan(String target) {
        log.info("[{}] Identificando tecnologias em: {}", getName(), target);

        return webClient
                .method(HttpMethod.GET)
                .uri(target)
                // exchangeToMono (not retrieve()) is required here: retrieve()
                // throws for any 4xx/5xx status by default, which would skip
                // fingerprinting entirely on WAF blocks or error pages.
                .exchangeToMono(response -> {
                    List<Finding> findings = buildFindings(response.headers().asHttpHeaders(), target);
                    return response.releaseBody().thenReturn(findings);
                })
                .onErrorResume(e -> {
                    log.warn("[{}] Erro ao analisar {}: {}", getName(), target, e.getMessage());
                    return Mono.just(List.of());
                });
    }

    private List<Finding> buildFindings(HttpHeaders headers, String target) {
        List<Finding> findings = new ArrayList<>();

        HEADER_FINGERPRINTS.forEach((headerName, tech) -> {
            List<String> values = headers.get(headerName);
            if (values != null && !values.isEmpty()) {
                findings.add(buildFingerprintFinding(
                        target, tech, headerName + ": " + values.get(0)
                ));
            }
        });

        List<String> cookies = headers.get("Set-Cookie");
        if (cookies != null) {
            for (String cookie : cookies) {
                COOKIE_FINGERPRINTS.forEach((cookieName, tech) -> {
                    if (cookie.toLowerCase().contains(cookieName.toLowerCase())) {
                        findings.add(buildFingerprintFinding(
                                target, tech, "Cookie detectado: " + cookieName
                        ));
                    }
                });
            }
        }

        List<String> serverHeader = headers.get("Server");
        if (serverHeader != null && !serverHeader.isEmpty()) {
            String serverValue = serverHeader.get(0);
            findings.add(Finding.builder()
                    .type(FindingType.FINGERPRINT)
                    .severity(Severity.INFO)
                    .title("Tecnologia identificada via header Server")
                    .description("O servidor identificou-se como: " + serverValue)
                    .evidence("Server: " + serverValue)
                    .recommendation("Oculte ou generalize o header 'Server' para dificultar reconhecimento.")
                    .target(target)
                    .build());
        }

        List<String> poweredBy = headers.get("X-Powered-By");
        if (poweredBy != null && !poweredBy.isEmpty()) {
            findings.add(Finding.builder()
                    .type(FindingType.FINGERPRINT)
                    .severity(Severity.LOW)
                    .title("Tecnologia de backend identificada via X-Powered-By")
                    .description("O header X-Powered-By revela a tecnologia do servidor.")
                    .evidence("X-Powered-By: " + poweredBy.get(0))
                    .recommendation("Remova o header X-Powered-By. No Spring Boot: server.server-header='' no application.properties.")
                    .target(target)
                    .build());
        }

        return findings;
    }

    private Finding buildFingerprintFinding(String target, String tech, String evidence) {
        return Finding.builder()
                .type(FindingType.FINGERPRINT)
                .severity(Severity.INFO)
                .title("Tecnologia identificada: " + tech)
                .description("A tecnologia '" + tech + "' foi identificada via análise de headers/cookies.")
                .evidence(evidence)
                .recommendation("Considere ocultar indicadores de tecnologia para dificultar reconhecimento por atacantes.")
                .target(target)
                .build();
    }
}
