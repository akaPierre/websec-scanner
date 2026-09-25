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

@Slf4j
@Component
@RequiredArgsConstructor
public class CorsScanner implements Scanner {

    // Package-private so tests can assert against the exact value sent.
    static final String PROBE_ORIGIN = "https://websec-scanner-cors-probe.invalid";

    private final WebClient webClient;

    @Override
    public String getName() {
        return "CORS Scanner";
    }

    @Override
    public Mono<List<Finding>> scan(String target) {
        log.info("[{}] Testando configuração de CORS em: {}", getName(), target);

        return webClient
                .method(HttpMethod.GET)
                .uri(target)
                .header(HttpHeaders.ORIGIN, PROBE_ORIGIN)
                .exchangeToMono(response -> {
                    List<Finding> findings = buildFindings(response.headers().asHttpHeaders(), target);
                    return response.releaseBody().thenReturn(findings);
                })
                .onErrorResume(e -> {
                    log.debug("[{}] Erro ao testar CORS em {}: {}", getName(), target, e.getMessage());
                    return Mono.just(List.of());
                });
    }

    private List<Finding> buildFindings(HttpHeaders headers, String target) {
        List<Finding> findings = new ArrayList<>();

        String allowOrigin = headers.getFirst("Access-Control-Allow-Origin");
        if (allowOrigin == null) return findings;

        boolean reflectsArbitraryOrigin = allowOrigin.equals(PROBE_ORIGIN);
        boolean allowsAnyOrigin = allowOrigin.equals("*");
        boolean allowsCredentials = "true".equalsIgnoreCase(headers.getFirst("Access-Control-Allow-Credentials"));

        if (reflectsArbitraryOrigin && allowsCredentials) {
            findings.add(Finding.builder()
                    .type(FindingType.CORS)
                    .severity(Severity.HIGH)
                    .title("CORS mal configurado: origem arbitrária refletida com credenciais permitidas")
                    .description("O servidor reflete qualquer valor de Origin enviado pelo cliente em " +
                            "Access-Control-Allow-Origin e também permite credenciais, possibilitando que " +
                            "qualquer site leia respostas autenticadas desta API.")
                    .evidence("Origin enviado: " + PROBE_ORIGIN + " | Access-Control-Allow-Origin: " +
                            allowOrigin + " | Access-Control-Allow-Credentials: true")
                    .recommendation("Nunca combine reflexão de Origin arbitrária com " +
                            "Access-Control-Allow-Credentials: true. Utilize uma lista branca de origens confiáveis.")
                    .target(target)
                    .build());
        } else if (reflectsArbitraryOrigin) {
            findings.add(Finding.builder()
                    .type(FindingType.CORS)
                    .severity(Severity.MEDIUM)
                    .title("CORS reflete origem arbitrária")
                    .description("O servidor reflete qualquer valor de Origin enviado pelo cliente em " +
                            "Access-Control-Allow-Origin, permitindo que outros sites leiam respostas desta API.")
                    .evidence("Origin enviado: " + PROBE_ORIGIN + " | Access-Control-Allow-Origin: " + allowOrigin)
                    .recommendation("Restrinja Access-Control-Allow-Origin a uma lista branca de origens confiáveis.")
                    .target(target)
                    .build());
        } else if (allowsAnyOrigin) {
            findings.add(Finding.builder()
                    .type(FindingType.CORS)
                    .severity(Severity.LOW)
                    .title("CORS permite qualquer origem (*)")
                    .description("O servidor permite requisições de qualquer origem via " +
                            "Access-Control-Allow-Origin: *. Aceitável para APIs públicas sem dados sensíveis.")
                    .evidence("Access-Control-Allow-Origin: *")
                    .recommendation("Confirme que esta API não expõe dados sensíveis; caso contrário, " +
                            "restrinja as origens permitidas.")
                    .target(target)
                    .build());
        }

        return findings;
    }
}
