package com.websec.scanner.scanner;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtScanner implements Scanner {

    private static final Pattern JWT_PATTERN = Pattern.compile(
            "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*$");

    private final WebClient webClient;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String getName() {
        return "JWT Scanner";
    }

    @Override
    public Mono<List<Finding>> scan(String target) {
        log.info("[{}] Procurando tokens JWT em: {}", getName(), target);

        return webClient
                .method(HttpMethod.GET)
                .uri(target)
                .exchangeToMono(response -> {
                    List<Finding> findings = buildFindings(response.headers().asHttpHeaders(), target);
                    return response.releaseBody().thenReturn(findings);
                })
                .onErrorResume(e -> {
                    log.debug("[{}] Erro ao analisar {}: {}", getName(), target, e.getMessage());
                    return Mono.just(List.of());
                });
    }

    private List<Finding> buildFindings(HttpHeaders headers, String target) {
        List<Finding> findings = new ArrayList<>();
        List<String> cookies = headers.get(HttpHeaders.SET_COOKIE);
        if (cookies == null) return findings;

        for (String cookie : cookies) {
            String[] parts = cookie.split(";", 2)[0].split("=", 2);
            if (parts.length != 2) continue;

            String cookieName = parts[0].trim();
            String value = parts[1].trim();

            if (!JWT_PATTERN.matcher(value).matches()) continue;

            checkJwt(cookieName, value, target, findings);
        }

        return findings;
    }

    private void checkJwt(String cookieName, String token, String target, List<Finding> findings) {
        String[] segments = token.split("\\.");
        if (segments.length < 2) return;

        try {
            String headerJson = new String(
                    Base64.getUrlDecoder().decode(padBase64Url(segments[0])), StandardCharsets.UTF_8);
            JsonNode headerNode = objectMapper.readTree(headerJson);
            String alg = headerNode.path("alg").asText("");

            if ("none".equalsIgnoreCase(alg)) {
                findings.add(Finding.builder()
                        .type(FindingType.JWT)
                        .severity(Severity.HIGH)
                        .title("Token JWT com algoritmo 'none': " + cookieName)
                        .description("O JWT no cookie '" + cookieName + "' declara o algoritmo 'none', " +
                                "que pode permitir a um atacante forjar tokens não assinados caso o servidor " +
                                "não valide o algoritmo corretamente.")
                        .evidence("Cookie: " + cookieName + " | Header JWT: " + headerJson)
                        .recommendation("Nunca aceite 'alg: none' ao validar JWTs. Fixe explicitamente o " +
                                "algoritmo esperado na biblioteca de verificação.")
                        .target(target)
                        .build());
            }
        } catch (Exception e) {
            log.debug("[{}] Não foi possível decodificar JWT do cookie {}: {}", getName(), cookieName, e.getMessage());
        }
    }

    private String padBase64Url(String segment) {
        int padding = (4 - segment.length() % 4) % 4;
        return segment + "=".repeat(padding);
    }
}
