package com.websec.scanner.scanner;

import com.websec.scanner.config.ScannerConfig;
import com.websec.scanner.model.Finding;
import com.websec.scanner.model.FindingType;
import com.websec.scanner.model.Severity;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class EndpointScanner implements Scanner {

    private final WebClient webClient;
    private final ScannerConfig config;

    private static final Map<String, Severity> ENDPOINT_SEVERITY = Map.ofEntries(
            Map.entry("/.git",                Severity.HIGH),
            Map.entry("/.env",                Severity.HIGH),
            Map.entry("/backup",              Severity.HIGH),
            Map.entry("/backup.zip",          Severity.HIGH),
            Map.entry("/backup.sql",          Severity.HIGH),
            Map.entry("/config",              Severity.HIGH),
            Map.entry("/config.php",          Severity.HIGH),
            Map.entry("/actuator/env",        Severity.HIGH),
            Map.entry("/phpmyadmin",          Severity.HIGH),
            Map.entry("/admin",               Severity.MEDIUM),
            Map.entry("/administrator",       Severity.MEDIUM),
            Map.entry("/panel",               Severity.MEDIUM),
            Map.entry("/dashboard",           Severity.MEDIUM),
            Map.entry("/wp-admin",            Severity.MEDIUM),
            Map.entry("/wp-login.php",        Severity.MEDIUM),
            Map.entry("/console",             Severity.MEDIUM),
            Map.entry("/actuator",            Severity.MEDIUM),
            Map.entry("/actuator/health",     Severity.LOW),
            Map.entry("/swagger-ui.html",     Severity.LOW),
            Map.entry("/api",                 Severity.LOW),
            Map.entry("/api/v1",              Severity.LOW),
            Map.entry("/api/v2",              Severity.LOW),
            Map.entry("/robots.txt",          Severity.INFO),
            Map.entry("/sitemap.xml",         Severity.INFO),
            Map.entry("/.well-known/security.txt", Severity.INFO)
    );

    @Override
    public String getName() {
        return "Endpoint Scanner";
    }

    @Override
    public Mono<List<Finding>> scan(String target) {
        List<String> endpoints = loadEndpoints();
        log.info("[{}] Testando {} endpoints em: {}", getName(), endpoints.size(), target);

        Duration delay = Duration.ofMillis(Math.max(0, config.getEndpointDelayMs()));

        return Flux.fromIterable(endpoints)
                .delayElements(delay)
                .concatMap(endpoint -> checkEndpoint(normalizeTarget(target) + endpoint, endpoint))
                .collectList();
    }

    private Mono<Finding> checkEndpoint(String url, String endpoint) {
        return webClient
                .method(HttpMethod.GET)
                .uri(url)
                // exchangeToMono (not retrieve()) is required here: retrieve()
                // throws WebClientResponseException for any 4xx/5xx status by
                // default, which would swallow the 403 case below as an error
                // before it ever reached the status check.
                .exchangeToMono(response -> {
                    int statusCode = response.statusCode().value();

                    boolean resourceExists = statusCode == 200
                            || statusCode == 201
                            || statusCode == 301
                            || statusCode == 302
                            || statusCode == 403;

                    Mono<Finding> finding = resourceExists
                            ? Mono.just(buildFinding(url, endpoint, statusCode))
                            : Mono.empty();

                    return response.releaseBody().then(finding);
                })
                .onErrorResume(e -> {
                    log.debug("[{}] Endpoint inacessível: {} → {}", getName(), url, e.getMessage());
                    return Mono.empty();
                });
    }

    private Finding buildFinding(String url, String endpoint, int statusCode) {
        Severity severity = ENDPOINT_SEVERITY.getOrDefault(endpoint, Severity.LOW);
        String statusDescription = describeStatus(statusCode);

        log.info("[{}] Endpoint encontrado: {} → HTTP {}", getName(), url, statusCode);

        return Finding.builder()
                .type(FindingType.ENDPOINT)
                .severity(severity)
                .title("Endpoint sensível acessível: " + endpoint)
                .description(getEndpointDescription(endpoint, statusCode))
                .evidence("GET " + url + " → HTTP " + statusCode + " " + statusDescription)
                .recommendation(getEndpointRecommendation(endpoint))
                .target(url)
                .build();
    }

    private List<String> loadEndpoints() {
        List<String> endpoints = new ArrayList<>();
        try {
            var resource = new ClassPathResource("wordlists/endpoints.txt");
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#")) {
                        endpoints.add(line);
                    }
                }
            }
        } catch (Exception e) {
            log.warn("[{}] Não foi possível carregar wordlist, usando lista padrão", getName());
            endpoints = List.of("/.git", "/.env", "/admin", "/backup", "/actuator/env");
        }
        return endpoints;
    }

    private String normalizeTarget(String target) {
        return target.endsWith("/") ? target.substring(0, target.length() - 1) : target;
    }

    private String describeStatus(int code) {
        return switch (code) {
            case 200 -> "OK (acesso total)";
            case 201 -> "Created";
            case 301 -> "Moved Permanently";
            case 302 -> "Found (redirect)";
            case 403 -> "Forbidden (existe mas acesso negado)";
            default  -> String.valueOf(code);
        };
    }

    private String getEndpointDescription(String endpoint, int statusCode) {
        String base = switch (endpoint) {
            case "/.git"           -> "Diretório .git exposto pode revelar código-fonte completo da aplicação.";
            case "/.env"           -> "Arquivo .env pode conter senhas, chaves de API e tokens secretos.";
            case "/backup",
                 "/backup.zip",
                 "/backup.sql"     -> "Arquivo de backup acessível pode conter dados sensíveis ou dump do banco.";
            case "/config",
                 "/config.php"     -> "Arquivo de configuração pode expor credenciais e parâmetros internos.";
            case "/actuator/env"   -> "Spring Actuator /env expõe variáveis de ambiente, incluindo senhas e tokens.";
            case "/phpmyadmin"     -> "PHPMyAdmin exposto permite ataques de força bruta ao banco de dados.";
            case "/wp-admin",
                 "/wp-login.php"   -> "Painel WordPress acessível publicamente. Sujeito a ataques de força bruta.";
            case "/swagger-ui.html"-> "Documentação Swagger exposta revela todos os endpoints da API.";
            default                -> "Endpoint sensível acessível publicamente.";
        };

        if (statusCode == 403) {
            base += " (Retornou 403 - o recurso existe mas está bloqueado. Verifique se o bloqueio é suficiente.)";
        }
        return base;
    }

    private String getEndpointRecommendation(String endpoint) {
        return switch (endpoint) {
            case "/.git"     -> "Bloqueie acesso ao diretório .git via configuração do servidor web. Nunca faça deploy com .git exposto.";
            case "/.env"     -> "Remova o .env do diretório público. Use variáveis de ambiente do sistema operacional ou cofres de segredos.";
            case "/backup",
                 "/backup.zip",
                 "/backup.sql" -> "Mova backups para fora do diretório web ou restrinja acesso por IP.";
            case "/actuator",
                 "/actuator/env",
                 "/actuator/health" -> "Proteja os endpoints do Spring Actuator com autenticação. Em produção, exponha apenas /health.";
            case "/swagger-ui.html" -> "Desabilite Swagger em produção ou proteja com autenticação.";
            default -> "Restrinja o acesso a este endpoint por IP, autenticação ou remova se não for necessário.";
        };
    }
}
