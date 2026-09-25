package com.websec.scanner.scanner;

import com.websec.scanner.model.Finding;
import com.websec.scanner.model.FindingType;
import com.websec.scanner.model.Severity;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class RedirectScanner implements Scanner {

    // Package-private so tests can assert against the exact value used.
    static final String PROBE_TARGET = "https://websec-scanner-redirect-probe.invalid/";

    private static final List<String> REDIRECT_PARAMS = List.of(
            "redirect", "redirect_uri", "redirectUrl", "url", "next",
            "return", "returnUrl", "continue", "dest", "destination", "r"
    );

    private static final int SCAN_CONCURRENCY = 5;

    private final WebClient webClient;

    @Override
    public String getName() {
        return "Open Redirect Scanner";
    }

    @Override
    public Mono<List<Finding>> scan(String target) {
        log.info("[{}] Testando {} parâmetros de redirecionamento em: {}",
                getName(), REDIRECT_PARAMS.size(), target);

        return Flux.fromIterable(REDIRECT_PARAMS)
                .flatMap(param -> checkParam(target, param), SCAN_CONCURRENCY)
                .collectList();
    }

    private Mono<Finding> checkParam(String target, String param) {
        String url = buildProbeUrl(target, param);

        return webClient
                .method(HttpMethod.GET)
                .uri(url)
                .exchangeToMono(response -> {
                    Mono<Finding> result = Mono.empty();

                    if (response.statusCode().is3xxRedirection()) {
                        String location = response.headers().asHttpHeaders().getFirst("Location");
                        if (location != null && location.startsWith(PROBE_TARGET)) {
                            log.info("[{}] Possível open redirect via '{}': {}", getName(), param, url);
                            result = Mono.just(Finding.builder()
                                    .type(FindingType.REDIRECT)
                                    .severity(Severity.MEDIUM)
                                    .title("Possível Open Redirect via parâmetro: " + param)
                                    .description("O parâmetro '" + param + "' é usado para redirecionar o " +
                                            "usuário sem validar se o destino pertence ao domínio da aplicação, " +
                                            "podendo ser usado em ataques de phishing.")
                                    .evidence("GET " + url + " → " + response.statusCode().value() +
                                            " Location: " + location)
                                    .recommendation("Valide que o parâmetro de redirecionamento aponta apenas " +
                                            "para URLs internas, usando uma lista branca de destinos permitidos.")
                                    .target(url)
                                    .build());
                        }
                    }

                    return response.releaseBody().then(result);
                })
                .onErrorResume(e -> {
                    log.debug("[{}] Erro ao testar parâmetro {} em {}: {}", getName(), param, url, e.getMessage());
                    return Mono.empty();
                });
    }

    private String buildProbeUrl(String target, String param) {
        String base = target.endsWith("/") ? target.substring(0, target.length() - 1) : target;
        String separator = base.contains("?") ? "&" : "?";
        return base + separator + param + "=" + URLEncoder.encode(PROBE_TARGET, StandardCharsets.UTF_8);
    }
}
