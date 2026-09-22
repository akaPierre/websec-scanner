package com.websec.scanner.scanner;

import com.websec.scanner.model.Finding;
import com.websec.scanner.model.FindingType;
import com.websec.scanner.model.Severity;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
public class HttpScanner implements Scanner {

    private final WebClient webClient;
    private final WebClient strictClient;

    @Autowired
    public HttpScanner(WebClient webClient) {
        this(webClient, WebClient.builder()
                // No insecure trust manager here on purpose: this client is used to
                // validate that the target's certificate is actually trustworthy.
                .defaultHeader("User-Agent", "WebSec-Scanner/1.0")
                .build());
    }

    // Visible for tests: lets a test point the cert-validation client at a
    // mock server instead of performing a real TLS handshake.
    HttpScanner(WebClient webClient, WebClient strictClient) {
        this.webClient = webClient;
        this.strictClient = strictClient;
    }

    @Override
    public String getName() {
        return "HTTP/SSL Scanner";
    }

    @Override
    public Mono<List<Finding>> scan(String target) {
        log.info("[{}] Analisando protocolo de: {}", getName(), target);

        boolean isPlainHttp = target.startsWith("http://");
        String httpsTarget = isPlainHttp ? target.replace("http://", "https://") : target;

        Mono<List<Finding>> redirectCheck = isPlainHttp
                ? checkHttpsRedirect(target)
                : Mono.just(List.of());

        Mono<List<Finding>> sslCheck = checkSslCertificate(httpsTarget);

        return Mono.zip(redirectCheck, sslCheck, (redirectFindings, sslFindings) -> {
            List<Finding> findings = new ArrayList<>();
            if (isPlainHttp) {
                findings.add(plainHttpFinding(target));
            }
            findings.addAll(redirectFindings);
            findings.addAll(sslFindings);
            return findings;
        });
    }

    private Finding plainHttpFinding(String target) {
        return Finding.builder()
                .type(FindingType.SSL)
                .severity(Severity.HIGH)
                .title("Site acessível via HTTP sem criptografia")
                .description("O alvo responde em HTTP puro, expondo dados em trânsito sem criptografia.")
                .evidence("URL acessível via HTTP: " + target)
                .recommendation("Configure redirecionamento obrigatório de HTTP para HTTPS e implemente HSTS.")
                .target(target)
                .build();
    }

    private Mono<List<Finding>> checkHttpsRedirect(String httpTarget) {
        return webClient
                .method(HttpMethod.GET)
                .uri(httpTarget)
                .exchangeToMono(response -> {
                    boolean isRedirect = response.statusCode().is3xxRedirection();
                    String location = response.headers().asHttpHeaders().getFirst("Location");
                    boolean redirectsToHttps = location != null && location.startsWith("https://");

                    List<Finding> findings = new ArrayList<>();
                    if (!isRedirect || !redirectsToHttps) {
                        findings.add(Finding.builder()
                                .type(FindingType.SSL)
                                .severity(Severity.HIGH)
                                .title("Sem redirecionamento HTTP → HTTPS")
                                .description("O servidor não redireciona automaticamente conexões HTTP para HTTPS.")
                                .evidence("Status HTTP: " + response.statusCode().value() +
                                        (location != null ? " | Location: " + location : " | Sem header Location"))
                                .recommendation("Configure redirect 301 de todas as rotas HTTP para HTTPS.")
                                .target(httpTarget)
                                .build());
                    } else {
                        log.info("[{}] Redirecionamento HTTP→HTTPS encontrado em: {}", getName(), httpTarget);
                    }

                    return response.releaseBody().thenReturn(findings);
                })
                .onErrorResume(e -> {
                    log.warn("[{}] Erro ao verificar redirect de {}: {}", getName(), httpTarget, e.getMessage());
                    return Mono.just(List.of());
                });
    }

    private Mono<List<Finding>> checkSslCertificate(String httpsTarget) {
        return strictClient
                .method(HttpMethod.GET)
                .uri(httpsTarget)
                .retrieve()
                .toBodilessEntity()
                .doOnSuccess(r -> log.info("[{}] Certificado SSL válido em: {}", getName(), httpsTarget))
                .thenReturn(List.<Finding>of())
                .onErrorResume(e -> {
                    String errorMsg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();

                    if (!isSslRelatedError(errorMsg)) {
                        return Mono.just(List.of());
                    }

                    return Mono.just(List.of(Finding.builder()
                            .type(FindingType.SSL)
                            .severity(Severity.HIGH)
                            .title("Certificado SSL inválido ou expirado")
                            .description("O certificado SSL do servidor não é confiável ou está expirado.")
                            .evidence("Erro SSL ao conectar: " + errorMsg)
                            .recommendation("Renove ou corrija o certificado SSL. Utilize Let's Encrypt para certificados gratuitos.")
                            .target(httpsTarget)
                            .build()));
                });
    }

    // Package-private and pure so it can be unit tested without any I/O.
    static boolean isSslRelatedError(String errorMessage) {
        String lower = errorMessage.toLowerCase();
        return lower.contains("ssl")
                || lower.contains("certificate")
                || lower.contains("pkix")
                || lower.contains("handshake");
    }
}
