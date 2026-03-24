package com.websec.scanner.scanner;

import com.websec.scanner.model.Finding;
import com.websec.scanner.model.FindingType;
import com.websec.scanner.model.Severity;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientException;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class HttpScanner implements Scanner {

    private final WebClient webClient;

    @Override
    public String getName() {
        return "HTTP/SSL Scanner";
    }

    @Override
    public List<Finding> scan(String target) {
        List<Finding> findings = new ArrayList<>();
        log.info("[{}] Analisando protocolo de: {}", getName(), target);

        if (target.startsWith("http://")) {
            findings.add(Finding.builder()
                    .type(FindingType.SSL)
                    .severity(Severity.HIGH)
                    .title("Site acessível via HTTP sem criptografia")
                    .description("O alvo responde em HTTP puro, expondo dados em trânsito sem criptografia.")
                    .evidence("URL acessível via HTTP: " + target)
                    .recommendation("Configure redirecionamento obrigatório de HTTP para HTTPS e implemente HSTS.")
                    .target(target)
                    .build());

            checkHttpsRedirect(target, findings);
        }

        String httpsTarget = target.startsWith("http://")
                ? target.replace("http://", "https://")
                : target;

        checkSslCertificate(httpsTarget, findings);

        return findings;
    }

    private void checkHttpsRedirect(String httpTarget, List<Finding> findings) {
        try {
            ClientResponse response = webClient
                    .method(HttpMethod.GET)
                    .uri(httpTarget)
                    .exchange()
                    .block();

            if (response == null) return;

            HttpStatus status = (HttpStatus) response.statusCode();
            response.releaseBody().block();
            boolean isRedirect = status.is3xxRedirection();
            String location = response.headers().asHttpHeaders().getFirst("Location");
            boolean redirectsToHttps = location != null && location.startsWith("https://");

            if (!isRedirect || !redirectsToHttps) {
                findings.add(Finding.builder()
                        .type(FindingType.SSL)
                        .severity(Severity.HIGH)
                        .title("Sem redirecionamento HTTP → HTTPS")
                        .description("O servidor não redireciona automaticamente conexões HTTP para HTTPS.")
                        .evidence("Status HTTP: " + status.value() +
                                (location != null ? " | Location: " + location : " | Sem header Location"))
                        .recommendation("Configure redirect 301 de todas as rotas HTTP para HTTPS.")
                        .target(httpTarget)
                        .build());
            } else {
                log.info("[{}] Redirecionamento HTTP→HTTPS encontrado em: {}", getName(), httpTarget);
            }

        } catch (WebClientException e) {
            log.warn("[{}] Erro ao verificar redirect de {}: {}", getName(), httpTarget, e.getMessage());
        }
    }

    private void checkSslCertificate(String httpsTarget, List<Finding> findings) {
        WebClient strictClient = WebClient.builder()
                .defaultHeader("User-Agent", "WebSec-Scanner/1.0")
                .build();

        try {
            strictClient
                    .method(HttpMethod.GET)
                    .uri(httpsTarget)
                    .retrieve()
                    .toBodilessEntity()
                    .block();

            log.info("[{}] Certificado SSL válido em: {}", getName(), httpsTarget);

        } catch (Exception e) {
            String errorMsg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();

            boolean isSslError = errorMsg.toLowerCase().contains("ssl")
                    || errorMsg.toLowerCase().contains("certificate")
                    || errorMsg.toLowerCase().contains("pkix")
                    || errorMsg.toLowerCase().contains("handshake");

            if (isSslError) {
                findings.add(Finding.builder()
                        .type(FindingType.SSL)
                        .severity(Severity.HIGH)
                        .title("Certificado SSL inválido ou expirado")
                        .description("O certificado SSL do servidor não é confiável ou está expirado.")
                        .evidence("Erro SSL ao conectar: " + errorMsg)
                        .recommendation("Renove ou corrija o certificado SSL. Utilize Let's Encrypt para certificados gratuitos.")
                        .target(httpsTarget)
                        .build());
            }
        }
    }
}