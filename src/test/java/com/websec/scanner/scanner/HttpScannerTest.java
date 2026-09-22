package com.websec.scanner.scanner;

import com.websec.scanner.model.FindingType;
import com.websec.scanner.model.Severity;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HttpScannerTest {

    // strictClient never touches the network in these tests: exchangeFunction
    // is stubbed directly so the SSL-certificate branch is deterministic and
    // doesn't require a real TLS handshake against a mock server.
    private static WebClient strictClientReturning(Mono<ClientResponse> response) {
        return WebClient.builder().exchangeFunction(request -> response).build();
    }

    private MockWebServer server;

    @BeforeEach
    void setUp() throws IOException {
        server = new MockWebServer();
        server.start();
    }

    @AfterEach
    void tearDown() throws IOException {
        server.shutdown();
    }

    // MockWebServer.url() resolves through the machine's reverse-DNS
    // hostname for loopback; addressing it by IP literal avoids a real DNS
    // lookup and the flakiness that comes with it.
    private String baseUrl() {
        return "http://127.0.0.1:" + server.getPort() + "/";
    }

    @Test
    void isSslRelatedErrorRecognizesKnownSslFailureMessages() {
        assertTrue(HttpScanner.isSslRelatedError("PKIX path building failed"));
        assertTrue(HttpScanner.isSslRelatedError("javax.net.ssl.SSLHandshakeException"));
        assertTrue(HttpScanner.isSslRelatedError("certificate expired"));
        assertFalse(HttpScanner.isSslRelatedError("Connection refused"));
        assertFalse(HttpScanner.isSslRelatedError("Read timed out"));
    }

    @Test
    void flagsPlainHttpAndMissingRedirectWhenCertIsValid() {
        server.enqueue(new MockResponse().setResponseCode(200));
        HttpScanner scanner = new HttpScanner(
                WebClient.create(),
                strictClientReturning(Mono.just(ClientResponse.create(HttpStatus.OK).build())));

        StepVerifier.create(scanner.scan(baseUrl()))
                .assertNext(findings -> {
                    assertThat(findings).hasSize(2);
                    assertThat(findings).allMatch(f -> f.getType() == FindingType.SSL);
                    assertThat(findings)
                            .extracting(f -> f.getTitle())
                            .anyMatch(t -> t.contains("HTTP sem criptografia"))
                            .anyMatch(t -> t.contains("Sem redirecionamento"));
                })
                .verifyComplete();
    }

    @Test
    void doesNotFlagMissingRedirectWhenServerRedirectsToHttps() {
        server.enqueue(new MockResponse()
                .setResponseCode(301)
                .setHeader("Location", "https://example.com/"));
        HttpScanner scanner = new HttpScanner(
                WebClient.create(),
                strictClientReturning(Mono.just(ClientResponse.create(HttpStatus.OK).build())));

        StepVerifier.create(scanner.scan(baseUrl()))
                .assertNext(findings -> {
                    assertThat(findings).hasSize(1);
                    assertThat(findings.get(0).getTitle()).contains("HTTP sem criptografia");
                })
                .verifyComplete();
    }

    @Test
    void flagsInvalidCertificateWhenStrictClientReportsAnSslError() {
        server.enqueue(new MockResponse().setResponseCode(200));
        HttpScanner scanner = new HttpScanner(
                WebClient.create(),
                strictClientReturning(Mono.error(new RuntimeException(
                        "PKIX path building failed: unable to find valid certification path"))));

        StepVerifier.create(scanner.scan(baseUrl()))
                .assertNext(findings -> {
                    assertThat(findings).hasSize(3);
                    assertThat(findings)
                            .filteredOn(f -> f.getTitle().contains("Certificado SSL inválido"))
                            .singleElement()
                            .satisfies(f -> assertThat(f.getSeverity()).isEqualTo(Severity.HIGH));
                })
                .verifyComplete();
    }
}
