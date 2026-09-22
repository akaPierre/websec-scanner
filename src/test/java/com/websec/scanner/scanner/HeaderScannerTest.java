package com.websec.scanner.scanner;

import com.websec.scanner.model.FindingType;
import com.websec.scanner.model.Severity;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.test.StepVerifier;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

class HeaderScannerTest {

    private MockWebServer server;
    private HeaderScanner scanner;

    @BeforeEach
    void setUp() throws IOException {
        server = new MockWebServer();
        server.start();
        scanner = new HeaderScanner(WebClient.create());
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
    void flagsAllMissingSecurityHeaders() {
        server.enqueue(new MockResponse().setResponseCode(200));

        StepVerifier.create(scanner.scan(baseUrl()))
                .assertNext(findings -> {
                    assertThat(findings).hasSize(6);
                    assertThat(findings).allMatch(f -> f.getType() == FindingType.HEADER);
                    assertThat(findings)
                            .extracting(f -> f.getTitle())
                            .anyMatch(t -> t.contains("Content-Security-Policy"));
                })
                .verifyComplete();
    }

    @Test
    void noFindingsWhenAllSecurityHeadersPresent() {
        server.enqueue(new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Security-Policy", "default-src 'self'")
                .setHeader("X-Frame-Options", "DENY")
                .setHeader("X-Content-Type-Options", "nosniff")
                .setHeader("Strict-Transport-Security", "max-age=31536000")
                .setHeader("Referrer-Policy", "no-referrer")
                .setHeader("Permissions-Policy", "geolocation=()"));

        StepVerifier.create(scanner.scan(baseUrl()))
                .assertNext(findings -> assertThat(findings).isEmpty())
                .verifyComplete();
    }

    @Test
    void flagsServerHeaderThatExposesAVersionNumber() {
        server.enqueue(new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Security-Policy", "default-src 'self'")
                .setHeader("X-Frame-Options", "DENY")
                .setHeader("X-Content-Type-Options", "nosniff")
                .setHeader("Strict-Transport-Security", "max-age=31536000")
                .setHeader("Referrer-Policy", "no-referrer")
                .setHeader("Permissions-Policy", "geolocation=()")
                .setHeader("Server", "nginx/1.18.0"));

        StepVerifier.create(scanner.scan(baseUrl()))
                .assertNext(findings -> {
                    assertThat(findings).hasSize(1);
                    assertThat(findings.get(0).getType()).isEqualTo(FindingType.FINGERPRINT);
                    assertThat(findings.get(0).getSeverity()).isEqualTo(Severity.LOW);
                })
                .verifyComplete();
    }

    @Test
    void stillAnalyzesHeadersWhenResponseStatusIsAClientError() {
        // Regression test: WebClient's retrieve() throws for any 4xx/5xx by
        // default, which used to skip header analysis entirely on WAF blocks
        // or error pages (e.g. a 403). HeaderScanner must use exchangeToMono
        // so it inspects headers regardless of status code.
        server.enqueue(new MockResponse().setResponseCode(403));

        StepVerifier.create(scanner.scan(baseUrl()))
                .assertNext(findings -> assertThat(findings).hasSize(6))
                .verifyComplete();
    }

    @Test
    void returnsEmptyListInsteadOfErroringWhenServerIsUnreachable() throws IOException {
        String unreachableUrl = baseUrl();
        server.shutdown();

        StepVerifier.create(scanner.scan(unreachableUrl))
                .assertNext(findings -> assertThat(findings).isEmpty())
                .verifyComplete();
    }
}
