package com.websec.scanner.scanner;

import com.websec.scanner.model.FindingType;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.test.StepVerifier;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

class FingerprintScannerTest {

    private MockWebServer server;
    private FingerprintScanner scanner;

    @BeforeEach
    void setUp() throws IOException {
        server = new MockWebServer();
        server.start();
        scanner = new FingerprintScanner(WebClient.create());
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
    void detectsTechnologyFromSessionCookie() {
        server.enqueue(new MockResponse()
                .setResponseCode(200)
                .setHeader("Set-Cookie", "JSESSIONID=ABC123; Path=/"));

        StepVerifier.create(scanner.scan(baseUrl()))
                .assertNext(findings -> assertThat(findings)
                        .anyMatch(f -> f.getType() == FindingType.FINGERPRINT
                                && f.getTitle().contains("Java EE / Spring")))
                .verifyComplete();
    }

    @Test
    void detectsTechnologyFromFrameworkHeader() {
        server.enqueue(new MockResponse()
                .setResponseCode(200)
                .setHeader("X-Powered-By", "Express"));

        StepVerifier.create(scanner.scan(baseUrl()))
                .assertNext(findings -> assertThat(findings)
                        .anyMatch(f -> f.getTitle().contains("X-Powered-By")))
                .verifyComplete();
    }

    @Test
    void stillDetectsFingerprintsWhenResponseStatusIsAClientError() {
        // Regression test: WebClient's retrieve() throws for any 4xx/5xx by
        // default, which used to skip fingerprinting entirely on WAF blocks
        // or error pages (e.g. a 403). FingerprintScanner must use
        // exchangeToMono so it inspects headers regardless of status code.
        server.enqueue(new MockResponse()
                .setResponseCode(403)
                .setHeader("X-Powered-By", "Express"));

        StepVerifier.create(scanner.scan(baseUrl()))
                .assertNext(findings -> assertThat(findings)
                        .anyMatch(f -> f.getTitle().contains("X-Powered-By")))
                .verifyComplete();
    }

    @Test
    void noFindingsWhenNoFingerprintingHeadersPresent() {
        server.enqueue(new MockResponse().setResponseCode(200));

        StepVerifier.create(scanner.scan(baseUrl()))
                .assertNext(findings -> assertThat(findings).isEmpty())
                .verifyComplete();
    }
}
