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

class CorsScannerTest {

    private MockWebServer server;
    private CorsScanner scanner;

    @BeforeEach
    void setUp() throws IOException {
        server = new MockWebServer();
        server.start();
        scanner = new CorsScanner(WebClient.create());
    }

    @AfterEach
    void tearDown() throws IOException {
        server.shutdown();
    }

    private String baseUrl() {
        return "http://127.0.0.1:" + server.getPort() + "/";
    }

    @Test
    void flagsHighSeverityWhenArbitraryOriginReflectedWithCredentials() {
        server.enqueue(new MockResponse()
                .setResponseCode(200)
                .setHeader("Access-Control-Allow-Origin", CorsScanner.PROBE_ORIGIN)
                .setHeader("Access-Control-Allow-Credentials", "true"));

        StepVerifier.create(scanner.scan(baseUrl()))
                .assertNext(findings -> {
                    assertThat(findings).hasSize(1);
                    assertThat(findings.get(0).getType()).isEqualTo(FindingType.CORS);
                    assertThat(findings.get(0).getSeverity()).isEqualTo(Severity.HIGH);
                })
                .verifyComplete();
    }

    @Test
    void flagsMediumSeverityWhenArbitraryOriginReflectedWithoutCredentials() {
        server.enqueue(new MockResponse()
                .setResponseCode(200)
                .setHeader("Access-Control-Allow-Origin", CorsScanner.PROBE_ORIGIN));

        StepVerifier.create(scanner.scan(baseUrl()))
                .assertNext(findings -> {
                    assertThat(findings).hasSize(1);
                    assertThat(findings.get(0).getSeverity()).isEqualTo(Severity.MEDIUM);
                })
                .verifyComplete();
    }

    @Test
    void flagsLowSeverityForWildcardOrigin() {
        server.enqueue(new MockResponse()
                .setResponseCode(200)
                .setHeader("Access-Control-Allow-Origin", "*"));

        StepVerifier.create(scanner.scan(baseUrl()))
                .assertNext(findings -> {
                    assertThat(findings).hasSize(1);
                    assertThat(findings.get(0).getSeverity()).isEqualTo(Severity.LOW);
                })
                .verifyComplete();
    }

    @Test
    void noFindingsWhenCorsHeaderAbsent() {
        server.enqueue(new MockResponse().setResponseCode(200));

        StepVerifier.create(scanner.scan(baseUrl()))
                .assertNext(findings -> assertThat(findings).isEmpty())
                .verifyComplete();
    }
}
