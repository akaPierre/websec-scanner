package com.websec.scanner.scanner;

import com.websec.scanner.config.ScannerConfig;
import com.websec.scanner.model.FindingType;
import com.websec.scanner.model.Severity;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.test.StepVerifier;

import java.io.IOException;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class EndpointScannerTest {

    private MockWebServer server;
    private EndpointScanner scanner;

    @BeforeEach
    void setUp() throws IOException {
        server = new MockWebServer();
        server.start();

        ScannerConfig config = new ScannerConfig();
        ReflectionTestUtils.setField(config, "endpointDelayMs", 0);

        scanner = new EndpointScanner(WebClient.create(), config);
    }

    @AfterEach
    void tearDown() throws IOException {
        server.shutdown();
    }

    // MockWebServer.url() resolves through the machine's (sometimes oddly
    // configured) reverse-DNS hostname for loopback; addressing it by IP
    // literal instead avoids a real DNS lookup and the flakiness that comes
    // with it.
    private String baseUrl() {
        return "http://127.0.0.1:" + server.getPort() + "/";
    }

    @Test
    void reportsExistingSensitiveEndpointsAndIgnoresMissingOnes() {
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                return switch (request.getPath()) {
                    case "/.env" -> new MockResponse().setResponseCode(200);
                    case "/admin" -> new MockResponse().setResponseCode(403);
                    default -> new MockResponse().setResponseCode(404);
                };
            }
        });

        StepVerifier.create(scanner.scan(baseUrl()).timeout(Duration.ofSeconds(30)))
                .assertNext(findings -> {
                    assertThat(findings).allMatch(f -> f.getType() == FindingType.ENDPOINT);

                    assertThat(findings)
                            .filteredOn(f -> f.getTarget().endsWith("/.env"))
                            .singleElement()
                            .satisfies(f -> assertThat(f.getSeverity()).isEqualTo(Severity.HIGH));

                    assertThat(findings)
                            .filteredOn(f -> f.getTarget().endsWith("/admin"))
                            .singleElement()
                            .satisfies(f -> assertThat(f.getSeverity()).isEqualTo(Severity.MEDIUM));

                    assertThat(findings).hasSize(2);
                })
                .verifyComplete();
    }

    @Test
    void returnsEmptyListWhenNothingIsExposed() {
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                return new MockResponse().setResponseCode(404);
            }
        });

        StepVerifier.create(scanner.scan(baseUrl()).timeout(Duration.ofSeconds(30)))
                .assertNext(findings -> assertThat(findings).isEmpty())
                .verifyComplete();
    }
}
