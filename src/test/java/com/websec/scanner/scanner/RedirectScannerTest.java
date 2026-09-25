package com.websec.scanner.scanner;

import com.websec.scanner.model.FindingType;
import okhttp3.HttpUrl;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.test.StepVerifier;

import java.io.IOException;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class RedirectScannerTest {

    private MockWebServer server;
    private RedirectScanner scanner;

    @BeforeEach
    void setUp() throws IOException {
        server = new MockWebServer();
        server.start();
        scanner = new RedirectScanner(WebClient.create());
    }

    @AfterEach
    void tearDown() throws IOException {
        server.shutdown();
    }

    private String baseUrl() {
        return "http://127.0.0.1:" + server.getPort() + "/";
    }

    @Test
    void flagsParameterThatRedirectsToTheProbeTarget() {
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                HttpUrl url = request.getRequestUrl();
                if (url != null && url.queryParameterNames().contains("redirect")) {
                    return new MockResponse()
                            .setResponseCode(302)
                            .setHeader("Location", RedirectScanner.PROBE_TARGET);
                }
                return new MockResponse().setResponseCode(200);
            }
        });

        StepVerifier.create(scanner.scan(baseUrl()).timeout(Duration.ofSeconds(30)))
                .assertNext(findings -> {
                    assertThat(findings).hasSize(1);
                    assertThat(findings.get(0).getType()).isEqualTo(FindingType.REDIRECT);
                    assertThat(findings.get(0).getTitle()).contains("redirect");
                })
                .verifyComplete();
    }

    @Test
    void doesNotFlagRedirectsToUnrelatedLocations() {
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                HttpUrl url = request.getRequestUrl();
                if (url != null && url.queryParameterNames().contains("next")) {
                    return new MockResponse()
                            .setResponseCode(302)
                            .setHeader("Location", "/dashboard");
                }
                return new MockResponse().setResponseCode(200);
            }
        });

        StepVerifier.create(scanner.scan(baseUrl()).timeout(Duration.ofSeconds(30)))
                .assertNext(findings -> assertThat(findings).isEmpty())
                .verifyComplete();
    }

    @Test
    void noFindingsWhenNothingRedirects() {
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                return new MockResponse().setResponseCode(200);
            }
        });

        StepVerifier.create(scanner.scan(baseUrl()).timeout(Duration.ofSeconds(30)))
                .assertNext(findings -> assertThat(findings).isEmpty())
                .verifyComplete();
    }
}
