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
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class JwtScannerTest {

    private MockWebServer server;
    private JwtScanner scanner;

    @BeforeEach
    void setUp() throws IOException {
        server = new MockWebServer();
        server.start();
        scanner = new JwtScanner(WebClient.create());
    }

    @AfterEach
    void tearDown() throws IOException {
        server.shutdown();
    }

    private String baseUrl() {
        return "http://127.0.0.1:" + server.getPort() + "/";
    }

    private static String base64Url(String json) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void flagsJwtWithNoneAlgorithm() {
        String token = base64Url("{\"alg\":\"none\",\"typ\":\"JWT\"}")
                + "." + base64Url("{\"sub\":\"1234567890\"}") + ".";

        server.enqueue(new MockResponse()
                .setResponseCode(200)
                .setHeader("Set-Cookie", "session=" + token + "; Path=/"));

        StepVerifier.create(scanner.scan(baseUrl()))
                .assertNext(findings -> {
                    assertThat(findings).hasSize(1);
                    assertThat(findings.get(0).getType()).isEqualTo(FindingType.JWT);
                    assertThat(findings.get(0).getSeverity()).isEqualTo(Severity.HIGH);
                    assertThat(findings.get(0).getTitle()).contains("session");
                })
                .verifyComplete();
    }

    @Test
    void noFindingsForNormallySignedJwt() {
        String token = base64Url("{\"alg\":\"HS256\",\"typ\":\"JWT\"}")
                + "." + base64Url("{\"sub\":\"1234567890\"}") + ".somesignature";

        server.enqueue(new MockResponse()
                .setResponseCode(200)
                .setHeader("Set-Cookie", "session=" + token + "; Path=/"));

        StepVerifier.create(scanner.scan(baseUrl()))
                .assertNext(findings -> assertThat(findings).isEmpty())
                .verifyComplete();
    }

    @Test
    void ignoresNonJwtCookiesWithoutError() {
        server.enqueue(new MockResponse()
                .setResponseCode(200)
                .setHeader("Set-Cookie", "session=just-a-random-opaque-value; Path=/"));

        StepVerifier.create(scanner.scan(baseUrl()))
                .assertNext(findings -> assertThat(findings).isEmpty())
                .verifyComplete();
    }
}
