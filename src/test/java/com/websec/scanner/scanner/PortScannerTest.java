package com.websec.scanner.scanner;

import com.websec.scanner.config.ScannerConfig;
import com.websec.scanner.model.Severity;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import reactor.test.StepVerifier;

import java.io.IOException;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class PortScannerTest {

    private ScannerConfig config;
    private ServerSocket listeningSocket;

    @BeforeEach
    void setUp() {
        config = new ScannerConfig();
        ReflectionTestUtils.setField(config, "portTimeoutMs", 500);
    }

    @AfterEach
    void tearDown() throws IOException {
        if (listeningSocket != null && !listeningSocket.isClosed()) {
            listeningSocket.close();
        }
    }

    @Test
    void reportsAnOpenPortAsAFinding() throws IOException {
        listeningSocket = new ServerSocket(0);
        int port = listeningSocket.getLocalPort();

        PortScanner scanner = new PortScanner(config, Map.of(port, "Test Service"));

        StepVerifier.create(scanner.scan("127.0.0.1").timeout(Duration.ofSeconds(10)))
                .assertNext(findings -> {
                    assertThat(findings).hasSize(1);
                    assertThat(findings.get(0).getSeverity()).isEqualTo(Severity.INFO);
                    assertThat(findings.get(0).getTitle()).contains(String.valueOf(port));
                    assertThat(findings.get(0).getEvidence()).contains("OPEN");
                })
                .verifyComplete();
    }

    @Test
    void reportsNoFindingWhenThePortIsClosed() throws IOException {
        int closedPort;
        try (ServerSocket probe = new ServerSocket(0)) {
            closedPort = probe.getLocalPort();
        }

        PortScanner scanner = new PortScanner(config, Map.of(closedPort, "Test Service"));

        StepVerifier.create(scanner.scan("127.0.0.1").timeout(Duration.ofSeconds(10)))
                .assertNext(findings -> assertThat(findings).isEmpty())
                .verifyComplete();
    }
}
