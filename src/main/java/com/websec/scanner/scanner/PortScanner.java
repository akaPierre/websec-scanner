package com.websec.scanner.scanner;

import com.websec.scanner.config.ScannerConfig;
import com.websec.scanner.model.Finding;
import com.websec.scanner.model.FindingType;
import com.websec.scanner.model.Severity;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class PortScanner implements Scanner {

    private final ScannerConfig config;

    private static final Map<Integer, String> TARGET_PORTS = new LinkedHashMap<>() {{
        put(21,   "FTP - Transferência de arquivos (sem criptografia)");
        put(22,   "SSH - Acesso remoto seguro");
        put(23,   "Telnet - Acesso remoto SEM criptografia");
        put(25,   "SMTP - Envio de e-mail");
        put(80,   "HTTP - Web sem criptografia");
        put(443,  "HTTPS - Web com criptografia");
        put(3306, "MySQL - Banco de dados");
        put(5432, "PostgreSQL - Banco de dados");
        put(6379, "Redis - Cache/banco em memória");
        put(8080, "HTTP alternativo / painel de admin");
        put(8443, "HTTPS alternativo");
        put(8888, "Jupyter Notebook / serviço genérico");
        put(9200, "Elasticsearch - REST API");
        put(27017,"MongoDB - Banco de dados");
    }};

    private static final Map<Integer, Severity> PORT_SEVERITY = Map.of(
            21,    Severity.HIGH,
            23,    Severity.HIGH,
            3306,  Severity.HIGH,
            5432,  Severity.HIGH,
            6379,  Severity.HIGH,
            9200,  Severity.HIGH,
            27017, Severity.HIGH,
            8080,  Severity.MEDIUM,
            8888,  Severity.MEDIUM,
            25,    Severity.MEDIUM
    );

    @Override
    public String getName() {
        return "Port Scanner";
    }

    @Override
    public List<Finding> scan(String target) {
        String host = extractHost(target);
        List<Finding> findings = new ArrayList<>();

        log.info("[{}] Escaneando portas de: {}", getName(), host);

        for (Map.Entry<Integer, String> entry : TARGET_PORTS.entrySet()) {
            int port = entry.getKey();
            String service = entry.getValue();

            if (isPortOpen(host, port)) {
                log.info("[{}] Porta aberta: {}:{}", getName(), host, port);

                Severity severity = PORT_SEVERITY.getOrDefault(port, Severity.INFO);

                findings.add(Finding.builder()
                        .type(FindingType.PORT)
                        .severity(severity)
                        .title("Porta aberta: " + port + " (" + extractServiceName(service) + ")")
                        .description("A porta " + port + " está acessível publicamente. Serviço: " + service)
                        .evidence(host + ":" + port + " → OPEN")
                        .recommendation(getPortRecommendation(port))
                        .target(host)
                        .build());
            } else {
                log.debug("[{}] Porta fechada: {}:{}", getName(), host, port);
            }
        }

        if (findings.isEmpty()) {
            log.info("[{}] Nenhuma porta sensível encontrada em: {}", getName(), host);
        }

        return findings;
    }

    private boolean isPortOpen(String host, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(
                new InetSocketAddress(host, port),
                config.getPortTimeoutMs()
            );
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private String extractHost(String target) {
        return target
                .replace("https://", "")
                .replace("http://", "")
                .split("/")[0]
                .split(":")[0];
    }

    private String extractServiceName(String description) {
        return description.split(" - ")[0];
    }

    private String getPortRecommendation(int port) {
        return switch (port) {
            case 21 -> "Desative o FTP e utilize SFTP ou SCP para transferência segura de arquivos.";
            case 22 -> "Restrinja acesso SSH por IP via firewall. Desative autenticação por senha; use chaves SSH.";
            case 23 -> "Desative o Telnet imediatamente. É um protocolo sem criptografia. Use SSH.";
            case 25 -> "Restrinja SMTP ao uso interno. Configure SPF, DKIM e DMARC.";
            case 3306 -> "Nunca exponha MySQL publicamente. Use firewall para restringir ao IP da aplicação.";
            case 5432 -> "Nunca exponha PostgreSQL publicamente. Restrinja acesso via pg_hba.conf e firewall.";
            case 6379 -> "Redis não deve ser exposto publicamente. Configure autenticação e bind somente ao localhost.";
            case 8080 -> "Verifique se é um painel administrativo exposto. Restrinja acesso por IP ou VPN.";
            case 8888 -> "Jupyter Notebook exposto publicamente é um risco crítico. Proteja com senha e restrinja IPs.";
            case 9200 -> "Elasticsearch exposto sem autenticação é crítico. Adicione X-Pack Security e restrinja acesso.";
            case 27017 -> "MongoDB exposto publicamente sem autenticação permite acesso total ao banco. Bloqueie imediatamente.";
            default -> "Avalie se esta porta precisa estar acessível publicamente. Restrinja via firewall se não for necessário.";
        };
    }
}