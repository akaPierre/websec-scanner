package com.websec.scanner.cli;

import com.websec.scanner.config.ScannerConfig;
import com.websec.scanner.engine.ScanEngine;
import com.websec.scanner.model.ScanReport;
import com.websec.scanner.report.ReportGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.fusesource.jansi.Ansi;
import org.fusesource.jansi.AnsiConsole;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.Scanner;
import java.util.regex.Pattern;

import static org.fusesource.jansi.Ansi.Color.*;
import static org.fusesource.jansi.Ansi.ansi;

@Slf4j
@Component
@RequiredArgsConstructor
public class ScannerCLI implements CommandLineRunner {

    private final ScanEngine scanEngine;
    private final ReportGenerator reportGenerator;
    private final ScannerConfig config;

    private static final Pattern DOMAIN_PATTERN = Pattern.compile(
            "^(?!-)([a-zA-Z0-9-]{1,63}\\.)+[a-zA-Z]{2,}$"
    );

    @Override
    public void run(String... args) {
        AnsiConsole.systemInstall();
        try {
            if (args.length > 0) {
                String domain = args[0].trim().toLowerCase();
                if (isValidDomain(domain)) {
                    runScan(domain);
                } else {
                    printError("Domínio inválido: " + domain);
                    printUsage();
                }
                return;
            }

            runInteractiveMode();

        } finally {
            AnsiConsole.systemUninstall();
        }
    }

    private void runInteractiveMode() {
        printWelcomeBanner();

        Scanner input = new Scanner(System.in);
        boolean running = true;

        while (running) {
            printMenu();
            String choice = input.nextLine().trim();

            switch (choice) {
                case "1" -> {
                    String domain = promptDomain(input);
                    if (domain != null) runScan(domain);
                }
                case "2" -> printHelp();
                case "3" -> {
                    printInfo("Encerrando WebSec Scanner. Até logo!");
                    running = false;
                }
                default  -> printError("Opção inválida. Digite 1, 2 ou 3.");
            }
        }

        input.close();
    }

    private String promptDomain(Scanner input) {
        System.out.print(ansi().fg(CYAN).a("\n  Digite o domínio alvo (ex: example.com): ")
                .reset());
        String domain = input.nextLine().trim().toLowerCase();

        domain = domain
                .replace("https://", "")
                .replace("http://", "")
                .replaceAll("/.*", "");

        if (!isValidDomain(domain)) {
            printError("Domínio inválido: '" + domain + "'");
            printInfo("Formato esperado: example.com ou sub.example.com");
            return null;
        }

        if (!confirmEthicalUse(input, domain)) {
            printInfo("Scan cancelado.");
            return null;
        }

        return domain;
    }

    private boolean confirmEthicalUse(Scanner input, String domain) {
        System.out.println();
        System.out.println(ansi().fg(YELLOW).bold().a(
                "  ┌─────────────────────────────────────────────────────────────┐\n" +
                "  │                    ⚠  AVISO IMPORTANTE                     │\n" +
                "  │                                                             │\n" +
                "  │  Esta ferramenta deve ser usada APENAS em sistemas que      │\n" +
                "  │  você possui AUTORIZAÇÃO EXPLÍCITA para testar.             │\n" +
                "  │                                                             │\n" +
                "  │  O uso não autorizado é ilegal e antiético.                 │\n" +
                "  └─────────────────────────────────────────────────────────────┘"
        ).reset());
        System.out.println();
        System.out.printf(ansi().fg(CYAN)
                .a("  Você confirma que possui autorização para escanear '%s'? (s/N): ")
                .reset().toString(), domain);

        String answer = input.nextLine().trim().toLowerCase();
        return answer.equals("s") || answer.equals("sim") || answer.equals("y") || answer.equals("yes");
    }

    private void runScan(String domain) {
        printInfo("Iniciando scan em: " + domain);
        printInfo("Isso pode levar alguns minutos...\n");

        try {
            long start = System.currentTimeMillis();

            Thread scanThread = new Thread(() -> {
                ScanReport report = scanEngine.run(domain);
                reportGenerator.generate(report, config.getReportOutputDir());
            });

            scanThread.start();
            showSpinner(scanThread);
            scanThread.join();

            long elapsed = System.currentTimeMillis() - start;
            printSuccess("Scan concluído em " + elapsed / 1000.0 + "s");

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            printError("Scan interrompido.");
        } catch (Exception e) {
            printError("Erro durante o scan: " + e.getMessage());
            log.error("Erro no scan de {}: ", domain, e);
        }
    }

    private void showSpinner(Thread scanThread) throws InterruptedException {
        String[] frames = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
        int i = 0;
        while (scanThread.isAlive()) {
            System.out.print(ansi().fg(CYAN)
                    .a("\r  " + frames[i % frames.length] + " Escaneando...")
                    .reset());
            System.out.flush();
            Thread.sleep(100);
            i++;
        }
        System.out.print("\r" + " ".repeat(30) + "\r");
    }

    private boolean isValidDomain(String domain) {
        if (domain == null || domain.isBlank()) return false;
        if (domain.length() > 253) return false;
        return DOMAIN_PATTERN.matcher(domain).matches();
    }

    private void printWelcomeBanner() {
        System.out.println();
        System.out.println(ansi().fg(CYAN).bold().a(
                "  ██╗    ██╗███████╗██████╗ ███████╗███████╗ ██████╗\n" +
                "  ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝\n" +
                "  ██║ █╗ ██║█████╗  ██████╔╝███████╗█████╗  ██║     \n" +
                "  ██║███╗██║██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║     \n" +
                "  ╚███╔███╔╝███████╗██████╔╝███████║███████╗╚██████╗\n" +
                "   ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝"
        ).reset());
        System.out.println(ansi().fg(WHITE).a(
                "               Web Security Vulnerability Scanner\n" +
                "                  Ferramenta Educativa v1.0.0\n"
        ).reset());
        System.out.println(ansi().fg(YELLOW).a(
                "  ⚠  Use apenas em sistemas com autorização explícita."
        ).reset());
        System.out.println();
    }

    private void printMenu() {
        System.out.println(ansi().fg(WHITE).bold().a("  ┌─────────────────────────────┐").reset());
        System.out.println(ansi().fg(WHITE).bold().a("  │         MENU PRINCIPAL      │").reset());
        System.out.println(ansi().fg(WHITE).bold().a("  ├─────────────────────────────┤").reset());
        System.out.println(ansi().fg(WHITE).a(      "  │  1. Iniciar novo scan        │").reset());
        System.out.println(ansi().fg(WHITE).a(      "  │  2. Ajuda / Como usar        │").reset());
        System.out.println(ansi().fg(WHITE).a(      "  │  3. Sair                     │").reset());
        System.out.println(ansi().fg(WHITE).bold().a("  └─────────────────────────────┘").reset());
        System.out.print(ansi().fg(CYAN).a("  Escolha uma opção: ").reset());
    }

    private void printHelp() {
        System.out.println();
        System.out.println(ansi().fg(WHITE).bold().a("  COMO USAR").reset());
        System.out.println(ansi().fg(WHITE).a("  " + "─".repeat(50)).reset());
        System.out.println(ansi().fg(WHITE).a(
                "\n  Modo interativo (este menu):\n" +
                "    Selecione a opção 1 e digite o domínio.\n" +
                "\n  Modo direto (linha de comando):\n" +
                "    java -jar websec-scanner.jar example.com\n" +
                "\n  O QUE É ANALISADO:\n" +
                "    • Subdomínios ativos via DNS\n" +
                "    • Headers de segurança HTTP\n" +
                "    • Uso de HTTP vs HTTPS\n" +
                "    • Certificado SSL\n" +
                "    • Portas abertas (FTP, SSH, DB...)\n" +
                "    • Endpoints sensíveis (/admin, /.env...)\n" +
                "    • Tecnologias expostas (fingerprinting)\n" +
                "    • Possível subdomain takeover\n" +
                "    • Cookies sem Secure/HttpOnly/SameSite\n" +
                "    • Configuração de CORS (origem refletida, credenciais)\n" +
                "    • Tokens JWT com algoritmo 'none'\n" +
                "    • Possível open redirect\n" +
                "\n  RELATÓRIOS:\n" +
                "    Salvos automaticamente em: ./reports/\n" +
                "    Formato: JSON estruturado\n"
        ).reset());
        System.out.println(ansi().fg(WHITE).a("  " + "─".repeat(50)).reset());
        System.out.println();
    }

    private void printUsage() {
        System.out.println(ansi().fg(WHITE).a(
                "\n  Uso: java -jar websec-scanner.jar <domínio>\n" +
                "  Ex:  java -jar websec-scanner.jar example.com\n"
        ).reset());
    }

    private void printError(String msg) {
        System.out.println(ansi().fg(RED).bold().a("\n  ✖ " + msg).reset());
    }

    private void printSuccess(String msg) {
        System.out.println(ansi().fg(GREEN).bold().a("  ✔ " + msg).reset());
    }

    private void printInfo(String msg) {
        System.out.println(ansi().fg(BLUE).a("  ℹ " + msg).reset());
    }
}