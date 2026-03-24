package com.websec.scanner.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.websec.scanner.model.Finding;
import com.websec.scanner.model.ScanReport;
import com.websec.scanner.model.Severity;
import lombok.extern.slf4j.Slf4j;
import org.fusesource.jansi.Ansi;
import org.fusesource.jansi.AnsiConsole;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.fusesource.jansi.Ansi.Color.*;
import static org.fusesource.jansi.Ansi.ansi;

@Slf4j
@Component
public class ReportGenerator {

    private static final int TERMINAL_WIDTH = 72;
    private final ObjectMapper objectMapper;

    public ReportGenerator() {
        this.objectMapper = new ObjectMapper()
                .enable(SerializationFeature.INDENT_OUTPUT);
    }

    public void generate(ScanReport report, String outputDir) {
        AnsiConsole.systemInstall();
        try {
            printConsoleReport(report);
            saveJsonReport(report, outputDir);
        } finally {
            AnsiConsole.systemUninstall();
        }
    }

    private void printConsoleReport(ScanReport report) {
        System.out.println();
        printBanner();
        printSummaryBox(report);
        printSeverityBar(report);
        printFindings(report);
        printFooter(report);
    }

    private void printBanner() {
        System.out.println(ansi().fg(CYAN).bold().a(
                "╔══════════════════════════════════════════════════════════════════════╗\n" +
                "║           WebSec Scanner — Relatório de Vulnerabilidades            ║\n" +
                "╚══════════════════════════════════════════════════════════════════════╝"
        ).reset());
        System.out.println();
    }

    private void printSummaryBox(ScanReport report) {
        long high   = report.countBySeverity(Severity.HIGH);
        long medium = report.countBySeverity(Severity.MEDIUM);
        long low    = report.countBySeverity(Severity.LOW);
        long info   = report.countBySeverity(Severity.INFO);

        System.out.println(ansi().fg(WHITE).bold().a("  RESUMO DO SCAN").reset());
        System.out.println(line('─'));
        System.out.printf("  %-20s %s%n", "Domínio:",       ansi().fg(CYAN).a(report.getDomain()).reset());
        System.out.printf("  %-20s %s%n", "Data/Hora:",     report.getScannedAt());
        System.out.printf("  %-20s %s%n", "Duração:",       report.getScanDuration());
        System.out.printf("  %-20s %s%n", "Total findings:", ansi().bold().a(report.getTotalFindings()).reset());
        System.out.println(line('─'));
        System.out.println();

        System.out.println(ansi().fg(WHITE).bold().a("  FINDINGS POR SEVERIDADE").reset());
        System.out.println(line('─'));
        System.out.printf("  %s  %-10s %s%n",
                severityBadge(Severity.HIGH),   "HIGH",   renderBar(high,   report.getTotalFindings(), RED));
        System.out.printf("  %s  %-10s %s%n",
                severityBadge(Severity.MEDIUM), "MEDIUM", renderBar(medium, report.getTotalFindings(), YELLOW));
        System.out.printf("  %s  %-10s %s%n",
                severityBadge(Severity.LOW),    "LOW",    renderBar(low,    report.getTotalFindings(), GREEN));
        System.out.printf("  %s  %-10s %s%n",
                severityBadge(Severity.INFO),   "INFO",   renderBar(info,   report.getTotalFindings(), BLUE));
        System.out.println(line('─'));
        System.out.println();
    }

    private void printSeverityBar(ScanReport report) {
        int total = report.getTotalFindings();
        if (total == 0) return;

        long high   = report.countBySeverity(Severity.HIGH);
        long medium = report.countBySeverity(Severity.MEDIUM);
        long low    = report.countBySeverity(Severity.LOW);
        int score = (int) Math.min(100, (high * 30 + medium * 10 + low * 3));

        Ansi.Color scoreColor = score >= 70 ? RED : score >= 40 ? YELLOW : GREEN;
        String riskLabel = score >= 70 ? "ALTO" : score >= 40 ? "MÉDIO" : "BAIXO";

        System.out.println(ansi().fg(WHITE).bold().a("  SCORE DE RISCO").reset());
        System.out.println(line('─'));
        System.out.printf("  Risco: %s  (%d/100)%n",
                ansi().fg(scoreColor).bold().a(riskLabel).reset(), score);
        System.out.println(line('─'));
        System.out.println();
    }

    private void printFindings(ScanReport report) {
        if (report.getFindings().isEmpty()) {
            System.out.println(ansi().fg(GREEN).bold()
                    .a("  ✔ Nenhuma vulnerabilidade encontrada!")
                    .reset());
            return;
        }

        Map<Severity, List<Finding>> grouped = report.findingsBySeverity();
        List<Severity> order = List.of(Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO);

        for (Severity severity : order) {
            List<Finding> group = grouped.getOrDefault(severity, List.of());
            if (group.isEmpty()) continue;

            System.out.println(ansi().fg(severityColor(severity)).bold()
                    .a("  ▌ " + severity.name() + " — " + group.size() + " finding(s)")
                    .reset());
            System.out.println(line('═'));

            for (int i = 0; i < group.size(); i++) {
                printFinding(group.get(i), i + 1);
            }
        }
    }

    private void printFinding(Finding finding, int index) {
        Ansi.Color color = severityColor(finding.getSeverity());

        System.out.printf("%n  %s [%s] %s%n",
                ansi().fg(color).bold().a("#" + index).reset(),
                ansi().fg(color).a(finding.getType().name()).reset(),
                ansi().bold().a(finding.getTitle()).reset());

        System.out.printf("  %-16s %s%n", "Alvo:",           finding.getTarget());
        System.out.printf("  %-16s %s%n", "Descrição:",      wrap(finding.getDescription(), 52, 18));
        System.out.printf("  %-16s %s%n", "Evidência:",
                ansi().fg(YELLOW).a(wrap(finding.getEvidence(), 52, 18)).reset());
        System.out.printf("  %-16s %s%n", "Recomendação:",
                ansi().fg(GREEN).a(wrap(finding.getRecommendation(), 52, 18)).reset());
        System.out.println(line('─'));
    }

    private void printFooter(ScanReport report) {
        System.out.println();
        System.out.println(ansi().fg(CYAN).a(
                "  ⚠  Esta ferramenta é exclusivamente para fins educacionais.\n" +
                "     Use apenas em sistemas que você possui autorização para testar."
        ).reset());
        System.out.println();
        System.out.println(ansi().fg(WHITE).a(
                "  Relatório JSON salvo em: reports/" + reportFileName(report.getDomain())
        ).reset());
        System.out.println();
    }

    private void saveJsonReport(ScanReport report, String outputDir) {
        try {
            Path dir = Paths.get(outputDir);
            Files.createDirectories(dir);

            String fileName = reportFileName(report.getDomain());
            Path outputPath = dir.resolve(fileName);

            ReportJson reportJson = buildReportJson(report);
            objectMapper.writeValue(outputPath.toFile(), reportJson);

            log.info("Relatório JSON salvo em: {}", outputPath.toAbsolutePath());

        } catch (IOException e) {
            log.error("Erro ao salvar relatório JSON: {}", e.getMessage());
        }
    }

    private ReportJson buildReportJson(ScanReport report) {
        List<ReportJson.FindingJson> findingsJson = report.getFindings().stream()
                .sorted(Comparator.comparing(f -> severityOrder(f.getSeverity())))
                .map(f -> ReportJson.FindingJson.builder()
                        .type(f.getType().name())
                        .severity(f.getSeverity().name())
                        .title(f.getTitle())
                        .description(f.getDescription())
                        .evidence(f.getEvidence())
                        .recommendation(f.getRecommendation())
                        .target(f.getTarget())
                        .build())
                .collect(Collectors.toList());

        return ReportJson.builder()
                .domain(report.getDomain())
                .scannedAt(report.getScannedAt())
                .scanDuration(report.getScanDuration())
                .totalFindings(report.getTotalFindings())
                .summary(ReportJson.Summary.builder()
                        .high((int) report.countBySeverity(Severity.HIGH))
                        .medium((int) report.countBySeverity(Severity.MEDIUM))
                        .low((int) report.countBySeverity(Severity.LOW))
                        .info((int) report.countBySeverity(Severity.INFO))
                        .build())
                .findings(findingsJson)
                .build();
    }

    @lombok.Data
    @lombok.Builder
    static class ReportJson {
        private String domain;
        private String scannedAt;
        private String scanDuration;
        private int totalFindings;
        private Summary summary;
        private List<FindingJson> findings;

        @lombok.Data
        @lombok.Builder
        static class Summary {
            private int high;
            private int medium;
            private int low;
            private int info;
        }

        @lombok.Data
        @lombok.Builder
        static class FindingJson {
            private String type;
            private String severity;
            private String title;
            private String description;
            private String evidence;
            private String recommendation;
            private String target;
        }
    }

    private String line(char ch) {
        return "  " + String.valueOf(ch).repeat(TERMINAL_WIDTH);
    }

    private String renderBar(long count, int total, Ansi.Color color) {
        if (total == 0) return ansi().fg(color).a("0 ░░░░░░░░░░░░░░░░░░░░").reset().toString();
        int filled = (int) Math.round((double) count / total * 20);
        String bar = "█".repeat(filled) + "░".repeat(20 - filled);
        return ansi().fg(color).a(String.format("%-3d %s", count, bar)).reset().toString();
    }

    private String severityBadge(Severity severity) {
        Ansi.Color color = severityColor(severity);
        return ansi().bg(color).fg(BLACK).bold()
                .a(" " + severity.name().charAt(0) + " ")
                .reset().toString();
    }

    private Ansi.Color severityColor(Severity severity) {
        return switch (severity) {
            case HIGH   -> RED;
            case MEDIUM -> YELLOW;
            case LOW    -> GREEN;
            case INFO   -> BLUE;
        };
    }

    private int severityOrder(Severity severity) {
        return switch (severity) {
            case HIGH   -> 0;
            case MEDIUM -> 1;
            case LOW    -> 2;
            case INFO   -> 3;
        };
    }

    private String wrap(String text, int maxWidth, int indent) {
        if (text == null || text.length() <= maxWidth) return text;
        String indentStr = " ".repeat(indent);
        StringBuilder sb = new StringBuilder();
        int start = 0;
        while (start < text.length()) {
            int end = Math.min(start + maxWidth, text.length());
            if (start > 0) sb.append("\n").append(indentStr);
            sb.append(text, start, end);
            start = end;
        }
        return sb.toString();
    }

    private String reportFileName(String domain) {
        String safeDomain = domain.replaceAll("[^a-zA-Z0-9.-]", "_");
        String timestamp = java.time.LocalDateTime.now()
                .format(java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        return "report_" + safeDomain + "_" + timestamp + ".json";
    }
}