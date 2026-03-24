package com.websec.scanner.model;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Data
@Builder
public class ScanReport {
    
    private String domain;
    private String scannedAt;
    private String scanDuration;
    private int totalFindings;
    private List<Finding> findings;

    public Map<Severity, List<Finding>> findingsBySeverity() {
        return findings.stream()
                .collect(Collectors.groupingBy(Finding::getSeverity));
    }

    public long countBySeverity(Severity severity) {
        return findings.stream()
                .filter(f -> f.getSeverity() == severity)
                .count();
    }

    public static String now() {
        return LocalDateTime.now()
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }
}