package com.websec.scanner.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class ScannerConfig {

    @Value("${scanner.http.timeout:5000}")
    private int httpTimeoutMs;

    @Value("${scanner.port.timeout:2000}")
    private int portTimeoutMs;

    @Value("${scanner.subdomain.max:50}")
    private int maxSubdomains;

    @Value("${scanner.endpoint.delay:200}")
    private int endpointDelayMs;

    @Value("${scanner.http.user-agent:WebSec-Scanner/1.0 (Educational Tool)}")
    private String userAgent;

    @Value("${scanner.report.output-dir:reports}")
    private String reportOutputDir;

    // 0 = unlimited (default). Overridable at runtime via --rate-limit so a
    // bounty program's stated rate limit can be respected without a rebuild.
    @Value("${scanner.rate-limit.requests-per-second:0}")
    private double maxRequestsPerSecond;

    // Empty = unrestricted (default, preserves single-domain CLI usage).
    // Overridable at runtime via --scope so scanning stays inside a bounty
    // program's declared scope.
    private List<String> scopePatterns = List.of();

    public int getHttpTimeoutMs()    { return httpTimeoutMs; }
    public int getPortTimeoutMs()    { return portTimeoutMs; }
    public int getMaxSubdomains()    { return maxSubdomains; }
    public int getEndpointDelayMs()  { return endpointDelayMs; }
    public String getUserAgent()     { return userAgent; }
    public String getReportOutputDir() { return reportOutputDir; }

    public double getMaxRequestsPerSecond()             { return maxRequestsPerSecond; }
    public void setMaxRequestsPerSecond(double value)   { this.maxRequestsPerSecond = value; }

    public List<String> getScopePatterns()              { return scopePatterns; }
    public void setScopePatterns(List<String> patterns) { this.scopePatterns = patterns; }
}