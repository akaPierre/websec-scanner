package com.websec.scanner.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class ScannerConfig {

    @Value("${scanner.http.timeout:5000}")
    private int httpTimeoutMs;

    @Value("${scanner.port.timeout:2000}")
    private int portTimeoutMs;

    @Value("${scanner.subdomain.max:50}")
    private int maxSubdomains;

    @Value("${scanner.http.user-agent:WebSec-Scanner/1.0 (Educational Tool)}")
    private String userAgent;

    @Value("${scanner.report.output-dir:reports}")
    private String reportOutputDir;

    public int getHttpTimeoutMs()    { return httpTimeoutMs; }
    public int getPortTimeoutMs()    { return portTimeoutMs; }
    public int getMaxSubdomains()    { return maxSubdomains; }
    public String getUserAgent()     { return userAgent; }
    public String getReportOutputDir() { return reportOutputDir; }
}