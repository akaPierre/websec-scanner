package com.websec.scanner.scope;

import com.websec.scanner.config.ScannerConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ScopeCheckerTest {

    private ScannerConfig config;
    private ScopeChecker scopeChecker;

    @BeforeEach
    void setUp() {
        config = new ScannerConfig();
        scopeChecker = new ScopeChecker(config);
    }

    @Test
    void allowsEverythingWhenNoScopeConfigured() {
        config.setScopePatterns(List.of());

        assertThat(scopeChecker.isInScope("https://anything.example.org/")).isTrue();
    }

    @Test
    void matchesExactDomainOnly() {
        config.setScopePatterns(List.of("example.com"));

        assertThat(scopeChecker.isInScope("https://example.com/")).isTrue();
        assertThat(scopeChecker.isInScope("https://other.com/")).isFalse();
    }

    @Test
    void wildcardMatchesSubdomainsButNotTheApex() {
        config.setScopePatterns(List.of("*.example.com"));

        assertThat(scopeChecker.isInScope("https://foo.example.com/")).isTrue();
        assertThat(scopeChecker.isInScope("https://foo.bar.example.com/")).isTrue();
        assertThat(scopeChecker.isInScope("https://example.com/")).isFalse();
    }

    @Test
    void denyRuleOverridesAnAllowRuleForTheSameHost() {
        config.setScopePatterns(List.of("*.example.com", "!staging.example.com"));

        assertThat(scopeChecker.isInScope("https://api.example.com/")).isTrue();
        assertThat(scopeChecker.isInScope("https://staging.example.com/")).isFalse();
    }

    @Test
    void hostExtractionIgnoresSchemePortAndPath() {
        config.setScopePatterns(List.of("example.com"));

        assertThat(scopeChecker.isInScope("http://example.com:8080/some/path")).isTrue();
    }

    @Test
    void unrelatedHostIsRejectedWhenScopeIsConfigured() {
        config.setScopePatterns(List.of("*.example.com"));

        assertThat(scopeChecker.isInScope("https://totally-unrelated.org/")).isFalse();
    }
}
