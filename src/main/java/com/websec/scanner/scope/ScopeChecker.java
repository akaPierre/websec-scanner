package com.websec.scanner.scope;

import com.websec.scanner.config.ScannerConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Decides whether a host is inside the scope declared for a scan.
 *
 * <p>Scope patterns come from {@link ScannerConfig#getScopePatterns()} (a
 * plain list, one pattern per line of the {@code --scope} file):
 * <ul>
 *   <li>{@code example.com} — matches that exact host only.</li>
 *   <li>{@code *.example.com} — matches any subdomain, but not the apex
 *       domain itself (list it separately if it should be included too).</li>
 *   <li>{@code !staging.example.com} — explicitly out of scope; a deny match
 *       always overrides an allow match for the same host.</li>
 * </ul>
 *
 * <p>An empty pattern list means no scope was configured, so every host is
 * treated as in-scope — this preserves the tool's original single-domain
 * behavior when scope enforcement isn't requested.
 */
@Component
@RequiredArgsConstructor
public class ScopeChecker {

    private final ScannerConfig config;

    public boolean isInScope(String target) {
        List<String> patterns = config.getScopePatterns();
        if (patterns.isEmpty()) return true;

        String host = extractHost(target);

        boolean allowed = false;
        boolean denied = false;

        for (String pattern : patterns) {
            String trimmed = pattern.trim();
            if (trimmed.isEmpty()) continue;

            boolean isDenyRule = trimmed.startsWith("!");
            String rule = isDenyRule ? trimmed.substring(1) : trimmed;

            if (matches(host, rule)) {
                if (isDenyRule) denied = true;
                else allowed = true;
            }
        }

        return allowed && !denied;
    }

    private boolean matches(String host, String rule) {
        String normalizedRule = rule.trim().toLowerCase();
        if (normalizedRule.startsWith("*.")) {
            return host.endsWith(normalizedRule.substring(1));
        }
        return host.equals(normalizedRule);
    }

    private String extractHost(String target) {
        return target
                .replace("https://", "")
                .replace("http://", "")
                .split("/")[0]
                .split(":")[0]
                .toLowerCase();
    }
}
