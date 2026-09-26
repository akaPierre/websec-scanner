package com.websec.scanner.scanner;

import com.websec.scanner.config.ScannerConfig;
import com.websec.scanner.model.Finding;
import com.websec.scanner.model.FindingType;
import com.websec.scanner.model.Severity;
import com.websec.scanner.scope.ScopeChecker;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;
import org.xbill.DNS.TextParseException;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class SubdomainScanner {

    private static final int RESOLVE_CONCURRENCY = 10;

    private final WebClient webClient;
    private final ScannerConfig config;
    private final ScopeChecker scopeChecker;

    private static final List<String> TAKEOVER_INDICATORS = List.of(
            "github.io",
            "herokuapp.com",
            "amazonaws.com",
            "azurewebsites.net",
            "netlify.app",
            "surge.sh",
            "ghost.io",
            "pantheon.io",
            "fastly.net",
            "shopify.com"
    );

    private static final List<String> TAKEOVER_BODY_INDICATORS = List.of(
            "there isn't a github pages site here",
            "no such app",
            "heroku | no such app",
            "project not found",
            "this netlify site is not deployed",
            "the site you were looking for doesn't exist"
    );

    public String getName() {
        return "Subdomain Scanner";
    }

    public List<String> discoverHosts(String domain) {
        return discoverHostsWithFindings(domain, new ArrayList<>());
    }

    public List<String> discoverHostsWithFindings(String domain, List<Finding> findings) {
        List<String> wordlist = loadSubdomainWordlist();
        int limit = Math.min(wordlist.size(), config.getMaxSubdomains());

        List<String> candidateHosts = new ArrayList<>(wordlist.subList(0, limit).stream()
                .map(prefix -> prefix + "." + domain)
                .toList());
        candidateHosts.add(domain);

        int beforeScopeFilter = candidateHosts.size();
        candidateHosts = candidateHosts.stream().filter(scopeChecker::isInScope).toList();
        if (candidateHosts.size() != beforeScopeFilter) {
            log.info("[{}] {} candidato(s) fora do escopo configurado foram ignorados",
                    getName(), beforeScopeFilter - candidateHosts.size());
        }

        log.info("[{}] Testando {} subdomínios para: {}", getName(), candidateHosts.size(), domain);

        List<SubdomainResult> results = Flux.fromIterable(candidateHosts)
                .flatMap(host -> Mono.fromCallable(() -> checkSubdomain(host))
                        .subscribeOn(Schedulers.boundedElastic())
                        .onErrorResume(e -> Mono.empty()), RESOLVE_CONCURRENCY)
                .collectList()
                .blockOptional(Duration.ofSeconds(90))
                .orElse(List.of());

        List<String> activeHosts = new ArrayList<>();

        for (SubdomainResult result : results) {
            if (!result.isActive()) continue;

            log.info("[{}] Subdomínio ativo: {}", getName(), result.getHost());
            activeHosts.add(result.getPreferredUrl());

            if (!result.getHost().equals(domain)) {
                findings.add(Finding.builder()
                        .type(FindingType.SUBDOMAIN)
                        .severity(Severity.INFO)
                        .title("Subdomínio ativo descoberto: " + result.getHost())
                        .description("O subdomínio está ativo e acessível via " +
                                (result.isHttps() ? "HTTPS" : "HTTP") + ".")
                        .evidence("DNS resolveu para: " + result.getResolvedIp() +
                                " | HTTP " + result.getStatusCode())
                        .recommendation("Certifique-se de que este subdomínio está autorizado " +
                                "e possui os mesmos controles de segurança do domínio principal.")
                        .target(result.getPreferredUrl())
                        .build());
            }

            if (result.getCname() != null) {
                checkTakeover(result, findings);
            }
        }

        log.info("[{}] {} hosts ativos encontrados", getName(), activeHosts.size());
        return activeHosts;
    }

    private SubdomainResult checkSubdomain(String host) {
        SubdomainResult result = new SubdomainResult(host);

        try {
            InetAddress address = InetAddress.getByName(host);
            result.setResolvedIp(address.getHostAddress());
        } catch (Exception e) {
            return result;
        }

        result.setCname(resolveCname(host));
        result.setActive(false);

        Integer httpsStatus = tryRequest("https://" + host);
        if (httpsStatus != null) {
            result.setActive(true);
            result.setHttps(true);
            result.setStatusCode(httpsStatus);
            result.setPreferredUrl("https://" + host);
            return result;
        }

        Integer httpStatus = tryRequest("http://" + host);
        if (httpStatus != null) {
            result.setActive(true);
            result.setHttps(false);
            result.setStatusCode(httpStatus);
            result.setPreferredUrl("http://" + host);
        }

        return result;
    }

    private Integer tryRequest(String url) {
        try {
            var response = webClient
                    .method(HttpMethod.GET)
                    .uri(url)
                    .retrieve()
                    .toBodilessEntity()
                    .onErrorResume(e -> Mono.empty())
                    .block();

            if (response != null) {
                return response.getStatusCode().value();
            }
        } catch (Exception e) {
            log.debug("[{}] Falha ao acessar {}: {}", getName(), url, e.getMessage());
        }
        return null;
    }

    private String resolveCname(String host) {
        try {
            Record[] records = new Lookup(host, Type.CNAME).run();
            if (records != null && records.length > 0) {
                return records[0].rdataToString();
            }
        } catch (TextParseException e) {
            log.debug("[{}] Erro ao resolver CNAME de {}", getName(), host);
        }
        return null;
    }

    private void checkTakeover(SubdomainResult result, List<Finding> findings) {
        String cname = result.getCname().toLowerCase();

        boolean pointsToVulnerableService = TAKEOVER_INDICATORS.stream()
                .anyMatch(cname::contains);

        if (!pointsToVulnerableService) return;

        try {
            String body = webClient
                    .method(HttpMethod.GET)
                    .uri(result.getPreferredUrl())
                    .retrieve()
                    .bodyToMono(String.class)
                    .onErrorReturn("")
                    .block();

            if (body == null) return;

            String bodyLower = body.toLowerCase();
            boolean confirmedTakeover = TAKEOVER_BODY_INDICATORS.stream()
                    .anyMatch(bodyLower::contains);

            if (confirmedTakeover) {
                findings.add(Finding.builder()
                        .type(FindingType.SUBDOMAIN)
                        .severity(Severity.HIGH)
                        .title("Possível Subdomain Takeover: " + result.getHost())
                        .description("O subdomínio possui CNAME apontando para serviço externo " +
                                "não configurado, permitindo que um atacante reivindique o subdomínio.")
                        .evidence("CNAME: " + result.getCname() +
                                " | Serviço não configurado detectado na resposta.")
                        .recommendation("Remova o registro DNS deste subdomínio ou configure " +
                                "o serviço externo corretamente para evitar subdomain takeover.")
                        .target(result.getPreferredUrl())
                        .build());

                log.warn("[{}] POSSÍVEL TAKEOVER DETECTADO: {}", getName(), result.getHost());

            } else {
                findings.add(Finding.builder()
                        .type(FindingType.SUBDOMAIN)
                        .severity(Severity.MEDIUM)
                        .title("Subdomínio com CNAME para serviço externo: " + result.getHost())
                        .description("O subdomínio possui CNAME apontando para '" + result.getCname() +
                                "'. Se o serviço externo for desativado, pode ocorrer subdomain takeover.")
                        .evidence("CNAME: " + result.getCname())
                        .recommendation("Monitore este subdomínio. Se o serviço externo for " +
                                "desativado, remova o registro DNS imediatamente.")
                        .target(result.getPreferredUrl())
                        .build());
            }

        } catch (Exception e) {
            log.debug("[{}] Erro ao verificar takeover de {}: {}", getName(), result.getHost(), e.getMessage());
        }
    }

    private List<String> loadSubdomainWordlist() {
        List<String> words = new ArrayList<>();
        try {
            var resource = new ClassPathResource("wordlists/subdomains.txt");
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#")) {
                        words.add(line);
                    }
                }
            }
        } catch (Exception e) {
            log.warn("[{}] Wordlist não encontrada, usando lista mínima", getName());
            words = List.of("www", "mail", "api", "dev", "staging", "admin", "app");
        }
        return words;
    }

    private static class SubdomainResult {
        private final String host;
        private String resolvedIp;
        private String cname;
        private String preferredUrl;
        private boolean active = false;
        private boolean https = false;
        private int statusCode = 0;

        SubdomainResult(String host) { this.host = host; }

        String getHost()         { return host; }
        String getResolvedIp()   { return resolvedIp; }
        String getCname()        { return cname; }
        String getPreferredUrl() { return preferredUrl; }
        boolean isActive()       { return active; }
        boolean isHttps()        { return https; }
        int getStatusCode()      { return statusCode; }

        void setResolvedIp(String v)   { this.resolvedIp = v; }
        void setCname(String v)        { this.cname = v; }
        void setPreferredUrl(String v) { this.preferredUrl = v; }
        void setActive(boolean v)      { this.active = v; }
        void setHttps(boolean v)       { this.https = v; }
        void setStatusCode(int v)      { this.statusCode = v; }
    }
}
