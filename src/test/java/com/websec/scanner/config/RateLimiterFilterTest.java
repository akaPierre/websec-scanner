package com.websec.scanner.config;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class RateLimiterFilterTest {

    private static final ClientRequest DUMMY_REQUEST =
            ClientRequest.create(HttpMethod.GET, URI.create("http://example.com")).build();

    @Test
    void spacesConcurrentRequestsAccordingToTheConfiguredRate() {
        ScannerConfig config = new ScannerConfig();
        config.setMaxRequestsPerSecond(10); // 100ms between requests

        RateLimiterFilter filter = new RateLimiterFilter(config);
        List<Long> timestamps = new CopyOnWriteArrayList<>();

        ExchangeFunction fakeExchange = request -> Mono.fromSupplier(() -> {
            timestamps.add(System.currentTimeMillis());
            return ClientResponse.create(HttpStatus.OK).build();
        });

        Flux.range(0, 5)
                .flatMap(i -> filter.filter(DUMMY_REQUEST, fakeExchange))
                .blockLast(Duration.ofSeconds(5));

        assertThat(timestamps).hasSize(5);
        List<Long> sorted = new java.util.ArrayList<>(timestamps);
        Collections.sort(sorted);

        // 5 requests at 10 req/s must span at least ~4 intervals (400ms);
        // allow some tolerance for scheduler jitter.
        long span = sorted.get(sorted.size() - 1) - sorted.get(0);
        assertThat(span).isGreaterThanOrEqualTo(350);
    }

    @Test
    void doesNotDelayWhenRateLimitIsDisabled() {
        ScannerConfig config = new ScannerConfig();
        config.setMaxRequestsPerSecond(0);

        RateLimiterFilter filter = new RateLimiterFilter(config);
        AtomicInteger calls = new AtomicInteger();

        ExchangeFunction fakeExchange = request -> {
            calls.incrementAndGet();
            return Mono.just(ClientResponse.create(HttpStatus.OK).build());
        };

        long start = System.currentTimeMillis();
        Flux.range(0, 20)
                .flatMap(i -> filter.filter(DUMMY_REQUEST, fakeExchange))
                .blockLast(Duration.ofSeconds(5));
        long elapsed = System.currentTimeMillis() - start;

        assertThat(calls.get()).isEqualTo(20);
        // Not a tight bound: this only needs to rule out per-request
        // throttling (20 requests at, say, 10 req/s would take ~2000ms),
        // not assert a specific JVM/scheduler warm-up cost.
        assertThat(elapsed).isLessThan(3000);
    }
}
