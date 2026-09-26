package com.websec.scanner.config;

import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Reservation-based rate limiter: each request atomically reserves the next
 * available time slot spaced {@code 1000 / requestsPerSecond} ms after the
 * previous one. Requests arriving after idle time run immediately instead of
 * bursting to catch up, and concurrent callers are still spaced correctly
 * since the reservation is a single atomic operation.
 *
 * <p>Reads the limit from {@link ScannerConfig} on every request (rather than
 * capturing it once) so a CLI flag applied before a scan starts takes effect
 * even though this filter is built during Spring context startup.
 */
public class RateLimiterFilter implements ExchangeFilterFunction {

    private final ScannerConfig config;
    private final AtomicLong nextFreeSlotMillis = new AtomicLong(0);

    public RateLimiterFilter(ScannerConfig config) {
        this.config = config;
    }

    @Override
    public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
        double requestsPerSecond = config.getMaxRequestsPerSecond();
        if (requestsPerSecond <= 0) {
            return next.exchange(request);
        }

        long intervalMs = Math.round(1000.0 / requestsPerSecond);
        long now = System.currentTimeMillis();
        long newSlot = nextFreeSlotMillis.accumulateAndGet(now,
                (prevSlot, currentNow) -> Math.max(prevSlot, currentNow) + intervalMs);
        long scheduledAt = newSlot - intervalMs;
        long delayMs = scheduledAt - now;

        if (delayMs <= 0) {
            return next.exchange(request);
        }
        return Mono.delay(Duration.ofMillis(delayMs)).then(next.exchange(request));
    }
}
