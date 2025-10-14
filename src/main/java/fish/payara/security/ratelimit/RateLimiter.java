package fish.payara.security.ratelimit;

import fish.payara.security.events.SecurityEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Event;
import jakarta.inject.Inject;

import java.time.Instant;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.logging.Logger;

/**
 * Rate limiter for Zero Trust security.
 * Prevents brute force attacks by limiting authentication attempts per IP/user.
 *
 * PRODUCTION NOTE: In production, use Redis for distributed rate limiting
 * across multiple application instances.
 */
@ApplicationScoped
public class RateLimiter {

    private static final Logger LOGGER = Logger.getLogger(RateLimiter.class.getName());

    // Map of key (IP or username) -> queue of attempt timestamps
    private final Map<String, Queue<Instant>> attemptHistory = new ConcurrentHashMap<>();

    @Inject
    private Event<SecurityEvent> securityEventPublisher;

    /**
     * Check if an action is allowed based on rate limits.
     *
     * @param key           Identifier (IP address or username)
     * @param maxAttempts   Maximum attempts allowed
     * @param windowSeconds Time window in seconds
     * @return true if allowed, false if rate limited
     */
    public boolean isAllowed(String key, int maxAttempts, int windowSeconds) {
        if (key == null || key.isBlank()) {
            return true;
        }

        Queue<Instant> attempts = attemptHistory.computeIfAbsent(key, k -> new ConcurrentLinkedQueue<>());

        // Clean up old attempts outside the time window
        Instant cutoff = Instant.now().minusSeconds(windowSeconds);
        attempts.removeIf(timestamp -> timestamp.isBefore(cutoff));

        // Check if under the limit
        if (attempts.size() < maxAttempts) {
            attempts.add(Instant.now());
            return true;
        }

        // Rate limited
        LOGGER.warning(String.format("Rate limit exceeded for key '%s'. Attempts: %d, Limit: %d, Window: %ds",
                key, attempts.size(), maxAttempts, windowSeconds));

        securityEventPublisher.fire(new SecurityEvent(
                SecurityEvent.Type.SUSPICIOUS_ACTIVITY,
                key,
                key,
                Map.of(
                        "action", "rate_limit_exceeded",
                        "attempts", attempts.size(),
                        "limit", maxAttempts,
                        "windowSeconds", windowSeconds
                )
        ));

        return false;
    }

    /**
     * Record an attempt (without checking the limit).
     */
    public void recordAttempt(String key) {
        if (key == null || key.isBlank()) {
            return;
        }

        Queue<Instant> attempts = attemptHistory.computeIfAbsent(key, k -> new ConcurrentLinkedQueue<>());
        attempts.add(Instant.now());
    }

    /**
     * Reset rate limit for a specific key.
     */
    public void reset(String key) {
        attemptHistory.remove(key);
        LOGGER.fine(String.format("Rate limit reset for key '%s'", key));
    }

    /**
     * Clean up old attempt histories.
     */
    public void cleanup(int maxAgeSeconds) {
        Instant cutoff = Instant.now().minusSeconds(maxAgeSeconds);
        int removedCount = 0;

        for (Map.Entry<String, Queue<Instant>> entry : attemptHistory.entrySet()) {
            entry.getValue().removeIf(timestamp -> timestamp.isBefore(cutoff));

            if (entry.getValue().isEmpty()) {
                attemptHistory.remove(entry.getKey());
                removedCount++;
            }
        }

        if (removedCount > 0) {
            LOGGER.fine(String.format("Cleaned up %d rate limit entries", removedCount));
        }
    }

    /**
     * Get attempt count for a key within the time window.
     */
    public int getAttemptCount(String key, int windowSeconds) {
        Queue<Instant> attempts = attemptHistory.get(key);

        if (attempts == null) {
            return 0;
        }

        Instant cutoff = Instant.now().minusSeconds(windowSeconds);
        return (int) attempts.stream()
                .filter(timestamp -> timestamp.isAfter(cutoff))
                .count();
    }
}
