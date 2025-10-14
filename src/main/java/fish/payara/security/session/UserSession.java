package fish.payara.security.session;

import java.time.Instant;
import java.util.Map;

/**
 * Represents an active user session in the Zero Trust architecture.
 * Sessions are tracked to enforce timeouts and detect anomalous behavior.
 */
public record UserSession(
        String sessionId,
        String username,
        String ipAddress,
        Instant createdAt,
        Instant expiresAt,
        Map<String, Object> metadata
) {
    /**
     * Check if this session is expired.
     */
    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    /**
     * Check if this session is still active.
     */
    public boolean isActive() {
        return !isExpired();
    }

    /**
     * Get remaining time in seconds until session expires.
     */
    public long getRemainingSeconds() {
        long remaining = expiresAt.getEpochSecond() - Instant.now().getEpochSecond();
        return Math.max(0, remaining);
    }
}
