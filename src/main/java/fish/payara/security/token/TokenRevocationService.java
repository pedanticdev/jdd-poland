package fish.payara.security.token;

import fish.payara.security.events.SecurityEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Event;
import jakarta.inject.Inject;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * Token revocation service for Zero Trust security.
 * Maintains a blacklist of revoked tokens to prevent their reuse.
 *
 * PRODUCTION NOTE: In production, this should use Redis or a distributed cache
 * to ensure revocation is consistent across multiple instances.
 */
@ApplicationScoped
public class TokenRevocationService {

    private static final Logger LOGGER = Logger.getLogger(TokenRevocationService.class.getName());

    // Map of token ID/JTI -> expiration time
    private final Map<String, Instant> revokedTokens = new ConcurrentHashMap<>();

    @Inject
    private Event<SecurityEvent> securityEventPublisher;

    /**
     * Revoke a token by its JTI (JWT ID).
     */
    public void revokeToken(String jti, String username, String reason, Instant tokenExpiry) {
        if (jti == null || jti.isBlank()) {
            LOGGER.warning("Attempted to revoke token with null or blank JTI");
            return;
        }

        revokedTokens.put(jti, tokenExpiry);

        LOGGER.info(String.format("Token revoked for user '%s'. JTI: %s, Reason: %s",
                username, jti, reason));

        securityEventPublisher.fire(new SecurityEvent(
                SecurityEvent.Type.SUSPICIOUS_ACTIVITY,
                username,
                "unknown",
                Map.of(
                        "action", "token_revocation",
                        "jti", jti,
                        "reason", reason,
                        "expiresAt", tokenExpiry.toString()
                )
        ));
    }

    /**
     * Check if a token has been revoked.
     */
    public boolean isRevoked(String jti) {
        if (jti == null || jti.isBlank()) {
            return false;
        }

        return revokedTokens.containsKey(jti);
    }

    /**
     * Get all revoked token JTIs.
     */
    public Set<String> getRevokedTokens() {
        return Set.copyOf(revokedTokens.keySet());
    }

    /**
     * Clean up expired revoked tokens.
     * Tokens remain in the revocation list until they expire naturally.
     */
    public void cleanupExpiredTokens() {
        Instant now = Instant.now();
        int removedCount = 0;

        for (Map.Entry<String, Instant> entry : revokedTokens.entrySet()) {
            if (now.isAfter(entry.getValue())) {
                revokedTokens.remove(entry.getKey());
                removedCount++;
            }
        }

        if (removedCount > 0) {
            LOGGER.info(String.format("Cleaned up %d expired revoked tokens", removedCount));
        }
    }

    /**
     * Get count of currently revoked tokens.
     */
    public int getRevokedTokenCount() {
        return revokedTokens.size();
    }
}
