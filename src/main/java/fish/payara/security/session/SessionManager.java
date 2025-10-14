package fish.payara.security.session;

import fish.payara.security.events.SecurityEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Event;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * Session management for Zero Trust security.
 * Tracks active sessions, enforces timeouts, and publishes session lifecycle events.
 */
@ApplicationScoped
public class SessionManager {

    private static final Logger LOGGER = Logger.getLogger(SessionManager.class.getName());

    private final Map<String, UserSession> activeSessions = new ConcurrentHashMap<>();

    @Inject
    private Event<SecurityEvent> securityEventPublisher;

    @Inject
    @ConfigProperty(name = "security.session.timeout", defaultValue = "1800")
    private Integer sessionTimeoutSeconds;

    /**
     * Create a new session for the authenticated user.
     */
    public UserSession createSession(String username, String ipAddress, Map<String, Object> metadata) {
        String sessionId = UUID.randomUUID().toString();
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(sessionTimeoutSeconds);

        UserSession session = new UserSession(
                sessionId,
                username,
                ipAddress,
                now,
                expiresAt,
                metadata
        );

        activeSessions.put(sessionId, session);

        LOGGER.info(String.format("Session created for user '%s' from IP %s. Session ID: %s, Expires: %s",
                username, ipAddress, sessionId, expiresAt));

        securityEventPublisher.fire(new SecurityEvent(
                SecurityEvent.Type.SESSION_CREATED,
                username,
                ipAddress,
                Map.of(
                        "sessionId", sessionId,
                        "expiresAt", expiresAt.toString(),
                        "timeoutSeconds", sessionTimeoutSeconds
                )
        ));

        return session;
    }

    /**
     * Validate if session is still active and not expired.
     */
    public boolean isSessionValid(String sessionId) {
        UserSession session = activeSessions.get(sessionId);

        if (session == null) {
            return false;
        }

        if (Instant.now().isAfter(session.expiresAt())) {
            expireSession(sessionId);
            return false;
        }

        return true;
    }

    /**
     * Get session details by session ID.
     */
    public UserSession getSession(String sessionId) {
        return activeSessions.get(sessionId);
    }

    /**
     * Renew session timeout (sliding expiration).
     */
    public void renewSession(String sessionId) {
        UserSession session = activeSessions.get(sessionId);

        if (session != null && Instant.now().isBefore(session.expiresAt())) {
            Instant newExpiresAt = Instant.now().plusSeconds(sessionTimeoutSeconds);
            UserSession renewedSession = new UserSession(
                    session.sessionId(),
                    session.username(),
                    session.ipAddress(),
                    session.createdAt(),
                    newExpiresAt,
                    session.metadata()
            );

            activeSessions.put(sessionId, renewedSession);

            LOGGER.fine(String.format("Session renewed for user '%s'. New expiry: %s",
                    session.username(), newExpiresAt));
        }
    }

    /**
     * Explicitly expire a session (logout or timeout).
     */
    public void expireSession(String sessionId) {
        UserSession session = activeSessions.remove(sessionId);

        if (session != null) {
            LOGGER.info(String.format("Session expired for user '%s'. Session ID: %s",
                    session.username(), sessionId));

            securityEventPublisher.fire(new SecurityEvent(
                    SecurityEvent.Type.SESSION_EXPIRED,
                    session.username(),
                    session.ipAddress(),
                    Map.of(
                            "sessionId", sessionId,
                            "reason", "explicit_expiration"
                    )
            ));
        }
    }

    /**
     * Clean up expired sessions (should be called periodically).
     */
    public void cleanupExpiredSessions() {
        Instant now = Instant.now();
        int expiredCount = 0;

        for (Map.Entry<String, UserSession> entry : activeSessions.entrySet()) {
            if (now.isAfter(entry.getValue().expiresAt())) {
                String sessionId = entry.getKey();
                UserSession session = activeSessions.remove(sessionId);

                if (session != null) {
                    expiredCount++;

                    securityEventPublisher.fire(new SecurityEvent(
                            SecurityEvent.Type.SESSION_EXPIRED,
                            session.username(),
                            session.ipAddress(),
                            Map.of(
                                    "sessionId", sessionId,
                                    "reason", "timeout"
                            )
                    ));
                }
            }
        }

        if (expiredCount > 0) {
            LOGGER.info(String.format("Cleaned up %d expired sessions", expiredCount));
        }
    }

    /**
     * Get count of active sessions.
     */
    public int getActiveSessionCount() {
        return activeSessions.size();
    }

    /**
     * Get all active sessions for a specific user.
     */
    public long getActiveSessionCountForUser(String username) {
        return activeSessions.values().stream()
                .filter(session -> session.username().equals(username))
                .count();
    }
}
