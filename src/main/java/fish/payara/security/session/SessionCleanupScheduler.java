package fish.payara.security.session;

import jakarta.ejb.Schedule;
import jakarta.ejb.Singleton;
import jakarta.ejb.Startup;
import jakarta.inject.Inject;

import java.util.logging.Logger;

/**
 * Scheduled task to clean up expired sessions.
 * Runs every 5 minutes to remove stale sessions and enforce Zero Trust timeout policies.
 */
@Singleton
@Startup
public class SessionCleanupScheduler {

    private static final Logger LOGGER = Logger.getLogger(SessionCleanupScheduler.class.getName());

    @Inject
    private SessionManager sessionManager;

    /**
     * Clean up expired sessions every 5 minutes.
     */
    @Schedule(hour = "*", minute = "*/5", persistent = false)
    public void cleanupExpiredSessions() {
        LOGGER.fine("Running scheduled session cleanup");
        sessionManager.cleanupExpiredSessions();
    }
}
