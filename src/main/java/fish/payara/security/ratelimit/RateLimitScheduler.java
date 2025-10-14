package fish.payara.security.ratelimit;

import jakarta.ejb.Schedule;
import jakarta.ejb.Singleton;
import jakarta.ejb.Startup;
import jakarta.inject.Inject;

import java.util.logging.Logger;

/**
 * Scheduled task to clean up old rate limit entries.
 * Runs every 15 minutes to remove stale data.
 */
@Singleton
@Startup
public class RateLimitScheduler {

    private static final Logger LOGGER = Logger.getLogger(RateLimitScheduler.class.getName());

    @Inject
    private RateLimiter rateLimiter;

    /**
     * Clean up rate limit entries older than 1 hour.
     */
    @Schedule(hour = "*", minute = "*/15", persistent = false)
    public void cleanupOldEntries() {
        LOGGER.fine("Running scheduled rate limit cleanup");
        rateLimiter.cleanup(3600); // 1 hour
    }
}
