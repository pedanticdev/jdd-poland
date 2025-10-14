package fish.payara.security.token;

import jakarta.ejb.Schedule;
import jakarta.ejb.Singleton;
import jakarta.ejb.Startup;
import jakarta.inject.Inject;

import java.util.logging.Logger;

/**
 * Scheduled task to clean up expired revoked tokens.
 * Runs every hour to remove tokens from the revocation list that have expired.
 */
@Singleton
@Startup
public class TokenRevocationScheduler {

    private static final Logger LOGGER = Logger.getLogger(TokenRevocationScheduler.class.getName());

    @Inject
    private TokenRevocationService tokenRevocationService;

    /**
     * Clean up expired revoked tokens every hour.
     */
    @Schedule(hour = "*", minute = "0", persistent = false)
    public void cleanupExpiredRevokedTokens() {
        LOGGER.fine("Running scheduled token revocation cleanup");
        tokenRevocationService.cleanupExpiredTokens();
    }
}
