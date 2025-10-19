package fish.payara.security.mfa;

import fish.payara.security.events.SecurityEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Event;
import jakarta.inject.Inject;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * Multi-Factor Authentication service for Zero Trust security.
 * Generates and validates time-based one-time passwords (TOTP).
 * Demonstrates MFA integration within Jakarta EE applications.
 */
@ApplicationScoped
public class MfaService {

    private static final Logger LOGGER = Logger.getLogger(MfaService.class.getName());
    private static final int OTP_LENGTH = 6;
    private static final int OTP_VALIDITY_MINUTES = 5;
    private static final SecureRandom RANDOM = new SecureRandom();
    // In-memory storage for demo purposes. In production, use database.
    private final Map<String, OtpData> otpStorage = new ConcurrentHashMap<>();
    @Inject
    private Event<SecurityEvent> securityEventPublisher;

    /**
     * Generate a one-time password for MFA.
     */
    public String generateOtp(String username, String ipAddress) {
        String otp = generateRandomOtp();
        Instant expiryTime = Instant.now().plus(OTP_VALIDITY_MINUTES, ChronoUnit.MINUTES);

        otpStorage.put(username, new OtpData(otp, expiryTime, false));

        LOGGER.info("OTP generated for user: " + username + " (expires in " + OTP_VALIDITY_MINUTES + " minutes)");

        securityEventPublisher.fire(new SecurityEvent(
                SecurityEvent.Type.DATA_ACCESS,
                username,
                ipAddress,
                Map.of("action", "MFA_OTP_GENERATED", "expiryTime", expiryTime.toString())
        ));

        // In production, send OTP via SMS/Email/Authenticator app
        // For demo purposes, we'll just log it
        LOGGER.info("OTP for " + username + ": " + otp);

        return otp;
    }

    /**
     * Validate a one-time password.
     */
    public boolean validateOtp(String username, String otp, String ipAddress) {
        OtpData otpData = otpStorage.get(username);

        if (otpData == null) {
            LOGGER.warning("No OTP found for user: " + username);
            publishValidationEvent(username, ipAddress, false, "NO_OTP_FOUND");
            return false;
        }

        if (otpData.used()) {
            LOGGER.warning("OTP already used for user: " + username);
            publishValidationEvent(username, ipAddress, false, "OTP_ALREADY_USED");
            return false;
        }

        if (Instant.now().isAfter(otpData.expiryTime())) {
            LOGGER.warning("OTP expired for user: " + username);
            otpStorage.remove(username);
            publishValidationEvent(username, ipAddress, false, "OTP_EXPIRED");
            return false;
        }

        if (!otpData.otp().equals(otp)) {
            LOGGER.warning("Invalid OTP for user: " + username);
            publishValidationEvent(username, ipAddress, false, "OTP_MISMATCH");
            return false;
        }

        // Mark OTP as used
        otpStorage.put(username, new OtpData(otpData.otp(), otpData.expiryTime(), true));

        LOGGER.info("OTP validated successfully for user: " + username);
        publishValidationEvent(username, ipAddress, true, "OTP_VALIDATED");

        return true;
    }

    /**
     * Check if MFA is required for the user.
     */
    public boolean isMfaRequired(String username) {
        // In production, check user preferences or security policy
        // For demo, we'll require MFA for specific roles or all users
        return true; // Require MFA for all users in Zero Trust model
    }

    /**
     * Check if MFA is already completed for the user in current session.
     */
    public boolean isMfaCompleted(String username) {
        OtpData otpData = otpStorage.get(username);
        return otpData != null && otpData.used();
    }

    private String generateRandomOtp() {
        int otp = RANDOM.nextInt((int) Math.pow(10, OTP_LENGTH));
        return String.format("%0" + OTP_LENGTH + "d", otp);
    }

    private void publishValidationEvent(String username, String ipAddress, boolean success, String reason) {
        securityEventPublisher.fire(new SecurityEvent(
                success ? SecurityEvent.Type.AUTHENTICATION_SUCCESS : SecurityEvent.Type.AUTHENTICATION_FAILURE,
                username,
                ipAddress,
                Map.of("action", "MFA_VALIDATION", "success", success, "reason", reason)
        ));
    }

    public record OtpData(String otp, Instant expiryTime, boolean used) {
    }
}
