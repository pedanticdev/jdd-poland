package fish.payara.security.monitoring;

import fish.payara.security.events.SecurityEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.ObservesAsync;
import org.eclipse.microprofile.metrics.Counter;
import org.eclipse.microprofile.metrics.annotation.Metric;

import jakarta.inject.Inject;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.logging.Logger;

/**
 * Security monitoring service for continuous validation.
 * Observes security events and maintains metrics for anomaly detection.
 */
@ApplicationScoped
public class SecurityMonitor {

    private static final Logger LOGGER = Logger.getLogger(SecurityMonitor.class.getName());
    private static final int MAX_EVENT_HISTORY = 1000;

    private final ConcurrentLinkedQueue<SecurityEvent> recentEvents = new ConcurrentLinkedQueue<>();

    @Inject
    @Metric(name = "security_authentication_success_total", absolute = true)
    private Counter authSuccessCounter;

    @Inject
    @Metric(name = "security_authentication_failure_total", absolute = true)
    private Counter authFailureCounter;

    @Inject
    @Metric(name = "security_authorization_failure_total", absolute = true)
    private Counter authzFailureCounter;

    @Inject
    @Metric(name = "security_suspicious_activity_total", absolute = true)
    private Counter suspiciousActivityCounter;

    /**
     * Asynchronously observe security events for monitoring.
     */
    public void onSecurityEvent(@ObservesAsync SecurityEvent event) {
        LOGGER.info("Security event: " + event);

        // Update metrics
        switch (event.getType()) {
            case AUTHENTICATION_SUCCESS:
                authSuccessCounter.inc();
                break;
            case AUTHENTICATION_FAILURE:
                authFailureCounter.inc();
                detectSuspiciousActivity(event);
                break;
            case AUTHORIZATION_FAILURE:
                authzFailureCounter.inc();
                detectSuspiciousActivity(event);
                break;
            case SUSPICIOUS_ACTIVITY:
                suspiciousActivityCounter.inc();
                handleSuspiciousActivity(event);
                break;
            default:
                break;
        }

        // Store event in history
        recentEvents.add(event);
        if (recentEvents.size() > MAX_EVENT_HISTORY) {
            recentEvents.poll();
        }
    }

    private void detectSuspiciousActivity(SecurityEvent event) {
        // Implement anomaly detection logic
        // Examples:
        // - Multiple failed attempts from same IP
        // - Access from unusual location
        // - Access at unusual time
        // - Rapid succession of requests

        String username = event.getUsername();
        String ipAddress = event.getIpAddress();

        long failureCount = recentEvents.stream()
                .filter(e -> e.getType() == SecurityEvent.Type.AUTHENTICATION_FAILURE ||
                             e.getType() == SecurityEvent.Type.AUTHORIZATION_FAILURE)
                .filter(e -> e.getUsername().equals(username) || e.getIpAddress().equals(ipAddress))
                .count();

        if (failureCount > 5) {
            LOGGER.warning("Suspicious activity detected for user: " + username + " from IP: " + ipAddress);
            suspiciousActivityCounter.inc();
        }
    }

    private void handleSuspiciousActivity(SecurityEvent event) {
        // Handle suspicious activity
        // Examples:
        // - Send alert to security team
        // - Trigger additional authentication challenges
        // - Temporarily block access
        // - Increase monitoring level

        LOGGER.severe("SECURITY ALERT: Suspicious activity - " + event);

        // In production, integrate with alerting systems
        // - Send email/SMS/Slack notification
        // - Create incident ticket
        // - Trigger automated response
    }

    public ConcurrentLinkedQueue<SecurityEvent> getRecentEvents() {
        return new ConcurrentLinkedQueue<>(recentEvents);
    }
}
