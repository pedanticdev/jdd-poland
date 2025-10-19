package fish.payara.healthcare.api;

import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.metrics.Counter;
import org.eclipse.microprofile.metrics.annotation.Metric;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.OperatingSystemMXBean;
import java.lang.management.RuntimeMXBean;
import java.util.HashMap;
import java.util.Map;

/**
 * Performance metrics and monitoring endpoints.
 * Demonstrates Zero Trust principle: maintain performance while enforcing security.
 */
@Path("/metrics")
@Produces(MediaType.APPLICATION_JSON)
@Tag(name = "Metrics", description = "Application performance and security metrics")
public class MetricsResource {

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

    @GET
    @Path("/security")
    @RolesAllowed({"ADMIN", "DOCTOR", "NURSE"})
    @Operation(summary = "Get security metrics", description = "Retrieve security-related metrics and counters")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Metrics retrieved successfully"),
            @APIResponse(responseCode = "403", description = "Insufficient permissions")
    })
    public Response getSecurityMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("authenticationSuccess", authSuccessCounter.getCount());
        metrics.put("authenticationFailure", authFailureCounter.getCount());
        metrics.put("authorizationFailure", authzFailureCounter.getCount());
        metrics.put("suspiciousActivity", suspiciousActivityCounter.getCount());

        return Response.ok(metrics).build();
    }

    @GET
    @Path("/performance")
    @RolesAllowed({"ADMIN"})
    @Operation(summary = "Get performance metrics", description = "Retrieve application performance metrics")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Metrics retrieved successfully"),
            @APIResponse(responseCode = "403", description = "Insufficient permissions")
    })
    public Response getPerformanceMetrics() {
        RuntimeMXBean runtimeBean = ManagementFactory.getRuntimeMXBean();
        MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
        OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();

        Map<String, Object> metrics = new HashMap<>();

        // Runtime metrics
        metrics.put("uptime", runtimeBean.getUptime());
        metrics.put("startTime", runtimeBean.getStartTime());

        // Memory metrics
        long heapUsed = memoryBean.getHeapMemoryUsage().getUsed();
        long heapMax = memoryBean.getHeapMemoryUsage().getMax();
        long nonHeapUsed = memoryBean.getNonHeapMemoryUsage().getUsed();

        metrics.put("heapUsedMB", heapUsed / (1024 * 1024));
        metrics.put("heapMaxMB", heapMax / (1024 * 1024));
        metrics.put("heapUsagePercent", (double) heapUsed / heapMax * 100);
        metrics.put("nonHeapUsedMB", nonHeapUsed / (1024 * 1024));

        // System metrics
        metrics.put("availableProcessors", osBean.getAvailableProcessors());
        metrics.put("systemLoadAverage", osBean.getSystemLoadAverage());

        return Response.ok(metrics).build();
    }

    @GET
    @Path("/health")
    @Operation(summary = "Health check", description = "Check application health status")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Application is healthy")
    })
    public Response healthCheck() {
        Map<String, Object> health = new HashMap<>();
        health.put("status", "UP");
        health.put("timestamp", System.currentTimeMillis());

        // Check memory pressure
        MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
        long heapUsed = memoryBean.getHeapMemoryUsage().getUsed();
        long heapMax = memoryBean.getHeapMemoryUsage().getMax();
        double heapUsagePercent = (double) heapUsed / heapMax * 100;

        health.put("memoryHealthy", heapUsagePercent < 90);
        health.put("heapUsagePercent", heapUsagePercent);

        return Response.ok(health).build();
    }
}
