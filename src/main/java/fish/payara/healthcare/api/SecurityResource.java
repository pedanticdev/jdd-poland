package fish.payara.healthcare.api;

import fish.payara.security.config.KeycloakConfig;
import fish.payara.security.events.SecurityEvent;
import fish.payara.security.monitoring.SecurityMonitor;
import fish.payara.security.ratelimit.RateLimiter;
import fish.payara.security.session.SessionManager;
import fish.payara.security.token.TokenRevocationService;
import fish.payara.security.token.TokenService;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

import java.util.List;
import java.util.Map;

/**
 * Security monitoring and token management endpoints.
 * Provides visibility into Zero Trust security operations.
 */
@Path("/security")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@Tag(name = "Security", description = "Security monitoring and token management")
public class SecurityResource {

    @Inject
    private TokenService tokenService;

    @Inject
    private KeycloakConfig keycloakConfig;

    @Inject
    private SecurityMonitor securityMonitor;

    @Inject
    private SessionManager sessionManager;

    @Inject
    private TokenRevocationService tokenRevocationService;

    @Inject
    private RateLimiter rateLimiter;

    @POST
    @Path("/token")
    @PermitAll
    @Operation(summary = "Obtain access token", description = "Get JWT token using username and password")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Token obtained successfully"),
            @APIResponse(responseCode = "401", description = "Invalid credentials")
    })
    public Response getToken(@Valid @NotNull TokenRequest request, @Context HttpServletRequest servletRequest) {
        String ipAddress = servletRequest.getRemoteAddr();

        // Rate limiting: 5 attempts per minute per IP
        if (!rateLimiter.isAllowed(ipAddress, 5, 60)) {
            return Response.status(Response.Status.TOO_MANY_REQUESTS)
                    .entity(new ErrorResponse("Too many authentication attempts. Please try again later."))
                    .build();
        }

        // Also rate limit by username: 10 attempts per 5 minutes
        if (!rateLimiter.isAllowed("user:" + request.username(), 10, 300)) {
            return Response.status(Response.Status.TOO_MANY_REQUESTS)
                    .entity(new ErrorResponse("Too many authentication attempts for this account. Please try again later."))
                    .build();
        }

        TokenService.TokenResponse tokenResponse = tokenService.getUserToken(
                request.username(),
                request.password(),
                ipAddress
        );

        if (tokenResponse == null) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(new ErrorResponse("Invalid credentials"))
                    .build();
        }

        return Response.ok(new TokenResponseDTO(
                tokenResponse.accessToken(),
                tokenResponse.tokenType(),
                tokenResponse.expiresIn(),
                tokenResponse.refreshToken()
        )).build();
    }

    @POST
    @Path("/token/refresh")
    @PermitAll
    @Operation(summary = "Refresh access token", description = "Obtain new access token using refresh token")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Token refreshed successfully"),
            @APIResponse(responseCode = "401", description = "Invalid refresh token")
    })
    public Response refreshToken(@Valid @NotNull RefreshTokenRequest request) {
        TokenService.TokenResponse tokenResponse = tokenService.refreshToken(request.refreshToken());

        if (tokenResponse == null) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(new ErrorResponse("Invalid refresh token"))
                    .build();
        }

        return Response.ok(new TokenResponseDTO(
                tokenResponse.accessToken(),
                tokenResponse.tokenType(),
                tokenResponse.expiresIn(),
                null
        )).build();
    }

    @GET
    @Path("/events")
    @RolesAllowed("ADMIN")
    @Operation(summary = "Get security events", description = "Retrieve recent security events for monitoring")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Events retrieved"),
            @APIResponse(responseCode = "403", description = "Insufficient permissions")
    })
    public Response getSecurityEvents(
            @QueryParam("limit") @DefaultValue("50") @Min(1) int limit) {
        List<SecurityEventDTO> events = securityMonitor.getRecentEvents().stream()
                .limit(limit)
                .map(this::toDTO)
                .toList();

        return Response.ok(events).build();
    }

    @GET
    @Path("/config")
    @PermitAll
    @Operation(summary = "Get security configuration", description = "Retrieve current security configuration (non-sensitive)")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Configuration retrieved")
    })
    public Response getSecurityConfig() {
        SecurityConfig config = new SecurityConfig(
                keycloakConfig.getRealm(),
                keycloakConfig.getAuthServerUrl(),
                keycloakConfig.getClientId(),
                keycloakConfig.getIssuer(),
                keycloakConfig.getTokenEndpoint(),
                keycloakConfig.getAuthorizationEndpoint()
        );

        return Response.ok(config).build();
    }

    @POST
    @Path("/logout")
    @RolesAllowed({"ADMIN", "DOCTOR", "NURSE"})
    @Operation(summary = "Logout and revoke token", description = "Logout user and add token to revocation list")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Logout successful"),
            @APIResponse(responseCode = "400", description = "Invalid request")
    })
    public Response logout(@Valid @NotNull LogoutRequest request, @Context HttpServletRequest servletRequest) {
        // In a real implementation, we would extract JTI from the JWT token
        // For this demo, we'll use a simplified approach
        String jti = extractJtiFromToken(request.token());

        if (jti != null) {
            tokenRevocationService.revokeToken(
                    jti,
                    request.username(),
                    "user_logout",
                    java.time.Instant.now().plusSeconds(3600) // Token expiry estimate
            );
        }

        // Also expire any active sessions for the user
        // This is a simplified version - in production you'd track session IDs

        return Response.ok(new MessageResponse("Logout successful")).build();
    }

    /**
     * Extract JTI (JWT ID) from token.
     * In production, use a proper JWT library for this.
     */
    private String extractJtiFromToken(String token) {
        try {
            if (token == null || !token.contains(".")) {
                return null;
            }

            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                return null;
            }

            String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));

            // Simple JSON parsing to extract jti claim
            // In production, use jakarta.json or other proper JSON library
            if (payload.contains("\"jti\"")) {
                int jtiStart = payload.indexOf("\"jti\"");
                int valueStart = payload.indexOf("\"", jtiStart + 6);
                int valueEnd = payload.indexOf("\"", valueStart + 1);

                if (valueStart > 0 && valueEnd > valueStart) {
                    return payload.substring(valueStart + 1, valueEnd);
                }
            }

            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private SecurityEventDTO toDTO(SecurityEvent event) {
        return new SecurityEventDTO(
                event.getId(),
                event.getType().toString(),
                event.getUsername(),
                event.getIpAddress(),
                event.getTimestamp().toString(),
                event.getMetadata()
        );
    }

    public record TokenRequest(
            @NotBlank(message = "Username is required")
            String username,
            @NotBlank(message = "Password is required")
            String password
    ) {
    }

    public record RefreshTokenRequest(
            @NotBlank(message = "Refresh token is required")
            String refreshToken
    ) {
    }

    public record SecurityEventDTO(
            String id,
            String type,
            String username,
            String ipAddress,
            String timestamp,
            Map<String, Object> metadata
    ) {
    }

    public record SecurityConfig(
            String realm,
            String authServerUrl,
            String clientId,
            String issuer,
            String tokenEndpoint,
            String authorizationEndpoint
    ) {
    }

    public record TokenResponseDTO(
            String access_token,
            String token_type,
            int expires_in,
            String refresh_token
    ) {
    }

    public record ErrorResponse(String error) {
    }

    public record LogoutRequest(
            @NotBlank(message = "Username is required")
            String username,
            @NotBlank(message = "Token is required")
            String token
    ) {
    }

    public record MessageResponse(String message) {
    }
}
