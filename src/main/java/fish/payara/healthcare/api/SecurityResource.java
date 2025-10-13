package fish.payara.healthcare.api;

import fish.payara.security.config.KeycloakConfig;
import fish.payara.security.events.SecurityEvent;
import fish.payara.security.monitoring.SecurityMonitor;
import fish.payara.security.token.TokenService;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.ws.rs.*;
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

    @POST
    @Path("/token")
    @Operation(summary = "Obtain access token", description = "Get JWT token using username and password")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Token obtained successfully"),
            @APIResponse(responseCode = "401", description = "Invalid credentials")
    })
    public Response getToken(@Valid @NotNull TokenRequest request) {
        TokenService.TokenResponse tokenResponse = tokenService.getUserToken(
                request.username(),
                request.password()
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
    @Operation(summary = "Get security events", description = "Retrieve recent security events for monitoring")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Events retrieved"),
            @APIResponse(responseCode = "403", description = "Insufficient permissions")
    })
    public Response getSecurityEvents(
            @QueryParam("limit") @DefaultValue("50") @Positive int limit) {
        List<SecurityEventDTO> events = securityMonitor.getRecentEvents().stream()
                .limit(limit)
                .map(this::toDTO)
                .toList();

        return Response.ok(events).build();
    }

    @GET
    @Path("/config")
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
}
