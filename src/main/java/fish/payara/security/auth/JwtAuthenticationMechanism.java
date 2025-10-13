package fish.payara.security.auth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import fish.payara.security.config.KeycloakConfig;
import fish.payara.security.events.SecurityEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Event;
import jakarta.inject.Inject;
import jakarta.security.enterprise.AuthenticationException;
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.security.enterprise.credential.Credential;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.time.Duration;
import java.util.*;
import java.util.logging.Logger;

/**
 * Custom HTTP Authentication Mechanism for Zero Trust JWT validation.
 * Validates OAuth 2.0 Bearer tokens from Keycloak with continuous verification.
 */
@ApplicationScoped
public class JwtAuthenticationMechanism implements HttpAuthenticationMechanism {

    private static final Logger LOGGER = Logger.getLogger(JwtAuthenticationMechanism.class.getName());
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    @Inject
    private KeycloakConfig keycloakConfig;

    @Inject
    private Event<SecurityEvent> securityEventPublisher;

    private JWKSet jwkSet;
    private long jwkSetLastFetched = 0;
    private static final long JWK_SET_CACHE_DURATION = 3600000; // 1 hour

    @Override
    public AuthenticationStatus validateRequest(
            HttpServletRequest request,
            HttpServletResponse response,
            HttpMessageContext httpMessageContext) throws AuthenticationException {

        String authHeader = request.getHeader(AUTHORIZATION_HEADER);

        // Allow unauthenticated access for public endpoints
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return httpMessageContext.doNothing();
        }

        String token = authHeader.substring(BEARER_PREFIX.length());

        try {
            CredentialValidationResult result = validateToken(token, request);

            if (result.getStatus() == CredentialValidationResult.Status.VALID) {
                securityEventPublisher.fire(new SecurityEvent(
                        SecurityEvent.Type.AUTHENTICATION_SUCCESS,
                        result.getCallerPrincipal().getName(),
                        request.getRemoteAddr(),
                        Map.of("roles", result.getCallerGroups())
                ));

                return httpMessageContext.notifyContainerAboutLogin(result);
            } else {
                securityEventPublisher.fire(new SecurityEvent(
                        SecurityEvent.Type.AUTHENTICATION_FAILURE,
                        "unknown",
                        request.getRemoteAddr(),
                        Map.of("reason", "Invalid token")
                ));

                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return httpMessageContext.responseUnauthorized();
            }
        } catch (Exception e) {
            LOGGER.warning("Token validation failed: " + e.getMessage());
            securityEventPublisher.fire(new SecurityEvent(
                    SecurityEvent.Type.AUTHENTICATION_FAILURE,
                    "unknown",
                    request.getRemoteAddr(),
                    Map.of("error", e.getMessage())
            ));

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return httpMessageContext.responseUnauthorized();
        }
    }

    private CredentialValidationResult validateToken(String token, HttpServletRequest request) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            // Verify signature using JWK
            if (!verifySignature(signedJWT)) {
                LOGGER.warning("JWT signature verification failed");
                return CredentialValidationResult.INVALID_RESULT;
            }

            // Validate claims
            Map<String, Object> claims = signedJWT.getJWTClaimsSet().getClaims();

            // Check expiration
            Date expirationTime = signedJWT.getJWTClaimsSet().getExpirationTime();
            if (expirationTime == null || expirationTime.before(new Date())) {
                LOGGER.warning("JWT token expired");
                return CredentialValidationResult.INVALID_RESULT;
            }

            // Check issuer
            String issuer = signedJWT.getJWTClaimsSet().getIssuer();
            if (!keycloakConfig.getIssuer().equals(issuer)) {
                LOGGER.warning("JWT issuer mismatch: " + issuer);
                return CredentialValidationResult.INVALID_RESULT;
            }

            // Extract user information
            String username = signedJWT.getJWTClaimsSet().getStringClaim("preferred_username");
            if (username == null) {
                username = signedJWT.getJWTClaimsSet().getSubject();
            }

            // Extract roles
            Set<String> roles = extractRoles(claims);

            // Build additional attributes for ABAC
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("email", signedJWT.getJWTClaimsSet().getStringClaim("email"));
            attributes.put("department", signedJWT.getJWTClaimsSet().getStringClaim("department"));
            attributes.put("ipAddress", request.getRemoteAddr());
            attributes.put("userAgent", request.getHeader("User-Agent"));
            attributes.put("authTime", new Date());

            return new CredentialValidationResult(username, roles);

        } catch (ParseException e) {
            LOGGER.severe("Failed to parse JWT token: " + e.getMessage());
            return CredentialValidationResult.INVALID_RESULT;
        }
    }

    private boolean verifySignature(SignedJWT signedJWT) {
        try {
            String keyId = signedJWT.getHeader().getKeyID();
            JWK jwk = getJWKSet().getKeyByKeyId(keyId);

            if (jwk == null) {
                LOGGER.warning("No JWK found for key ID: " + keyId);
                return false;
            }

            RSAKey rsaKey = (RSAKey) jwk;
            JWSVerifier verifier = new RSASSAVerifier(rsaKey);

            return signedJWT.verify(verifier);
        } catch (JOSEException e) {
            LOGGER.severe("JWT signature verification error: " + e.getMessage());
            return false;
        }
    }

    private JWKSet getJWKSet() {
        long now = System.currentTimeMillis();

        // Refresh JWK Set if cache expired
        if (jwkSet == null || (now - jwkSetLastFetched) > JWK_SET_CACHE_DURATION) {
            try {
                HttpClient client = HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(10))
                        .build();

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(keycloakConfig.getJwksUri()))
                        .GET()
                        .build();

                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() == 200) {
                    jwkSet = JWKSet.parse(response.body());
                    jwkSetLastFetched = now;
                    LOGGER.info("JWK Set refreshed from Keycloak");
                }
            } catch (IOException | InterruptedException | ParseException e) {
                LOGGER.severe("Failed to fetch JWK Set: " + e.getMessage());
            }
        }

        return jwkSet;
    }

    @SuppressWarnings("unchecked")
    private Set<String> extractRoles(Map<String, Object> claims) {
        Set<String> roles = new HashSet<>();

        // Check for roles in different claim locations
        if (claims.containsKey("roles")) {
            Object rolesObj = claims.get("roles");
            if (rolesObj instanceof List) {
                roles.addAll((List<String>) rolesObj);
            }
        }

        if (claims.containsKey("realm_access")) {
            Map<String, Object> realmAccess = (Map<String, Object>) claims.get("realm_access");
            if (realmAccess != null && realmAccess.containsKey("roles")) {
                roles.addAll((List<String>) realmAccess.get("roles"));
            }
        }

        return roles;
    }
}
