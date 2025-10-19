package fish.payara.security.identitystore;

import fish.payara.security.config.KeycloakConfig;
import fish.payara.security.events.SecurityEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Event;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.security.enterprise.credential.Credential;
import jakarta.security.enterprise.credential.UsernamePasswordCredential;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.security.enterprise.identitystore.IdentityStore;

import java.io.StringReader;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Jakarta Security IdentityStore implementation for Keycloak/OIDC authentication.
 * Validates credentials against Keycloak and extracts roles from JWT claims.
 * Part of the standard Jakarta Security authentication flow.
 */
@ApplicationScoped
public class KeycloakIdentityStore implements IdentityStore {

    private static final Logger LOGGER = Logger.getLogger(KeycloakIdentityStore.class.getName());
    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    @Inject
    private KeycloakConfig keycloakConfig;

    @Inject
    private Event<SecurityEvent> securityEventPublisher;

    @Override
    public CredentialValidationResult validate(Credential credential) {
        if (credential instanceof UsernamePasswordCredential) {
            UsernamePasswordCredential usernamePassword = (UsernamePasswordCredential) credential;
            return validateUsernamePassword(usernamePassword);
        }
        return CredentialValidationResult.NOT_VALIDATED_RESULT;
    }

    private CredentialValidationResult validateUsernamePassword(UsernamePasswordCredential credential) {
        String username = credential.getCaller();
        String password = credential.getPasswordAsString();

        try {
            // Obtain token from Keycloak using password grant
            String requestBody = String.format(
                    "grant_type=password&client_id=%s&client_secret=%s&username=%s&password=%s&scope=openid microprofile-jwt",
                    URLEncoder.encode(keycloakConfig.getClientId(), StandardCharsets.UTF_8),
                    URLEncoder.encode(keycloakConfig.getClientSecret(), StandardCharsets.UTF_8),
                    URLEncoder.encode(username, StandardCharsets.UTF_8),
                    URLEncoder.encode(password, StandardCharsets.UTF_8)
            );

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(keycloakConfig.getTokenEndpoint()))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                JsonObject tokenData = parseJsonResponse(response.body());
                String accessToken = tokenData.getString("access_token");

                // Extract roles from JWT claims
                Set<String> roles = extractRolesFromToken(accessToken);
                Set<String> groups = extractGroupsFromToken(accessToken);

                LOGGER.info("User authenticated: " + username + " with roles: " + roles);

                securityEventPublisher.fire(new SecurityEvent(
                        SecurityEvent.Type.AUTHENTICATION_SUCCESS,
                        username,
                        "unknown",
                        Map.of("method", "password_grant", "roles", roles)
                ));

                return new CredentialValidationResult(username, roles);
            } else {
                LOGGER.warning("Authentication failed for user: " + username + " - Status: " + response.statusCode());
                securityEventPublisher.fire(new SecurityEvent(
                        SecurityEvent.Type.AUTHENTICATION_FAILURE,
                        username,
                        "unknown",
                        Map.of("reason", "Invalid credentials", "status", response.statusCode())
                ));
                return CredentialValidationResult.INVALID_RESULT;
            }
        } catch (Exception e) {
            LOGGER.severe("Error during authentication: " + e.getMessage());
            securityEventPublisher.fire(new SecurityEvent(
                    SecurityEvent.Type.AUTHENTICATION_FAILURE,
                    username,
                    "unknown",
                    Map.of("reason", "System error", "error", e.getMessage())
            ));
            return CredentialValidationResult.NOT_VALIDATED_RESULT;
        }
    }

    private Set<String> extractRolesFromToken(String accessToken) {
        try {
            // Decode JWT payload (basic Base64 decoding for demonstration)
            String[] parts = accessToken.split("\\.");
            if (parts.length < 2) {
                return Set.of();
            }

            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            JsonObject claims = parseJsonResponse(payload);

            Set<String> roles = new HashSet<>();

            // Extract realm roles
            if (claims.containsKey("realm_access")) {
                JsonObject realmAccess = claims.getJsonObject("realm_access");
                if (realmAccess.containsKey("roles")) {
                    JsonArray rolesArray = realmAccess.getJsonArray("roles");
                    rolesArray.forEach(role -> roles.add(role.toString().replace("\"", "")));
                }
            }

            // Extract resource/client roles
            if (claims.containsKey("resource_access")) {
                JsonObject resourceAccess = claims.getJsonObject("resource_access");
                if (resourceAccess.containsKey(keycloakConfig.getClientId())) {
                    JsonObject clientAccess = resourceAccess.getJsonObject(keycloakConfig.getClientId());
                    if (clientAccess.containsKey("roles")) {
                        JsonArray rolesArray = clientAccess.getJsonArray("roles");
                        rolesArray.forEach(role -> roles.add(role.toString().replace("\"", "")));
                    }
                }
            }

            // Extract groups claim (often used as roles)
            if (claims.containsKey("groups")) {
                JsonArray groupsArray = claims.getJsonArray("groups");
                groupsArray.forEach(group -> {
                    String groupName = group.toString().replace("\"", "");
                    // Remove leading slash if present
                    roles.add(groupName.startsWith("/") ? groupName.substring(1) : groupName);
                });
            }

            return roles;
        } catch (Exception e) {
            LOGGER.warning("Error extracting roles from token: " + e.getMessage());
            return Set.of();
        }
    }

    private Set<String> extractGroupsFromToken(String accessToken) {
        try {
            String[] parts = accessToken.split("\\.");
            if (parts.length < 2) {
                return Set.of();
            }

            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            JsonObject claims = parseJsonResponse(payload);

            Set<String> groups = new HashSet<>();
            if (claims.containsKey("groups")) {
                JsonArray groupsArray = claims.getJsonArray("groups");
                groupsArray.forEach(group -> groups.add(group.toString().replace("\"", "")));
            }

            return groups;
        } catch (Exception e) {
            LOGGER.warning("Error extracting groups from token: " + e.getMessage());
            return Set.of();
        }
    }

    private JsonObject parseJsonResponse(String jsonResponse) {
        try (JsonReader reader = Json.createReader(new StringReader(jsonResponse))) {
            return reader.readObject();
        }
    }

    @Override
    public Set<ValidationType> validationTypes() {
        return Set.of(ValidationType.VALIDATE);
    }
}
