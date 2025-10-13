package fish.payara.security.token;

import fish.payara.security.config.KeycloakConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;

import java.io.StringReader;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.logging.Logger;

/**
 * Token service for OAuth 2.0 token operations.
 * Handles token acquisition, refresh, and service-to-service authentication.
 */
@ApplicationScoped
public class TokenService {

    private static final Logger LOGGER = Logger.getLogger(TokenService.class.getName());
    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    @Inject
    private KeycloakConfig keycloakConfig;

    /**
     * Obtain access token using client credentials grant (service-to-service).
     */
    public TokenResponse getServiceToken(String clientId, String clientSecret) {
        try {
            String requestBody = String.format(
                    "grant_type=client_credentials&client_id=%s&client_secret=%s",
                    URLEncoder.encode(clientId, StandardCharsets.UTF_8),
                    URLEncoder.encode(clientSecret, StandardCharsets.UTF_8)
            );

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(keycloakConfig.getTokenEndpoint()))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                return parseTokenResponse(response.body());
            } else {
                LOGGER.severe("Failed to obtain service token: " + response.statusCode() + " - " + response.body());
                return null;
            }
        } catch (Exception e) {
            LOGGER.severe("Error obtaining service token: " + e.getMessage());
            return null;
        }
    }

    /**
     * Obtain access token using password grant (for testing).
     */
    public TokenResponse getUserToken(String username, String password) {
        try {
            String requestBody = String.format(
                    "grant_type=password&client_id=%s&client_secret=%s&username=%s&password=%s",
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
                return parseTokenResponse(response.body());
            } else {
                LOGGER.warning("Failed to obtain user token for " + username + ": " + response.statusCode());
                return null;
            }
        } catch (Exception e) {
            LOGGER.severe("Error obtaining user token: " + e.getMessage());
            return null;
        }
    }

    /**
     * Refresh an access token using refresh token.
     */
    public TokenResponse refreshToken(String refreshToken) {
        try {
            String requestBody = String.format(
                    "grant_type=refresh_token&client_id=%s&client_secret=%s&refresh_token=%s",
                    URLEncoder.encode(keycloakConfig.getClientId(), StandardCharsets.UTF_8),
                    URLEncoder.encode(keycloakConfig.getClientSecret(), StandardCharsets.UTF_8),
                    URLEncoder.encode(refreshToken, StandardCharsets.UTF_8)
            );

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(keycloakConfig.getTokenEndpoint()))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                LOGGER.info("Token refreshed successfully");
                return parseTokenResponse(response.body());
            } else {
                LOGGER.warning("Failed to refresh token: " + response.statusCode());
                return null;
            }
        } catch (Exception e) {
            LOGGER.severe("Error refreshing token: " + e.getMessage());
            return null;
        }
    }

    /**
     * Validate token by calling userinfo endpoint.
     */
    public boolean validateToken(String accessToken) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(keycloakConfig.getUserInfoEndpoint()))
                    .header("Authorization", "Bearer " + accessToken)
                    .GET()
                    .build();

            HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());

            return response.statusCode() == 200;
        } catch (Exception e) {
            LOGGER.warning("Token validation failed: " + e.getMessage());
            return false;
        }
    }

    private TokenResponse parseTokenResponse(String jsonResponse) {
        try (JsonReader reader = Json.createReader(new StringReader(jsonResponse))) {
            JsonObject json = reader.readObject();

            String accessToken = json.getString("access_token");
            String tokenType = json.getString("token_type", "Bearer");
            int expiresIn = json.getInt("expires_in", 300);
            String refreshToken = json.getString("refresh_token", null);
            String scope = json.getString("scope", null);

            return new TokenResponse(accessToken, tokenType, expiresIn, refreshToken, scope);
        }
    }

    public record TokenResponse(
            String accessToken,
            String tokenType,
            int expiresIn,
            String refreshToken,
            String scope
    ) {
        public String getAuthorizationHeader() {
            return tokenType + " " + accessToken;
        }
    }
}
