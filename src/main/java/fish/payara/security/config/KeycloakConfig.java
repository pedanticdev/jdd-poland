package fish.payara.security.config;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.io.Serializable;

/**
 * Keycloak OIDC configuration for Zero Trust authentication.
 * Provides centralized configuration for OAuth 2.0/OpenID Connect integration.
 */
@ApplicationScoped
public class KeycloakConfig implements Serializable {

    @Inject
    @ConfigProperty(name = "keycloak.realm")
    private String realm;

    @Inject
    @ConfigProperty(name = "keycloak.auth-server-url")
    private String authServerUrl;

    @Inject
    @ConfigProperty(name = "keycloak.client-id")
    private String clientId;

    @Inject
    @ConfigProperty(name = "keycloak.client-secret")
    private String clientSecret;

    @Inject
    @ConfigProperty(name = "keycloak.issuer")
    private String issuer;

    public String getRealm() {
        return realm;
    }

    public String getAuthServerUrl() {
        return authServerUrl;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getTokenEndpoint() {
        return authServerUrl + "/realms/" + realm + "/protocol/openid-connect/token";
    }

    public String getUserInfoEndpoint() {
        return authServerUrl + "/realms/" + realm + "/protocol/openid-connect/userinfo";
    }

    public String getJwksUri() {
        return authServerUrl + "/realms/" + realm + "/protocol/openid-connect/certs";
    }

    public String getAuthorizationEndpoint() {
        return authServerUrl + "/realms/" + realm + "/protocol/openid-connect/auth";
    }

    public String getLogoutEndpoint() {
        return authServerUrl + "/realms/" + realm + "/protocol/openid-connect/logout";
    }
}
