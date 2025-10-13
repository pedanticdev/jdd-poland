package fish.payara.security.events;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Security event for continuous validation and monitoring.
 * Part of the Zero Trust continuous verification strategy.
 */
public class SecurityEvent {

    private final String id;
    private final Type type;
    private final String username;
    private final String ipAddress;
    private final Instant timestamp;
    private final Map<String, Object> metadata;

    public SecurityEvent(Type type, String username, String ipAddress, Map<String, Object> metadata) {
        this.id = UUID.randomUUID().toString();
        this.type = type;
        this.username = username;
        this.ipAddress = ipAddress;
        this.timestamp = Instant.now();
        this.metadata = metadata;
    }

    public enum Type {
        AUTHENTICATION_SUCCESS,
        AUTHENTICATION_FAILURE,
        AUTHORIZATION_SUCCESS,
        AUTHORIZATION_FAILURE,
        SESSION_CREATED,
        SESSION_EXPIRED,
        TOKEN_REFRESH,
        SUSPICIOUS_ACTIVITY,
        DATA_ACCESS,
        CONFIGURATION_CHANGE
    }

    public String getId() {
        return id;
    }

    public Type getType() {
        return type;
    }

    public String getUsername() {
        return username;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    @Override
    public String toString() {
        return "SecurityEvent{" +
                "id='" + id + '\'' +
                ", type=" + type +
                ", username='" + username + '\'' +
                ", ipAddress='" + ipAddress + '\'' +
                ", timestamp=" + timestamp +
                ", metadata=" + metadata +
                '}';
    }
}
