package fish.payara.security.interceptors;

import fish.payara.security.annotations.Encrypted;
import fish.payara.security.events.SecurityEvent;
import jakarta.annotation.Priority;
import jakarta.enterprise.event.Event;
import jakarta.inject.Inject;
import jakarta.interceptor.AroundInvoke;
import jakarta.interceptor.Interceptor;
import jakarta.interceptor.InvocationContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.ForbiddenException;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Encryption interceptor for enforcing encrypted data transit.
 * Validates that sensitive data is transmitted over secure channels (TLS/HTTPS).
 * Demonstrates Jakarta's annotation-based approach to security enforcement.
 */
@Interceptor
@Encrypted
@Priority(Interceptor.Priority.PLATFORM_BEFORE + 200)
public class EncryptionInterceptor {

    private static final Logger LOGGER = Logger.getLogger(EncryptionInterceptor.class.getName());

    @Inject
    private HttpServletRequest request;

    @Inject
    private Event<SecurityEvent> securityEventPublisher;

    @AroundInvoke
    public Object enforceEncryption(InvocationContext context) throws Exception {
        Method method = context.getMethod();
        Encrypted encrypted = method.getAnnotation(Encrypted.class);

        if (encrypted == null) {
            encrypted = method.getDeclaringClass().getAnnotation(Encrypted.class);
        }

        if (encrypted != null && encrypted.requireTls()) {
            validateTls();
        }

        // Log encryption enforcement
        LOGGER.info(String.format(
                "Encryption enforced for %s.%s (Algorithm: %s, TLS Required: %s)",
                method.getDeclaringClass().getSimpleName(),
                method.getName(),
                encrypted != null ? encrypted.algorithm() : "default",
                encrypted != null ? encrypted.requireTls() : "default"
        ));

        // Publish security event
        securityEventPublisher.fire(new SecurityEvent(
                SecurityEvent.Type.DATA_ACCESS,
                request.getRemoteUser() != null ? request.getRemoteUser() : "anonymous",
                request.getRemoteAddr(),
                Map.of(
                        "action", "ENCRYPTED_OPERATION",
                        "method", method.getName(),
                        "algorithm", encrypted != null ? encrypted.algorithm().toString() : "default",
                        "tlsRequired", encrypted != null ? encrypted.requireTls() : true
                )
        ));

        return context.proceed();
    }

    private void validateTls() {
        if (request == null) {
            LOGGER.warning("HttpServletRequest not available, skipping TLS validation");
            return;
        }

        boolean isSecure = request.isSecure();
        String protocol = request.getProtocol();

        if (!isSecure) {
            String errorMessage = String.format(
                    "TLS/HTTPS required for encrypted data transit. Current: secure=%s, protocol=%s",
                    isSecure, protocol
            );

            LOGGER.severe(errorMessage);

            securityEventPublisher.fire(new SecurityEvent(
                    SecurityEvent.Type.SUSPICIOUS_ACTIVITY,
                    request.getRemoteUser() != null ? request.getRemoteUser() : "anonymous",
                    request.getRemoteAddr(),
                    Map.of(
                            "action", "TLS_VIOLATION",
                            "secure", isSecure,
                            "protocol", protocol
                    )
            ));

            throw new ForbiddenException("HTTPS/TLS required for this operation");
        }

        LOGGER.fine("TLS validation passed: " + protocol);
    }
}
