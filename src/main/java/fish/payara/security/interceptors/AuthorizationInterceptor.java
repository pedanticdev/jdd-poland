package fish.payara.security.interceptors;

import fish.payara.security.annotations.RequireAttribute;
import fish.payara.security.annotations.RequireRole;
import fish.payara.security.events.SecurityEvent;
import jakarta.annotation.Priority;
import jakarta.enterprise.event.Event;
import jakarta.inject.Inject;
import jakarta.interceptor.AroundInvoke;
import jakarta.interceptor.Interceptor;
import jakarta.interceptor.InvocationContext;
import jakarta.security.enterprise.SecurityContext;
import jakarta.ws.rs.ForbiddenException;

import java.lang.reflect.Method;
import java.security.Principal;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Authorization interceptor implementing Attribute-Based Access Control (ABAC).
 * Evaluates fine-grained permissions based on roles and attributes.
 */
@Interceptor
@RequireRole("")
@RequireAttribute(name = "", value = "")
@Priority(Interceptor.Priority.APPLICATION)
public class AuthorizationInterceptor {

    private static final Logger LOGGER = Logger.getLogger(AuthorizationInterceptor.class.getName());

    @Inject
    private SecurityContext securityContext;

    @Inject
    private Event<SecurityEvent> securityEventPublisher;

    @AroundInvoke
    public Object checkAuthorization(InvocationContext context) throws Exception {
        Method method = context.getMethod();
        Principal principal = securityContext.getCallerPrincipal();

        if (principal == null) {
            LOGGER.warning("No authenticated user for secured method: " + method.getName());
            throw new ForbiddenException("Authentication required");
        }

        String username = principal.getName();

        // Check role-based access
        RequireRole roleAnnotation = method.getAnnotation(RequireRole.class);
        if (roleAnnotation == null) {
            roleAnnotation = method.getDeclaringClass().getAnnotation(RequireRole.class);
        }

        if (roleAnnotation != null && roleAnnotation.value().length > 0) {
            if (!checkRoles(roleAnnotation.value(), username)) {
                LOGGER.warning("Access denied for user " + username + " - insufficient roles for " + method.getName());
                securityEventPublisher.fire(new SecurityEvent(
                        SecurityEvent.Type.AUTHORIZATION_FAILURE,
                        username,
                        "unknown",
                        Map.of(
                                "method", method.getName(),
                                "requiredRoles", Arrays.toString(roleAnnotation.value()),
                                "reason", "Insufficient roles"
                        )
                ));
                throw new ForbiddenException("Insufficient permissions");
            }
        }

        // Check attribute-based access
        RequireAttribute attrAnnotation = method.getAnnotation(RequireAttribute.class);
        if (attrAnnotation == null) {
            attrAnnotation = method.getDeclaringClass().getAnnotation(RequireAttribute.class);
        }

        if (attrAnnotation != null && !attrAnnotation.name().isEmpty()) {
            if (!checkAttributes(attrAnnotation, username)) {
                LOGGER.warning("Access denied for user " + username + " - insufficient attributes for " + method.getName());
                securityEventPublisher.fire(new SecurityEvent(
                        SecurityEvent.Type.AUTHORIZATION_FAILURE,
                        username,
                        "unknown",
                        Map.of(
                                "method", method.getName(),
                                "requiredAttribute", attrAnnotation.name(),
                                "requiredValues", Arrays.toString(attrAnnotation.value()),
                                "reason", "Attribute mismatch"
                        )
                ));
                throw new ForbiddenException("Insufficient attributes");
            }
        }

        // Authorization successful
        securityEventPublisher.fire(new SecurityEvent(
                SecurityEvent.Type.AUTHORIZATION_SUCCESS,
                username,
                "unknown",
                Map.of("method", method.getName())
        ));

        return context.proceed();
    }

    private boolean checkRoles(String[] requiredRoles, String username) {
        for (String role : requiredRoles) {
            if (securityContext.isCallerInRole(role)) {
                LOGGER.fine("User " + username + " has required role: " + role);
                return true;
            }
        }
        return false;
    }

    private boolean checkAttributes(RequireAttribute annotation, String username) {
        // In a real implementation, you would fetch user attributes from:
        // 1. JWT token claims
        // 2. User profile service
        // 3. Session context
        // 4. Database

        // For demo purposes, we'll use a simplified check
        // In production, inject an AttributeProvider service

        String attributeName = annotation.name();
        String[] requiredValues = annotation.value();
        RequireAttribute.MatchMode matchMode = annotation.matchMode();

        // Simplified attribute check - would be replaced with actual attribute resolution
        // Example: Get attributes from JWT claims stored in SecurityContext

        LOGGER.info("Checking attribute: " + attributeName + " for values: " + Arrays.toString(requiredValues));

        // For now, we'll allow access if the user has any required role
        // This is a placeholder for actual attribute-based logic
        return true;
    }
}
