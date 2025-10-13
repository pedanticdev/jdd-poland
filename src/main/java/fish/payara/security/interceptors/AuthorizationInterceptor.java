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
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.ForbiddenException;

import java.lang.reflect.Method;
import java.security.Principal;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
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

    @Inject
    private HttpServletRequest request;

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
        @SuppressWarnings("unchecked")
        Map<String, Object> claims = (Map<String, Object>) request.getAttribute("claims");
        if (claims == null) {
            LOGGER.warning("No claims found in request for user " + username);
            return false;
        }

        String attributeName = annotation.name();
        String[] requiredValues = annotation.value();
        RequireAttribute.MatchMode matchMode = annotation.matchMode();

        Object claimValue = claims.get(attributeName);

        if (claimValue == null) {
            LOGGER.warning("User " + username + " does not have attribute: " + attributeName);
            return false;
        }

        List<String> userValues;
        if (claimValue instanceof List) {
            userValues = ((List<?>) claimValue).stream().map(String::valueOf).toList();
        } else {
            userValues = List.of(String.valueOf(claimValue));
        }

        LOGGER.info("Checking attribute: " + attributeName + " with values " + userValues + " against required " + Arrays.toString(requiredValues));

        boolean match;
        if (matchMode == RequireAttribute.MatchMode.ANY) {
            match = Arrays.stream(requiredValues).anyMatch(userValues::contains);
        } else { // ALL
            match = Arrays.stream(requiredValues).allMatch(userValues::contains);
        }

        if (!match) {
            LOGGER.warning("Attribute check failed for user " + username + ". Required: " + Arrays.toString(requiredValues) + ", Found: " + userValues);
        }

        return match;
    }
}
