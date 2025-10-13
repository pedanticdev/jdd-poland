package fish.payara.security.interceptors;

import fish.payara.security.annotations.RequireAttribute;
import fish.payara.security.events.SecurityEvent;
import jakarta.annotation.Priority;
import jakarta.enterprise.event.Event;
import jakarta.inject.Inject;
import jakarta.interceptor.AroundInvoke;
import jakarta.interceptor.Interceptor;
import jakarta.interceptor.InvocationContext;
import jakarta.security.enterprise.SecurityContext;
import jakarta.ws.rs.ForbiddenException;
import org.eclipse.microprofile.jwt.JsonWebToken;

import java.lang.reflect.Method;
import java.security.Principal;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Logger;

/**
 * Authorization interceptor implementing Attribute-Based Access Control (ABAC).
 * Evaluates fine-grained permissions based on JWT claims.
 * This is an example of extending Jakarta Security for custom authorization logic.
 */
@Interceptor
@RequireAttribute(name = "", value = "")
@Priority(Interceptor.Priority.APPLICATION)
public class AuthorizationInterceptor {

    private static final Logger LOGGER = Logger.getLogger(AuthorizationInterceptor.class.getName());

    @Inject
    private SecurityContext securityContext;

    @Inject
    private Event<SecurityEvent> securityEventPublisher;

    @Inject
    private JsonWebToken jwt;

    @AroundInvoke
    public Object checkAuthorization(InvocationContext context) throws Exception {
        Method method = context.getMethod();
        Principal principal = securityContext.getCallerPrincipal();

        if (principal == null || jwt == null || jwt.getRawToken() == null) {
            LOGGER.warning("No authenticated user for secured method: " + method.getName());
            throw new ForbiddenException("Authentication required");
        }

        String username = principal.getName();

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
                        "unknown", // IP address can be retrieved from request if needed
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

        // Authorization successful for this interceptor's concerns
        securityEventPublisher.fire(new SecurityEvent(
                SecurityEvent.Type.AUTHORIZATION_SUCCESS,
                username,
                "unknown",
                Map.of("method", method.getName(), "interceptor", "ABAC")
        ));

        return context.proceed();
    }

    private boolean checkAttributes(RequireAttribute annotation, String username) {
        String attributeName = annotation.name();
        String[] requiredValues = annotation.value();
        RequireAttribute.MatchMode matchMode = annotation.matchMode();

        Optional<Object> claimValue = jwt.claim(attributeName);

        if (claimValue.isEmpty()) {
            LOGGER.warning("User " + username + " does not have attribute: " + attributeName);
            return false;
        }

        Object value = claimValue.get();
        List<String> userValues;

        if (value instanceof List) {
            userValues = ((List<?>) value).stream().map(String::valueOf).toList();
        } else {
            userValues = List.of(String.valueOf(value));
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
