package fish.payara.security.interceptors;

import fish.payara.security.annotations.Audited;
import fish.payara.security.events.SecurityEvent;
import jakarta.annotation.Priority;
import jakarta.enterprise.event.Event;
import jakarta.inject.Inject;
import jakarta.interceptor.AroundInvoke;
import jakarta.interceptor.Interceptor;
import jakarta.interceptor.InvocationContext;
import jakarta.security.enterprise.SecurityContext;
import jakarta.servlet.http.HttpServletRequest;

import java.lang.reflect.Method;
import java.security.Principal;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Audit interceptor for security monitoring and compliance.
 * Records all access to sensitive data and operations.
 */
@Interceptor
@Audited
@Priority(Interceptor.Priority.APPLICATION + 100)
public class AuditInterceptor {

    private static final Logger LOGGER = Logger.getLogger(AuditInterceptor.class.getName());

    @Inject
    private SecurityContext securityContext;

    @Inject
    private Event<SecurityEvent> securityEventPublisher;

    @Inject
    private HttpServletRequest request;

    @AroundInvoke
    public Object auditMethodCall(InvocationContext context) throws Exception {
        Method method = context.getMethod();
        Audited auditAnnotation = method.getAnnotation(Audited.class);

        if (auditAnnotation == null) {
            auditAnnotation = method.getDeclaringClass().getAnnotation(Audited.class);
        }

        String action = auditAnnotation.action();
        if (action.isEmpty()) {
            action = method.getName();
        }

        Principal principal = securityContext.getCallerPrincipal();
        String username = principal != null ? principal.getName() : "anonymous";
        String ipAddress = request != null ? request.getRemoteAddr() : "unknown";

        Instant startTime = Instant.now();
        Object result = null;
        Exception exception = null;

        try {
            result = context.proceed();
            return result;
        } catch (Exception e) {
            exception = e;
            throw e;
        } finally {
            Instant endTime = Instant.now();
            long duration = endTime.toEpochMilli() - startTime.toEpochMilli();

            Map<String, Object> metadata = new HashMap<>();
            metadata.put("action", action);
            metadata.put("method", method.getName());
            metadata.put("class", method.getDeclaringClass().getSimpleName());
            metadata.put("level", auditAnnotation.level().toString());
            metadata.put("duration", duration);
            metadata.put("success", exception == null);
            metadata.put("userAgent", request != null ? request.getHeader("User-Agent") : "unknown");

            if (exception != null) {
                metadata.put("error", exception.getClass().getSimpleName());
                metadata.put("errorMessage", exception.getMessage());
            }

            if (result != null) {
                metadata.put("resultType", result.getClass().getSimpleName());
            }

            securityEventPublisher.fire(new SecurityEvent(
                    SecurityEvent.Type.DATA_ACCESS,
                    username,
                    ipAddress,
                    metadata
            ));

            LOGGER.info(String.format(
                    "AUDIT: User=%s, Action=%s, Success=%b, Duration=%dms, IP=%s",
                    username, action, exception == null, duration, ipAddress
            ));
        }
    }
}
