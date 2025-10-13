package fish.payara.security.annotations;

import jakarta.enterprise.util.Nonbinding;
import jakarta.interceptor.InterceptorBinding;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Role-based access control annotation.
 * More flexible than standard @RolesAllowed as it works with CDI interceptors.
 * <p>
 * Example:
 *
 * @RequireRole({"DOCTOR", "NURSE"})
 * public void accessPatientRecords() { ... }
 */
@InterceptorBinding
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface RequireRole {

    /**
     * The required role(s)
     */
    @Nonbinding
    String[] value();
}
