package fish.payara.security.annotations;

import jakarta.enterprise.util.Nonbinding;
import jakarta.interceptor.InterceptorBinding;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks methods that should be audited for security monitoring.
 * Part of the continuous validation strategy in Zero Trust architecture.
 * <p>
 * Example:
 *
 * @Audited(action = "VIEW_PATIENT_RECORD")
 * public Patient getPatient(String id) { ... }
 */
@InterceptorBinding
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface Audited {

    /**
     * Description of the action being audited
     */
    @Nonbinding
    String action() default "";

    /**
     * Sensitivity level of the data being accessed
     */
    @Nonbinding
    SensitivityLevel level() default SensitivityLevel.MEDIUM;

    enum SensitivityLevel {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }
}
