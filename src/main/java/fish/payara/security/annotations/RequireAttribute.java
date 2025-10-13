package fish.payara.security.annotations;

import jakarta.enterprise.util.Nonbinding;
import jakarta.interceptor.InterceptorBinding;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Attribute-Based Access Control annotation for fine-grained authorization.
 * Requires specific attribute values for access to be granted.
 * <p>
 * Example:
 *
 * @RequireAttribute(name = "department", value = "Cardiology")
 * public void viewCardiologyRecords() { ... }
 */
@InterceptorBinding
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface RequireAttribute {

    /**
     * The attribute name to check
     */
    @Nonbinding
    String name();

    /**
     * The required attribute value(s)
     */
    @Nonbinding
    String[] value();

    /**
     * Whether to match ANY of the values (OR) or ALL values (AND)
     */
    @Nonbinding
    MatchMode matchMode() default MatchMode.ANY;

    enum MatchMode {
        ANY,  // Match if any value matches
        ALL   // Match only if all values match
    }
}
