package fish.payara.security.annotations;

import jakarta.interceptor.InterceptorBinding;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to mark data that requires encryption in transit.
 * Demonstrates Jakarta's security annotation approach for encrypted data transit.
 * Part of Zero Trust security: never trust the network, always encrypt.
 */
@InterceptorBinding
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface Encrypted {

    /**
     * Algorithm to use for encryption.
     */
    Algorithm algorithm() default Algorithm.AES_256_GCM;

    /**
     * Whether to enforce TLS for the request.
     */
    boolean requireTls() default true;

    /**
     * Encryption algorithms supported.
     */
    enum Algorithm {
        AES_256_GCM,
        AES_128_GCM,
        CHACHA20_POLY1305
    }
}
