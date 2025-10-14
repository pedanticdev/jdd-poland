package fish.payara.security.audit;

import fish.payara.security.annotations.Audited;
import jakarta.data.repository.CrudRepository;
import jakarta.data.repository.Repository;

import java.time.Instant;
import java.util.List;

/**
 * Repository for persistent audit log entries.
 * Provides query methods for security event analysis and compliance reporting.
 */
@Repository
public interface AuditLogRepository extends CrudRepository<AuditLogEntry, String> {

    /**
     * Find all audit entries for a specific user.
     */
    List<AuditLogEntry> findByUsername(String username);

    /**
     * Find all audit entries for a specific IP address.
     */
    List<AuditLogEntry> findByIpAddress(String ipAddress);

    /**
     * Find all audit entries within a time range.
     */
    List<AuditLogEntry> findByTimestampBetween(Instant start, Instant end);

    /**
     * Find all failed operations (security violations).
     */
    List<AuditLogEntry> findBySuccessFalse();

    /**
     * Find all high-sensitivity operations.
     */
    List<AuditLogEntry> findBySensitivityLevel(Audited.SensitivityLevel level);

    /**
     * Find all audit entries for a specific action.
     */
    List<AuditLogEntry> findByAction(String action);

    /**
     * Count total audit entries.
     */
    long count();
}
