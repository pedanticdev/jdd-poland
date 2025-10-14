package fish.payara.security.monitoring;

import jakarta.enterprise.context.ApplicationScoped;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

/**
 * Simple in-memory audit log used in the demo to illustrate continuous validation.
 * Keeps a rolling window of recent security-relevant actions that were intercepted.
 */
@ApplicationScoped
public class SecurityLog {

    private static final int MAX_ENTRIES = 50;
    private final Deque<AuditEntry> entries = new ArrayDeque<>();

    public synchronized void record(AuditEntry entry) {
        entries.addFirst(entry);
        while (entries.size() > MAX_ENTRIES) {
            entries.removeLast();
        }
    }

    public synchronized List<AuditEntry> recentEntries() {
        return new ArrayList<>(entries);
    }

    public record AuditEntry(
            String action,
            String resource,
            String principal,
            boolean success,
            Instant at,
            String details
    ) {
    }
}
