package custody.orchestrator.audit;

import java.util.Map;
import java.util.Optional;

/** Where the orchestrator records its decisions. {@link AuditLog} is the real one. */
public interface Audit {

    /** The newest entry: its sequence number and hash. */
    record Head(long seq, String hash) {}

    /**
     * Appends an entry and returns once it's on disk. Throws if it can't be written; callers
     * treat that as "don't proceed", so nothing is signed without a record of it.
     */
    void record(String event, Map<String, Object> data);

    Optional<Head> head();

    /** Records nothing. For tests of other components. */
    Audit NONE = new Audit() {
        @Override
        public void record(String event, Map<String, Object> data) {}

        @Override
        public Optional<Head> head() {
            return Optional.empty();
        }
    };
}
