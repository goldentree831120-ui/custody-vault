package custody.orchestrator;

/** A request the orchestrator refused, with a stable code for API clients. */
public final class Rejection extends RuntimeException {

    public enum Code {
        // the intent itself
        BAD_SIGNATURE(400),
        UNKNOWN_APPROVER(403),
        EXPIRED(400),
        DEADLINE_TOO_FAR(400),
        NONCE_REUSED(409),
        // the approver's owner key
        NOT_AN_OWNER(403),
        // the proposal
        UNKNOWN_PROPOSAL(404),
        PROPOSAL_MISMATCH(409),
        PROPOSAL_CLOSED(409),
        ALREADY_APPROVED(409),
        NOT_READY(409),
        // policy
        PAUSED(409),
        ZERO_AMOUNT(400),
        DESTINATION_NOT_ALLOWED(422),
        OVER_DAILY_LIMIT(422),
        OVER_ORCHESTRATOR_CAP(422),
        // further down
        ON_CHAIN_REVERT(422),
        SIGNER_REFUSED(502),
        TX_FAILED(502);

        public final int httpStatus;

        Code(int httpStatus) {
            this.httpStatus = httpStatus;
        }
    }

    public final Code code;

    public Rejection(Code code, String message) {
        super(message);
        this.code = code;
    }
}
