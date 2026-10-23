package custody.orchestrator;

import custody.orchestrator.Intents.SignedIntent;
import java.math.BigInteger;
import java.util.List;
import java.util.Optional;

/** Everything the orchestrator needs from the chain. {@link VaultClient} is the real one; tests use a fake. */
public interface Chain {

    record Proposal(
            boolean isWithdrawal,
            String asset,
            String to,
            BigInteger amount,
            long createdAt,
            long thresholdReachedAt,
            boolean executed,
            boolean cancelled) {}

    record Log(String address, List<String> topics, String data) {}

    record Receipt(String txHash, boolean success, List<Log> logs) {}

    /** The vault rejected the call in simulation; {@code error} is the custom error's name. */
    final class Reverted extends RuntimeException {
        public final String error;

        public Reverted(String error) {
            super("vault would revert with " + error);
            this.error = error;
        }
    }

    // reads ------------------------------------------------------------------------------------
    long chainId();

    long chainTime();

    boolean isOwner(String address);

    boolean paused();

    boolean isAllowedDestination(String to);

    BigInteger dailyLimit(String asset);

    BigInteger availableToWithdraw(String asset);

    Optional<Proposal> proposal(BigInteger id);

    boolean hasApproved(BigInteger id, String owner);

    BigInteger approvalCount(BigInteger id);

    BigInteger threshold();

    /** Earliest execution time, or 2^256-1 while approvals are missing. */
    BigInteger executableAt(BigInteger id);

    // writes -----------------------------------------------------------------------------------

    /** eth_call from {@code from}; throws {@link Reverted} if the vault would revert. */
    void simulate(String from, byte[] calldata);

    /** Builds the transaction, has the signer sign it, sends it and waits for the receipt. */
    Receipt send(String keySlot, byte[] calldata, Optional<SignedIntent> authorization);
}
