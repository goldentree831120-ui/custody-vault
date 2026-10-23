package custody.orchestrator.hsm;

import custody.orchestrator.Intents.SignedIntent;
import custody.orchestrator.eth.Eip1559Tx;
import java.util.List;
import java.util.Optional;

/**
 * The boundary to wherever the vault owners' keys live: in production an HSM (PKCS#11, a cloud
 * KMS) or an MPC signing network; in this repository only {@link MockHsmSigner}.
 *
 * <p>The design assumption is that <b>the signer does not trust the orchestrator</b>. Every request
 * carries the approver's signed intent, and the signer re-checks it with its own policy before
 * signing. A compromised orchestrator can delay or drop requests, but can't get a signature for a
 * transaction no approver authorised.
 */
public interface HsmSigner {

    /** Key slots this signer holds, one per vault owner (e.g. "owner-1"). */
    List<String> keySlots();

    /** The on-chain owner address of a key slot. Public information; the key never leaves the signer. */
    String ownerAddress(String keySlot);

    /** The approver (person or device) whose intents authorise this key slot. */
    String boundApprover(String keySlot);

    /**
     * Signs {@code tx} with the key in {@code keySlot} and returns the raw signed transaction.
     *
     * @param authorization the approver's signed intent. Required for propose, approve and cancel.
     *     Empty only for {@code execute}, which can only carry out what M owners already approved.
     * @throws HsmRefusal if the signer's own policy rejects the request
     */
    byte[] signTransaction(String keySlot, Eip1559Tx tx, Optional<SignedIntent> authorization);

    /** A refusal by the signer's own policy. */
    final class HsmRefusal extends RuntimeException {
        public HsmRefusal(String message) {
            super(message);
        }
    }
}
