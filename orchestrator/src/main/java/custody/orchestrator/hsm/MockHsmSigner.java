package custody.orchestrator.hsm;

import custody.orchestrator.Intents.Cancellation;
import custody.orchestrator.Intents.Domain;
import custody.orchestrator.Intents.SignedIntent;
import custody.orchestrator.Intents.WithdrawalApproval;
import custody.orchestrator.Intents.WithdrawalRequest;
import custody.orchestrator.VaultCalls;
import custody.orchestrator.crypto.Address;
import custody.orchestrator.crypto.Hex;
import custody.orchestrator.crypto.Secp256k1;
import custody.orchestrator.eth.Eip1559Tx;
import java.math.BigInteger;
import java.time.Clock;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * MOCK. A stand-in for an HSM or MPC signer, holding Anvil's public test keys in memory. It is
 * not secure storage and is not meant to be: it exists to show the <i>interface</i> and the
 * <i>policy</i> a real signer should enforce.
 *
 * <p>What it models faithfully: the key never leaves the class (there is no getter), and the
 * signer has its own policy that doesn't trust the caller. It signs only:
 *
 * <ul>
 *   <li>transactions on the local Anvil chain, to the configured vault, with no ETH value;
 *   <li>calldata that is exactly {@code proposeWithdrawal}, {@code approve} or {@code cancel}
 *       built from an intent signed by the approver bound to that key slot, unexpired and with an
 *       unused nonce; or exactly {@code execute(id)}, which only carries out what M owners already
 *       approved and the contract still allows.
 * </ul>
 *
 * <p>What a real one adds: tamper-resistant key storage, keys generated inside the device, a
 * trusted clock, persistent replay state, and an audit trail it signs itself.
 */
public final class MockHsmSigner implements HsmSigner {
    private static final System.Logger LOG = System.getLogger("MOCK-HSM");

    private record Slot(BigInteger key, String owner, String approver) {
        @Override
        public String toString() {
            return "Slot[owner=" + owner + ", approver=" + approver + "]"; // never print the key
        }
    }

    private final Domain domain;
    private final Clock clock;
    private final Map<String, Slot> slots = new LinkedHashMap<>();
    private final Set<String> usedNonces = new HashSet<>();

    /**
     * @param ownerKeyIndexByApprover approver address → the Anvil account index of the owner key it
     *     controls. Slots are named owner-1, owner-2, ... in the map's iteration order.
     */
    public MockHsmSigner(Domain domain, Map<String, Integer> ownerKeyIndexByApprover, Clock clock) {
        if (domain.chainId() != AnvilTestKeys.ANVIL_CHAIN_ID) {
            throw new IllegalStateException("MockHsmSigner holds public test keys and only runs on the local Anvil chain "
                    + AnvilTestKeys.ANVIL_CHAIN_ID + ", not chain " + domain.chainId());
        }
        this.domain = domain;
        this.clock = clock;
        int n = 1;
        for (Map.Entry<String, Integer> e : ownerKeyIndexByApprover.entrySet()) {
            BigInteger key = AnvilTestKeys.key(e.getValue());
            slots.put("owner-" + n++, new Slot(key, Secp256k1.address(key), Address.parse(e.getKey())));
        }
        LOG.log(System.Logger.Level.WARNING, "MOCK HSM: test keys only, chain {0}, {1} key slots. Not a real HSM.",
                Long.toString(domain.chainId()), slots.size());
    }

    @Override
    public List<String> keySlots() {
        return List.copyOf(slots.keySet());
    }

    @Override
    public String ownerAddress(String keySlot) {
        return slot(keySlot).owner();
    }

    @Override
    public String boundApprover(String keySlot) {
        return slot(keySlot).approver();
    }

    @Override
    public synchronized byte[] signTransaction(String keySlot, Eip1559Tx tx, Optional<SignedIntent> authorization) {
        Slot slot = slot(keySlot);
        if (tx.chainId() != domain.chainId()) refuse("wrong chain " + tx.chainId());
        if (tx.to() == null || !Address.same(tx.to(), domain.vault())) refuse("destination is not the vault");
        if (tx.value().signum() != 0) refuse("transactions must not carry ETH");

        byte[] data = tx.data();
        if (authorization.isEmpty()) {
            // execute(id) is the only call allowed without an intent.
            if (data.length != 36 || !Arrays.equals(Arrays.copyOf(data, 4), VaultCalls.EXECUTE_SELECTOR)) {
                refuse("only execute(id) may be signed without an approver intent");
            }
        } else {
            SignedIntent s = authorization.get();
            String signer = s.signer(domain).orElse(null);
            if (signer == null || !Address.same(signer, slot.approver())) {
                refuse("intent is not signed by the approver bound to " + keySlot);
            }
            if (clock.instant().getEpochSecond() > s.intent().deadline()) refuse("intent expired");
            byte[] expected = switch (s.intent()) {
                case WithdrawalRequest r -> VaultCalls.proposeWithdrawal(r.asset(), r.to(), r.amount());
                case WithdrawalApproval a -> VaultCalls.approve(a.proposalId());
                case Cancellation c -> VaultCalls.cancel(c.proposalId());
            };
            if (!Arrays.equals(expected, data)) refuse("calldata does not match the signed intent");
            String nonceKey = signer.toLowerCase() + ":" + s.intent().nonce();
            if (!usedNonces.add(nonceKey)) refuse("intent nonce already used");
        }

        Secp256k1.Signature sig = Secp256k1.sign(tx.signingHash(), slot.key());
        LOG.log(System.Logger.Level.INFO, "MOCK HSM signed for {0} ({1}): selector {2}",
                keySlot, slot.owner(), Hex.encode(Arrays.copyOf(data, 4)));
        return tx.encodeSigned(sig);
    }

    private Slot slot(String keySlot) {
        Slot s = slots.get(keySlot);
        if (s == null) throw new HsmRefusal("unknown key slot " + keySlot);
        return s;
    }

    private static void refuse(String why) {
        LOG.log(System.Logger.Level.WARNING, "MOCK HSM refused: {0}", why);
        throw new HsmRefusal(why);
    }

    @Override
    public String toString() {
        return "MockHsmSigner[TEST KEYS ONLY, chain " + domain.chainId() + ", slots " + slots.keySet() + "]";
    }
}
