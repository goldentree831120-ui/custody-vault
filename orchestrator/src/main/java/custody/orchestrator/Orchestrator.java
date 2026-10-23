package custody.orchestrator;

import static custody.orchestrator.Rejection.Code.*;

import custody.orchestrator.Chain.Proposal;
import custody.orchestrator.Chain.Receipt;
import custody.orchestrator.Intents.Cancellation;
import custody.orchestrator.Intents.Domain;
import custody.orchestrator.Intents.SignedIntent;
import custody.orchestrator.Intents.WithdrawalApproval;
import custody.orchestrator.Intents.WithdrawalRequest;
import custody.orchestrator.crypto.Address;
import custody.orchestrator.crypto.Hex;
import custody.orchestrator.hsm.HsmSigner;
import java.math.BigInteger;
import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Turns approvers' signed intents into vault transactions.
 *
 * <p>Order of checks for every intent: the signature and who signed it; expiry and replay; that
 * the approver's owner key is still a vault owner; the request against the vault's current state
 * and policy (and the orchestrator's own, stricter cap); a simulation of the exact call; and only
 * then the signer, which re-checks the intent itself. The vault contract enforces every rule
 * again on-chain. The checks here exist to refuse early with a clear reason and to keep an
 * obviously bad request away from the keys, not to replace the contract's checks.
 */
public final class Orchestrator {
    private static final System.Logger LOG = System.getLogger("orchestrator");
    private static final BigInteger NOT_READY_SENTINEL = BigInteger.TWO.pow(256).subtract(BigInteger.ONE);

    /**
     * @param maxIntentLifetime deadlines further in the future are refused, so a stolen or forgotten
     *     signed intent can't be held back and used weeks later
     * @param perRequestCap optional per-asset cap, stricter than the vault's daily limit
     */
    public record Policy(Duration maxIntentLifetime, Map<String, BigInteger> perRequestCap) {
        public Policy {
            Map<String, BigInteger> caps = new LinkedHashMap<>();
            perRequestCap.forEach((k, v) -> caps.put(Address.parse(k), v));
            perRequestCap = Map.copyOf(caps);
        }

        public static Policy defaults() {
            return new Policy(Duration.ofHours(1), Map.of());
        }
    }

    public record Outcome(
            String action, BigInteger proposalId, String keySlot, String owner, String txHash,
            BigInteger approvals, BigInteger threshold, BigInteger executableAt) {
        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("action", action);
            m.put("proposalId", proposalId.toString());
            m.put("keySlot", keySlot);
            m.put("owner", owner);
            m.put("txHash", txHash);
            m.put("approvals", approvals.toString());
            m.put("threshold", threshold.toString());
            m.put("executableAt", executableAt.equals(NOT_READY_SENTINEL) ? null : executableAt.toString());
            return m;
        }
    }

    private final Domain domain;
    private final HsmSigner signer;
    private final Chain chain;
    private final NonceStore nonces;
    private final Clock clock;
    private final Policy policy;

    public Orchestrator(Domain domain, HsmSigner signer, Chain chain, NonceStore nonces, Clock clock, Policy policy) {
        if (chain.chainId() != domain.chainId()) {
            throw new IllegalStateException("RPC is on chain " + chain.chainId() + " but the domain says " + domain.chainId());
        }
        this.domain = domain;
        this.signer = signer;
        this.chain = chain;
        this.nonces = nonces;
        this.clock = clock;
        this.policy = policy;
    }

    public Domain domain() {
        return domain;
    }

    /** One request at a time: owner-account transaction nonces stay in order and checks can't interleave. */
    public synchronized Outcome submit(SignedIntent s) {
        // 1. Who signed it, and which owner key that approver controls.
        String approver = s.signer(domain).orElseThrow(() -> reject(BAD_SIGNATURE, "signature is malformed"));
        String slot = signer.keySlots().stream()
                .filter(k -> Address.same(signer.boundApprover(k), approver))
                .findFirst()
                .orElseThrow(() -> reject(UNKNOWN_APPROVER,
                        "signed by " + approver + ", which is not a registered approver for this vault and chain"));
        String owner = signer.ownerAddress(slot);

        // 2. Expiry and replay.
        long now = clock.instant().getEpochSecond();
        if (now > s.intent().deadline()) throw reject(EXPIRED, "intent expired at " + s.intent().deadline());
        if (s.intent().deadline() > now + policy.maxIntentLifetime().toSeconds()) {
            throw reject(DEADLINE_TOO_FAR, "deadline is more than " + policy.maxIntentLifetime() + " away");
        }
        if (nonces.isUsed(approver, s.intent().nonce())) throw reject(NONCE_REUSED, "nonce " + s.intent().nonce() + " already used");

        // 3. The owner key must still be an owner (owners can be removed on-chain).
        if (!chain.isOwner(owner)) throw reject(NOT_AN_OWNER, keySlotDesc(slot, owner) + " is no longer a vault owner");

        // 4. The request against the vault's state and policy.
        final byte[] calldata;
        final String action;
        switch (s.intent()) {
            case WithdrawalRequest r -> {
                checkWithdrawalPolicy(r.asset(), r.to(), r.amount());
                calldata = VaultCalls.proposeWithdrawal(r.asset(), r.to(), r.amount());
                action = "proposed";
            }
            case WithdrawalApproval a -> {
                Proposal p = openProposal(a.proposalId());
                if (!p.isWithdrawal() || !Address.same(p.asset(), a.asset()) || !Address.same(p.to(), a.to())
                        || !p.amount().equals(a.amount())) {
                    throw reject(PROPOSAL_MISMATCH, "proposal " + a.proposalId() + " is not the withdrawal the approver signed");
                }
                if (chain.hasApproved(a.proposalId(), owner)) {
                    throw reject(ALREADY_APPROVED, keySlotDesc(slot, owner) + " already approved proposal " + a.proposalId());
                }
                checkWithdrawalPolicy(a.asset(), a.to(), a.amount());
                calldata = VaultCalls.approve(a.proposalId());
                action = "approved";
            }
            case Cancellation c -> {
                openProposal(c.proposalId());
                calldata = VaultCalls.cancel(c.proposalId());
                action = "cancelled";
            }
        }

        // 5. Simulate the exact call from the owner's address.
        simulate(owner, calldata);

        // 6. Use up the nonce (durably) before anything is signed: if a later step fails, the
        //    approver signs a fresh intent. Failing closed beats any chance of a double use.
        if (!nonces.markUsed(approver, s.intent().nonce())) throw reject(NONCE_REUSED, "nonce already used");

        Receipt receipt = sendSigned(slot, calldata, Optional.of(s));
        BigInteger id = switch (s.intent()) {
            case WithdrawalRequest r -> proposedId(receipt);
            case WithdrawalApproval a -> a.proposalId();
            case Cancellation c -> c.proposalId();
        };
        LOG.log(System.Logger.Level.INFO, "{0} proposal {1} for approver {2} via {3}: {4}",
                action, id, approver, slot, receipt.txHash());
        return outcome(action, id, slot, owner, receipt.txHash());
    }

    /**
     * Executes a proposal once the vault says it's ready. Needs no intent: execution only carries
     * out what M owners approved, and the contract re-checks everything.
     */
    public synchronized Outcome execute(BigInteger id) {
        openProposal(id);
        BigInteger readyAt = chain.executableAt(id);
        if (readyAt.equals(NOT_READY_SENTINEL)) {
            throw reject(NOT_READY, "proposal " + id + " has " + chain.approvalCount(id) + " of " + chain.threshold() + " approvals");
        }
        if (BigInteger.valueOf(chain.chainTime()).compareTo(readyAt) < 0) {
            throw reject(NOT_READY, "proposal " + id + " is timelocked until " + readyAt);
        }
        String slot = signer.keySlots().stream()
                .filter(k -> chain.isOwner(signer.ownerAddress(k)))
                .findFirst()
                .orElseThrow(() -> reject(NOT_AN_OWNER, "no key slot holds a current owner key"));
        String owner = signer.ownerAddress(slot);
        byte[] calldata = VaultCalls.execute(id);
        simulate(owner, calldata);
        Receipt receipt = sendSigned(slot, calldata, Optional.empty());
        LOG.log(System.Logger.Level.INFO, "executed proposal {0} via {1}: {2}", id, slot, receipt.txHash());
        return outcome("executed", id, slot, owner, receipt.txHash());
    }

    /** Read-only view of a proposal for the API. */
    public Map<String, Object> status(BigInteger id) {
        Proposal p = chain.proposal(id).orElseThrow(() -> reject(UNKNOWN_PROPOSAL, "no proposal " + id));
        BigInteger readyAt = chain.executableAt(id);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("proposalId", id.toString());
        m.put("kind", p.isWithdrawal() ? "withdrawal" : "config");
        m.put("asset", p.asset());
        m.put("to", p.to());
        m.put("amount", p.amount().toString());
        m.put("state", p.executed() ? "executed" : p.cancelled() ? "cancelled" : "open");
        m.put("approvals", chain.approvalCount(id).toString());
        m.put("threshold", chain.threshold().toString());
        m.put("executableAt", readyAt.equals(NOT_READY_SENTINEL) ? null : readyAt.toString());
        return m;
    }

    // ---------------------------------------------------------------------------------------

    private void checkWithdrawalPolicy(String asset, String to, BigInteger amount) {
        if (amount.signum() == 0) throw reject(ZERO_AMOUNT, "amount is zero");
        if (chain.paused()) throw reject(PAUSED, "the vault is paused");
        if (!chain.isAllowedDestination(to)) throw reject(DESTINATION_NOT_ALLOWED, to + " is not an allowlisted destination");
        BigInteger limit = chain.dailyLimit(asset);
        if (amount.compareTo(limit) > 0) {
            throw reject(OVER_DAILY_LIMIT, "amount " + amount + " exceeds the vault's daily limit " + limit + " for " + asset);
        }
        BigInteger cap = policy.perRequestCap().get(Address.parse(asset));
        if (cap != null && amount.compareTo(cap) > 0) {
            throw reject(OVER_ORCHESTRATOR_CAP, "amount " + amount + " exceeds the orchestrator's cap " + cap + " for " + asset);
        }
    }

    private Proposal openProposal(BigInteger id) {
        Proposal p = chain.proposal(id).orElseThrow(() -> reject(UNKNOWN_PROPOSAL, "no proposal " + id));
        if (p.executed() || p.cancelled()) {
            throw reject(PROPOSAL_CLOSED, "proposal " + id + " is already " + (p.executed() ? "executed" : "cancelled"));
        }
        return p;
    }

    private void simulate(String owner, byte[] calldata) {
        try {
            chain.simulate(owner, calldata);
        } catch (Chain.Reverted e) {
            throw reject(ON_CHAIN_REVERT, "the vault would reject this: " + e.error);
        }
    }

    private Receipt sendSigned(String slot, byte[] calldata, Optional<SignedIntent> auth) {
        Receipt r;
        try {
            r = chain.send(slot, calldata, auth);
        } catch (HsmSigner.HsmRefusal e) {
            throw reject(SIGNER_REFUSED, "signer refused: " + e.getMessage());
        }
        if (!r.success()) throw reject(TX_FAILED, "transaction " + r.txHash() + " reverted");
        return r;
    }

    private BigInteger proposedId(Receipt r) {
        return r.logs().stream()
                .filter(l -> Address.same(l.address(), domain.vault()) && !l.topics().isEmpty()
                        && l.topics().get(0).equalsIgnoreCase(VaultCalls.PROPOSED_TOPIC))
                .map(l -> Hex.toBigInteger(l.topics().get(1)))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("no Proposed event in " + r.txHash()));
    }

    private Outcome outcome(String action, BigInteger id, String slot, String owner, String txHash) {
        return new Outcome(action, id, slot, owner, txHash, chain.approvalCount(id), chain.threshold(), chain.executableAt(id));
    }

    private static String keySlotDesc(String slot, String owner) {
        return slot + " (" + owner + ")";
    }

    private static Rejection reject(Rejection.Code code, String message) {
        return new Rejection(code, message);
    }
}
