package custody.orchestrator;

import custody.orchestrator.Intents.SignedIntent;
import custody.orchestrator.crypto.Hex;
import custody.orchestrator.eth.Abi;
import custody.orchestrator.eth.Eip1559Tx;
import custody.orchestrator.hsm.HsmSigner;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * An in-memory stand-in for the vault, enough to drive the orchestrator's checks. Transactions
 * still go through the real (mock) signer, so its policy is exercised too.
 */
final class FakeChain implements Chain {
    static final BigInteger NOT_READY = BigInteger.TWO.pow(256).subtract(BigInteger.ONE);

    final long chainId;
    final String vault;
    HsmSigner signer;

    final Set<String> owners = new HashSet<>();
    final Set<String> allowlist = new HashSet<>();
    final Map<String, BigInteger> dailyLimits = new HashMap<>();
    final List<Proposal> proposals = new ArrayList<>();
    final Map<BigInteger, Set<String>> approvals = new HashMap<>();
    final Map<BigInteger, BigInteger> executableAt = new HashMap<>();
    boolean paused;
    long time = 1_800_000_000L;
    String revertWith; // simulate() throws Reverted(revertWith) when set
    boolean nextTxFails;
    final List<byte[]> sent = new ArrayList<>();

    FakeChain(long chainId, String vault) {
        this.chainId = chainId;
        this.vault = vault;
    }

    @Override public long chainId() { return chainId; }
    @Override public long chainTime() { return time; }
    @Override public boolean isOwner(String a) { return owners.contains(a.toLowerCase()); }
    @Override public boolean paused() { return paused; }
    @Override public boolean isAllowedDestination(String to) { return allowlist.contains(to.toLowerCase()); }
    @Override public BigInteger dailyLimit(String asset) { return dailyLimits.getOrDefault(asset.toLowerCase(), BigInteger.ZERO); }
    @Override public BigInteger availableToWithdraw(String asset) { return dailyLimit(asset); }

    @Override
    public Optional<Proposal> proposal(BigInteger id) {
        return id.compareTo(BigInteger.valueOf(proposals.size())) < 0 ? Optional.of(proposals.get(id.intValueExact())) : Optional.empty();
    }

    @Override public boolean hasApproved(BigInteger id, String owner) { return approvals.getOrDefault(id, Set.of()).contains(owner.toLowerCase()); }
    @Override public BigInteger approvalCount(BigInteger id) { return BigInteger.valueOf(approvals.getOrDefault(id, Set.of()).size()); }
    @Override public BigInteger threshold() { return BigInteger.TWO; }
    @Override public BigInteger executableAt(BigInteger id) { return executableAt.getOrDefault(id, NOT_READY); }

    @Override
    public void simulate(String from, byte[] calldata) {
        if (revertWith != null) throw new Reverted(revertWith);
    }

    @Override
    public Receipt send(String keySlot, byte[] calldata, Optional<SignedIntent> auth) {
        Eip1559Tx tx = new Eip1559Tx(chainId, BigInteger.valueOf(sent.size()), BigInteger.ONE, BigInteger.TEN,
                BigInteger.valueOf(300_000), vault, BigInteger.ZERO, calldata);
        signer.signTransaction(keySlot, tx, auth); // throws HsmRefusal if the signer says no
        sent.add(calldata);
        String hash = Hex.encode(Abi.uint(BigInteger.valueOf(sent.size())));
        if (nextTxFails) {
            nextTxFails = false;
            return new Receipt(hash, false, List.of());
        }
        String owner = signer.ownerAddress(keySlot).toLowerCase();
        String sel = Hex.encode(Arrays.copyOf(calldata, 4));
        List<Log> logs = new ArrayList<>();
        if (sel.equals(Hex.encode(Arrays.copyOf(VaultCalls.proposeWithdrawal(vault, vault, BigInteger.ONE), 4)))) {
            BigInteger id = BigInteger.valueOf(proposals.size());
            byte[] args = Abi.slice(calldata, 4);
            proposals.add(new Proposal(true, Abi.addressAt(args, 0), Abi.addressAt(args, 1), Abi.uintAt(args, 2),
                    time, 0, false, false));
            approvals.computeIfAbsent(id, k -> new HashSet<>()).add(owner);
            logs.add(new Log(vault, List.of(VaultCalls.PROPOSED_TOPIC, Hex.encode(Abi.uint(id)),
                    Hex.encode(Abi.encodeArgs(owner))), "0x"));
        } else if (sel.equals(Hex.encode(Arrays.copyOf(VaultCalls.approve(BigInteger.ONE), 4)))) {
            approvals.computeIfAbsent(Abi.uintAt(Abi.slice(calldata, 4), 0), k -> new HashSet<>()).add(owner);
        }
        return new Receipt(hash, true, logs);
    }

    /** Adds a withdrawal proposal directly, as if proposed by someone else. */
    BigInteger addProposal(boolean withdrawal, String asset, String to, BigInteger amount) {
        proposals.add(new Proposal(withdrawal, asset, to, amount, time, 0, false, false));
        return BigInteger.valueOf(proposals.size() - 1);
    }

    void close(BigInteger id, boolean executed) {
        Proposal p = proposals.get(id.intValueExact());
        proposals.set(id.intValueExact(), new Proposal(p.isWithdrawal(), p.asset(), p.to(), p.amount(), p.createdAt(),
                p.thresholdReachedAt(), executed, !executed));
    }
}
