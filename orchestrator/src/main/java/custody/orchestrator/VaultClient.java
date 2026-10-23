package custody.orchestrator;

import custody.orchestrator.Intents.SignedIntent;
import custody.orchestrator.crypto.Hex;
import custody.orchestrator.eth.Abi;
import custody.orchestrator.eth.Eip1559Tx;
import custody.orchestrator.eth.JsonRpc;
import custody.orchestrator.eth.JsonRpc.RpcException;
import custody.orchestrator.hsm.HsmSigner;
import java.math.BigInteger;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** {@link Chain} over JSON-RPC, for one CustodyVault. Transactions are signed by the {@link HsmSigner}. */
public final class VaultClient implements Chain {
    private final JsonRpc rpc;
    private final String vault;
    private final HsmSigner signer;
    private final long chainId;

    public VaultClient(JsonRpc rpc, String vault, HsmSigner signer) {
        this.rpc = rpc;
        this.vault = vault;
        this.signer = signer;
        this.chainId = rpc.chainId();
    }

    private byte[] view(String signature, Object... args) {
        return rpc.call(null, vault, Abi.call(signature, args));
    }

    @Override
    public long chainId() {
        return chainId;
    }

    @Override
    public long chainTime() {
        return rpc.latestTimestamp();
    }

    @Override
    public boolean isOwner(String address) {
        return Abi.boolAt(view("isOwner(address)", address), 0);
    }

    @Override
    public boolean paused() {
        return Abi.boolAt(view("paused()"), 0);
    }

    @Override
    public boolean isAllowedDestination(String to) {
        return Abi.boolAt(view("isAllowedDestination(address)", to), 0);
    }

    @Override
    public BigInteger dailyLimit(String asset) {
        return Abi.uintAt(view("assetPolicy(address)", asset), 0);
    }

    @Override
    public BigInteger availableToWithdraw(String asset) {
        return Abi.uintAt(view("availableToWithdraw(address)", asset), 0);
    }

    @Override
    public Optional<Proposal> proposal(BigInteger id) {
        byte[] r;
        try {
            r = view("getProposal(uint256)", id);
        } catch (RpcException e) {
            if ("UnknownProposal".equals(VaultCalls.errorName(e.data))) return Optional.empty();
            throw e;
        }
        // Return data: [offset to tuple] then the tuple (it's dynamic because of `bytes data`).
        byte[] t = Abi.slice(r, Abi.uintAt(r, 0).intValueExact());
        return Optional.of(new Proposal(
                Abi.uintAt(t, 0).signum() == 0, // Kind.Withdrawal = 0
                Abi.addressAt(t, 1),
                Abi.addressAt(t, 2),
                Abi.uintAt(t, 3),
                Abi.uintAt(t, 5).longValueExact(),
                Abi.uintAt(t, 6).longValueExact(),
                Abi.boolAt(t, 9),
                Abi.boolAt(t, 10)));
    }

    @Override
    public boolean hasApproved(BigInteger id, String owner) {
        return Abi.boolAt(view("hasApproved(uint256,address)", id, owner), 0);
    }

    @Override
    public BigInteger approvalCount(BigInteger id) {
        return Abi.uintAt(view("approvalCount(uint256)", id), 0);
    }

    @Override
    public BigInteger threshold() {
        return Abi.uintAt(view("threshold()"), 0);
    }

    @Override
    public BigInteger executableAt(BigInteger id) {
        return Abi.uintAt(view("executableAt(uint256)", id), 0);
    }

    @Override
    public void simulate(String from, byte[] calldata) {
        try {
            rpc.call(from, vault, calldata);
        } catch (RpcException e) {
            if (e.data != null) throw new Reverted(VaultCalls.errorName(e.data));
            throw e;
        }
    }

    @Override
    public Receipt send(String keySlot, byte[] calldata, Optional<SignedIntent> authorization) {
        String from = signer.ownerAddress(keySlot);
        BigInteger gas = rpc.estimateGas(from, vault, calldata, BigInteger.ZERO);
        BigInteger tip = BigInteger.valueOf(1_000_000_000L); // 1 gwei
        BigInteger maxFee = rpc.baseFee().multiply(BigInteger.TWO).add(tip);
        Eip1559Tx tx = new Eip1559Tx(chainId, rpc.pendingNonce(from), tip, maxFee,
                gas.multiply(BigInteger.valueOf(12)).divide(BigInteger.TEN), // +20% headroom
                vault, BigInteger.ZERO, calldata);
        byte[] raw = signer.signTransaction(keySlot, tx, authorization);
        String hash = rpc.sendRawTransaction(raw);
        return toReceipt(rpc.waitForReceipt(hash, Duration.ofSeconds(60)));
    }

    @SuppressWarnings("unchecked")
    static Receipt toReceipt(Map<String, Object> r) {
        List<Log> logs = new ArrayList<>();
        for (Object o : (List<Object>) r.get("logs")) {
            Map<String, Object> l = (Map<String, Object>) o;
            logs.add(new Log((String) l.get("address"), (List<String>) (List<?>) l.get("topics"), (String) l.get("data")));
        }
        return new Receipt((String) r.get("transactionHash"), Hex.toBigInteger((String) r.get("status")).signum() == 1, logs);
    }
}
