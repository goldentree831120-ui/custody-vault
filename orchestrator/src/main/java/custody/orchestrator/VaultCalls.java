package custody.orchestrator;

import custody.orchestrator.crypto.Hex;
import custody.orchestrator.crypto.Keccak;
import custody.orchestrator.eth.Abi;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Calldata for the CustodyVault functions this service calls, and its custom-error names. */
public final class VaultCalls {
    private VaultCalls() {}

    public static final byte[] EXECUTE_SELECTOR = Keccak.selector("execute(uint256)");

    public static byte[] proposeWithdrawal(String asset, String to, BigInteger amount) {
        return Abi.call("proposeWithdrawal(address,address,uint256)", asset, to, amount);
    }

    public static byte[] approve(BigInteger id) {
        return Abi.call("approve(uint256)", id);
    }

    public static byte[] cancel(BigInteger id) {
        return Abi.call("cancel(uint256)", id);
    }

    public static byte[] execute(BigInteger id) {
        return Abi.call("execute(uint256)", id);
    }

    /** topic0 of Proposed(uint256 indexed id, Kind kind, address indexed proposer). */
    public static final String PROPOSED_TOPIC = Hex.encode(Keccak.hash("Proposed(uint256,uint8,address)"));

    private static final List<String> ERRORS = List.of(
            "NotOwner()", "NotSelf()", "InvalidOwners()", "InvalidThreshold()", "InvalidTimelock()", "IsPaused()",
            "DestinationNotAllowed(address)", "ZeroAmount()", "UseReceiveForEth()",
            "AmountExceedsDailyLimit(uint256,uint256)", "RateLimited(uint256,uint256)",
            "InsufficientVaultBalance(uint256,uint256)", "UnknownProposal(uint256)", "ProposalClosed(uint256)",
            "ProposalExpired(uint256)", "ProposalStale(uint256)", "AlreadyApproved(uint256)", "NotApproved(uint256)",
            "NotEnoughApprovals(uint256,uint256,uint256)", "TimelockActive(uint256,uint256)",
            "ConfigCallNotAllowed(bytes4)", "ConfigCallFailed(bytes)", "EthTransferFailed()",
            "ReentrancyGuardReentrantCall()", "SafeERC20FailedOperation(address)");

    private static final Map<String, String> ERROR_BY_SELECTOR = new HashMap<>();

    static {
        for (String e : ERRORS) ERROR_BY_SELECTOR.put(Hex.encode(Keccak.selector(e)), e.substring(0, e.indexOf('(')));
    }

    /** The custom error's name for revert data like 0x5f0e2a3b..., or "unknown revert". */
    public static String errorName(String revertData) {
        if (revertData == null || revertData.length() < 10) return "unknown revert";
        byte[] d = Hex.decode(revertData);
        return ERROR_BY_SELECTOR.getOrDefault(Hex.encode(Arrays.copyOf(d, 4)), "unknown revert");
    }
}
