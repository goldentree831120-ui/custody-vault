package custody.orchestrator.dev;

import custody.orchestrator.crypto.Address;
import custody.orchestrator.crypto.Hex;
import custody.orchestrator.crypto.Secp256k1;
import custody.orchestrator.eth.Abi;
import custody.orchestrator.eth.Eip1559Tx;
import custody.orchestrator.eth.JsonRpc;
import custody.orchestrator.hsm.AnvilTestKeys;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * LOCAL TEST SETUP ONLY. Deploys a CustodyVault on a local Anvil chain and configures it, standing
 * in for the key ceremony and initial configuration a real deployment would do. Uses Anvil's public
 * test keys directly and refuses to run on any other chain.
 *
 * <p>Accounts (Anvil indexes): owners #0-#2 (keys "in the HSM"), approver devices #4-#6, an unknown
 * approver #7, the allowlisted destination #8, the deployer #9.
 */
public final class LocalVault {
    private LocalVault() {}

    public static final int[] OWNER_KEYS = {0, 1, 2};
    public static final int[] APPROVER_KEYS = {4, 5, 6};
    public static final int STRANGER_KEY = 7;
    public static final int DESTINATION_KEY = 8;
    public static final int DEPLOYER_KEY = 9;

    public static final String ETH = "0x0000000000000000000000000000000000000000";
    public static final BigInteger ONE_ETH = BigInteger.TEN.pow(18);
    public static final BigInteger DAILY_LIMIT = ONE_ETH.multiply(BigInteger.valueOf(10));
    public static final BigInteger LARGE_THRESHOLD = ONE_ETH.multiply(BigInteger.valueOf(5));
    public static final long TIMELOCK_SECONDS = 3600;

    public static String address(int anvilIndex) {
        return Secp256k1.address(AnvilTestKeys.key(anvilIndex));
    }

    /** approver address → owner key index, the binding the mock HSM is provisioned with. */
    public static Map<String, Integer> approverBindings() {
        Map<String, Integer> m = new LinkedHashMap<>(); // ordered: approver A -> owner-1, B -> owner-2, C -> owner-3
        for (int i = 0; i < 3; i++) m.put(address(APPROVER_KEYS[i]), OWNER_KEYS[i]);
        return m;
    }

    /**
     * Deploys a 2-of-3 vault with a 1 hour timelock, funds it with 100 ETH, allowlists the
     * destination and sets the ETH policy (10 ETH/day, timelock from 5 ETH). The two config
     * changes go through the vault's own proposals and timelock, as they must. Then advances the
     * chain by a day so the rate-limit bucket is full.
     */
    public static String deployAndConfigure(JsonRpc rpc, Path artifact) {
        if (rpc.chainId() != AnvilTestKeys.ANVIL_CHAIN_ID) {
            throw new IllegalStateException("LocalVault only runs on a local Anvil chain (31337)");
        }
        String[] owners = {address(OWNER_KEYS[0]), address(OWNER_KEYS[1]), address(OWNER_KEYS[2])};
        byte[] init = Abi.concat(bytecode(artifact),
                Abi.encodeArgs(owners, BigInteger.TWO, BigInteger.valueOf(TIMELOCK_SECONDS)));
        Map<String, Object> deployed = send(rpc, DEPLOYER_KEY, null, BigInteger.ZERO, init);
        String vault = Address.checksum((String) deployed.get("contractAddress"));

        send(rpc, DEPLOYER_KEY, vault, ONE_ETH.multiply(BigInteger.valueOf(100)), new byte[0]);

        byte[] setDest = Abi.call("setDestination(address,bool)", address(DESTINATION_KEY), true);
        byte[] setPolicy = Abi.call("setAssetPolicy(address,uint128,uint128)", ETH, DAILY_LIMIT, LARGE_THRESHOLD);
        for (byte[] cfg : new byte[][] {setDest, setPolicy}) {
            send(rpc, OWNER_KEYS[0], vault, BigInteger.ZERO, Abi.call("proposeConfig(bytes)", (Object) cfg));
        }
        for (int id = 0; id < 2; id++) {
            send(rpc, OWNER_KEYS[1], vault, BigInteger.ZERO, Abi.call("approve(uint256)", id));
        }
        increaseTime(rpc, TIMELOCK_SECONDS + 1);
        for (int id = 0; id < 2; id++) {
            send(rpc, OWNER_KEYS[0], vault, BigInteger.ZERO, Abi.call("execute(uint256)", id));
        }
        // A newly configured asset starts with an empty rate-limit bucket (by design: outflow since
        // configuration never exceeds the limit). Let one day pass so the full 10 ETH is available.
        increaseTime(rpc, 86_400);
        return vault;
    }

    public static void increaseTime(JsonRpc rpc, long seconds) {
        rpc.request("evm_increaseTime", seconds);
        rpc.request("evm_mine");
    }

    public static BigInteger balance(JsonRpc rpc, String address) {
        return Hex.toBigInteger((String) rpc.request("eth_getBalance", address, "latest"));
    }

    /** Signs with a test key directly (setup only; the orchestrator always goes through the signer). */
    public static Map<String, Object> send(JsonRpc rpc, int keyIndex, String to, BigInteger value, byte[] data) {
        BigInteger key = AnvilTestKeys.key(keyIndex);
        String from = Secp256k1.address(key);
        BigInteger gas = rpc.estimateGas(from, to, data, value);
        BigInteger tip = BigInteger.valueOf(1_000_000_000L);
        Eip1559Tx tx = new Eip1559Tx(AnvilTestKeys.ANVIL_CHAIN_ID, rpc.pendingNonce(from), tip,
                rpc.baseFee().multiply(BigInteger.TWO).add(tip), gas.multiply(BigInteger.TWO), to, value, data);
        String hash = rpc.sendRawTransaction(tx.encodeSigned(Secp256k1.sign(tx.signingHash(), key)));
        Map<String, Object> receipt = rpc.waitForReceipt(hash, Duration.ofSeconds(30));
        if (Hex.toBigInteger((String) receipt.get("status")).signum() != 1) {
            throw new IllegalStateException("setup transaction reverted: " + hash);
        }
        return receipt;
    }

    private static final Pattern BYTECODE =
            Pattern.compile("\"bytecode\"\\s*:\\s*\\{\\s*\"object\"\\s*:\\s*\"(0x[0-9a-fA-F]+)\"");

    /** Creation bytecode from Foundry's build output (out/CustodyVault.sol/CustodyVault.json). */
    static byte[] bytecode(Path artifact) {
        String text;
        try {
            text = Files.readString(artifact);
        } catch (IOException e) {
            throw new IllegalStateException("can't read " + artifact + " (run `forge build` in the repository root first)", e);
        }
        Matcher m = BYTECODE.matcher(text);
        if (!m.find()) throw new IllegalStateException("no bytecode in " + artifact);
        return Hex.decode(m.group(1));
    }
}
