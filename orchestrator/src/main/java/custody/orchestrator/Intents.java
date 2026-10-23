package custody.orchestrator;

import custody.orchestrator.crypto.Address;
import custody.orchestrator.crypto.Hex;
import custody.orchestrator.crypto.Keccak;
import custody.orchestrator.crypto.Secp256k1;
import custody.orchestrator.eth.Abi;
import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * What an approver signs. Each intent is EIP-712 typed data, so a wallet shows the approver the
 * actual fields (asset, destination, amount) instead of an opaque hash.
 *
 * <p>The domain binds every signature to one orchestrator deployment: one chain id and one vault
 * address. A signature made for another vault or chain recovers to a different (unknown) address.
 */
public final class Intents {
    private Intents() {}

    public static final String DOMAIN_NAME = "CustodyVault Orchestrator";
    public static final String DOMAIN_VERSION = "1";

    private static final byte[] DOMAIN_TYPEHASH =
            Keccak.hash("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    public record Domain(long chainId, String vault) {
        public Domain {
            vault = Address.parse(vault);
        }

        public byte[] separator() {
            return Keccak.hash(Abi.concat(
                    DOMAIN_TYPEHASH,
                    Keccak.hash(DOMAIN_NAME),
                    Keccak.hash(DOMAIN_VERSION),
                    Abi.uint(BigInteger.valueOf(chainId)),
                    Abi.encodeArgs(vault)));
        }
    }

    /** Every intent carries a per-approver nonce (single use) and a deadline (unix seconds). */
    public sealed interface Intent permits WithdrawalRequest, WithdrawalApproval, Cancellation {
        BigInteger nonce();

        long deadline();

        byte[] structHash();

        String typeName();

        Map<String, Object> toJson();
    }

    /** "Create a withdrawal proposal." The proposer's own approval is counted by the vault. */
    public record WithdrawalRequest(String asset, String to, BigInteger amount, BigInteger nonce, long deadline)
            implements Intent {
        static final String TYPE = "WithdrawalRequest(address asset,address to,uint256 amount,uint256 nonce,uint256 deadline)";

        public WithdrawalRequest {
            asset = Address.parse(asset);
            to = Address.parse(to);
            requireUint(amount, "amount");
            requireUint(nonce, "nonce");
        }

        public byte[] structHash() {
            return Keccak.hash(Abi.concat(Keccak.hash(TYPE), Abi.encodeArgs(asset, to, amount, nonce, deadline)));
        }

        public String typeName() {
            return "WithdrawalRequest";
        }

        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("asset", asset);
            m.put("to", to);
            m.put("amount", amount.toString());
            m.put("nonce", nonce.toString());
            m.put("deadline", Long.toString(deadline));
            return m;
        }
    }

    /**
     * "Approve proposal N, which sends AMOUNT of ASSET to TO." The approver signs the content, not
     * only the id, and the orchestrator checks the content against the proposal on-chain. So an
     * approver can't be tricked into approving proposal N when N is something else.
     */
    public record WithdrawalApproval(
            BigInteger proposalId, String asset, String to, BigInteger amount, BigInteger nonce, long deadline)
            implements Intent {
        static final String TYPE =
                "WithdrawalApproval(uint256 proposalId,address asset,address to,uint256 amount,uint256 nonce,uint256 deadline)";

        public WithdrawalApproval {
            requireUint(proposalId, "proposalId");
            asset = Address.parse(asset);
            to = Address.parse(to);
            requireUint(amount, "amount");
            requireUint(nonce, "nonce");
        }

        public byte[] structHash() {
            return Keccak.hash(
                    Abi.concat(Keccak.hash(TYPE), Abi.encodeArgs(proposalId, asset, to, amount, nonce, deadline)));
        }

        public String typeName() {
            return "WithdrawalApproval";
        }

        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("proposalId", proposalId.toString());
            m.put("asset", asset);
            m.put("to", to);
            m.put("amount", amount.toString());
            m.put("nonce", nonce.toString());
            m.put("deadline", Long.toString(deadline));
            return m;
        }
    }

    /** "Cancel proposal N." One owner is enough: this is the vault's veto. */
    public record Cancellation(BigInteger proposalId, BigInteger nonce, long deadline) implements Intent {
        static final String TYPE = "Cancellation(uint256 proposalId,uint256 nonce,uint256 deadline)";

        public Cancellation {
            requireUint(proposalId, "proposalId");
            requireUint(nonce, "nonce");
        }

        public byte[] structHash() {
            return Keccak.hash(Abi.concat(Keccak.hash(TYPE), Abi.encodeArgs(proposalId, nonce, deadline)));
        }

        public String typeName() {
            return "Cancellation";
        }

        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("proposalId", proposalId.toString());
            m.put("nonce", nonce.toString());
            m.put("deadline", Long.toString(deadline));
            return m;
        }
    }

    /** keccak(0x19 0x01 || domainSeparator || structHash): what the approver's key signs. */
    public static byte[] digest(Domain domain, Intent intent) {
        return Keccak.hash(new byte[] {0x19, 0x01}, domain.separator(), intent.structHash());
    }

    public record SignedIntent(Intent intent, byte[] signature) {
        /** The approver address that signed this intent under {@code domain}, or empty if the signature is malformed. */
        public Optional<String> signer(Domain domain) {
            final Secp256k1.Signature sig;
            try {
                sig = Secp256k1.Signature.fromBytes65(signature);
            } catch (IllegalArgumentException e) {
                return Optional.empty();
            }
            return Secp256k1.recoverAddress(digest(domain, intent), sig);
        }
    }

    public static SignedIntent sign(Domain domain, Intent intent, BigInteger approverKey) {
        return new SignedIntent(intent, Secp256k1.sign(digest(domain, intent), approverKey).toBytes65());
    }

    // ---- JSON -----------------------------------------------------------------------------

    /** Parses {"type": ..., "message": {...}, "signature": "0x..."}. Numbers are decimal strings. */
    @SuppressWarnings("unchecked")
    public static SignedIntent fromJson(Map<String, Object> body) {
        Object type = body.get("type");
        if (!(body.get("message") instanceof Map<?, ?> raw)) throw new IllegalArgumentException("missing 'message' object");
        Map<String, Object> m = (Map<String, Object>) raw;
        if (!(body.get("signature") instanceof String sigHex)) throw new IllegalArgumentException("missing 'signature'");
        byte[] sig;
        try {
            sig = Hex.decode(sigHex);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("signature is not hex");
        }
        Intent intent = switch (String.valueOf(type)) {
            case "WithdrawalRequest" -> {
                expectKeys(m, "asset", "to", "amount", "nonce", "deadline");
                yield new WithdrawalRequest(str(m, "asset"), str(m, "to"), num(m, "amount"), num(m, "nonce"),
                        num(m, "deadline").longValueExact());
            }
            case "WithdrawalApproval" -> {
                expectKeys(m, "proposalId", "asset", "to", "amount", "nonce", "deadline");
                yield new WithdrawalApproval(num(m, "proposalId"), str(m, "asset"), str(m, "to"), num(m, "amount"),
                        num(m, "nonce"), num(m, "deadline").longValueExact());
            }
            case "Cancellation" -> {
                expectKeys(m, "proposalId", "nonce", "deadline");
                yield new Cancellation(num(m, "proposalId"), num(m, "nonce"), num(m, "deadline").longValueExact());
            }
            default -> throw new IllegalArgumentException("unknown intent type: " + type);
        };
        return new SignedIntent(intent, sig);
    }

    public static Map<String, Object> toJson(SignedIntent s) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", s.intent().typeName());
        m.put("message", s.intent().toJson());
        m.put("signature", Hex.encode(s.signature()));
        return m;
    }

    private static void expectKeys(Map<String, Object> m, String... keys) {
        if (m.size() != keys.length || !m.keySet().containsAll(java.util.List.of(keys))) {
            throw new IllegalArgumentException("message must have exactly: " + String.join(", ", keys));
        }
    }

    private static String str(Map<String, Object> m, String k) {
        if (!(m.get(k) instanceof String s)) throw new IllegalArgumentException(k + " must be a string");
        return s;
    }

    /** Decimal string only: JSON numbers lose precision above 2^53 in many clients. */
    private static BigInteger num(Map<String, Object> m, String k) {
        if (!(m.get(k) instanceof String s) || !s.matches("0|[1-9][0-9]{0,77}")) {
            throw new IllegalArgumentException(k + " must be a decimal string");
        }
        return new BigInteger(s);
    }

    private static void requireUint(BigInteger v, String name) {
        if (v == null || v.signum() < 0 || v.bitLength() > 256) throw new IllegalArgumentException(name + " out of range");
    }
}
