package custody.orchestrator;

import static org.junit.jupiter.api.Assertions.*;

import custody.orchestrator.Intents.Domain;
import custody.orchestrator.Intents.SignedIntent;
import custody.orchestrator.Intents.WithdrawalRequest;
import custody.orchestrator.crypto.Secp256k1;
import custody.orchestrator.eth.Json;
import custody.orchestrator.hsm.AnvilTestKeys;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class IntentsAndNoncesTest {
    static final Domain DOMAIN = new Domain(31337, "0x5FbDB2315678afecb367f032d93F642f64180aa3");
    static final String ETH = "0x0000000000000000000000000000000000000000";
    static final String DEST = "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f";

    @Test
    void jsonRoundTripKeepsTheSigner() {
        SignedIntent s = Intents.sign(DOMAIN, new WithdrawalRequest(ETH, DEST, BigInteger.TEN, BigInteger.ONE, 1_900_000_000L),
                AnvilTestKeys.key(4));
        SignedIntent back = Intents.fromJson(Json.parseObject(Json.write(Intents.toJson(s))));
        assertEquals(s.intent(), back.intent());
        assertEquals(s.signer(DOMAIN), back.signer(DOMAIN));
        assertEquals(Secp256k1.address(AnvilTestKeys.key(4)), back.signer(DOMAIN).orElseThrow());
    }

    @SuppressWarnings("unchecked")
    @Test
    void jsonParsingIsStrict() {
        Map<String, Object> good = Intents.toJson(Intents.sign(DOMAIN,
                new WithdrawalRequest(ETH, DEST, BigInteger.TEN, BigInteger.ONE, 1_900_000_000L), AnvilTestKeys.key(4)));
        assertDoesNotThrow(() -> Intents.fromJson(good));

        // amounts as JSON numbers (precision loss in many clients), leading zeros, negatives
        for (Object badAmount : new Object[] {new java.math.BigDecimal("10"), "010", "-1", "1e3", "0x0a", ""}) {
            Map<String, Object> b = copy(good);
            ((Map<String, Object>) b.get("message")).put("amount", badAmount);
            assertThrows(IllegalArgumentException.class, () -> Intents.fromJson(b), String.valueOf(badAmount));
        }
        // an unknown extra field is refused, not ignored
        Map<String, Object> extra = copy(good);
        ((Map<String, Object>) extra.get("message")).put("memo", "hi");
        assertThrows(IllegalArgumentException.class, () -> Intents.fromJson(extra));
        // a missing field
        Map<String, Object> missing = copy(good);
        ((Map<String, Object>) missing.get("message")).remove("deadline");
        assertThrows(IllegalArgumentException.class, () -> Intents.fromJson(missing));
        // unknown type, bad address checksum, non-hex signature
        Map<String, Object> type = copy(good);
        type.put("type", "Transfer");
        assertThrows(IllegalArgumentException.class, () -> Intents.fromJson(type));
        Map<String, Object> addr = copy(good);
        ((Map<String, Object>) addr.get("message")).put("to", "0x23618e81e3f5cdF7f54C3d65f7FBc0aBf5B21E8f");
        assertThrows(IllegalArgumentException.class, () -> Intents.fromJson(addr));
        Map<String, Object> sig = copy(good);
        sig.put("signature", "0xzz");
        assertThrows(IllegalArgumentException.class, () -> Intents.fromJson(sig));
        // amount above 2^256 - 1
        Map<String, Object> huge = copy(good);
        ((Map<String, Object>) huge.get("message")).put("amount", BigInteger.TWO.pow(256).toString());
        assertThrows(IllegalArgumentException.class, () -> Intents.fromJson(huge));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> copy(Map<String, Object> m) {
        Map<String, Object> out = new LinkedHashMap<>(m);
        out.put("message", new LinkedHashMap<>((Map<String, Object>) m.get("message")));
        return out;
    }

    @Test
    void fileNonceStoreSurvivesARestart() throws Exception {
        Path dir = Files.createTempDirectory("nonces");
        Path f = dir.resolve("used.txt");
        String approver = "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65";
        NonceStore a = new NonceStore.FileBacked(f);
        assertTrue(a.markUsed(approver, BigInteger.ONE));
        assertFalse(a.markUsed(approver, BigInteger.ONE));
        assertFalse(a.markUsed(approver.toLowerCase(), BigInteger.ONE)); // address case doesn't matter

        NonceStore b = new NonceStore.FileBacked(f); // "after a restart"
        assertTrue(b.isUsed(approver, BigInteger.ONE));
        assertFalse(b.isUsed(approver, BigInteger.TWO));
        assertFalse(b.markUsed(approver, BigInteger.ONE));
    }
}
