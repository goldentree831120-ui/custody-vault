package custody.orchestrator.hsm;

import static org.junit.jupiter.api.Assertions.*;

import custody.orchestrator.Intents;
import custody.orchestrator.Intents.Domain;
import custody.orchestrator.Intents.SignedIntent;
import custody.orchestrator.Intents.WithdrawalApproval;
import custody.orchestrator.Intents.WithdrawalRequest;
import custody.orchestrator.VaultCalls;
import custody.orchestrator.crypto.Hex;
import custody.orchestrator.crypto.Keccak;
import custody.orchestrator.crypto.Secp256k1;
import custody.orchestrator.eth.Eip1559Tx;
import java.math.BigInteger;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class MockHsmSignerTest {
    static final String VAULT = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
    static final String ETH = "0x0000000000000000000000000000000000000000";
    static final long NOW = 1_800_000_000L;
    static final String DEST = Secp256k1.address(AnvilTestKeys.key(8));

    Domain domain = new Domain(31337, VAULT);
    MockHsmSigner hsm;

    @BeforeEach
    void setUp() {
        Map<String, Integer> bindings = new LinkedHashMap<>();
        bindings.put(Secp256k1.address(AnvilTestKeys.key(4)), 0);
        bindings.put(Secp256k1.address(AnvilTestKeys.key(5)), 1);
        hsm = new MockHsmSigner(domain, bindings, Clock.fixed(Instant.ofEpochSecond(NOW), ZoneOffset.UTC));
    }

    Eip1559Tx tx(byte[] data) {
        return tx(31337, VAULT, BigInteger.ZERO, data);
    }

    Eip1559Tx tx(long chainId, String to, BigInteger value, byte[] data) {
        return new Eip1559Tx(chainId, BigInteger.ZERO, BigInteger.ONE, BigInteger.TEN, BigInteger.valueOf(100_000), to, value, data);
    }

    SignedIntent requestBy(int approverKey, BigInteger nonce, long deadline) {
        return Intents.sign(domain, new WithdrawalRequest(ETH, DEST, BigInteger.TEN, nonce, deadline), AnvilTestKeys.key(approverKey));
    }

    void assertRefused(String slot, Eip1559Tx tx, Optional<SignedIntent> auth, String reason) {
        HsmSigner.HsmRefusal e = assertThrows(HsmSigner.HsmRefusal.class, () -> hsm.signTransaction(slot, tx, auth));
        assertTrue(e.getMessage().contains(reason), e.getMessage());
    }

    @Test
    void refusesToRunOnAnyChainButAnvil() {
        assertThrows(IllegalStateException.class, () -> new MockHsmSigner(new Domain(1, VAULT), Map.of(), Clock.systemUTC()));
        assertThrows(IllegalStateException.class, () -> new MockHsmSigner(new Domain(11155111, VAULT), Map.of(), Clock.systemUTC()));
    }

    @Test
    void signsExactlyTheAuthorisedCallWithTheOwnerKey() {
        SignedIntent s = requestBy(4, BigInteger.ONE, NOW + 60);
        Eip1559Tx t = tx(VaultCalls.proposeWithdrawal(ETH, DEST, BigInteger.TEN));
        byte[] raw = hsm.signTransaction("owner-1", t, Optional.of(s));
        // Deterministic (RFC 6979) signing: identical to signing with owner-1's key (Anvil #0) directly.
        assertArrayEquals(t.encodeSigned(Secp256k1.sign(t.signingHash(), AnvilTestKeys.key(0))), raw);
        assertEquals(Secp256k1.address(AnvilTestKeys.key(0)), hsm.ownerAddress("owner-1"));
    }

    @Test
    void refusesCalldataThatDiffersFromTheIntent() {
        SignedIntent s = requestBy(4, BigInteger.ONE, NOW + 60);
        assertRefused("owner-1", tx(VaultCalls.proposeWithdrawal(ETH, VAULT, BigInteger.TEN)), Optional.of(s), "calldata");
        assertRefused("owner-1", tx(VaultCalls.proposeWithdrawal(ETH, DEST, BigInteger.TWO.pow(100))), Optional.of(s), "calldata");
        assertRefused("owner-1", tx(VaultCalls.approve(BigInteger.ONE)), Optional.of(s), "calldata");
    }

    @Test
    void approvalIntentAuthorisesOnlyThatProposalId() {
        SignedIntent a = Intents.sign(domain,
                new WithdrawalApproval(BigInteger.valueOf(3), ETH, DEST, BigInteger.TEN, BigInteger.ONE, NOW + 60),
                AnvilTestKeys.key(5));
        assertRefused("owner-2", tx(VaultCalls.approve(BigInteger.valueOf(4))), Optional.of(a), "calldata");
        hsm.signTransaction("owner-2", tx(VaultCalls.approve(BigInteger.valueOf(3))), Optional.of(a));
    }

    @Test
    void refusesAnotherApproversIntent() {
        SignedIntent byA = requestBy(4, BigInteger.ONE, NOW + 60);
        assertRefused("owner-2", tx(VaultCalls.proposeWithdrawal(ETH, DEST, BigInteger.TEN)), Optional.of(byA), "not signed by the approver");
        SignedIntent byStranger = requestBy(7, BigInteger.ONE, NOW + 60);
        assertRefused("owner-1", tx(VaultCalls.proposeWithdrawal(ETH, DEST, BigInteger.TEN)), Optional.of(byStranger), "not signed by the approver");
    }

    @Test
    void refusesExpiredIntentsAndReplays() {
        byte[] data = VaultCalls.proposeWithdrawal(ETH, DEST, BigInteger.TEN);
        assertRefused("owner-1", tx(data), Optional.of(requestBy(4, BigInteger.ONE, NOW - 1)), "expired");
        SignedIntent s = requestBy(4, BigInteger.TWO, NOW + 60);
        hsm.signTransaction("owner-1", tx(data), Optional.of(s));
        assertRefused("owner-1", tx(data), Optional.of(s), "nonce already used");
    }

    @Test
    void refusesWrongChainDestinationOrValue() {
        SignedIntent s = requestBy(4, BigInteger.ONE, NOW + 60);
        byte[] data = VaultCalls.proposeWithdrawal(ETH, DEST, BigInteger.TEN);
        assertRefused("owner-1", tx(1, VAULT, BigInteger.ZERO, data), Optional.of(s), "wrong chain");
        assertRefused("owner-1", tx(31337, DEST, BigInteger.ZERO, data), Optional.of(s), "not the vault");
        assertRefused("owner-1", tx(31337, VAULT, BigInteger.ONE, data), Optional.of(s), "ETH");
        assertRefused("owner-1", tx(31337, null, BigInteger.ZERO, data), Optional.of(s), "not the vault");
    }

    @Test
    void withoutAnIntentOnlyExecuteIsSigned() {
        hsm.signTransaction("owner-1", tx(VaultCalls.execute(BigInteger.ONE)), Optional.empty());
        assertRefused("owner-1", tx(VaultCalls.approve(BigInteger.ONE)), Optional.empty(), "only execute");
        assertRefused("owner-1", tx(VaultCalls.cancel(BigInteger.ONE)), Optional.empty(), "only execute");
        byte[] padded = Arrays.copyOf(VaultCalls.execute(BigInteger.ONE), 68); // execute selector + extra bytes
        assertRefused("owner-1", tx(padded), Optional.empty(), "only execute");
        assertRefused("owner-1", tx(Keccak.selector("pause()")), Optional.empty(), "only execute");
    }

    @Test
    void unknownSlotIsRefused() {
        assertRefused("owner-9", tx(VaultCalls.execute(BigInteger.ONE)), Optional.empty(), "unknown key slot");
    }

    @Test
    void neverPrintsKeyMaterial() {
        String s = hsm.toString();
        assertTrue(s.contains("TEST KEYS ONLY"));
        for (int i = 0; i < 10; i++) {
            assertFalse(s.contains(AnvilTestKeys.key(i).toString(16)));
            assertFalse(s.contains(Hex.strip(Hex.encode(Hex.toBytesPadded(AnvilTestKeys.key(i), 32)))));
        }
    }
}
