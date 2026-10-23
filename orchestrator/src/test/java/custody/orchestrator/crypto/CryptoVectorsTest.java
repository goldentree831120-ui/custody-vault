package custody.orchestrator.crypto;

import static org.junit.jupiter.api.Assertions.*;

import custody.orchestrator.Intents;
import custody.orchestrator.Intents.Domain;
import custody.orchestrator.Intents.WithdrawalApproval;
import custody.orchestrator.VaultCalls;
import custody.orchestrator.eth.Eip1559Tx;
import custody.orchestrator.hsm.AnvilTestKeys;
import java.math.BigInteger;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * Known-answer tests. The hand-written parts (EIP-712 hashing, transaction encoding, recovery)
 * are checked against values produced by an independent implementation, Foundry's {@code cast}
 * (version 1.5.1), so a bug here can't hide behind a matching bug in the test.
 */
class CryptoVectorsTest {

    @Test
    void keccakOfEmptyInput() {
        assertEquals("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", Hex.encode(Keccak.hash(new byte[0])));
    }

    @Test
    void selectors() {
        assertEquals("0xb759f954", Hex.encode(Keccak.selector("approve(uint256)")));
        assertEquals("0xfe0d94c1", Hex.encode(Keccak.selector("execute(uint256)")));
    }

    @Test
    void addressesOfAnvilKeys() {
        assertEquals("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", Secp256k1.address(AnvilTestKeys.key(0)));
        assertEquals("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65", Secp256k1.address(AnvilTestKeys.key(4)));
    }

    /**
     * cast wallet sign --private-key (Anvil #4) --data --from-file td.json, where td.json is this
     * WithdrawalApproval under the orchestrator's domain (see docs in the README).
     */
    @Test
    void eip712SignatureMatchesCast() {
        Domain d = new Domain(31337, "0x5FbDB2315678afecb367f032d93F642f64180aa3");
        WithdrawalApproval a = new WithdrawalApproval(BigInteger.valueOf(7), "0x0000000000000000000000000000000000000000",
                "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f", new BigInteger("1000000000000000000"),
                BigInteger.valueOf(42), 1_900_000_000L);
        Intents.SignedIntent s = Intents.sign(d, a, AnvilTestKeys.key(4));
        assertEquals("0x63e6b69454a1e82863beadc339c3b6b2ff14dac991f51c9d0c7e99b3792b0389"
                + "4b52bbd69161d2fd8060862f89c0dd0fb32a59f28f4788c1056c606d584fab2a1b", Hex.encode(s.signature()));
        assertEquals(Optional.of("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"), s.signer(d));
    }

    /**
     * cast mktx --private-key (Anvil #0) --chain 31337 --nonce 5 --gas-limit 100000
     * --priority-gas-price 1000000000 --gas-price 3000000000 0x5FbD...0aa3 "approve(uint256)" 7
     */
    @Test
    void signedTransactionMatchesCast() {
        Eip1559Tx tx = new Eip1559Tx(31337, BigInteger.valueOf(5), BigInteger.valueOf(1_000_000_000L),
                BigInteger.valueOf(3_000_000_000L), BigInteger.valueOf(100_000),
                "0x5FbDB2315678afecb367f032d93F642f64180aa3", BigInteger.ZERO, VaultCalls.approve(BigInteger.valueOf(7)));
        byte[] raw = tx.encodeSigned(Secp256k1.sign(tx.signingHash(), AnvilTestKeys.key(0)));
        assertEquals("0x02f891827a6905843b9aca0084b2d05e00830186a0945fbdb2315678afecb367f032d93f642f64180aa380a4b759f954"
                + "0000000000000000000000000000000000000000000000000000000000000007c080a03b9854c6d0829282e11cdf929de4c1dc"
                + "197b8c9f09721620d0c6a11051587f1ba079ce6ba404f9570ef9d67b6a16b0a12d3bdbc0570113b21d135b44bdf28b6d73",
                Hex.encode(raw));
    }

    @Test
    void signaturesAreLowSAndRecoverable() {
        for (int i = 0; i < 50; i++) {
            byte[] h = Keccak.hash("message " + i);
            BigInteger key = AnvilTestKeys.key(i % 10);
            Secp256k1.Signature s = Secp256k1.sign(h, key);
            assertTrue(s.s().compareTo(Secp256k1.N.shiftRight(1)) <= 0);
            assertEquals(Optional.of(Secp256k1.address(key)), Secp256k1.recoverAddress(h, s));
            assertEquals(s, Secp256k1.Signature.fromBytes65(s.toBytes65()));
        }
    }

    @Test
    void highSSignatureIsRejected() {
        Secp256k1.Signature s = Secp256k1.sign(Keccak.hash("x"), AnvilTestKeys.key(0));
        // (r, n - s, flipped v) is the "other" valid ECDSA signature: EIP-2 forbids it.
        Secp256k1.Signature malleated = new Secp256k1.Signature(s.r(), Secp256k1.N.subtract(s.s()), 1 - s.recId());
        assertThrows(IllegalArgumentException.class, () -> Secp256k1.Signature.fromBytes65(malleated.toBytes65()));
    }

    @Test
    void malformedSignaturesAreRejected() {
        byte[] good = Secp256k1.sign(Keccak.hash("x"), AnvilTestKeys.key(0)).toBytes65();
        byte[] badV = good.clone();
        badV[64] = 29;
        assertThrows(IllegalArgumentException.class, () -> Secp256k1.Signature.fromBytes65(badV));
        byte[] zeroR = good.clone();
        java.util.Arrays.fill(zeroR, 0, 32, (byte) 0);
        assertThrows(IllegalArgumentException.class, () -> Secp256k1.Signature.fromBytes65(zeroR));
        assertThrows(IllegalArgumentException.class, () -> Secp256k1.Signature.fromBytes65(new byte[64]));
    }

    @Test
    void addressChecksum() {
        String a = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
        assertEquals(a, Address.parse(a.toLowerCase()));
        assertEquals(a, Address.parse("0x" + a.substring(2).toUpperCase()));
        assertThrows(IllegalArgumentException.class, () -> Address.parse("0x5fbDB2315678afecb367f032d93F642f64180aa3"));
        assertThrows(IllegalArgumentException.class, () -> Address.parse("0x1234"));
        assertThrows(IllegalArgumentException.class, () -> Address.parse("5FbDB2315678afecb367f032d93F642f64180aa3"));
    }
}
