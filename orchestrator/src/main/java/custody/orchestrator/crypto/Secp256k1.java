package custody.orchestrator.crypto;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Optional;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

/**
 * secp256k1 signing and public-key recovery as Ethereum uses them.
 *
 * <p>The ECDSA itself comes from Bouncy Castle; this class adds the Ethereum conventions: RFC 6979
 * deterministic nonces, low-s signatures (EIP-2), a recovery id, and addresses as the last 20 bytes
 * of keccak(pubkey).
 */
public final class Secp256k1 {
    private static final X9ECParameters PARAMS = CustomNamedCurves.getByName("secp256k1");
    static final ECDomainParameters CURVE =
            new ECDomainParameters(PARAMS.getCurve(), PARAMS.getG(), PARAMS.getN(), PARAMS.getH());
    static final BigInteger N = PARAMS.getN();
    private static final BigInteger HALF_N = N.shiftRight(1);

    private Secp256k1() {}

    /** r, s and recovery id (0 or 1). {@code s} is always in the lower half of the curve order. */
    public record Signature(BigInteger r, BigInteger s, int recId) {
        /** 65-byte r || s || v with v = 27 + recId, the form wallets produce for signed messages. */
        public byte[] toBytes65() {
            byte[] out = new byte[65];
            System.arraycopy(Hex.toBytesPadded(r, 32), 0, out, 0, 32);
            System.arraycopy(Hex.toBytesPadded(s, 32), 0, out, 32, 32);
            out[64] = (byte) (27 + recId);
            return out;
        }

        /** Parses r || s || v. Accepts v as 27/28 or 0/1; rejects high-s and out-of-range values. */
        public static Signature fromBytes65(byte[] b) {
            if (b.length != 65) throw new IllegalArgumentException("signature must be 65 bytes");
            BigInteger r = new BigInteger(1, Arrays.copyOfRange(b, 0, 32));
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(b, 32, 64));
            int v = b[64] & 0xff;
            int recId = v >= 27 ? v - 27 : v;
            if (recId != 0 && recId != 1) throw new IllegalArgumentException("invalid v");
            if (r.signum() <= 0 || r.compareTo(N) >= 0) throw new IllegalArgumentException("invalid r");
            // EIP-2: a high-s signature is a second valid encoding of the same signature (malleability).
            if (s.signum() <= 0 || s.compareTo(HALF_N) > 0) throw new IllegalArgumentException("invalid s (high-s)");
            return new Signature(r, s, recId);
        }
    }

    public static Signature sign(byte[] hash32, BigInteger privateKey) {
        if (hash32.length != 32) throw new IllegalArgumentException("hash must be 32 bytes");
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, new ECPrivateKeyParameters(privateKey, CURVE));
        BigInteger[] rs = signer.generateSignature(hash32);
        BigInteger r = rs[0];
        BigInteger s = rs[1];
        if (s.compareTo(HALF_N) > 0) s = N.subtract(s);

        byte[] expected = publicKeyBytes(privateKey);
        for (int recId = 0; recId < 2; recId++) {
            Optional<byte[]> pub = recoverPublicKey(hash32, r, s, recId);
            if (pub.isPresent() && Arrays.equals(pub.get(), expected)) return new Signature(r, s, recId);
        }
        throw new IllegalStateException("could not compute recovery id");
    }

    /** Returns the 20-byte address that produced the signature, or empty if it can't be recovered. */
    public static Optional<String> recoverAddress(byte[] hash32, Signature sig) {
        return recoverPublicKey(hash32, sig.r(), sig.s(), sig.recId()).map(Secp256k1::addressOfPublicKey);
    }

    public static String address(BigInteger privateKey) {
        return addressOfPublicKey(publicKeyBytes(privateKey));
    }

    /** 64-byte uncompressed public key without the 0x04 prefix. */
    static byte[] publicKeyBytes(BigInteger privateKey) {
        if (privateKey.signum() <= 0 || privateKey.compareTo(N) >= 0) throw new IllegalArgumentException("invalid private key");
        ECPoint q = new FixedPointCombMultiplier().multiply(CURVE.getG(), privateKey).normalize();
        byte[] enc = q.getEncoded(false);
        return Arrays.copyOfRange(enc, 1, 65);
    }

    static String addressOfPublicKey(byte[] pub64) {
        byte[] h = Keccak.hash(pub64);
        return Address.checksum(Hex.encode(Arrays.copyOfRange(h, 12, 32)));
    }

    /** SEC 1 v2, section 4.1.6. Only x = r (j = 0) is tried; r >= p - n is practically impossible. */
    private static Optional<byte[]> recoverPublicKey(byte[] hash32, BigInteger r, BigInteger s, int recId) {
        BigInteger p = PARAMS.getCurve().getField().getCharacteristic();
        if (r.compareTo(p) >= 0) return Optional.empty();
        ECPoint bigR;
        try {
            byte[] compressed = new byte[33];
            compressed[0] = (byte) (recId == 1 ? 0x03 : 0x02);
            System.arraycopy(Hex.toBytesPadded(r, 32), 0, compressed, 1, 32);
            bigR = CURVE.getCurve().decodePoint(compressed);
        } catch (IllegalArgumentException e) {
            return Optional.empty(); // x is not on the curve
        }
        if (!bigR.multiply(N).isInfinity()) return Optional.empty();

        BigInteger e = new BigInteger(1, hash32);
        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(N);
        BigInteger rInv = r.modInverse(N);
        BigInteger srInv = rInv.multiply(s).mod(N);
        BigInteger eInvrInv = rInv.multiply(eInv).mod(N);
        ECPoint q = ECAlgorithms.sumOfTwoMultiplies(CURVE.getG(), eInvrInv, bigR, srInv).normalize();
        if (q.isInfinity()) return Optional.empty();
        byte[] enc = q.getEncoded(false);
        return Optional.of(Arrays.copyOfRange(enc, 1, 65));
    }
}
