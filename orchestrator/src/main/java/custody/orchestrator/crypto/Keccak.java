package custody.orchestrator.crypto;

import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.digests.KeccakDigest;

/** Ethereum's Keccak-256 (the original Keccak padding, not NIST SHA3-256). */
public final class Keccak {
    private Keccak() {}

    public static byte[] hash(byte[]... parts) {
        KeccakDigest d = new KeccakDigest(256);
        for (byte[] p : parts) d.update(p, 0, p.length);
        byte[] out = new byte[32];
        d.doFinal(out, 0);
        return out;
    }

    public static byte[] hash(String utf8) {
        return hash(utf8.getBytes(StandardCharsets.UTF_8));
    }

    /** First 4 bytes of keccak(signature), e.g. "approve(uint256)". */
    public static byte[] selector(String signature) {
        byte[] h = hash(signature);
        return new byte[] {h[0], h[1], h[2], h[3]};
    }
}
