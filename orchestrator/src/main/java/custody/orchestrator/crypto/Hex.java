package custody.orchestrator.crypto;

import java.math.BigInteger;
import java.util.HexFormat;

/** Hex helpers. Accepts input with or without a 0x prefix; always produces lowercase with 0x. */
public final class Hex {
    private static final HexFormat HEX = HexFormat.of();

    private Hex() {}

    public static byte[] decode(String s) {
        String h = strip(s);
        if (h.length() % 2 == 1) h = "0" + h;
        return HEX.parseHex(h);
    }

    public static String encode(byte[] b) {
        return "0x" + HEX.formatHex(b);
    }

    public static String strip(String s) {
        if (s == null) throw new IllegalArgumentException("hex string is null");
        return s.startsWith("0x") || s.startsWith("0X") ? s.substring(2) : s;
    }

    public static BigInteger toBigInteger(String s) {
        String h = strip(s);
        return h.isEmpty() ? BigInteger.ZERO : new BigInteger(h, 16);
    }

    public static String fromBigInteger(BigInteger v) {
        return "0x" + v.toString(16);
    }

    /** Big-endian unsigned bytes of v, left-padded to exactly {@code len} bytes. */
    public static byte[] toBytesPadded(BigInteger v, int len) {
        if (v.signum() < 0) throw new IllegalArgumentException("negative value");
        byte[] raw = v.toByteArray();
        int start = raw.length > 1 && raw[0] == 0 ? 1 : 0;
        int n = raw.length - start;
        if (n > len) throw new IllegalArgumentException("value does not fit in " + len + " bytes");
        byte[] out = new byte[len];
        System.arraycopy(raw, start, out, len - n, n);
        return out;
    }

    /** Big-endian unsigned bytes with no leading zeros (empty for zero), as RLP wants. */
    public static byte[] toMinimalBytes(BigInteger v) {
        if (v.signum() < 0) throw new IllegalArgumentException("negative value");
        if (v.signum() == 0) return new byte[0];
        byte[] raw = v.toByteArray();
        if (raw[0] == 0) {
            byte[] out = new byte[raw.length - 1];
            System.arraycopy(raw, 1, out, 0, out.length);
            return out;
        }
        return raw;
    }
}
