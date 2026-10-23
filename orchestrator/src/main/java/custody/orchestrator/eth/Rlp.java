package custody.orchestrator.eth;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.List;

/** Recursive Length Prefix encoding (encoder only: transactions are built here, never parsed). */
public final class Rlp {
    private Rlp() {}

    /** Items are byte[] or List of items. */
    public static byte[] encode(Object item) {
        if (item instanceof byte[] b) {
            if (b.length == 1 && (b[0] & 0xff) < 0x80) return b;
            return concat(header(0x80, b.length), b);
        }
        if (item instanceof List<?> list) {
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            for (Object o : list) body.writeBytes(encode(o));
            return concat(header(0xc0, body.size()), body.toByteArray());
        }
        throw new IllegalArgumentException("RLP item must be byte[] or List: " + item);
    }

    private static byte[] header(int offset, int len) {
        if (len < 56) return new byte[] {(byte) (offset + len)};
        byte[] l = BigInteger.valueOf(len).toByteArray();
        int start = l[0] == 0 ? 1 : 0;
        int n = l.length - start;
        byte[] out = new byte[1 + n];
        out[0] = (byte) (offset + 55 + n);
        System.arraycopy(l, start, out, 1, n);
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
