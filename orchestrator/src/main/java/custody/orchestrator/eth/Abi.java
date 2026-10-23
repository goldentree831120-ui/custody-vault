package custody.orchestrator.eth;

import custody.orchestrator.crypto.Address;
import custody.orchestrator.crypto.Hex;
import custody.orchestrator.crypto.Keccak;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The small part of the Solidity ABI this service needs. Argument types come from the Java type:
 * String = address, BigInteger/Long/Integer = uint256, Boolean = bool, byte[] = bytes (dynamic),
 * String[] = address[] (dynamic).
 */
public final class Abi {
    private Abi() {}

    public static byte[] call(String signature, Object... args) {
        return concat(Keccak.selector(signature), encodeArgs(args));
    }

    public static byte[] encodeArgs(Object... args) {
        List<byte[]> heads = new ArrayList<>();
        List<byte[]> tails = new ArrayList<>();
        int headSize = 32 * args.length;
        int tailOffset = headSize;
        for (Object a : args) {
            if (a instanceof String[] addrs) {
                heads.add(uint(BigInteger.valueOf(tailOffset)));
                ByteArrayOutputStream t = new ByteArrayOutputStream();
                t.writeBytes(uint(BigInteger.valueOf(addrs.length)));
                for (String x : addrs) t.writeBytes(word(x));
                tails.add(t.toByteArray());
                tailOffset += t.size();
            } else if (a instanceof byte[] b) {
                heads.add(uint(BigInteger.valueOf(tailOffset)));
                byte[] t = concat(uint(BigInteger.valueOf(b.length)), padRight(b));
                tails.add(t);
                tailOffset += t.length;
            } else {
                heads.add(word(a));
            }
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        heads.forEach(out::writeBytes);
        tails.forEach(out::writeBytes);
        return out.toByteArray();
    }

    private static byte[] word(Object a) {
        if (a instanceof String s) return Hex.toBytesPadded(Hex.toBigInteger(Address.parse(s)), 32);
        if (a instanceof BigInteger v) return uint(v);
        if (a instanceof Long v) return uint(BigInteger.valueOf(v));
        if (a instanceof Integer v) return uint(BigInteger.valueOf(v));
        if (a instanceof Boolean v) return uint(v ? BigInteger.ONE : BigInteger.ZERO);
        throw new IllegalArgumentException("unsupported ABI argument: " + a);
    }

    public static byte[] uint(BigInteger v) {
        return Hex.toBytesPadded(v, 32);
    }

    private static byte[] padRight(byte[] b) {
        int len = (b.length + 31) / 32 * 32;
        return Arrays.copyOf(b, len);
    }

    // ---- decoding -------------------------------------------------------------------------

    public static BigInteger uintAt(byte[] data, int wordIndex) {
        int off = wordIndex * 32;
        if (data.length < off + 32) throw new IllegalArgumentException("ABI data too short");
        return new BigInteger(1, Arrays.copyOfRange(data, off, off + 32));
    }

    public static boolean boolAt(byte[] data, int wordIndex) {
        return uintAt(data, wordIndex).signum() != 0;
    }

    public static String addressAt(byte[] data, int wordIndex) {
        int off = wordIndex * 32;
        if (data.length < off + 32) throw new IllegalArgumentException("ABI data too short");
        return Address.checksum(Hex.encode(Arrays.copyOfRange(data, off + 12, off + 32)));
    }

    /** Dynamic bytes whose offset (in bytes, relative to {@code base}) is stored in word {@code wordIndex}. */
    public static byte[] bytesAt(byte[] data, int base, int wordIndex) {
        int off = base + uintAt(slice(data, base), wordIndex).intValueExact();
        int len = uintAt(slice(data, off), 0).intValueExact();
        return Arrays.copyOfRange(data, off + 32, off + 32 + len);
    }

    public static byte[] slice(byte[] data, int from) {
        return Arrays.copyOfRange(data, from, data.length);
    }

    public static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) out.writeBytes(p);
        return out.toByteArray();
    }
}
