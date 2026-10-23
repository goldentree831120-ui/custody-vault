package custody.orchestrator.crypto;

import java.util.Locale;
import java.util.regex.Pattern;

/** Ethereum addresses: validation and EIP-55 checksum formatting. */
public final class Address {
    private static final Pattern HEX40 = Pattern.compile("^0x[0-9a-fA-F]{40}$");

    private Address() {}

    /**
     * Parses an address and returns it checksummed. All-lowercase and all-uppercase input is
     * accepted; mixed case must match the checksum, because a wrong mixed-case address is usually
     * a typo.
     */
    public static String parse(String s) {
        if (s == null || !HEX40.matcher(s).matches()) throw new IllegalArgumentException("not an address: " + s);
        String body = s.substring(2);
        String out = checksum(s);
        boolean mixed = !body.equals(body.toLowerCase(Locale.ROOT)) && !body.equals(body.toUpperCase(Locale.ROOT));
        if (mixed && !out.equals(s)) throw new IllegalArgumentException("bad address checksum: " + s);
        return out;
    }

    public static String checksum(String s) {
        String lower = Hex.strip(s).toLowerCase(Locale.ROOT);
        if (lower.length() != 40) throw new IllegalArgumentException("not an address: " + s);
        String hash = Hex.encode(Keccak.hash(lower)).substring(2);
        StringBuilder sb = new StringBuilder("0x");
        for (int i = 0; i < 40; i++) {
            char c = lower.charAt(i);
            sb.append(Character.digit(hash.charAt(i), 16) >= 8 ? Character.toUpperCase(c) : c);
        }
        return sb.toString();
    }

    public static boolean same(String a, String b) {
        return a.equalsIgnoreCase(b);
    }
}
