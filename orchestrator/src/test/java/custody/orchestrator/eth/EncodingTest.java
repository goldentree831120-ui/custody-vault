package custody.orchestrator.eth;

import static org.junit.jupiter.api.Assertions.*;

import custody.orchestrator.crypto.Hex;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class EncodingTest {

    // ---- RLP (vectors from the Ethereum wiki / yellow paper appendix B) ------------------------

    @Test
    void rlpVectors() {
        assertEquals("0x83646f67", Hex.encode(Rlp.encode("dog".getBytes(StandardCharsets.US_ASCII))));
        assertEquals("0xc0", Hex.encode(Rlp.encode(List.of())));
        assertEquals("0x80", Hex.encode(Rlp.encode(new byte[0])));
        assertEquals("0x0f", Hex.encode(Rlp.encode(new byte[] {0x0f})));
        assertEquals("0x8180", Hex.encode(Rlp.encode(new byte[] {(byte) 0x80})));
        assertEquals("0xc88363617483646f67", Hex.encode(Rlp.encode(List.of(
                "cat".getBytes(StandardCharsets.US_ASCII), "dog".getBytes(StandardCharsets.US_ASCII)))));
        byte[] lorem = "Lorem ipsum dolor sit amet, consectetur adipisicing elit".getBytes(StandardCharsets.US_ASCII);
        assertEquals(56, lorem.length);
        assertEquals("0xb838", Hex.encode(Rlp.encode(lorem)).substring(0, 6));
        // [ [], [[]], [ [], [[]] ] ]
        assertEquals("0xc7c0c1c0c3c0c1c0", Hex.encode(Rlp.encode(List.of(List.of(), List.of(List.of()),
                List.of(List.of(), List.of(List.of()))))));
    }

    @Test
    void minimalIntegerBytes() {
        assertEquals(0, Hex.toMinimalBytes(BigInteger.ZERO).length);
        assertEquals("0x0400", Hex.encode(Hex.toMinimalBytes(BigInteger.valueOf(1024))));
        assertEquals("0xff", Hex.encode(Hex.toMinimalBytes(BigInteger.valueOf(255))));
        assertThrows(IllegalArgumentException.class, () -> Hex.toBytesPadded(BigInteger.TWO.pow(256), 32));
    }

    // ---- ABI ---------------------------------------------------------------------------------

    @Test
    void abiStaticAndDynamicArguments() {
        // Same as `cast abi-encode "f(bytes)" 0xdeadbeef`
        byte[] d = Abi.encodeArgs((Object) new byte[] {(byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef});
        assertEquals("0x"
                + "0000000000000000000000000000000000000000000000000000000000000020"
                + "0000000000000000000000000000000000000000000000000000000000000004"
                + "deadbeef00000000000000000000000000000000000000000000000000000000", Hex.encode(d));

        byte[] arr = Abi.encodeArgs(new String[] {"0x0000000000000000000000000000000000000001",
                "0x0000000000000000000000000000000000000002"}, BigInteger.TWO);
        assertEquals(BigInteger.valueOf(64), Abi.uintAt(arr, 0)); // offset of the array
        assertEquals(BigInteger.TWO, Abi.uintAt(arr, 1));
        assertEquals(BigInteger.TWO, Abi.uintAt(arr, 2)); // length
        assertEquals("0x0000000000000000000000000000000000000002", Abi.addressAt(arr, 4));
    }

    // ---- JSON --------------------------------------------------------------------------------

    @Test
    void jsonRoundTrip() {
        String text = "{\"a\":[1,true,null,\"x\\n\\\"y\\u0041\"],\"b\":{\"c\":\"0x01\"}}";
        Map<String, Object> m = Json.parseObject(text);
        assertEquals("x\n\"yA", ((List<?>) m.get("a")).get(3));
        assertEquals(m, Json.parseObject(Json.write(m)));
    }

    @Test
    void jsonRejectsMalformedInput() {
        for (String bad : List.of("", "{", "{\"a\":1,}", "{\"a\":1}x", "{\"a\":1,\"a\":2}", "[1,2", "{\"a\":tru}",
                "\"unterminated", "{\"a\":\"\u0001\"}", "[" .repeat(100) + "]".repeat(100))) {
            assertThrows(IllegalArgumentException.class, () -> Json.parse(bad), bad);
        }
    }
}
