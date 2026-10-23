package custody.orchestrator.eth;

import custody.orchestrator.crypto.Hex;
import custody.orchestrator.crypto.Keccak;
import custody.orchestrator.crypto.Secp256k1;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/** An unsigned EIP-1559 (type 2) transaction. No access list. */
public record Eip1559Tx(
        long chainId,
        BigInteger nonce,
        BigInteger maxPriorityFeePerGas,
        BigInteger maxFeePerGas,
        BigInteger gasLimit,
        String to,
        BigInteger value,
        byte[] data) {

    private List<Object> fields() {
        List<Object> f = new ArrayList<>();
        f.add(Hex.toMinimalBytes(BigInteger.valueOf(chainId)));
        f.add(Hex.toMinimalBytes(nonce));
        f.add(Hex.toMinimalBytes(maxPriorityFeePerGas));
        f.add(Hex.toMinimalBytes(maxFeePerGas));
        f.add(Hex.toMinimalBytes(gasLimit));
        f.add(to == null ? new byte[0] : Hex.decode(to));
        f.add(Hex.toMinimalBytes(value));
        f.add(data);
        f.add(List.of()); // access list
        return f;
    }

    /** keccak(0x02 || rlp(fields)): the hash the sender's key signs. */
    public byte[] signingHash() {
        return Keccak.hash(new byte[] {0x02}, Rlp.encode(fields()));
    }

    /** 0x02 || rlp(fields ++ [yParity, r, s]): what eth_sendRawTransaction takes. */
    public byte[] encodeSigned(Secp256k1.Signature sig) {
        List<Object> f = fields();
        f.add(Hex.toMinimalBytes(BigInteger.valueOf(sig.recId())));
        f.add(Hex.toMinimalBytes(sig.r()));
        f.add(Hex.toMinimalBytes(sig.s()));
        byte[] rlp = Rlp.encode(f);
        byte[] out = new byte[rlp.length + 1];
        out[0] = 0x02;
        System.arraycopy(rlp, 0, out, 1, rlp.length);
        return out;
    }
}
