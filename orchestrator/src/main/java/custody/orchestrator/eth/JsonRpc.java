package custody.orchestrator.eth;

import custody.orchestrator.crypto.Hex;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

/** A small Ethereum JSON-RPC client over java.net.http. */
public class JsonRpc {
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final URI uri;
    private final AtomicLong ids = new AtomicLong();

    public JsonRpc(String url) {
        this.uri = URI.create(url);
    }

    /** A JSON-RPC error. For reverts, {@code data} holds the revert bytes (custom error) when the node returns them. */
    public static final class RpcException extends RuntimeException {
        public final long code;
        public final String data;

        RpcException(long code, String message, String data) {
            super(message);
            this.code = code;
            this.data = data;
        }
    }

    public Object request(String method, Object... params) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("jsonrpc", "2.0");
        body.put("id", ids.incrementAndGet());
        body.put("method", method);
        body.put("params", List.of(params));
        HttpRequest req = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(Json.write(body)))
                .build();
        String text;
        try {
            HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
            text = res.body();
            if (res.statusCode() != 200 && !text.startsWith("{")) {
                throw new IOException("HTTP " + res.statusCode() + " from RPC");
            }
        } catch (IOException e) {
            throw new IllegalStateException("RPC " + method + " failed: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted", e);
        }
        Map<String, Object> res = Json.parseObject(text);
        if (res.get("error") instanceof Map<?, ?> err) {
            Object data = err.get("data");
            if (data instanceof Map<?, ?> m) data = m.get("data"); // some nodes nest it
            throw new RpcException(
                    ((Number) err.get("code")).longValue(),
                    String.valueOf(err.get("message")),
                    data instanceof String d ? d : null);
        }
        return res.get("result");
    }

    public long chainId() {
        return Hex.toBigInteger((String) request("eth_chainId")).longValueExact();
    }

    public BigInteger pendingNonce(String address) {
        return Hex.toBigInteger((String) request("eth_getTransactionCount", address, "pending"));
    }

    public byte[] call(String from, String to, byte[] data) {
        Map<String, Object> tx = new LinkedHashMap<>();
        if (from != null) tx.put("from", from);
        tx.put("to", to);
        tx.put("data", Hex.encode(data));
        return Hex.decode((String) request("eth_call", tx, "latest"));
    }

    public BigInteger estimateGas(String from, String to, byte[] data, BigInteger value) {
        Map<String, Object> tx = new LinkedHashMap<>();
        tx.put("from", from);
        if (to != null) tx.put("to", to);
        tx.put("data", Hex.encode(data));
        tx.put("value", Hex.fromBigInteger(value));
        return Hex.toBigInteger((String) request("eth_estimateGas", tx));
    }

    /** Latest block's base fee and timestamp. */
    @SuppressWarnings("unchecked")
    public Map<String, Object> latestBlock() {
        return (Map<String, Object>) request("eth_getBlockByNumber", "latest", false);
    }

    public BigInteger baseFee() {
        Object fee = latestBlock().get("baseFeePerGas");
        return fee == null ? BigInteger.ZERO : Hex.toBigInteger((String) fee);
    }

    public long latestTimestamp() {
        return Hex.toBigInteger((String) latestBlock().get("timestamp")).longValueExact();
    }

    public String sendRawTransaction(byte[] raw) {
        return (String) request("eth_sendRawTransaction", Hex.encode(raw));
    }

    @SuppressWarnings("unchecked")
    public Optional<Map<String, Object>> receipt(String txHash) {
        return Optional.ofNullable((Map<String, Object>) request("eth_getTransactionReceipt", txHash));
    }

    /** Polls until the transaction is mined. Anvil mines instantly; real chains take seconds. */
    public Map<String, Object> waitForReceipt(String txHash, Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (System.nanoTime() < deadline) {
            Optional<Map<String, Object>> r = receipt(txHash);
            if (r.isPresent()) return r.get();
            try {
                Thread.sleep(200);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("interrupted", e);
            }
        }
        throw new IllegalStateException("no receipt for " + txHash + " after " + timeout);
    }
}
