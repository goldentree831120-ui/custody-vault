package custody.orchestrator.api;

import static org.junit.jupiter.api.Assertions.*;

import custody.orchestrator.Chain;
import custody.orchestrator.Intents;
import custody.orchestrator.Intents.Domain;
import custody.orchestrator.NonceStore;
import custody.orchestrator.Orchestrator;
import custody.orchestrator.eth.Json;
import custody.orchestrator.hsm.HsmSigner;
import custody.orchestrator.hsm.MockHsmSigner;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The HTTP layer: routing, input limits and the error shape. The orchestrator's logic is tested elsewhere. */
class HttpApiTest {
    static final String VAULT = "0x5FbDB2315678afecb367f032d93F642f64180aa3";

    HttpApi api;
    String base;
    final HttpClient http = HttpClient.newHttpClient();
    boolean explode;

    @BeforeEach
    void setUp() throws Exception {
        Domain domain = new Domain(31337, VAULT);
        HsmSigner hsm = new MockHsmSigner(domain, Map.of(), Clock.systemUTC());
        Chain chain = new Chain() {
            public long chainId() { return 31337; }
            public long chainTime() { return 0; }
            public boolean isOwner(String a) { return false; }
            public boolean paused() { return false; }
            public boolean isAllowedDestination(String to) { return false; }
            public BigInteger dailyLimit(String asset) { return BigInteger.ZERO; }
            public BigInteger availableToWithdraw(String asset) { return BigInteger.ZERO; }
            public Optional<Proposal> proposal(BigInteger id) {
                if (explode) throw new IllegalStateException("secret internal detail: rpc key abc123");
                return Optional.empty();
            }
            public boolean hasApproved(BigInteger id, String owner) { return false; }
            public BigInteger approvalCount(BigInteger id) { return BigInteger.ZERO; }
            public BigInteger threshold() { return BigInteger.TWO; }
            public BigInteger executableAt(BigInteger id) { return BigInteger.ZERO; }
            public void simulate(String from, byte[] calldata) {}
            public Receipt send(String keySlot, byte[] calldata, Optional<Intents.SignedIntent> a) {
                throw new AssertionError("must not send");
            }
        };
        Orchestrator orch = new Orchestrator(domain, hsm, chain, new NonceStore.InMemory(), Clock.systemUTC(),
                Orchestrator.Policy.defaults());
        api = new HttpApi(orch, 0);
        api.start();
        base = "http://127.0.0.1:" + api.port();
    }

    @AfterEach
    void tearDown() {
        api.stop();
    }

    HttpResponse<String> call(String method, String path, String contentType, String body) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path));
        if (contentType != null) b.header("Content-Type", contentType);
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    static String code(HttpResponse<String> r) {
        return (String) ((Map<?, ?>) Json.parseObject(r.body()).get("error")).get("code");
    }

    @Test
    void healthAndDomain() throws Exception {
        HttpResponse<String> r = call("GET", "/health", null, null);
        assertEquals(200, r.statusCode());
        assertTrue(r.body().contains("MOCK HSM"));
        assertEquals("no-store", r.headers().firstValue("Cache-Control").orElse(""));

        Map<String, Object> d = Json.parseObject(call("GET", "/v1/domain", null, null).body());
        Map<?, ?> domain = (Map<?, ?>) d.get("domain");
        assertEquals(Intents.DOMAIN_NAME, domain.get("name"));
        assertEquals(VAULT, domain.get("verifyingContract"));
        assertEquals(6, ((List<?>) ((Map<?, ?>) d.get("types")).get("WithdrawalApproval")).size());
    }

    @Test
    void inputIsValidated() throws Exception {
        HttpResponse<String> r = call("POST", "/v1/intents", "text/plain", "{}");
        assertEquals(400, r.statusCode());
        assertEquals("BAD_REQUEST", code(r));

        r = call("POST", "/v1/intents", "application/json", "{not json");
        assertEquals(400, r.statusCode());

        r = call("POST", "/v1/intents", "application/json", "{\"type\":\"WithdrawalRequest\"}");
        assertEquals(400, r.statusCode());

        r = call("POST", "/v1/intents", "application/json", "{\"pad\":\"" + "x".repeat(20_000) + "\"}");
        assertEquals(400, r.statusCode());
        assertTrue(r.body().contains("larger than"));
    }

    @Test
    void unknownRoutesAndMethods() throws Exception {
        assertEquals(404, call("GET", "/v1/intents", null, null).statusCode());
        assertEquals(404, call("DELETE", "/v1/proposals/1", null, null).statusCode());
        assertEquals(404, call("GET", "/v1/proposals/01", null, null).statusCode());
        assertEquals(404, call("GET", "/v1/proposals/-1", null, null).statusCode());
        HttpResponse<String> r = call("GET", "/v1/proposals/5", null, null);
        assertEquals(404, r.statusCode());
        assertEquals("UNKNOWN_PROPOSAL", code(r));
    }

    @Test
    void internalErrorsDontLeakDetails() throws Exception {
        explode = true;
        HttpResponse<String> r = call("GET", "/v1/proposals/1", null, null);
        assertEquals(500, r.statusCode());
        assertEquals("INTERNAL", code(r));
        assertFalse(r.body().contains("abc123"));
    }
}
