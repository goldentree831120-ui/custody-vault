package custody.orchestrator.dev;

import static custody.orchestrator.dev.LocalVault.*;

import custody.orchestrator.Intents;
import custody.orchestrator.Intents.Cancellation;
import custody.orchestrator.Intents.Domain;
import custody.orchestrator.Intents.Intent;
import custody.orchestrator.Intents.WithdrawalApproval;
import custody.orchestrator.Intents.WithdrawalRequest;
import custody.orchestrator.NonceStore;
import custody.orchestrator.Orchestrator;
import custody.orchestrator.VaultCalls;
import custody.orchestrator.VaultClient;
import custody.orchestrator.api.HttpApi;
import custody.orchestrator.eth.Eip1559Tx;
import custody.orchestrator.eth.Json;
import custody.orchestrator.eth.JsonRpc;
import custody.orchestrator.hsm.AnvilTestKeys;
import custody.orchestrator.hsm.HsmSigner;
import custody.orchestrator.hsm.MockHsmSigner;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

/**
 * End-to-end run against a local Anvil chain, through the HTTP API, with a check after every step.
 * Approvers sign intents on "their own devices" (here: their test keys, in this process) and POST
 * them; the orchestrator does the rest. Throws on the first failed check.
 */
public final class Demo {
    private final JsonRpc rpc;
    private final PrintStream out;
    private final HttpClient http = HttpClient.newHttpClient();
    private final AtomicLong nonce = new AtomicLong(1);
    private Domain domain;
    private String base;
    private int checks;

    public Demo(JsonRpc rpc, PrintStream out) {
        this.rpc = rpc;
        this.out = out;
    }

    public record Result(int checks, String vault) {}

    public Result run(Path artifact) throws Exception {
        out.println("== setup: deploy a 2-of-3 vault on Anvil (1 h timelock from 5 ETH, 10 ETH/day), fund it with 100 ETH");
        String vault = deployAndConfigure(rpc, artifact);
        domain = new Domain(rpc.chainId(), vault);
        HsmSigner hsm = new MockHsmSigner(domain, approverBindings(), Clock.systemUTC());
        Orchestrator orch = new Orchestrator(domain, hsm, new VaultClient(rpc, vault, hsm),
                new NonceStore.InMemory(), Clock.systemUTC(), Orchestrator.Policy.defaults());
        HttpApi api = new HttpApi(orch, 0);
        api.start();
        base = "http://127.0.0.1:" + api.port();
        out.println("   vault " + vault + ", orchestrator on " + base + ", signer: " + hsm);
        String dest = address(DESTINATION_KEY);
        try {
            check("health", get("/health").get("signer").toString().contains("MOCK"));

            out.println("\n== 1. small withdrawal (1 ETH): approver A requests, approver B approves, execute at once");
            BigInteger before = balance(rpc, dest);
            Map<String, Object> r = post("/v1/intents", signed(0, request(dest, ONE_ETH)));
            BigInteger id = new BigInteger((String) r.get("proposalId"));
            check("A's request created proposal " + id + " with 1 of 2 approvals", "1".equals(r.get("approvals")));
            r = post("/v1/intents", signed(1, approval(id, dest, ONE_ETH)));
            check("B's approval reached the threshold (2 of 2)", "2".equals(r.get("approvals")));
            r = post("/v1/proposals/" + id + "/execute", null);
            check("executed: " + r.get("txHash"), "executed".equals(r.get("action")));
            check("destination received exactly 1 ETH", balance(rpc, dest).subtract(before).equals(ONE_ETH));

            out.println("\n== 2. large withdrawal (6 ETH): timelocked for 1 hour after the 2nd approval");
            BigInteger six = ONE_ETH.multiply(BigInteger.valueOf(6));
            id = idOf(post("/v1/intents", signed(0, request(dest, six))));
            post("/v1/intents", signed(2, approval(id, dest, six)));
            expectError("execute before the timelock", "/v1/proposals/" + id + "/execute", null, "NOT_READY");
            increaseTime(rpc, TIMELOCK_SECONDS + 1);
            out.println("   (chain time advanced by 1 hour)");
            before = balance(rpc, dest);
            post("/v1/proposals/" + id + "/execute", null);
            check("executed after the timelock; destination received 6 ETH", balance(rpc, dest).subtract(before).equals(six));

            out.println("\n== 3. what the orchestrator refuses");
            BigInteger two = ONE_ETH.multiply(BigInteger.TWO);
            id = idOf(post("/v1/intents", signed(0, request(dest, two))));
            Map<String, Object> approvalB = signed(1, approval(id, dest, two));
            expectError("approval for a different amount than the proposal", "/v1/intents",
                    signed(1, approval(id, dest, ONE_ETH)), "PROPOSAL_MISMATCH");
            post("/v1/intents", approvalB);
            expectError("the same signed approval sent again (replay)", "/v1/intents", approvalB, "NONCE_REUSED");
            expectError("withdrawal to a destination not on the allowlist", "/v1/intents",
                    signed(0, request(address(STRANGER_KEY), ONE_ETH)), "DESTINATION_NOT_ALLOWED");
            expectError("withdrawal above the daily limit (11 ETH)", "/v1/intents",
                    signed(0, request(dest, ONE_ETH.multiply(BigInteger.valueOf(11)))), "OVER_DAILY_LIMIT");
            expectError("intent signed by a key that isn't a registered approver", "/v1/intents",
                    Intents.toJson(Intents.sign(domain, request(dest, ONE_ETH), AnvilTestKeys.key(STRANGER_KEY))),
                    "UNKNOWN_APPROVER");
            expectError("intent signed for another vault (domain mismatch)", "/v1/intents",
                    Intents.toJson(Intents.sign(new Domain(domain.chainId(), address(DEPLOYER_KEY)),
                            request(dest, ONE_ETH), AnvilTestKeys.key(APPROVER_KEYS[0]))),
                    "UNKNOWN_APPROVER");
            long now = Clock.systemUTC().instant().getEpochSecond();
            expectError("expired intent", "/v1/intents",
                    signed(0, new WithdrawalRequest(ETH, dest, ONE_ETH, nextNonce(), now - 1)), "EXPIRED");
            expectError("intent valid for a week (the limit is 1 hour)", "/v1/intents",
                    signed(0, new WithdrawalRequest(ETH, dest, ONE_ETH, nextNonce(), now + 7 * 86400)), "DEADLINE_TOO_FAR");

            out.println("\n== 4. the signer doesn't trust the orchestrator");
            Intents.SignedIntent good = Intents.sign(domain, request(dest, ONE_ETH), AnvilTestKeys.key(APPROVER_KEYS[0]));
            byte[] evil = VaultCalls.proposeWithdrawal(ETH, address(STRANGER_KEY), ONE_ETH);
            checkRefused("valid intent, but calldata sends to another address", hsm, "owner-1", evil, Optional.of(good));
            checkRefused("A's intent used with B's key slot", hsm, "owner-2",
                    VaultCalls.proposeWithdrawal(ETH, dest, ONE_ETH), Optional.of(good));
            checkRefused("calldata other than execute() with no intent", hsm, "owner-1",
                    VaultCalls.approve(BigInteger.ONE), Optional.empty());

            out.println("\n== 5. any one owner can veto: approver C cancels a pending withdrawal");
            id = idOf(post("/v1/intents", signed(0, request(dest, ONE_ETH))));
            r = post("/v1/intents", signed(2, new Cancellation(id, nextNonce(), deadline())));
            check("cancelled", "cancelled".equals(get("/v1/proposals/" + id).get("state")));
            expectError("approving a cancelled proposal", "/v1/intents", signed(1, approval(id, dest, ONE_ETH)), "PROPOSAL_CLOSED");
        } finally {
            api.stop();
        }
        out.println("\nall " + checks + " checks passed");
        return new Result(checks, vault);
    }

    // ---- helpers --------------------------------------------------------------------------

    private long deadline() {
        return Clock.systemUTC().instant().getEpochSecond() + 600;
    }

    private BigInteger nextNonce() {
        return BigInteger.valueOf(nonce.getAndIncrement());
    }

    private WithdrawalRequest request(String to, BigInteger amount) {
        return new WithdrawalRequest(ETH, to, amount, nextNonce(), deadline());
    }

    private WithdrawalApproval approval(BigInteger id, String to, BigInteger amount) {
        return new WithdrawalApproval(id, ETH, to, amount, nextNonce(), deadline());
    }

    /** Approver 0, 1 or 2 (A, B, C) signs on their own device. */
    private Map<String, Object> signed(int approver, Intent intent) {
        return Intents.toJson(Intents.sign(domain, intent, AnvilTestKeys.key(APPROVER_KEYS[approver])));
    }

    private static BigInteger idOf(Map<String, Object> r) {
        return new BigInteger((String) r.get("proposalId"));
    }

    private void check(String what, boolean ok) {
        if (!ok) throw new AssertionError("CHECK FAILED: " + what);
        checks++;
        out.println("   ok  " + what);
    }

    private void checkRefused(String what, HsmSigner hsm, String slot, byte[] data, Optional<Intents.SignedIntent> auth) {
        Eip1559Tx tx = new Eip1559Tx(domain.chainId(), BigInteger.ZERO, BigInteger.ONE, BigInteger.TEN,
                BigInteger.valueOf(200_000), domain.vault(), BigInteger.ZERO, data);
        try {
            hsm.signTransaction(slot, tx, auth);
        } catch (HsmSigner.HsmRefusal e) {
            check("signer refused: " + what + " (" + e.getMessage() + ")", true);
            return;
        }
        throw new AssertionError("CHECK FAILED: signer signed " + what);
    }

    private void expectError(String what, String path, Map<String, Object> body, String code) throws Exception {
        HttpResponse<String> res = send(path, body);
        Map<String, Object> m = Json.parseObject(res.body());
        Object got = m.get("error") instanceof Map<?, ?> e ? e.get("code") : "success";
        if (!code.equals(got)) throw new AssertionError("CHECK FAILED: " + what + ": expected " + code + ", got " + res.body());
        check("refused " + what + " -> " + code, true);
    }

    private Map<String, Object> post(String path, Map<String, Object> body) throws Exception {
        HttpResponse<String> res = send(path, body);
        if (res.statusCode() != 200) throw new AssertionError("POST " + path + " failed: " + res.body());
        return Json.parseObject(res.body());
    }

    private Map<String, Object> get(String path) throws Exception {
        HttpResponse<String> res = http.send(HttpRequest.newBuilder(URI.create(base + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        if (res.statusCode() != 200) throw new AssertionError("GET " + path + " failed: " + res.body());
        return Json.parseObject(res.body());
    }

    private HttpResponse<String> send(String path, Map<String, Object> body) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(base + path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body == null ? "{}" : Json.write(body)))
                .build();
        return http.send(req, HttpResponse.BodyHandlers.ofString());
    }
}
