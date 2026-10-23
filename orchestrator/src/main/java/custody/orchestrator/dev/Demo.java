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
import custody.orchestrator.audit.AuditLog;
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
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
        // Kept after the run (target/ is git-ignored) so it can be inspected and re-verified.
        Path auditDir = Files.createDirectories(Path.of("target", "demo-audit"));
        for (String f : new String[] {"audit.log", "audit.anchors", "tampered.log", "cut.log"}) {
            Files.deleteIfExists(auditDir.resolve(f));
        }
        Path auditLog = auditDir.resolve("audit.log");
        Path anchors = auditDir.resolve("audit.anchors");
        AuditLog audit = AuditLog.open(auditLog, anchors, Clock.systemUTC(), 5);
        Orchestrator orch = new Orchestrator(domain, hsm, new VaultClient(rpc, vault, hsm),
                new NonceStore.InMemory(), Clock.systemUTC(), Orchestrator.Policy.defaults(), audit);
        audit.record("service.started", Map.of("vault", vault, "chainId", Long.toString(domain.chainId()), "signer", hsm.toString()));
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

        out.println("\n== 6. the audit log (" + auditLog.toAbsolutePath() + ")");
        audit.anchor();
        auditChecks(auditLog, anchors, auditDir);
        out.println("\nall " + checks + " checks passed");
        return new Result(checks, vault);
    }

    /** The log's own checks, then five ways of tampering with a copy of it. */
    private void auditChecks(Path log, Path anchors, Path dir) throws Exception {
        AuditLog.Result r = AuditLog.verify(log, anchors);
        check("verifies: " + r.summary(), r.ok());

        List<String> lines = Files.readAllLines(log);
        Map<String, Integer> counts = new TreeMap<>();
        int signed = 0, mined = 0, signersMatch = 0, received = 0;
        for (String line : lines) {
            Map<String, Object> e = Json.parseObject(line);
            String ev = (String) e.get("event");
            counts.merge(ev, 1, Integer::sum);
            if (ev.equals("sign.requested")) signed++;
            if (ev.equals("tx.mined")) mined++;
            if (ev.equals("intent.received")) {
                received++;
                @SuppressWarnings("unchecked")
                Map<String, Object> d = (Map<String, Object>) e.get("data");
                @SuppressWarnings("unchecked")
                Intents.SignedIntent si = Intents.fromJson((Map<String, Object>) d.get("intent"));
                if (Objects.equals(si.signer(domain).orElse(null), d.get("signer"))) signersMatch++;
            }
        }
        out.println("   events: " + counts);
        check("every transaction has a sign.requested entry written before it (" + signed + " signed, " + mined + " mined)",
                signed == mined && signed == 10);
        check("every logged intent still carries a signature that recovers to the logged approver ("
                + signersMatch + "/" + received + ")", signersMatch == received && received > 0);

        // Tampering, each on a fresh copy.
        String target = lines.stream().filter(l -> l.contains("\"intent.received\"") && l.contains("\"1000000000000000000\""))
                .findFirst().orElseThrow();
        int t = lines.indexOf(target);
        tamper(dir, "an amount edited in one entry", anchors, copyWith(lines, t, target.replace("\"1000000000000000000\"", "\"9000000000000000000\"")));
        List<String> deleted = new ArrayList<>(lines);
        deleted.remove(t);
        tamper(dir, "one entry deleted", anchors, deleted);
        List<String> swapped = new ArrayList<>(lines);
        Collections.swap(swapped, t, t + 1);
        tamper(dir, "two entries swapped", anchors, swapped);
        List<String> cut = new ArrayList<>(lines.subList(0, lines.size() - 3));
        Path emptyAnchors = dir.resolve("none.anchors");
        Path cutLog = write(dir, "cut.log", cut);
        check("cutting off the last 3 entries is NOT detected by the chain alone: "
                + AuditLog.verify(cutLog, emptyAnchors).summary().replaceAll(", head.*", ""), AuditLog.verify(cutLog, emptyAnchors).ok());
        tamper(dir, "the last 3 entries cut off (caught by the anchor)", anchors, cut);
        tamper(dir, "the whole chain rebuilt after an edit (caught by the anchor)", anchors, rechain(copyWith(lines, t,
                target.replace("\"1000000000000000000\"", "\"9000000000000000000\""))));
    }

    private static List<String> copyWith(List<String> lines, int i, String replacement) {
        List<String> c = new ArrayList<>(lines);
        c.set(i, replacement);
        return c;
    }

    /** What an attacker with write access to the log could do: recompute every prev/hash. */
    @SuppressWarnings("unchecked")
    private static List<String> rechain(List<String> lines) {
        List<String> out = new ArrayList<>();
        String prev = AuditLog.GENESIS;
        for (String l : lines) {
            Map<String, Object> e = Json.parseObject(l);
            e.remove("hash");
            e.put("prev", prev);
            prev = AuditLog.hashOf(e);
            e.put("hash", prev);
            out.add(Json.write(e));
        }
        return out;
    }

    private static Path write(Path dir, String name, List<String> lines) throws Exception {
        Path p = dir.resolve(name);
        Files.writeString(p, String.join("\n", lines) + "\n");
        return p;
    }

    private void tamper(Path dir, String what, Path anchors, List<String> lines) throws Exception {
        AuditLog.Result r = AuditLog.verify(write(dir, "tampered.log", lines), anchors);
        if (r.ok()) throw new AssertionError("CHECK FAILED: tampering not detected: " + what);
        check("detected " + what + " -> " + r.problem(), true);
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
