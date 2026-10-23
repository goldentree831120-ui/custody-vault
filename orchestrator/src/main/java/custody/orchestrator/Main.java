package custody.orchestrator;

import custody.orchestrator.api.HttpApi;
import custody.orchestrator.audit.AuditLog;
import custody.orchestrator.dev.Demo;
import custody.orchestrator.dev.LocalVault;
import custody.orchestrator.eth.JsonRpc;
import custody.orchestrator.hsm.MockHsmSigner;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

/**
 * {@code demo}: deploy a vault on a running local Anvil and run the end-to-end scenario.
 * {@code serve}: deploy a vault on a running local Anvil and keep the API running for manual use.
 *
 * <p>Environment: RPC_URL (default http://127.0.0.1:8545), PORT (default 8088, serve only),
 * ARTIFACT (default ../out/CustodyVault.sol/CustodyVault.json); serve only: NONCE_FILE, AUDIT_LOG,
 * AUDIT_ANCHORS (defaults: files named after the vault address in the current directory).
 *
 * <p>{@code verify <audit.log> [<anchors>]}: check an audit log's hash chain and anchors; exit 1 if broken.
 */
public final class Main {
    public static void main(String[] args) throws Exception {
        if (System.getProperty("java.util.logging.SimpleFormatter.format") == null) {
            System.setProperty("java.util.logging.SimpleFormatter.format", "%4$s %3$s: %5$s%n"); // one line per log
        }
        String cmd = args.length > 0 ? args[0] : "demo";
        if (cmd.equals("verify")) {
            verify(args);
            return;
        }
        JsonRpc rpc = new JsonRpc(env("RPC_URL", "http://127.0.0.1:8545"));
        Path artifact = Path.of(env("ARTIFACT", "../out/CustodyVault.sol/CustodyVault.json"));
        switch (cmd) {
            case "demo" -> new Demo(rpc, System.out).run(artifact);
            case "serve" -> serve(rpc, artifact);
            default -> {
                System.err.println("usage: Main demo | serve | verify <audit.log> [<anchors.log>]");
                System.exit(2);
            }
        }
    }

    private static void serve(JsonRpc rpc, Path artifact) throws Exception {
        String vault = LocalVault.deployAndConfigure(rpc, artifact);
        Intents.Domain domain = new Intents.Domain(rpc.chainId(), vault);
        MockHsmSigner hsm = new MockHsmSigner(domain, LocalVault.approverBindings(), Clock.systemUTC());
        Orchestrator orch = new Orchestrator(domain, hsm, new VaultClient(rpc, vault, hsm),
                new NonceStore.FileBacked(Path.of(env("NONCE_FILE", "used-nonces-" + vault + ".txt"))),
                Clock.systemUTC(), Orchestrator.Policy.defaults(),
                AuditLog.open(Path.of(env("AUDIT_LOG", "audit-" + vault + ".log")),
                        Path.of(env("AUDIT_ANCHORS", "audit-" + vault + ".anchors")), Clock.systemUTC(), 10));
        orch.audit().record("service.started", Map.of("vault", vault, "chainId", Long.toString(domain.chainId()),
                "signer", hsm.toString()));
        HttpApi api = new HttpApi(orch, Integer.parseInt(env("PORT", "8088")));
        api.start();
        System.out.println("vault " + vault + "; orchestrator on http://127.0.0.1:" + api.port() + " (Ctrl+C to stop)");
        CountDownLatch stop = new CountDownLatch(1);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            api.stop();
            stop.countDown();
        }));
        stop.await();
    }

    /** Exit code 0 if the log and its anchors verify, 1 if not. */
    private static void verify(String[] args) {
        if (args.length < 2) {
            System.err.println("usage: Main verify <audit.log> [<anchors.log>]");
            System.exit(2);
        }
        Path log = Path.of(args[1]);
        Path anchors = args.length > 2 ? Path.of(args[2]) : Path.of(args[1].replaceFirst("\\.log$", "") + ".anchors");
        AuditLog.Result r = AuditLog.verify(log, anchors);
        System.out.println(log + ": " + r.summary());
        System.exit(r.ok() ? 0 : 1);
    }

    private static String env(String k, String dflt) {
        String v = System.getenv(k);
        return v == null || v.isBlank() ? dflt : v;
    }
}
