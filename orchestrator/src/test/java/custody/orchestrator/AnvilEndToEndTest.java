package custody.orchestrator;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import custody.orchestrator.dev.Demo;
import custody.orchestrator.eth.JsonRpc;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * The whole flow on a real local chain: starts Anvil, deploys the real CustodyVault (from
 * Foundry's build output), and runs {@link Demo} through the HTTP API.
 *
 * <p>Skipped if Anvil or the build output is missing, unless -DrequireAnvil=true (CI sets it,
 * so CI can't silently skip it).
 */
class AnvilEndToEndTest {
    static final Path ARTIFACT = Path.of("../out/CustodyVault.sol/CustodyVault.json");

    @Test
    void fullFlowOnAnvil() throws Exception {
        boolean required = Boolean.getBoolean("requireAnvil");
        boolean available = onPath("anvil") && Files.exists(ARTIFACT);
        if (required) assertTrue(available, "anvil and ../out (forge build) are required");
        assumeTrue(available, "anvil or ../out missing: skipping (run `forge build` in the repo root)");

        int port;
        try (ServerSocket s = new ServerSocket(0)) {
            port = s.getLocalPort();
        }
        Process anvil = new ProcessBuilder("anvil", "--port", Integer.toString(port), "--silent")
                .redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .start();
        try {
            JsonRpc rpc = new JsonRpc("http://127.0.0.1:" + port);
            waitForRpc(rpc);
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            PrintStream out = new PrintStream(buf, true, StandardCharsets.UTF_8);
            Demo.Result r = new Demo(rpc, out).run(ARTIFACT);
            System.out.print(buf.toString(StandardCharsets.UTF_8));
            assertEquals(20, r.checks());
        } finally {
            anvil.destroy();
            anvil.waitFor(5, TimeUnit.SECONDS);
        }
    }

    private static void waitForRpc(JsonRpc rpc) throws InterruptedException {
        for (int i = 0; i < 50; i++) {
            try {
                rpc.chainId();
                return;
            } catch (IllegalStateException e) {
                Thread.sleep(100);
            }
        }
        fail("anvil did not start");
    }

    private static boolean onPath(String exe) {
        for (String dir : System.getenv().getOrDefault("PATH", "").split(java.io.File.pathSeparator)) {
            if (Files.isExecutable(Path.of(dir, exe))) return true;
        }
        return false;
    }
}
