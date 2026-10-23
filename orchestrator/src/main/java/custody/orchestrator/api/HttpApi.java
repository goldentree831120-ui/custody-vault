package custody.orchestrator.api;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import custody.orchestrator.Intents;
import custody.orchestrator.Orchestrator;
import custody.orchestrator.Rejection;
import custody.orchestrator.eth.Json;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The orchestrator's HTTP API, on the JDK's built-in server. It binds to 127.0.0.1 only: it is an
 * internal service, and in a real deployment it would sit behind authenticated, TLS-terminating
 * infrastructure. Its security doesn't rest on the network, though: nothing happens without an
 * approver's signature.
 *
 * <pre>
 * GET  /health
 * GET  /v1/domain                      EIP-712 domain and types, for building intents
 * POST /v1/intents                     {"type", "message", "signature"}
 * GET  /v1/proposals/{id}
 * POST /v1/proposals/{id}/execute
 * GET  /v1/audit/head                  newest audit entry's seq and hash, for external anchoring
 * </pre>
 */
public final class HttpApi {
    private static final int MAX_BODY = 16 * 1024;
    private static final Pattern PROPOSAL = Pattern.compile("^/v1/proposals/(0|[1-9][0-9]{0,30})(/execute)?$");
    private static final System.Logger LOG = System.getLogger("http");

    private final HttpServer server;
    private final Orchestrator orchestrator;

    public HttpApi(Orchestrator orchestrator, int port) throws IOException {
        this.orchestrator = orchestrator;
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/", this::handle);
        server.setExecutor(Executors.newFixedThreadPool(4));
    }

    public void start() {
        server.start();
    }

    public void stop() {
        server.stop(0);
        ((java.util.concurrent.ExecutorService) server.getExecutor()).shutdownNow();
    }

    public int port() {
        return server.getAddress().getPort();
    }

    private void handle(HttpExchange ex) throws IOException {
        try (ex) {
            String path = ex.getRequestURI().getPath();
            String method = ex.getRequestMethod();
            try {
                if (path.equals("/health") && method.equals("GET")) {
                    reply(ex, 200, Map.of("status", "ok", "chainId", orchestrator.domain().chainId(),
                            "vault", orchestrator.domain().vault(), "signer", "MOCK HSM (test keys only)"));
                } else if (path.equals("/v1/domain") && method.equals("GET")) {
                    reply(ex, 200, domainJson());
                } else if (path.equals("/v1/audit/head") && method.equals("GET")) {
                    Map<String, Object> h = new LinkedHashMap<>();
                    orchestrator.audit().head().ifPresentOrElse(x -> {
                        h.put("seq", x.seq());
                        h.put("hash", x.hash());
                    }, () -> {
                        h.put("seq", 0);
                        h.put("hash", null);
                    });
                    reply(ex, 200, h);
                } else if (path.equals("/v1/intents") && method.equals("POST")) {
                    Map<String, Object> body = readJson(ex);
                    Intents.SignedIntent s;
                    try {
                        s = Intents.fromJson(body);
                    } catch (IllegalArgumentException | ArithmeticException e) {
                        throw new BadRequest(e.getMessage());
                    }
                    reply(ex, 200, orchestrator.submit(s).toJson());
                } else {
                    Matcher m = PROPOSAL.matcher(path);
                    if (m.matches() && m.group(2) == null && method.equals("GET")) {
                        reply(ex, 200, orchestrator.status(new BigInteger(m.group(1))));
                    } else if (m.matches() && m.group(2) != null && method.equals("POST")) {
                        reply(ex, 200, orchestrator.execute(new BigInteger(m.group(1))).toJson());
                    } else {
                        error(ex, 404, "NOT_FOUND", "no route " + method + " " + path);
                    }
                }
            } catch (Rejection r) {
                error(ex, r.code.httpStatus, r.code.name(), r.getMessage());
            } catch (BadRequest b) {
                error(ex, 400, "BAD_REQUEST", b.getMessage());
            } catch (RuntimeException e) {
                LOG.log(System.Logger.Level.ERROR, "unexpected error on " + method + " " + path, e);
                error(ex, 500, "INTERNAL", "internal error"); // never leak internals to the client
            }
        }
    }

    private static final class BadRequest extends RuntimeException {
        BadRequest(String m) {
            super(m);
        }
    }

    private static Map<String, Object> readJson(HttpExchange ex) throws IOException {
        String ct = ex.getRequestHeaders().getFirst("Content-Type");
        if (ct == null || !ct.toLowerCase().startsWith("application/json")) throw new BadRequest("Content-Type must be application/json");
        byte[] body;
        try (InputStream in = ex.getRequestBody()) {
            body = in.readNBytes(MAX_BODY + 1);
        }
        if (body.length > MAX_BODY) throw new BadRequest("body larger than " + MAX_BODY + " bytes");
        try {
            return Json.parseObject(new String(body, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            throw new BadRequest(e.getMessage());
        }
    }

    private Map<String, Object> domainJson() {
        Map<String, Object> domain = new LinkedHashMap<>();
        domain.put("name", Intents.DOMAIN_NAME);
        domain.put("version", Intents.DOMAIN_VERSION);
        domain.put("chainId", orchestrator.domain().chainId());
        domain.put("verifyingContract", orchestrator.domain().vault());
        Map<String, Object> types = new LinkedHashMap<>();
        types.put("WithdrawalRequest", fields("address asset", "address to", "uint256 amount", "uint256 nonce", "uint256 deadline"));
        types.put("WithdrawalApproval", fields("uint256 proposalId", "address asset", "address to", "uint256 amount",
                "uint256 nonce", "uint256 deadline"));
        types.put("Cancellation", fields("uint256 proposalId", "uint256 nonce", "uint256 deadline"));
        return Map.of("domain", domain, "types", types);
    }

    private static List<Map<String, String>> fields(String... defs) {
        return java.util.Arrays.stream(defs).map(d -> {
            String[] p = d.split(" ");
            Map<String, String> f = new LinkedHashMap<>();
            f.put("name", p[1]);
            f.put("type", p[0]);
            return f;
        }).toList();
    }

    private static void error(HttpExchange ex, int status, String code, String message) throws IOException {
        Map<String, Object> err = new LinkedHashMap<>();
        err.put("code", code);
        err.put("message", message);
        reply(ex, status, Map.of("error", err));
    }

    private static void reply(HttpExchange ex, int status, Object body) throws IOException {
        byte[] b = Json.write(body).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        ex.sendResponseHeaders(status, b.length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(b);
        }
    }
}
