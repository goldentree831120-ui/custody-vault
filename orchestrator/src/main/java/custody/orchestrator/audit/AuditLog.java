package custody.orchestrator.audit;

import custody.orchestrator.crypto.Hex;
import custody.orchestrator.eth.Json;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * An append-only, hash-chained audit log in JSON Lines.
 *
 * <pre>
 * {"seq":1,"time":"...","event":"service.started","data":{...},"prev":"0x00…00","hash":"0x…"}
 * {"seq":2,"time":"...","event":"intent.received","data":{...},"prev":"&lt;hash of 1&gt;","hash":"0x…"}
 * </pre>
 *
 * <p>{@code hash = SHA-256("custody-audit-v1\n" || the entry without its hash field)}, and the entry
 * includes {@code prev}, the previous entry's hash. Changing, deleting, inserting or reordering any
 * entry therefore breaks the chain at that point, and {@link #verify} reports where.
 *
 * <p>What a chain alone can't detect: someone who can rewrite the file can cut entries off the end,
 * or rebuild the whole chain with different content. So every {@code anchorEvery} entries the head
 * (seq + hash) is also written to a separate <b>anchor</b> file, which in production belongs on
 * storage the log's host can't rewrite (WORM storage, another party, a public chain). Verification
 * then checks that every anchored head is still in the log.
 */
public final class AuditLog implements Audit {
    public static final String GENESIS = "0x" + "0".repeat(64);
    private static final byte[] DOMAIN = "custody-audit-v1\n".getBytes(StandardCharsets.UTF_8);

    private final Path file;
    private final Path anchorFile;
    private final Clock clock;
    private final int anchorEvery;
    private long seq;
    private String head;

    private AuditLog(Path file, Path anchorFile, Clock clock, int anchorEvery, long seq, String head) {
        this.file = file;
        this.anchorFile = anchorFile;
        this.clock = clock;
        this.anchorEvery = anchorEvery;
        this.seq = seq;
        this.head = head;
    }

    /**
     * Opens (or creates) a log. An existing log is verified first, with its anchors; if it fails,
     * this throws and the service doesn't start: a tampered log is a reason to stop, not to append.
     */
    public static AuditLog open(Path file, Path anchorFile, Clock clock, int anchorEvery) {
        if (anchorEvery < 1) throw new IllegalArgumentException("anchorEvery must be >= 1");
        Result r = verify(file, anchorFile);
        if (!r.ok()) throw new IllegalStateException("audit log failed verification, refusing to start: " + r.problem());
        return new AuditLog(file, anchorFile, clock, anchorEvery, r.entries(), r.headHash());
    }

    @Override
    public synchronized void record(String event, Map<String, Object> data) {
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("seq", seq + 1);
        e.put("time", clock.instant().toString());
        e.put("event", event);
        e.put("data", data);
        e.put("prev", head);
        // Normalise through the parser so the stored line is exactly what verify() will rebuild.
        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) Json.parse(Json.write(e));
        String hash = hashOf(body);
        body.put("hash", hash);
        append(file, Json.write(body));
        seq++;
        head = hash;
        if (seq % anchorEvery == 0) anchor();
    }

    /** Writes the current head to the anchor file now (also done every {@code anchorEvery} entries). */
    public synchronized void anchor() {
        if (seq == 0) return;
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("seq", seq);
        a.put("hash", head);
        a.put("time", clock.instant().toString());
        append(anchorFile, Json.write(a));
    }

    @Override
    public synchronized Optional<Head> head() {
        return seq == 0 ? Optional.empty() : Optional.of(new Head(seq, head));
    }

    private static void append(Path p, String line) {
        try (FileChannel ch = FileChannel.open(p, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND)) {
            ByteBuffer b = ByteBuffer.wrap((line + "\n").getBytes(StandardCharsets.UTF_8));
            while (b.hasRemaining()) ch.write(b);
            ch.force(true); // on disk before the caller goes on (e.g. before signing)
        } catch (IOException ex) {
            throw new UncheckedIOException("cannot append to " + p, ex);
        }
    }

    /** The hash of an entry (without its "hash" field). Public so tools and tests can rebuild a chain. */
    public static String hashOf(Map<String, Object> entryWithoutHash) {
        try {
            MessageDigest d = MessageDigest.getInstance("SHA-256");
            d.update(DOMAIN);
            d.update(Json.write(entryWithoutHash).getBytes(StandardCharsets.UTF_8));
            return Hex.encode(d.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    // ---- verification ---------------------------------------------------------------------

    /**
     * @param problem empty if ok; otherwise the first problem found, naming the line
     */
    public record Result(boolean ok, long entries, String headHash, long anchorsChecked, String problem) {
        public String summary() {
            return ok ? entries + " entries, chain intact, " + anchorsChecked + " anchor(s) match, head " + headHash
                    : "FAILED: " + problem;
        }
    }

    /** Checks the whole chain, then every anchor. A missing log (and no anchors) is a valid empty log. */
    public static Result verify(Path file, Path anchorFile) {
        List<String> lines = readLines(file);
        if (lines == null) return new Result(false, 0, GENESIS, 0, "cannot read " + file);
        if (!lines.isEmpty() && lines.get(lines.size() - 1).isEmpty()) lines.remove(lines.size() - 1);

        List<String> hashes = new ArrayList<>(); // hashes.get(i) = hash of entry seq i+1
        String prev = GENESIS;
        for (int i = 0; i < lines.size(); i++) {
            int lineNo = i + 1;
            String line = lines.get(i);
            Map<String, Object> e;
            try {
                e = Json.parseObject(line);
            } catch (IllegalArgumentException ex) {
                return fail(lineNo - 1, prev, "line " + lineNo + ": not valid JSON"
                        + (lineNo == lines.size() ? " (incomplete last line? the log may have been cut off mid-write)" : ""));
            }
            if (!List.of("seq", "time", "event", "data", "prev", "hash").equals(new ArrayList<>(e.keySet()))) {
                return fail(lineNo - 1, prev, "line " + lineNo + ": unexpected fields " + e.keySet());
            }
            if (!(e.get("seq") instanceof Number n) || n.longValue() != lineNo || !String.valueOf(n).equals(Integer.toString(lineNo))) {
                return fail(lineNo - 1, prev, "line " + lineNo + ": seq is " + e.get("seq") + ", expected " + lineNo
                        + " (an entry was deleted, inserted or moved here)");
            }
            if (!prev.equals(e.get("prev"))) {
                return fail(lineNo - 1, prev, "line " + lineNo + ": prev does not match the hash of line " + (lineNo - 1)
                        + " (an entry before it was changed or replaced)");
            }
            Object stored = e.remove("hash");
            String computed = hashOf(e);
            if (!computed.equals(stored)) {
                return fail(lineNo - 1, prev, "line " + lineNo + ": hash does not match the entry's contents (the entry was modified)");
            }
            e.put("hash", stored);
            if (!Json.write(e).equals(line)) {
                return fail(lineNo - 1, prev, "line " + lineNo + ": not in canonical form (the line was edited)");
            }
            hashes.add(computed);
            prev = computed;
        }

        // Anchors: each anchored head must still be in the log, with the same hash.
        List<String> anchors = readLines(anchorFile);
        if (anchors == null) return fail(hashes.size(), prev, "cannot read anchor file " + anchorFile);
        long checked = 0;
        for (int i = 0; i < anchors.size(); i++) {
            String a = anchors.get(i);
            if (a.isEmpty()) continue;
            Map<String, Object> m;
            try {
                m = Json.parseObject(a);
            } catch (IllegalArgumentException ex) {
                return fail(hashes.size(), prev, "anchor line " + (i + 1) + ": not valid JSON");
            }
            if (!(m.get("seq") instanceof Number num) || num.longValue() < 1) {
                return fail(hashes.size(), prev, "anchor line " + (i + 1) + ": bad seq");
            }
            long s = num.longValue();
            if (s > hashes.size()) {
                return fail(hashes.size(), prev, "anchor line " + (i + 1) + " records entry " + s + ", but the log has only "
                        + hashes.size() + " (entries were cut off the end)");
            }
            if (!hashes.get((int) s - 1).equals(m.get("hash"))) {
                return fail(hashes.size(), prev, "anchor line " + (i + 1) + ": entry " + s
                        + " has a different hash than when it was anchored (the log was rewritten)");
            }
            checked++;
        }
        return new Result(true, hashes.size(), prev, checked, "");
    }

    private static Result fail(long validEntries, String head, String problem) {
        return new Result(false, validEntries, head, 0, problem);
    }

    /** Lines of the file, an empty list if it doesn't exist, or null if it can't be read. */
    private static List<String> readLines(Path p) {
        if (!Files.exists(p)) return new ArrayList<>();
        try {
            return new ArrayList<>(List.of(Files.readString(p, StandardCharsets.UTF_8).split("\n", -1)));
        } catch (IOException e) {
            return null;
        }
    }
}
