package custody.orchestrator.audit;

import static org.junit.jupiter.api.Assertions.*;

import custody.orchestrator.eth.Json;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AuditLogTest {
    final Clock clock = Clock.fixed(Instant.parse("2026-10-23T06:00:00Z"), ZoneOffset.UTC);
    Path dir;
    Path log;
    Path anchors;

    @BeforeEach
    void setUp() throws Exception {
        dir = Files.createTempDirectory("audit-test");
        log = dir.resolve("audit.log");
        anchors = dir.resolve("audit.anchors");
    }

    /** Ten entries, anchored every 4 (at 4 and 8) and once more at the end (10). */
    List<String> writeTen() throws Exception {
        AuditLog a = AuditLog.open(log, anchors, clock, 4);
        for (int i = 1; i <= 10; i++) {
            Map<String, Object> d = new LinkedHashMap<>();
            d.put("i", Integer.toString(i));
            d.put("amount", "1000000000000000000");
            d.put("note", "unicode ✓ and \"quotes\" and \\ backslash");
            a.record("test.event", d);
        }
        a.anchor();
        return Files.readAllLines(log);
    }

    AuditLog.Result verifyLines(List<String> lines) throws Exception {
        Path p = dir.resolve("copy.log");
        Files.writeString(p, String.join("\n", lines) + "\n");
        return AuditLog.verify(p, anchors);
    }

    void assertDetected(List<String> tampered, String expectedProblem) throws Exception {
        AuditLog.Result r = verifyLines(tampered);
        assertFalse(r.ok(), "tampering not detected");
        assertTrue(r.problem().contains(expectedProblem), r.problem());
    }

    static List<String> with(List<String> lines, int i, String line) {
        List<String> c = new ArrayList<>(lines);
        c.set(i, line);
        return c;
    }

    // ---- writing ---------------------------------------------------------------------------

    @Test
    void emptyOrMissingLogIsValid() {
        assertTrue(AuditLog.verify(log, anchors).ok());
        assertEquals(0, AuditLog.verify(log, anchors).entries());
    }

    @Test
    void entriesChainAndVerify() throws Exception {
        List<String> lines = writeTen();
        assertEquals(10, lines.size());
        AuditLog.Result r = AuditLog.verify(log, anchors);
        assertTrue(r.ok(), r.problem());
        assertEquals(10, r.entries());
        assertEquals(3, r.anchorsChecked());

        Map<String, Object> first = Json.parseObject(lines.get(0));
        assertEquals(AuditLog.GENESIS, first.get("prev"));
        assertEquals("2026-10-23T06:00:00Z", first.get("time"));
        for (int i = 1; i < lines.size(); i++) {
            assertEquals(Json.parseObject(lines.get(i - 1)).get("hash"), Json.parseObject(lines.get(i)).get("prev"));
        }
        assertEquals(Json.parseObject(lines.get(9)).get("hash"), r.headHash());
    }

    @Test
    void reopeningContinuesTheChain() throws Exception {
        writeTen();
        AuditLog a = AuditLog.open(log, anchors, clock, 4);
        assertEquals(10, a.head().orElseThrow().seq());
        a.record("after.restart", Map.of());
        AuditLog.Result r = AuditLog.verify(log, anchors);
        assertTrue(r.ok(), r.problem());
        assertEquals(11, r.entries());
    }

    @Test
    void refusesToStartOnATamperedLog() throws Exception {
        List<String> lines = writeTen();
        Files.writeString(log, String.join("\n", with(lines, 3, lines.get(3).replace("\"i\":\"4\"", "\"i\":\"5\""))) + "\n");
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> AuditLog.open(log, anchors, clock, 4));
        assertTrue(e.getMessage().contains("line 4"), e.getMessage());
    }

    // ---- tampering the chain catches -------------------------------------------------------

    @Test
    void modifiedFieldsAreDetected() throws Exception {
        List<String> l = writeTen();
        assertDetected(with(l, 4, l.get(4).replace("1000000000000000000", "9000000000000000000")), "line 5: hash does not match");
        assertDetected(with(l, 4, l.get(4).replace("2026-10-23T06:00:00Z", "2026-10-22T06:00:00Z")), "line 5: hash does not match");
        assertDetected(with(l, 4, l.get(4).replace("test.event", "test.other")), "line 5: hash does not match");
        assertDetected(with(l, 9, l.get(9).replace("\"i\":\"10\"", "\"i\":\"11\"")), "line 10: hash does not match");
    }

    @Test
    void deletedInsertedAndReorderedEntriesAreDetected() throws Exception {
        List<String> l = writeTen();
        List<String> first = new ArrayList<>(l);
        first.remove(0);
        assertDetected(first, "line 1: seq is 2");
        List<String> middle = new ArrayList<>(l);
        middle.remove(5);
        assertDetected(middle, "line 6: seq is 7");
        List<String> dup = new ArrayList<>(l);
        dup.add(3, l.get(3));
        assertDetected(dup, "line 5: seq is 4");
        List<String> swapped = new ArrayList<>(l);
        Collections.swap(swapped, 2, 3);
        assertDetected(swapped, "line 3: seq is 4");
    }

    @Test
    void renumberedButUnhashedEntryIsDetected() throws Exception {
        // Delete line 6, then fix line 7's seq to 6: the prev link is now wrong.
        List<String> l = writeTen();
        List<String> c = new ArrayList<>(l);
        c.remove(5);
        Map<String, Object> e = Json.parseObject(c.get(5));
        e.put("seq", 6);
        c.set(5, Json.write(e));
        assertDetected(c, "line 6: prev does not match");
    }

    @Test
    void formattingEditsAndBrokenLinesAreDetected() throws Exception {
        List<String> l = writeTen();
        assertDetected(with(l, 2, l.get(2).replace("\"seq\":3,", "\"seq\": 3,")), "line 3: not in canonical form");
        assertDetected(with(l, 2, l.get(2).replace("\"prev\"", "\"extra\":\"x\",\"prev\"")), "line 3: unexpected fields");
        assertDetected(with(l, 9, l.get(9).substring(0, 40)), "line 10: not valid JSON (incomplete last line");
    }

    // ---- what needs the anchors ------------------------------------------------------------

    @Test
    void truncationPassesTheChainButNotTheAnchors() throws Exception {
        List<String> l = writeTen();
        List<String> cut = new ArrayList<>(l.subList(0, 9));
        Path p = dir.resolve("cut.log");
        Files.writeString(p, String.join("\n", cut) + "\n");
        assertTrue(AuditLog.verify(p, dir.resolve("no-anchors")).ok(), "a chain alone can't see truncation");
        assertDetected(cut, "records entry 10, but the log has only 9");
    }

    @Test
    void fullyRebuiltChainIsCaughtByTheAnchors() throws Exception {
        List<String> l = writeTen();
        List<String> forged = new ArrayList<>();
        String prev = AuditLog.GENESIS;
        for (String line : l) {
            Map<String, Object> e = Json.parseObject(line.replace("\"i\":\"2\"", "\"i\":\"22\""));
            e.remove("hash");
            e.put("prev", prev);
            prev = AuditLog.hashOf(e);
            e.put("hash", prev);
            forged.add(Json.write(e));
        }
        Path p = dir.resolve("forged.log");
        Files.writeString(p, String.join("\n", forged) + "\n");
        assertTrue(AuditLog.verify(p, dir.resolve("no-anchors")).ok(), "a rebuilt chain is internally consistent");
        assertDetected(forged, "entry 4 has a different hash than when it was anchored");
    }

    @Test
    void tamperedAnchorFileIsDetected() throws Exception {
        writeTen();
        List<String> a = Files.readAllLines(anchors);
        Map<String, Object> m = Json.parseObject(a.get(0));
        m.put("hash", AuditLog.GENESIS);
        a.set(0, Json.write(m));
        Files.writeString(anchors, String.join("\n", a) + "\n");
        assertFalse(AuditLog.verify(log, anchors).ok());
    }

    @Test
    void anchorsAreWrittenEveryNEntries() throws Exception {
        writeTen();
        List<String> a = Files.readAllLines(anchors);
        assertEquals(List.of("4", "8", "10"), a.stream().map(x -> String.valueOf(Json.parseObject(x).get("seq"))).toList());
    }
}
