package custody.orchestrator;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Remembers which (approver, nonce) pairs have been used, so a signed intent works once.
 *
 * <p>The file-backed store survives restarts: without it, a restart within an intent's lifetime
 * would let someone replay a captured WithdrawalRequest and create a duplicate proposal.
 */
public interface NonceStore {

    boolean isUsed(String approver, BigInteger nonce);

    /** Atomically marks the pair used. Returns false if it already was. */
    boolean markUsed(String approver, BigInteger nonce);

    static String key(String approver, BigInteger nonce) {
        return approver.toLowerCase(Locale.ROOT) + ":" + nonce;
    }

    final class InMemory implements NonceStore {
        private final Set<String> used = new HashSet<>();

        @Override
        public synchronized boolean isUsed(String approver, BigInteger nonce) {
            return used.contains(key(approver, nonce));
        }

        @Override
        public synchronized boolean markUsed(String approver, BigInteger nonce) {
            return used.add(key(approver, nonce));
        }
    }

    /** One line per used nonce, appended and forced to disk before the transaction is signed. */
    final class FileBacked implements NonceStore {
        private final Path file;
        private final Set<String> used = new HashSet<>();

        public FileBacked(Path file) {
            this.file = file;
            try {
                if (Files.exists(file)) {
                    for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                        if (!line.isBlank()) used.add(line.trim());
                    }
                }
            } catch (IOException e) {
                throw new UncheckedIOException("cannot read nonce store " + file, e);
            }
        }

        @Override
        public synchronized boolean isUsed(String approver, BigInteger nonce) {
            return used.contains(key(approver, nonce));
        }

        @Override
        public synchronized boolean markUsed(String approver, BigInteger nonce) {
            String k = key(approver, nonce);
            if (used.contains(k)) return false;
            try (FileChannel ch = FileChannel.open(file, StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                    StandardOpenOption.APPEND)) {
                ch.write(java.nio.ByteBuffer.wrap((k + "\n").getBytes(StandardCharsets.UTF_8)));
                ch.force(true);
            } catch (IOException e) {
                throw new UncheckedIOException("cannot write nonce store " + file, e); // fail closed
            }
            used.add(k);
            return true;
        }
    }
}
