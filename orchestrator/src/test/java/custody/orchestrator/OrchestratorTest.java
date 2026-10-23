package custody.orchestrator;

import static custody.orchestrator.Rejection.Code.*;
import static org.junit.jupiter.api.Assertions.*;

import custody.orchestrator.Intents.Cancellation;
import custody.orchestrator.Intents.Domain;
import custody.orchestrator.Intents.Intent;
import custody.orchestrator.Intents.SignedIntent;
import custody.orchestrator.Intents.WithdrawalApproval;
import custody.orchestrator.Intents.WithdrawalRequest;
import custody.orchestrator.audit.Audit;
import custody.orchestrator.crypto.Secp256k1;
import custody.orchestrator.hsm.AnvilTestKeys;
import custody.orchestrator.hsm.MockHsmSigner;
import java.math.BigInteger;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class OrchestratorTest {
    static final String VAULT = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
    static final String ETH = "0x0000000000000000000000000000000000000000";
    static final String TOKEN = "0x00000000000000000000000000000000000000aa";
    static final String DEST = addr(8);
    static final String OTHER = addr(7);
    static final BigInteger AMOUNT = BigInteger.valueOf(1_000);
    static final long NOW = 1_800_000_000L;

    static final BigInteger APPROVER_A = AnvilTestKeys.key(4);
    static final BigInteger APPROVER_B = AnvilTestKeys.key(5);
    static final BigInteger STRANGER = AnvilTestKeys.key(7);

    Domain domain;
    FakeChain chain;
    MockHsmSigner hsm;
    NonceStore nonces;
    Orchestrator orch;
    long nextNonce = 1;
    RecordingAudit audit = new RecordingAudit();

    /** Keeps entries in memory; can be told to fail on one event type, as a full disk would. */
    static final class RecordingAudit implements Audit {
        final List<String> events = new ArrayList<>();
        final List<Map<String, Object>> data = new ArrayList<>();
        String failOn;

        @Override
        public void record(String event, Map<String, Object> d) {
            if (event.equals(failOn)) throw new java.io.UncheckedIOException(new java.io.IOException("disk full"));
            events.add(event);
            data.add(d);
        }

        @Override
        public Optional<Head> head() {
            return events.isEmpty() ? Optional.empty() : Optional.of(new Head(events.size(), "0x"));
        }
    }

    static String addr(int i) {
        return Secp256k1.address(AnvilTestKeys.key(i));
    }

    @BeforeEach
    void setUp() {
        domain = new Domain(31337, VAULT);
        Clock clock = Clock.fixed(Instant.ofEpochSecond(NOW), ZoneOffset.UTC);
        Map<String, Integer> bindings = new LinkedHashMap<>();
        bindings.put(addr(4), 0);
        bindings.put(addr(5), 1);
        bindings.put(addr(6), 2);
        hsm = new MockHsmSigner(domain, bindings, clock);
        chain = new FakeChain(31337, VAULT);
        chain.signer = hsm;
        for (int i = 0; i < 3; i++) chain.owners.add(addr(i).toLowerCase());
        chain.allowlist.add(DEST.toLowerCase());
        chain.dailyLimits.put(ETH, BigInteger.valueOf(10_000));
        chain.dailyLimits.put(TOKEN, BigInteger.valueOf(10_000));
        nonces = new NonceStore.InMemory();
        orch = new Orchestrator(domain, hsm, chain, nonces, clock,
                new Orchestrator.Policy(Duration.ofHours(1), Map.of(TOKEN, BigInteger.valueOf(500))), audit);
    }

    // ---- helpers ---------------------------------------------------------------------------

    WithdrawalRequest request(String to, BigInteger amount) {
        return new WithdrawalRequest(ETH, to, amount, BigInteger.valueOf(nextNonce++), NOW + 600);
    }

    WithdrawalApproval approval(BigInteger id, String asset, String to, BigInteger amount) {
        return new WithdrawalApproval(id, asset, to, amount, BigInteger.valueOf(nextNonce++), NOW + 600);
    }

    SignedIntent sign(Intent i, BigInteger key) {
        return Intents.sign(domain, i, key);
    }

    void assertRejected(Rejection.Code code, SignedIntent s) {
        int before = chain.sent.size();
        Rejection r = assertThrows(Rejection.class, () -> orch.submit(s));
        assertEquals(code, r.code, r.getMessage());
        assertEquals(before, chain.sent.size(), "nothing may be sent when a request is rejected");
    }

    // ---- happy paths -----------------------------------------------------------------------

    @Test
    void requestThenApprovalReachesThreshold() {
        Orchestrator.Outcome o = orch.submit(sign(request(DEST, AMOUNT), APPROVER_A));
        assertEquals("proposed", o.action());
        assertEquals(BigInteger.ZERO, o.proposalId());
        assertEquals("owner-1", o.keySlot());
        assertArrayEquals(VaultCalls.proposeWithdrawal(ETH, DEST, AMOUNT), chain.sent.get(0));

        o = orch.submit(sign(approval(BigInteger.ZERO, ETH, DEST, AMOUNT), APPROVER_B));
        assertEquals("approved", o.action());
        assertEquals("owner-2", o.keySlot());
        assertEquals(BigInteger.TWO, o.approvals());
        assertArrayEquals(VaultCalls.approve(BigInteger.ZERO), chain.sent.get(1));
    }

    @Test
    void cancellationNeedsOnlyOneApprover() {
        BigInteger id = chain.addProposal(true, ETH, DEST, AMOUNT);
        Orchestrator.Outcome o = orch.submit(sign(new Cancellation(id, BigInteger.ONE, NOW + 60), APPROVER_B));
        assertEquals("cancelled", o.action());
        assertArrayEquals(VaultCalls.cancel(id), chain.sent.get(0));
    }

    // ---- the intent ------------------------------------------------------------------------

    @Test
    void malformedSignatureIsRejected() {
        SignedIntent good = sign(request(DEST, AMOUNT), APPROVER_A);
        byte[] bad = Arrays.copyOf(good.signature(), 65);
        bad[64] = 5; // invalid v
        assertRejected(BAD_SIGNATURE, new SignedIntent(good.intent(), bad));
        assertRejected(BAD_SIGNATURE, new SignedIntent(good.intent(), new byte[10]));
    }

    @Test
    void tamperedIntentRecoversToSomeoneElse() {
        SignedIntent good = sign(request(DEST, AMOUNT), APPROVER_A);
        WithdrawalRequest r = (WithdrawalRequest) good.intent();
        WithdrawalRequest bigger = new WithdrawalRequest(r.asset(), r.to(), r.amount().add(BigInteger.ONE), r.nonce(), r.deadline());
        assertRejected(UNKNOWN_APPROVER, new SignedIntent(bigger, good.signature()));
    }

    @Test
    void unregisteredApproverIsRejected() {
        assertRejected(UNKNOWN_APPROVER, sign(request(DEST, AMOUNT), STRANGER));
    }

    @Test
    void signatureForAnotherVaultOrChainIsRejected() {
        WithdrawalRequest r = request(DEST, AMOUNT);
        assertRejected(UNKNOWN_APPROVER, Intents.sign(new Domain(31337, OTHER), r, APPROVER_A));
        assertRejected(UNKNOWN_APPROVER, Intents.sign(new Domain(1, VAULT), r, APPROVER_A));
    }

    @Test
    void expiredAndFarFutureDeadlinesAreRejected() {
        assertRejected(EXPIRED, sign(new WithdrawalRequest(ETH, DEST, AMOUNT, BigInteger.ONE, NOW - 1), APPROVER_A));
        assertRejected(DEADLINE_TOO_FAR, sign(new WithdrawalRequest(ETH, DEST, AMOUNT, BigInteger.ONE, NOW + 3601), APPROVER_A));
        orch.submit(sign(new WithdrawalRequest(ETH, DEST, AMOUNT, BigInteger.ONE, NOW + 3600), APPROVER_A)); // boundary is fine
        orch.submit(sign(new WithdrawalRequest(ETH, DEST, AMOUNT, BigInteger.TWO, NOW), APPROVER_A)); // so is "expires now"
    }

    @Test
    void replayIsRejected() {
        SignedIntent s = sign(request(DEST, AMOUNT), APPROVER_A);
        orch.submit(s);
        assertRejected(NONCE_REUSED, s);
    }

    @Test
    void nonceIsPerApprover() {
        orch.submit(sign(new WithdrawalRequest(ETH, DEST, AMOUNT, BigInteger.ONE, NOW + 60), APPROVER_A));
        orch.submit(sign(new WithdrawalRequest(ETH, DEST, AMOUNT, BigInteger.ONE, NOW + 60), APPROVER_B));
        assertEquals(2, chain.sent.size());
    }

    @Test
    void rejectedIntentDoesNotUseUpItsNonce() {
        chain.paused = true;
        SignedIntent s = sign(request(DEST, AMOUNT), APPROVER_A);
        assertRejected(PAUSED, s);
        chain.paused = false;
        orch.submit(s); // the same signed intent works once the problem is fixed
        assertEquals(1, chain.sent.size());
    }

    @Test
    void nonceIsUsedUpEvenIfTheTransactionFails() {
        SignedIntent s = sign(request(DEST, AMOUNT), APPROVER_A);
        chain.nextTxFails = true;
        Rejection r = assertThrows(Rejection.class, () -> orch.submit(s));
        assertEquals(TX_FAILED, r.code);
        assertTrue(nonces.isUsed(Secp256k1.address(APPROVER_A), ((WithdrawalRequest) s.intent()).nonce()));
        assertRejected(NONCE_REUSED, s); // fail closed: the approver signs a fresh intent
    }

    @Test
    void removedOwnerIsRejected() {
        chain.owners.remove(addr(0).toLowerCase());
        assertRejected(NOT_AN_OWNER, sign(request(DEST, AMOUNT), APPROVER_A));
    }

    // ---- the proposal ----------------------------------------------------------------------

    @Test
    void approvalMustMatchTheProposalOnChain() {
        BigInteger id = chain.addProposal(true, ETH, DEST, AMOUNT);
        assertRejected(PROPOSAL_MISMATCH, sign(approval(id, ETH, DEST, AMOUNT.add(BigInteger.ONE)), APPROVER_B));
        assertRejected(PROPOSAL_MISMATCH, sign(approval(id, TOKEN, DEST, AMOUNT), APPROVER_B));
        chain.allowlist.add(OTHER.toLowerCase());
        assertRejected(PROPOSAL_MISMATCH, sign(approval(id, ETH, OTHER, AMOUNT), APPROVER_B));
        BigInteger config = chain.addProposal(false, ETH, ETH, BigInteger.ZERO);
        assertRejected(PROPOSAL_MISMATCH, sign(approval(config, ETH, ETH, BigInteger.ZERO), APPROVER_B));
        orch.submit(sign(approval(id, ETH, DEST, AMOUNT), APPROVER_B));
    }

    @Test
    void unknownClosedOrAlreadyApprovedProposalsAreRejected() {
        assertRejected(UNKNOWN_PROPOSAL, sign(approval(BigInteger.valueOf(99), ETH, DEST, AMOUNT), APPROVER_B));
        BigInteger id = chain.addProposal(true, ETH, DEST, AMOUNT);
        orch.submit(sign(approval(id, ETH, DEST, AMOUNT), APPROVER_B));
        assertRejected(ALREADY_APPROVED, sign(approval(id, ETH, DEST, AMOUNT), APPROVER_B));
        chain.close(id, true);
        assertRejected(PROPOSAL_CLOSED, sign(approval(id, ETH, DEST, AMOUNT), APPROVER_A));
        assertRejected(PROPOSAL_CLOSED, sign(new Cancellation(id, BigInteger.valueOf(77), NOW + 60), APPROVER_A));
    }

    // ---- policy ----------------------------------------------------------------------------

    @Test
    void withdrawalPolicyIsCheckedBeforeSigning() {
        assertRejected(ZERO_AMOUNT, sign(request(DEST, BigInteger.ZERO), APPROVER_A));
        assertRejected(DESTINATION_NOT_ALLOWED, sign(request(OTHER, AMOUNT), APPROVER_A));
        assertRejected(OVER_DAILY_LIMIT, sign(request(DEST, BigInteger.valueOf(10_001)), APPROVER_A));
        chain.paused = true;
        assertRejected(PAUSED, sign(request(DEST, AMOUNT), APPROVER_A));
    }

    @Test
    void approvalsArePolicyCheckedToo() {
        // The destination was allowlisted when proposed and removed since: don't add an approval to it.
        BigInteger id = chain.addProposal(true, ETH, DEST, AMOUNT);
        chain.allowlist.clear();
        assertRejected(DESTINATION_NOT_ALLOWED, sign(approval(id, ETH, DEST, AMOUNT), APPROVER_B));
    }

    @Test
    void orchestratorCapIsStricterThanTheVault() {
        WithdrawalRequest r = new WithdrawalRequest(TOKEN, DEST, BigInteger.valueOf(501), BigInteger.ONE, NOW + 60);
        assertRejected(OVER_ORCHESTRATOR_CAP, sign(r, APPROVER_A));
        orch.submit(sign(new WithdrawalRequest(TOKEN, DEST, BigInteger.valueOf(500), BigInteger.TWO, NOW + 60), APPROVER_A));
    }

    @Test
    void simulatedRevertIsReportedByName() {
        chain.revertWith = "RateLimited";
        SignedIntent s = sign(request(DEST, AMOUNT), APPROVER_A);
        Rejection r = assertThrows(Rejection.class, () -> orch.submit(s));
        assertEquals(ON_CHAIN_REVERT, r.code);
        assertTrue(r.getMessage().contains("RateLimited"));
        assertTrue(chain.sent.isEmpty());
    }

    // ---- execute ---------------------------------------------------------------------------

    @Test
    void executeWaitsForApprovalsAndTimelock() {
        BigInteger id = chain.addProposal(true, ETH, DEST, AMOUNT);
        assertEquals(NOT_READY, assertThrows(Rejection.class, () -> orch.execute(id)).code);
        chain.executableAt.put(id, BigInteger.valueOf(chain.time + 3600));
        assertEquals(NOT_READY, assertThrows(Rejection.class, () -> orch.execute(id)).code);
        chain.time += 3600;
        Orchestrator.Outcome o = orch.execute(id);
        assertEquals("executed", o.action());
        assertArrayEquals(VaultCalls.execute(id), chain.sent.get(0));
    }

    @Test
    void executeUsesAKeyThatIsStillAnOwner() {
        BigInteger id = chain.addProposal(true, ETH, DEST, AMOUNT);
        chain.executableAt.put(id, BigInteger.valueOf(chain.time));
        chain.owners.remove(addr(0).toLowerCase());
        assertEquals("owner-2", orch.execute(id).keySlot());
    }

    @Test
    void refusesToStartAgainstTheWrongChain() {
        FakeChain mainnet = new FakeChain(1, VAULT);
        assertThrows(IllegalStateException.class, () -> new Orchestrator(domain, hsm, mainnet, nonces,
                Clock.systemUTC(), Orchestrator.Policy.defaults()));
    }

    // ---- audit -----------------------------------------------------------------------------

    @Test
    void auditRecordsEachStepInOrder() {
        orch.submit(sign(request(DEST, AMOUNT), APPROVER_A));
        assertEquals(List.of("intent.received", "sign.requested", "tx.mined", "request.completed"), audit.events);
        assertEquals(Secp256k1.address(APPROVER_A), audit.data.get(0).get("signer"));
        assertEquals("1", audit.data.get(1).get("ref")); // later entries point back to the request's entry
        assertEquals("owner-1", audit.data.get(1).get("keySlot"));
        assertEquals("proposed", audit.data.get(3).get("action"));
    }

    @Test
    void rejectionsAreRecordedWithTheirCode() {
        assertRejected(DESTINATION_NOT_ALLOWED, sign(request(OTHER, AMOUNT), APPROVER_A));
        assertEquals(List.of("intent.received", "request.rejected"), audit.events);
        assertEquals("DESTINATION_NOT_ALLOWED", audit.data.get(1).get("code"));
    }

    @Test
    void nothingIsSignedIfTheSigningRequestCantBeRecorded() {
        audit.failOn = "sign.requested";
        SignedIntent s = sign(request(DEST, AMOUNT), APPROVER_A);
        assertThrows(java.io.UncheckedIOException.class, () -> orch.submit(s));
        assertTrue(chain.sent.isEmpty(), "a transaction was signed without an audit entry");
    }

    @Test
    void nothingHappensIfTheRequestCantBeRecorded() {
        audit.failOn = "intent.received";
        assertThrows(java.io.UncheckedIOException.class, () -> orch.submit(sign(request(DEST, AMOUNT), APPROVER_A)));
        assertTrue(chain.sent.isEmpty());
    }

    @Test
    void executionIsAuditedToo() {
        BigInteger id = chain.addProposal(true, ETH, DEST, AMOUNT);
        chain.executableAt.put(id, BigInteger.valueOf(chain.time));
        orch.execute(id);
        assertEquals(List.of("execute.requested", "sign.requested", "tx.mined", "request.completed"), audit.events);
    }
}
