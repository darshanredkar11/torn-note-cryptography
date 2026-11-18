package io.tornnote.wallet;

import io.tornnote.TornNote;
import org.junit.jupiter.api.Test;

import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class WebAuthnBoundAuthorizationServiceTest {
    private static final Instant NOW = Instant.parse("2026-11-19T00:01:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final Instant ISSUED = NOW.minusSeconds(5);
    private static final Instant EXPIRES = NOW.plusSeconds(300);
    private static final WebAuthnBoundAuthorizationService.RequestPrincipal PRINCIPAL =
            new WebAuthnBoundAuthorizationService.RequestPrincipal("tenant-001", "subject-001", "sid-001");

    private static final class FakeAssertionEngine implements WebAuthnAssertionEngine {
        private final VerifiedAssertion result;
        FakeAssertionEngine(VerifiedAssertion result) { this.result = result; }

        @Override public PreparedAssertion start(String subjectId) {
            return new PreparedAssertion("{\"subject\":\"" + subjectId + "\"}",
                    "{\"publicKey\":{\"challenge\":\"server-created\"}}");
        }
        @Override public VerifiedAssertion finish(String request, String response) {
            assertNotNull(request);
            assertNotNull(response);
            return result;
        }
    }

    private static TransactionEnvelopeV1 transaction() {
        byte[] nonce = new byte[32];
        new SecureRandom().nextBytes(nonce);
        return new TransactionEnvelopeV1("txn-webauthn-001", "tenant-001", "subject-001",
                "finance-approval", "CHANGE_SUPPLIER_BANK_ACCOUNT", "supplier-001",
                "resource-v7", "policy-v3",
                Map.of("amount_minor", "850000", "currency", "INR", "beneficiary_account", "XX-4821"),
                nonce, ISSUED, EXPIRES);
    }

    private static WebAuthnBoundAuthorizationService service(
            FakeAssertionEngine engine, BoundAuthorizationStore.InMemory store,
            NoteInventoryIssuer issuer) {
        return new WebAuthnBoundAuthorizationService(engine, store,
                new AuthorizationVerifier(issuer.issuerPublicKey(),
                        new AuthorizationVerifier.InMemorySpendStore(), CLOCK),
                (tenant, subject, key) -> tenant.equals("tenant-001") && subject.equals("subject-001"),
                CLOCK, new SecureRandom(), Duration.ofSeconds(90));
    }

    @Test
    void bothProofSystemsMustBeValidBeforeOutboxCommit() throws Exception {
        NoteInventoryIssuer issuer = NoteInventoryIssuer.create();
        var inventory = issuer.issue("webauthn-bound-inventory", 2);
        var walletNote = inventory.walletCredentials().get(0);
        var identity = TornNote.keys("ed25519");
        var tx = transaction();
        var noteEnvelope = new NoteAuthorizationEnvelopeV1(tx, inventory.manifest(),
                walletNote.publicNote(), identity.pair().getPublic());
        var signatures = walletNote.authorizeBound(identity, inventory.manifest(), noteEnvelope);
        var store = new BoundAuthorizationStore.InMemory();
        var service = service(new FakeAssertionEngine(
                new WebAuthnAssertionEngine.VerifiedAssertion(true, true, "subject-001", "credential-id", 8)),
                store, issuer);

        var started = service.start(PRINCIPAL, tx, inventory.manifest(), walletNote.publicNote(), identity.pair().getPublic());
        assertEquals(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(noteEnvelope.digest()),
                started.noteAuthorizationDigestBase64Url());

        var result = service.finish(started.challengeId(), PRINCIPAL, tx, inventory.manifest(), walletNote.publicNote(),
                identity.pair().getPublic(), signatures, "{\"type\":\"webauthn.get\"}");

        assertTrue(result.accepted(), result.reason());
        assertEquals("CONSUMED", store.stateOf(started.challengeId()));
        assertEquals(1, store.outboxSnapshot().size());
        assertTrue(store.isSpent(inventory.manifest().inventoryId() + ":"
                + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(walletNote.publicNote().noteId())));
    }

    @Test
    void invalidOrUnverifiedPasskeyCannotConsumeNoteOrEnqueueAction() throws Exception {
        NoteInventoryIssuer issuer = NoteInventoryIssuer.create();
        var inventory = issuer.issue("webauthn-reject-uv", 1);
        var walletNote = inventory.walletCredentials().get(0);
        var identity = TornNote.keys("ed25519");
        var tx = transaction();
        var envelope = new NoteAuthorizationEnvelopeV1(tx, inventory.manifest(),
                walletNote.publicNote(), identity.pair().getPublic());
        var signatures = walletNote.authorizeBound(identity, inventory.manifest(), envelope);
        var store = new BoundAuthorizationStore.InMemory();
        var service = service(new FakeAssertionEngine(
                new WebAuthnAssertionEngine.VerifiedAssertion(true, false, "subject-001", "credential-id", 1)),
                store, issuer);

        var started = service.start(PRINCIPAL, tx, inventory.manifest(), walletNote.publicNote(), identity.pair().getPublic());
        var result = service.finish(started.challengeId(), PRINCIPAL, tx, inventory.manifest(), walletNote.publicNote(),
                identity.pair().getPublic(), signatures, "{\"fake\":true}");

        assertFalse(result.accepted());
        assertEquals("webauthn-user-verification-required", result.reason());
        assertEquals(0, store.outboxSnapshot().size());
        assertEquals("INVALID", store.stateOf(started.challengeId()));
    }

    @Test
    void transactionSplicedAfterChallengeCreationIsRejected() throws Exception {
        NoteInventoryIssuer issuer = NoteInventoryIssuer.create();
        var inventory = issuer.issue("webauthn-reject-splice", 1);
        var walletNote = inventory.walletCredentials().get(0);
        var identity = TornNote.keys("ed25519");
        var tx = transaction();
        var envelope = new NoteAuthorizationEnvelopeV1(tx, inventory.manifest(),
                walletNote.publicNote(), identity.pair().getPublic());
        var signatures = walletNote.authorizeBound(identity, inventory.manifest(), envelope);
        var store = new BoundAuthorizationStore.InMemory();
        var service = service(new FakeAssertionEngine(
                new WebAuthnAssertionEngine.VerifiedAssertion(true, true, "subject-001", "credential-id", 1)),
                store, issuer);

        var started = service.start(PRINCIPAL, tx, inventory.manifest(), walletNote.publicNote(), identity.pair().getPublic());
        var changed = new TransactionEnvelopeV1(tx.transactionId(), tx.tenantId(), tx.subjectId(),
                tx.audience(), tx.actionType(), tx.targetId(), tx.resourceVersion(), tx.policyVersion(),
                Map.of("amount_minor", "850001", "currency", "INR", "beneficiary_account", "XX-4821"),
                tx.nonce(), tx.issuedAt(), tx.expiresAt());

        var result = service.finish(started.challengeId(), PRINCIPAL, changed, inventory.manifest(),
                walletNote.publicNote(), identity.pair().getPublic(), signatures, "{\"fake\":true}");
        assertFalse(result.accepted());
        assertEquals("transaction-or-note-binding-mismatch", result.reason());
        assertEquals("INVALID", store.stateOf(started.challengeId()));
        assertTrue(store.outboxSnapshot().isEmpty());
    }

    @Test
    void credentialSubjectMustMatchTheBoundSubject() throws Exception {
        NoteInventoryIssuer issuer = NoteInventoryIssuer.create();
        var inventory = issuer.issue("webauthn-reject-subject", 1);
        var walletNote = inventory.walletCredentials().get(0);
        var identity = TornNote.keys("ed25519");
        var tx = transaction();
        var envelope = new NoteAuthorizationEnvelopeV1(tx, inventory.manifest(),
                walletNote.publicNote(), identity.pair().getPublic());
        var signatures = walletNote.authorizeBound(identity, inventory.manifest(), envelope);
        var store = new BoundAuthorizationStore.InMemory();
        var service = service(new FakeAssertionEngine(
                new WebAuthnAssertionEngine.VerifiedAssertion(true, true, "somebody-else", "credential-id", 1)),
                store, issuer);
        var started = service.start(PRINCIPAL, tx, inventory.manifest(), walletNote.publicNote(), identity.pair().getPublic());

        var result = service.finish(started.challengeId(), PRINCIPAL, tx, inventory.manifest(), walletNote.publicNote(),
                identity.pair().getPublic(), signatures, "{\"fake\":true}");
        assertFalse(result.accepted());
        assertEquals("webauthn-subject-mismatch", result.reason());
    }

    @Test
    void anotherSessionCannotClaimOrBurnThePendingChallenge() throws Exception {
        NoteInventoryIssuer issuer = NoteInventoryIssuer.create();
        var inventory = issuer.issue("webauthn-session-binding", 1);
        var walletNote = inventory.walletCredentials().get(0);
        var identity = TornNote.keys("ed25519");
        var tx = transaction();
        var store = new BoundAuthorizationStore.InMemory();
        var service = service(new FakeAssertionEngine(
                new WebAuthnAssertionEngine.VerifiedAssertion(true, true, "subject-001", "credential-id", 1)),
                store, issuer);
        var started = service.start(PRINCIPAL, tx, inventory.manifest(),
                walletNote.publicNote(), identity.pair().getPublic());

        var wrongPrincipal = new WebAuthnBoundAuthorizationService.RequestPrincipal(
                "tenant-001", "subject-001", "different-session");
        var stolenIdAttempt = service.finish(started.challengeId(), wrongPrincipal, tx, inventory.manifest(),
                walletNote.publicNote(), identity.pair().getPublic(), null, "{}");
        assertFalse(stolenIdAttempt.accepted());
        assertEquals("PENDING", store.stateOf(started.challengeId()));

        var envelope = new NoteAuthorizationEnvelopeV1(tx, inventory.manifest(),
                walletNote.publicNote(), identity.pair().getPublic());
        var signatures = walletNote.authorizeBound(identity, inventory.manifest(), envelope);
        var legitimate = service.finish(started.challengeId(), PRINCIPAL, tx, inventory.manifest(),
                walletNote.publicNote(), identity.pair().getPublic(), signatures, "{}");
        assertTrue(legitimate.accepted(), legitimate.reason());
    }

    @Test
    void oneChallengeCanBeClaimedOnlyOnceUnderConcurrency() throws Exception {
        var store = new BoundAuthorizationStore.InMemory();
        byte[] txDigest = new byte[32];
        byte[] noteDigest = new byte[32];
        var pending = new BoundAuthorizationStore.PendingAssertion("challenge-1", "request", "tx",
                "tenant", "subject", "sid", "audience", txDigest, noteDigest, NOW.plusSeconds(30));
        store.create(pending);
        var ready = new CountDownLatch(10);
        var start = new CountDownLatch(1);
        var claims = new AtomicInteger();

        try (var pool = Executors.newFixedThreadPool(10)) {
            for (int i=0;i<10;i++) pool.submit(() -> {
                ready.countDown();
                try {
                    start.await();
                    if (store.claim("challenge-1", "tenant", "subject", "sid", NOW).isPresent()) claims.incrementAndGet();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
            ready.await();
            start.countDown();
            pool.shutdown();
            while (!pool.isTerminated()) Thread.sleep(5);
        }
        assertEquals(1, claims.get());
    }
}
