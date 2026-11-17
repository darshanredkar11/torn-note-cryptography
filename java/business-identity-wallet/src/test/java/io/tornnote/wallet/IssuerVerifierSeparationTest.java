package io.tornnote.wallet;

import io.tornnote.TornNote;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class IssuerVerifierSeparationTest {
    private static final String TX =
            "{\"operation\":\"CHANGE_SUPPLIER_BANK_ACCOUNT\","
            + "\"supplier\":\"ACME Components\",\"account\":\"XX-4821\","
            + "\"amount\":850000,\"currency\":\"INR\",\"requestId\":\"REQ-77\"}";

    @Test void verifierWorksWithOnlyIssuerPublicKeyAndWalletPublicNote() throws Exception {
        NoteInventoryIssuer issuer = NoteInventoryIssuer.create();
        var inventory = issuer.issue("supplier-bank-change-2026-01", 8);
        var walletCredential = inventory.walletCredentials().get(3);
        var identity = TornNote.keys("ed25519");
        var signatures = walletCredential.authorize(identity, inventory.manifest(), TX);

        // This verifier is constructed from the pinned issuer public key only.
        // It never receives the issuer object or wallet credential/private fragments.
        var verifier = new AuthorizationVerifier(issuer.issuerPublicKey(),
                new AuthorizationVerifier.InMemorySpendStore());
        var result = verifier.verifyAndConsume(inventory.manifest(), walletCredential.publicNote(),
                identity.pair().getPublic(), TX, signatures);

        assertTrue(result.accepted(), result.reason());
    }

    @Test void manifestTamperingIsRejectedBeforeSignatureVerification() throws Exception {
        NoteInventoryIssuer issuer = NoteInventoryIssuer.create();
        var inventory = issuer.issue("manifest-tamper", 4);
        var walletCredential = inventory.walletCredentials().get(1);
        var identity = TornNote.keys("ed25519");
        var signatures = walletCredential.authorize(identity, inventory.manifest(), TX);
        byte[] changedRoot = inventory.manifest().root();
        changedRoot[0] ^= 0x01;
        var forgedManifest = new InventoryManifest(inventory.manifest().inventoryId(),
                inventory.manifest().noteCount(), changedRoot, inventory.manifest().signature());
        var verifier = new AuthorizationVerifier(issuer.issuerPublicKey(),
                new AuthorizationVerifier.InMemorySpendStore());

        var result = verifier.verifyAndConsume(forgedManifest, walletCredential.publicNote(),
                identity.pair().getPublic(), TX, signatures);
        assertFalse(result.accepted());
        assertEquals("issuer-manifest-invalid", result.reason());
    }

    @Test void manifestSignedByUntrustedIssuerIsRejected() throws Exception {
        NoteInventoryIssuer trustedIssuer = NoteInventoryIssuer.create();
        NoteInventoryIssuer untrustedIssuer = NoteInventoryIssuer.create();
        var inventory = untrustedIssuer.issue("untrusted-inventory", 2);
        var walletCredential = inventory.walletCredentials().get(0);
        var identity = TornNote.keys("ed25519");
        var signatures = walletCredential.authorize(identity, inventory.manifest(), TX);
        var verifier = new AuthorizationVerifier(trustedIssuer.issuerPublicKey(),
                new AuthorizationVerifier.InMemorySpendStore());

        var result = verifier.verifyAndConsume(inventory.manifest(), walletCredential.publicNote(),
                identity.pair().getPublic(), TX, signatures);
        assertFalse(result.accepted());
        assertEquals("issuer-manifest-invalid", result.reason());
    }

    @Test void fabricatedNoteOutsideIssuerInventoryIsRejected() throws Exception {
        NoteInventoryIssuer issuer = NoteInventoryIssuer.create();
        var inventory = issuer.issue("fabricated-note", 2);
        var walletCredential = inventory.walletCredentials().get(0);
        var identity = TornNote.keys("ed25519");
        var fabricatedA = TornNote.keys("ed25519");
        var fabricatedB = TornNote.keys("ed25519");
        var fakeNote = new NoteInventoryIssuer.PublicNote(inventory.manifest().inventoryId(),
                "not-issued".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                fabricatedA.pair().getPublic(), fabricatedB.pair().getPublic(),
                walletCredential.publicNote().proof(), walletCredential.publicNote().index());
        var fakeSignatures = TornNote.authorize(identity, fabricatedA, fabricatedB,
                inventory.manifest().root(), fakeNote.noteId(), fakeNote.publicA(), fakeNote.publicB(),
                TX, fakeNote.proof(), fakeNote.index());
        var verifier = new AuthorizationVerifier(issuer.issuerPublicKey(),
                new AuthorizationVerifier.InMemorySpendStore());

        var result = verifier.verifyAndConsume(inventory.manifest(), fakeNote,
                identity.pair().getPublic(), TX, fakeSignatures);
        assertFalse(result.accepted());
        assertEquals("signature-or-inventory-proof-invalid", result.reason());
    }

    @Test void onlyOneConcurrentVerifierCallCanConsumeTheSameNote() throws Exception {
        NoteInventoryIssuer issuer = NoteInventoryIssuer.create();
        var inventory = issuer.issue("concurrent-spend", 2);
        var walletCredential = inventory.walletCredentials().get(0);
        var identity = TornNote.keys("ed25519");
        var signatures = walletCredential.authorize(identity, inventory.manifest(), TX);
        var verifier = new AuthorizationVerifier(issuer.issuerPublicKey(),
                new AuthorizationVerifier.InMemorySpendStore());
        int contenders = 12;
        var ready = new CountDownLatch(contenders);
        var start = new CountDownLatch(1);
        var accepted = new AtomicInteger();

        try (var pool = Executors.newFixedThreadPool(contenders)) {
            for (int i = 0; i < contenders; i++) {
                pool.submit(() -> {
                    ready.countDown();
                    try {
                        start.await();
                        var result = verifier.verifyAndConsume(inventory.manifest(), walletCredential.publicNote(),
                                identity.pair().getPublic(), TX, signatures);
                        if (result.accepted()) accepted.incrementAndGet();
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });
            }
            ready.await();
            start.countDown();
            pool.shutdown();
            while (!pool.isTerminated()) Thread.sleep(5);
        }
        assertEquals(1, accepted.get(), "exactly one verifier should consume the note");
    }
}