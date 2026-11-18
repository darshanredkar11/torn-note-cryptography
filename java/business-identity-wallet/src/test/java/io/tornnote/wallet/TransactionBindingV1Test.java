package io.tornnote.wallet;

import io.tornnote.TornNote;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class TransactionBindingV1Test {
    private static final Instant ISSUED_AT = Instant.parse("2026-11-19T00:00:00Z");
    private static final Instant EXPIRES_AT = Instant.parse("2026-11-19T00:02:00Z");
    private static final java.time.Clock TEST_CLOCK =
            java.time.Clock.fixed(Instant.parse("2026-11-19T00:01:00Z"), java.time.ZoneOffset.UTC);

    private static byte[] nonce() {
        byte[] value = new byte[32];
        new SecureRandom().nextBytes(value);
        return value;
    }

    private static TransactionEnvelopeV1 transaction(Map<String, String> payload) {
        return new TransactionEnvelopeV1("txn-001", "tenant-001", "subject-001", "finance-approval",
                "CHANGE_SUPPLIER_BANK_ACCOUNT", "supplier-001", "resource-v7", "policy-v3",
                payload, nonce(), ISSUED_AT, EXPIRES_AT);
    }

    @Test
    void payloadInsertionOrderDoesNotChangeCanonicalDigest() {
        Map<String, String> first = new LinkedHashMap<>();
        first.put("amount_minor", "850000");
        first.put("currency", "INR");
        first.put("beneficiary_account", "XX-4821");
        Map<String, String> second = new LinkedHashMap<>();
        second.put("beneficiary_account", "XX-4821");
        second.put("currency", "INR");
        second.put("amount_minor", "850000");
        byte[] fixedNonce = nonce();

        var a = new TransactionEnvelopeV1("txn-001", "tenant-001", "subject-001", "finance-approval",
                "CHANGE_SUPPLIER_BANK_ACCOUNT", "supplier-001", "resource-v7", "policy-v3",
                first, fixedNonce, ISSUED_AT, EXPIRES_AT);
        var b = new TransactionEnvelopeV1("txn-001", "tenant-001", "subject-001", "finance-approval",
                "CHANGE_SUPPLIER_BANK_ACCOUNT", "supplier-001", "resource-v7", "policy-v3",
                second, fixedNonce, ISSUED_AT, EXPIRES_AT);

        assertArrayEquals(a.canonicalBytes(), b.canonicalBytes());
        assertArrayEquals(a.digest(), b.digest());
    }

    @Test
    void idempotencyKeyIsTenantScopedAndStableForTransactionRetries() {
        var first = new TransactionEnvelopeV1("same-id", "tenant-a", "subject", "audience",
                "UPDATE", "target", "resource-v1", "policy-v1",
                Map.of("value", "one"), nonce(), ISSUED_AT, EXPIRES_AT);
        var retry = new TransactionEnvelopeV1("same-id", "tenant-a", "subject", "audience",
                "UPDATE", "target", "resource-v1", "policy-v1",
                Map.of("value", "two"), nonce(), ISSUED_AT, EXPIRES_AT);
        var otherTenant = new TransactionEnvelopeV1("same-id", "tenant-b", "subject", "audience",
                "UPDATE", "target", "resource-v1", "policy-v1",
                Map.of("value", "one"), nonce(), ISSUED_AT, EXPIRES_AT);

        assertEquals(first.idempotencyKey(), retry.idempotencyKey());
        assertNotEquals(first.idempotencyKey(), otherTenant.idempotencyKey());
    }

    @Test
    void transactionDigestChangesWhenApprovedPayloadChanges() {
        var original = transaction(Map.of("amount_minor", "850000", "currency", "INR"));
        var changed = new TransactionEnvelopeV1(original.transactionId(), original.tenantId(),
                original.subjectId(), original.audience(), original.actionType(), original.targetId(),
                original.resourceVersion(), original.policyVersion(),
                Map.of("amount_minor", "850001", "currency", "INR"),
                original.nonce(), original.issuedAt(), original.expiresAt());

        assertFalse(java.security.MessageDigest.isEqual(original.digest(), changed.digest()));
        assertThrows(IllegalArgumentException.class, () -> new TransactionEnvelopeV1(
                "txn", "tenant", "subject", "audience", "action", "target", "v1", "p1",
                Map.of("Amount", "1"), nonce(), ISSUED_AT, EXPIRES_AT));
    }

    @Test
    void signaturesAreBoundToTheExactTransactionAndNote() throws Exception {
        NoteInventoryIssuer issuer = NoteInventoryIssuer.create();
        var inventory = issuer.issue("finance-inventory-2026-11", 4);
        var walletNote = inventory.walletCredentials().get(1);
        var identity = TornNote.keys("ed25519");
        var verifier = new AuthorizationVerifier(issuer.issuerPublicKey(),
                new AuthorizationVerifier.InMemorySpendStore(), TEST_CLOCK);
        var approved = transaction(Map.of("amount_minor", "850000", "currency", "INR",
                "beneficiary_account", "XX-4821"));
        var envelope = new NoteAuthorizationEnvelopeV1(approved, inventory.manifest(),
                walletNote.publicNote(), identity.pair().getPublic());
        var signatures = walletNote.authorizeBound(identity, inventory.manifest(), envelope);

        assertTrue(verifier.verifyBound(inventory.manifest(), walletNote.publicNote(),
                identity.pair().getPublic(), approved, envelope, signatures).accepted());

        var altered = new TransactionEnvelopeV1(approved.transactionId(), approved.tenantId(),
                approved.subjectId(), approved.audience(), approved.actionType(), approved.targetId(),
                approved.resourceVersion(), approved.policyVersion(),
                Map.of("amount_minor", "850001", "currency", "INR", "beneficiary_account", "XX-4821"),
                approved.nonce(), approved.issuedAt(), approved.expiresAt());
        var alteredEnvelope = new NoteAuthorizationEnvelopeV1(altered, inventory.manifest(),
                walletNote.publicNote(), identity.pair().getPublic());
        var spliced = verifier.verifyBound(inventory.manifest(), walletNote.publicNote(),
                identity.pair().getPublic(), altered, alteredEnvelope, signatures);
        assertFalse(spliced.accepted());
        assertEquals("note-authorization-signature-invalid", spliced.reason());

        var accepted = verifier.verifyBoundAndConsume(inventory.manifest(), walletNote.publicNote(),
                identity.pair().getPublic(), approved, envelope, signatures);
        assertTrue(accepted.accepted(), accepted.reason());
        var replay = verifier.verifyBoundAndConsume(inventory.manifest(), walletNote.publicNote(),
                identity.pair().getPublic(), approved, envelope, signatures);
        assertFalse(replay.accepted());
        assertEquals("note-already-spent", replay.reason());
    }

    @Test
    void sameTransactionCannotBeSplicedWithAnotherNote() throws Exception {
        NoteInventoryIssuer issuer = NoteInventoryIssuer.create();
        var inventory = issuer.issue("same-transaction-different-note", 2);
        var noteA = inventory.walletCredentials().get(0);
        var noteB = inventory.walletCredentials().get(1);
        var identity = TornNote.keys("ed25519");
        var tx = transaction(Map.of("amount_minor", "2500", "currency", "INR"));
        var envelopeA = new NoteAuthorizationEnvelopeV1(tx, inventory.manifest(),
                noteA.publicNote(), identity.pair().getPublic());
        var signaturesA = noteA.authorizeBound(identity, inventory.manifest(), envelopeA);
        var envelopeB = new NoteAuthorizationEnvelopeV1(tx, inventory.manifest(),
                noteB.publicNote(), identity.pair().getPublic());
        var verifier = new AuthorizationVerifier(issuer.issuerPublicKey(),
                new AuthorizationVerifier.InMemorySpendStore(), TEST_CLOCK);

        var spliced = verifier.verifyBound(inventory.manifest(), noteB.publicNote(),
                identity.pair().getPublic(), tx, envelopeB, signaturesA);
        assertFalse(spliced.accepted());
        assertEquals("note-authorization-signature-invalid", spliced.reason());
    }

    @Test
    void legacySignaturesCannotBeReplayedAsV1BoundSignatures() throws Exception {
        NoteInventoryIssuer issuer = NoteInventoryIssuer.create();
        var inventory = issuer.issue("protocol-separation", 1);
        var walletNote = inventory.walletCredentials().get(0);
        var identity = TornNote.keys("ed25519");
        var tx = transaction(Map.of("amount_minor", "42"));
        var envelope = new NoteAuthorizationEnvelopeV1(tx, inventory.manifest(),
                walletNote.publicNote(), identity.pair().getPublic());
        var legacy = walletNote.authorize(identity, inventory.manifest(), "legacy-transaction");
        var verifier = new AuthorizationVerifier(issuer.issuerPublicKey(),
                new AuthorizationVerifier.InMemorySpendStore(), TEST_CLOCK);

        var result = verifier.verifyBound(inventory.manifest(), walletNote.publicNote(),
                identity.pair().getPublic(), tx, envelope, legacy);
        assertFalse(result.accepted());
        assertEquals("note-authorization-signature-invalid", result.reason());
    }
}
