package io.tornnote.wallet;

import io.tornnote.TornNote;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.time.Clock;
import java.util.Base64;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Verification-side component. It receives only public issuer and note data,
 * transaction bytes, and the three signatures. It never receives wallet
 * fragment private keys or the issuer signing private key.
 */
public final class AuthorizationVerifier {
    private final PublicKey trustedIssuerKey;
    private final SpendStore spendStore;
    private final Clock clock;

    public AuthorizationVerifier(PublicKey trustedIssuerKey, SpendStore spendStore) {
        this(trustedIssuerKey, spendStore, Clock.systemUTC());
    }

    public AuthorizationVerifier(PublicKey trustedIssuerKey, SpendStore spendStore, Clock clock) {
        this.trustedIssuerKey = Objects.requireNonNull(trustedIssuerKey, "trustedIssuerKey");
        this.spendStore = Objects.requireNonNull(spendStore, "spendStore");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public Result verifyAndConsume(InventoryManifest manifest,
                                   NoteInventoryIssuer.PublicNote note,
                                   PublicKey identityPublicKey,
                                   String canonicalTransaction,
                                   TornNote.SignatureSet signatures)
            throws GeneralSecurityException {
        Result verification = verify(manifest, note, identityPublicKey, canonicalTransaction, signatures);
        if (!verification.accepted()) return verification;
        String spendKey = manifest.inventoryId() + ":"
                + Base64.getUrlEncoder().withoutPadding().encodeToString(note.noteId());
        if (!spendStore.consumeIfAbsent(spendKey)) return Result.reject("note-already-spent");
        return Result.accept();
    }

    /** Verify the legacy profile without consuming its note. */
    public Result verify(InventoryManifest manifest,
                         NoteInventoryIssuer.PublicNote note,
                         PublicKey identityPublicKey,
                         String canonicalTransaction,
                         TornNote.SignatureSet signatures)
            throws GeneralSecurityException {
        if (manifest == null || !manifest.verify(trustedIssuerKey))
            return Result.reject("issuer-manifest-invalid");
        if (note == null || !manifest.inventoryId().equals(note.inventoryId()))
            return Result.reject("note-inventory-mismatch");
        if (identityPublicKey == null || canonicalTransaction == null || signatures == null)
            return Result.reject("authorization-input-missing");
        if (note.index() < 0 || note.index() >= manifest.noteCount())
            return Result.reject("note-index-out-of-range");
        boolean valid = TornNote.verifyAuthorization(identityPublicKey, note.factorA(), note.factorB(),
                manifest.root(), note.noteId(), note.publicA(), note.publicB(),
                canonicalTransaction, note.proof(), note.index(), signatures, false);
        return valid ? Result.accept() : Result.reject("signature-or-inventory-proof-invalid");
    }

    /** Verify the V1 transaction and note envelope without consuming the note. */
    public Result verifyBound(InventoryManifest manifest,
                              NoteInventoryIssuer.PublicNote note,
                              PublicKey identityPublicKey,
                              TransactionEnvelopeV1 transaction,
                              NoteAuthorizationEnvelopeV1 envelope,
                              TornNote.SignatureSet signatures)
            throws GeneralSecurityException {
        if (manifest == null || !manifest.verify(trustedIssuerKey))
            return Result.reject("issuer-manifest-invalid");
        if (note == null || !manifest.inventoryId().equals(note.inventoryId()))
            return Result.reject("note-inventory-mismatch");
        if (identityPublicKey == null || transaction == null || envelope == null || signatures == null)
            return Result.reject("authorization-input-missing");
        if (note.index() < 0 || note.index() >= manifest.noteCount())
            return Result.reject("note-index-out-of-range");
        if (!transaction.isValidAt(clock.instant()))
            return Result.reject("transaction-expired-or-not-yet-valid");
        if (!envelope.matches(transaction) || !envelope.matches(manifest, note, identityPublicKey))
            return Result.reject("note-authorization-context-mismatch");
        boolean valid = TornNote.verifyBoundAuthorization(identityPublicKey, note.factorA(), note.factorB(),
                manifest.root(), note.noteId(), note.publicA(), note.publicB(), envelope.digest(),
                note.proof(), note.index(), signatures, false);
        return valid ? Result.accept() : Result.reject("note-authorization-signature-invalid");
    }

    /** Verify and atomically consume the note using the configured spend store. */
    public Result verifyBoundAndConsume(InventoryManifest manifest,
                                       NoteInventoryIssuer.PublicNote note,
                                       PublicKey identityPublicKey,
                                       TransactionEnvelopeV1 transaction,
                                       NoteAuthorizationEnvelopeV1 envelope,
                                       TornNote.SignatureSet signatures)
            throws GeneralSecurityException {
        Result verification = verifyBound(manifest, note, identityPublicKey, transaction, envelope, signatures);
        if (!verification.accepted()) return verification;
        String spendKey = transaction.tenantId() + ":" + manifest.inventoryId() + ":"
                + Base64.getUrlEncoder().withoutPadding().encodeToString(note.noteId());
        if (!spendStore.consumeIfAbsent(spendKey)) return Result.reject("note-already-spent");
        return Result.accept();
    }

    public record Result(boolean accepted, String reason) {
        static Result accept() { return new Result(true, "accepted"); }
        static Result reject(String reason) { return new Result(false, reason); }
    }

    @FunctionalInterface
    public interface SpendStore {
        /** Atomically mark this identifier spent, returning true only to the first caller. */
        boolean consumeIfAbsent(String spendKey);
    }

    /** Test/demo adapter only. Replace with durable transactional storage in production. */
    public static final class InMemorySpendStore implements SpendStore {
        private final Set<String> consumed = ConcurrentHashMap.newKeySet();
        @Override public boolean consumeIfAbsent(String spendKey) { return consumed.add(spendKey); }
    }
}