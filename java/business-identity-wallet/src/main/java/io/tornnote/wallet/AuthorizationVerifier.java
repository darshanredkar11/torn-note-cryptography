package io.tornnote.wallet;

import io.tornnote.TornNote;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
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

    public AuthorizationVerifier(PublicKey trustedIssuerKey, SpendStore spendStore) {
        this.trustedIssuerKey = Objects.requireNonNull(trustedIssuerKey, "trustedIssuerKey");
        this.spendStore = Objects.requireNonNull(spendStore, "spendStore");
    }

    public Result verifyAndConsume(InventoryManifest manifest,
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
        if (!valid) return Result.reject("signature-or-inventory-proof-invalid");

        // The store must implement this as an atomic insert-if-absent operation
        // (for example, a database unique key on inventory_id + note_id).
        String spendKey = manifest.inventoryId() + ":"
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