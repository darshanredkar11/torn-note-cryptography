package io.tornnote.wallet;

import io.tornnote.TornNote;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;

/**
 * Coordinates a WebAuthn assertion and Torn Note V1 proof over the same transaction.
 * All authoritative transaction/note inputs must be loaded by the application, not
 * accepted as authoritative client-supplied digest values.
 */
public final class WebAuthnBoundAuthorizationService {
    private final WebAuthnAssertionEngine assertionEngine;
    private final BoundAuthorizationStore store;
    private final AuthorizationVerifier noteVerifier;
    private final SubjectKeyRegistry subjectKeyRegistry;
    private final Clock clock;
    private final SecureRandom random;
    private final Duration challengeTtl;

    public WebAuthnBoundAuthorizationService(
            WebAuthnAssertionEngine assertionEngine,
            BoundAuthorizationStore store,
            AuthorizationVerifier noteVerifier,
            SubjectKeyRegistry subjectKeyRegistry) {
        this(assertionEngine, store, noteVerifier, subjectKeyRegistry,
                Clock.systemUTC(), new SecureRandom(), Duration.ofSeconds(90));
    }

    public WebAuthnBoundAuthorizationService(
            WebAuthnAssertionEngine assertionEngine,
            BoundAuthorizationStore store,
            AuthorizationVerifier noteVerifier,
            SubjectKeyRegistry subjectKeyRegistry,
            Clock clock,
            SecureRandom random,
            Duration challengeTtl) {
        this.assertionEngine = Objects.requireNonNull(assertionEngine, "assertionEngine");
        this.store = Objects.requireNonNull(store, "store");
        this.noteVerifier = Objects.requireNonNull(noteVerifier, "noteVerifier");
        this.subjectKeyRegistry = Objects.requireNonNull(subjectKeyRegistry, "subjectKeyRegistry");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.random = Objects.requireNonNull(random, "random");
        this.challengeTtl = Objects.requireNonNull(challengeTtl, "challengeTtl");
        if (challengeTtl.isNegative() || challengeTtl.isZero())
            throw new IllegalArgumentException("challenge-ttl-must-be-positive");
    }

    /**
     * Start a fresh WebAuthn assertion for an already-frozen transaction and note.
     * SubjectKeyRegistry must verify that the master identity public key is assigned
     * to the same tenant/subject used by the WebAuthn credential repository.
     */
    public Started start(RequestPrincipal principal,
                         TransactionEnvelopeV1 transaction,
                         InventoryManifest manifest,
                         NoteInventoryIssuer.PublicNote note,
                         PublicKey identityPublicKey) throws Exception {
        Objects.requireNonNull(transaction, "transaction");
        Objects.requireNonNull(manifest, "manifest");
        Objects.requireNonNull(note, "note");
        Objects.requireNonNull(identityPublicKey, "identityPublicKey");
        Instant now = clock.instant();
        if (!transaction.isValidAt(now)) throw new IllegalArgumentException("transaction-expired-or-not-yet-valid");
        if (principal == null
                || !transaction.tenantId().equals(principal.tenantId())
                || !transaction.subjectId().equals(principal.subjectId()))
            throw new SecurityException("authenticated-session-does-not-match-transaction");
        if (!subjectKeyRegistry.isAssigned(transaction.tenantId(), transaction.subjectId(), identityPublicKey))
            throw new SecurityException("identity-key-not-assigned-to-subject");

        NoteAuthorizationEnvelopeV1 envelope =
                new NoteAuthorizationEnvelopeV1(transaction, manifest, note, identityPublicKey);
        WebAuthnAssertionEngine.PreparedAssertion assertion = assertionEngine.start(transaction.subjectId());

        byte[] challengeIdBytes = new byte[32];
        random.nextBytes(challengeIdBytes);
        String challengeId = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeIdBytes);
        Instant proposedExpiry = now.plus(challengeTtl);
        Instant expiresAt = transaction.expiresAt().isBefore(proposedExpiry)
                ? transaction.expiresAt() : proposedExpiry;

        BoundAuthorizationStore.PendingAssertion pending = new BoundAuthorizationStore.PendingAssertion(
                challengeId, assertion.assertionRequestJson(), transaction.transactionId(),
                transaction.tenantId(), transaction.subjectId(), principal.sessionId(), transaction.audience(),
                transaction.digest(), envelope.digest(), expiresAt);
        store.create(pending);

        return new Started(challengeId, assertion.credentialGetOptionsJson(),
                Base64.getUrlEncoder().withoutPadding().encodeToString(envelope.digest()), expiresAt);
    }

    /**
     * Finish one ceremony. The store claim makes the challenge one-attempt. On
     * successful verification, commit() atomically spends the note and inserts
     * the protected business action into the outbox.
     */
    public Result finish(String challengeId,
                         RequestPrincipal principal,
                         TransactionEnvelopeV1 transaction,
                         InventoryManifest manifest,
                         NoteInventoryIssuer.PublicNote note,
                         PublicKey identityPublicKey,
                         TornNote.SignatureSet noteSignatures,
                         String assertionResponseJson) {
        if (principal == null) return Result.reject("authenticated-session-required");
        Instant now = clock.instant();
        Optional<BoundAuthorizationStore.PendingAssertion> claimed =
                store.claim(challengeId, principal.tenantId(), principal.subjectId(), principal.sessionId(), now);
        if (claimed.isEmpty()) return Result.reject("challenge-not-pending-or-already-used");

        BoundAuthorizationStore.PendingAssertion pending = claimed.get();
        try {
            if (transaction == null || manifest == null || note == null || identityPublicKey == null
                    || noteSignatures == null || assertionResponseJson == null)
                return reject(challengeId, "authorization-input-missing");
            if (!pending.sessionId().equals(principal.sessionId()))
                return reject(challengeId, "authenticated-session-binding-mismatch");

            NoteAuthorizationEnvelopeV1 envelope =
                    new NoteAuthorizationEnvelopeV1(transaction, manifest, note, identityPublicKey);
            if (!pending.transactionId().equals(transaction.transactionId())
                    || !pending.tenantId().equals(transaction.tenantId())
                    || !pending.subjectId().equals(transaction.subjectId())
                    || !pending.audience().equals(transaction.audience())
                    || !MessageDigest.isEqual(pending.transactionDigest(), transaction.digest())
                    || !MessageDigest.isEqual(pending.noteAuthorizationDigest(), envelope.digest()))
                return reject(challengeId, "transaction-or-note-binding-mismatch");

            if (!subjectKeyRegistry.isAssigned(transaction.tenantId(), transaction.subjectId(), identityPublicKey))
                return reject(challengeId, "identity-key-not-assigned-to-subject");

            AuthorizationVerifier.Result noteResult = noteVerifier.verifyBound(
                    manifest, note, identityPublicKey, transaction, envelope, noteSignatures);
            if (!noteResult.accepted()) return reject(challengeId, noteResult.reason());

            WebAuthnAssertionEngine.VerifiedAssertion assertion =
                    assertionEngine.finish(pending.assertionRequestJson(), assertionResponseJson);
            if (!assertion.success()) return reject(challengeId, "webauthn-assertion-invalid");
            if (!assertion.userVerified()) return reject(challengeId, "webauthn-user-verification-required");
            if (!transaction.subjectId().equals(assertion.username()))
                return reject(challengeId, "webauthn-subject-mismatch");

            String spendKey = manifest.inventoryId() + ":"
                    + Base64.getUrlEncoder().withoutPadding().encodeToString(note.noteId());
            BoundAuthorizationStore.OutboxCommand outbox = new BoundAuthorizationStore.OutboxCommand(
                    transaction.transactionId(), transaction.transactionId(), transaction.tenantId(),
                    transaction.subjectId(), transaction.audience(), transaction.actionType(),
                    transaction.targetId(), transaction.digest(), transaction.canonicalBytes(),
                    transaction.payloadFields());
            if (!store.commit(challengeId, spendKey, outbox, clock.instant()))
                return Result.reject("challenge-or-note-consume-conflict");

            return Result.accept(transaction.transactionId(), Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(transaction.digest()));
        } catch (Exception e) {
            return reject(challengeId, "authorization-verification-failed");
        }
    }

    private Result reject(String challengeId, String reason) {
        store.invalidate(challengeId, reason);
        return Result.reject(reason);
    }

    public record RequestPrincipal(String tenantId, String subjectId, String sessionId) {
        public RequestPrincipal {
            Objects.requireNonNull(tenantId, "tenantId");
            Objects.requireNonNull(subjectId, "subjectId");
            Objects.requireNonNull(sessionId, "sessionId");
            if (tenantId.isBlank() || subjectId.isBlank() || sessionId.isBlank())
                throw new IllegalArgumentException("principal-fields-must-be-nonblank");
        }
    }

    public record Started(String challengeId, String credentialGetOptionsJson,
                          String noteAuthorizationDigestBase64Url, Instant expiresAt) {}

    public record Result(boolean accepted, String reason, String transactionId, String transactionDigest) {
        static Result accept(String transactionId, String digest) {
            return new Result(true, "accepted", transactionId, digest);
        }
        static Result reject(String reason) {
            return new Result(false, reason, null, null);
        }
    }

    @FunctionalInterface
    public interface SubjectKeyRegistry {
        boolean isAssigned(String tenantId, String subjectId, PublicKey identityPublicKey);
    }
}
