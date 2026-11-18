package io.tornnote.wallet;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

/**
 * Durable boundary for one-time WebAuthn challenges, note spends and action outbox.
 *
 * Production implementations MUST make claim() a conditional PENDING -> VERIFYING
 * transition and commit() one database transaction covering VERIFYING -> CONSUMED,
 * unique note spend, authorization decision and transactional outbox insert.
 */
public interface BoundAuthorizationStore {
    void create(PendingAssertion pending);
    Optional<PendingAssertion> claim(String challengeId, Instant now);
    boolean commit(String challengeId, String spendKey, OutboxCommand command, Instant now);
    void invalidate(String challengeId, String reason);

    record PendingAssertion(
            String challengeId,
            String assertionRequestJson,
            String transactionId,
            String tenantId,
            String subjectId,
            String audience,
            byte[] transactionDigest,
            byte[] noteAuthorizationDigest,
            Instant expiresAt) {
        public PendingAssertion {
            Objects.requireNonNull(challengeId, "challengeId");
            Objects.requireNonNull(assertionRequestJson, "assertionRequestJson");
            Objects.requireNonNull(transactionId, "transactionId");
            Objects.requireNonNull(tenantId, "tenantId");
            Objects.requireNonNull(subjectId, "subjectId");
            Objects.requireNonNull(audience, "audience");
            Objects.requireNonNull(expiresAt, "expiresAt");
            if (transactionDigest == null || transactionDigest.length != 32)
                throw new IllegalArgumentException("transaction-digest-must-be-32-bytes");
            if (noteAuthorizationDigest == null || noteAuthorizationDigest.length != 32)
                throw new IllegalArgumentException("note-digest-must-be-32-bytes");
            transactionDigest = transactionDigest.clone();
            noteAuthorizationDigest = noteAuthorizationDigest.clone();
        }
        @Override public byte[] transactionDigest() { return transactionDigest.clone(); }
        @Override public byte[] noteAuthorizationDigest() { return noteAuthorizationDigest.clone(); }
    }

    record OutboxCommand(
            String idempotencyKey,
            String transactionId,
            String tenantId,
            String subjectId,
            String audience,
            String actionType,
            String targetId,
            byte[] transactionDigest,
            byte[] canonicalTransaction,
            Map<String, String> payloadFields) {
        public OutboxCommand {
            Objects.requireNonNull(idempotencyKey, "idempotencyKey");
            Objects.requireNonNull(transactionId, "transactionId");
            Objects.requireNonNull(tenantId, "tenantId");
            Objects.requireNonNull(subjectId, "subjectId");
            Objects.requireNonNull(audience, "audience");
            Objects.requireNonNull(actionType, "actionType");
            Objects.requireNonNull(targetId, "targetId");
            if (transactionDigest == null || transactionDigest.length != 32)
                throw new IllegalArgumentException("transaction-digest-must-be-32-bytes");
            Objects.requireNonNull(canonicalTransaction, "canonicalTransaction");
            transactionDigest = transactionDigest.clone();
            canonicalTransaction = canonicalTransaction.clone();
            payloadFields = Collections.unmodifiableMap(new TreeMap<>(payloadFields));
        }
        @Override public byte[] transactionDigest() { return transactionDigest.clone(); }
        @Override public byte[] canonicalTransaction() { return canonicalTransaction.clone(); }
    }

    /**
     * Test/demo adapter only. It is process-local and is NOT safe for serverless
     * multi-instance production deployment.
     */
    final class InMemory implements BoundAuthorizationStore {
        private enum State { PENDING, VERIFYING, CONSUMED, INVALID, EXPIRED }
        private static final class Entry {
            final PendingAssertion pending;
            State state = State.PENDING;
            String reason;
            Entry(PendingAssertion pending) { this.pending = pending; }
        }

        private final Map<String, Entry> challenges = new HashMap<>();
        private final Set<String> spentNotes = new HashSet<>();
        private final Map<String, OutboxCommand> outbox = new HashMap<>();

        @Override public synchronized void create(PendingAssertion pending) {
            Objects.requireNonNull(pending, "pending");
            if (challenges.putIfAbsent(pending.challengeId(), new Entry(pending)) != null)
                throw new IllegalStateException("challenge-id-collision");
        }

        @Override public synchronized Optional<PendingAssertion> claim(String challengeId, Instant now) {
            Entry entry = challenges.get(challengeId);
            if (entry == null || entry.state != State.PENDING) return Optional.empty();
            if (!now.isBefore(entry.pending.expiresAt())) {
                entry.state = State.EXPIRED;
                entry.reason = "challenge-expired";
                return Optional.empty();
            }
            entry.state = State.VERIFYING;
            return Optional.of(entry.pending);
        }

        @Override public synchronized boolean commit(
                String challengeId, String spendKey, OutboxCommand command, Instant now) {
            Entry entry = challenges.get(challengeId);
            if (entry == null || entry.state != State.VERIFYING
                    || !now.isBefore(entry.pending.expiresAt())
                    || spentNotes.contains(spendKey)
                    || outbox.containsKey(command.idempotencyKey())) {
                if (entry != null && entry.state == State.VERIFYING) {
                    entry.state = State.INVALID;
                    entry.reason = "commit-conflict-or-expiry";
                }
                return false;
            }
            // These mutations are one synchronized critical section in this test adapter.
            spentNotes.add(spendKey);
            outbox.put(command.idempotencyKey(), command);
            entry.state = State.CONSUMED;
            entry.reason = "accepted";
            return true;
        }

        @Override public synchronized void invalidate(String challengeId, String reason) {
            Entry entry = challenges.get(challengeId);
            if (entry != null && (entry.state == State.PENDING || entry.state == State.VERIFYING)) {
                entry.state = State.INVALID;
                entry.reason = Objects.requireNonNullElse(reason, "invalidated");
            }
        }

        public synchronized boolean isSpent(String spendKey) { return spentNotes.contains(spendKey); }
        public synchronized List<OutboxCommand> outboxSnapshot() { return new ArrayList<>(outbox.values()); }
        public synchronized String stateOf(String challengeId) {
            Entry entry = challenges.get(challengeId);
            return entry == null ? "MISSING" : entry.state.name();
        }
        public synchronized String reasonOf(String challengeId) {
            Entry entry = challenges.get(challengeId);
            return entry == null ? null : entry.reason;
        }
    }
}
