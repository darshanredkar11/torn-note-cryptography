package io.tornnote.wallet;

import com.mongodb.MongoException;
import com.mongodb.ReadPreference;
import com.mongodb.TransactionOptions;
import com.mongodb.WriteConcern;
import com.mongodb.client.ClientSession;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.FindOneAndUpdateOptions;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.model.Indexes;
import com.mongodb.client.model.ReturnDocument;
import com.mongodb.client.model.Updates;
import org.bson.Document;

import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static com.mongodb.client.model.Filters.*;

/** MongoDB production adapter for challenges, spends, decisions and outbox creation. */
public final class MongoBoundAuthorizationStore implements BoundAuthorizationStore {
    static final String CHALLENGES = "webauthn_challenges";
    static final String SPENT_NOTES = "spent_notes";
    static final String AUTHORIZATIONS = "authorization_decisions";
    static final String OUTBOX = "authorization_outbox";

    private static final TransactionOptions TX_OPTIONS = TransactionOptions.builder()
            .readConcern(com.mongodb.ReadConcern.SNAPSHOT)
            .writeConcern(WriteConcern.MAJORITY)
            .readPreference(ReadPreference.primary())
            .build();

    private final MongoClient client;
    private final MongoCollection<Document> challenges;
    private final MongoCollection<Document> spentNotes;
    private final MongoCollection<Document> authorizations;
    private final MongoCollection<Document> outbox;

    public MongoBoundAuthorizationStore(MongoClient client, MongoDatabase database) {
        this.client = java.util.Objects.requireNonNull(client, "client");
        java.util.Objects.requireNonNull(database, "database");
        this.challenges = database.getCollection(CHALLENGES);
        this.spentNotes = database.getCollection(SPENT_NOTES);
        this.authorizations = database.getCollection(AUTHORIZATIONS);
        this.outbox = database.getCollection(OUTBOX);
        ensureIndexes();
    }

    private void ensureIndexes() {
        challenges.createIndex(Indexes.ascending("expiresAt"),
                new IndexOptions().expireAfter(0L, TimeUnit.SECONDS));
        challenges.createIndex(Indexes.compoundIndex(
                Indexes.ascending("tenantId"), Indexes.ascending("subjectId"),
                Indexes.ascending("sessionId"), Indexes.ascending("state")));
        outbox.createIndex(Indexes.compoundIndex(
                Indexes.ascending("status"), Indexes.ascending("nextAttemptAt"),
                Indexes.ascending("createdAt")));
        outbox.createIndex(Indexes.compoundIndex(
                Indexes.ascending("status"), Indexes.ascending("leaseUntil")));
    }

    @Override
    public void create(PendingAssertion pending) {
        java.util.Objects.requireNonNull(pending, "pending");
        challenges.insertOne(new Document("_id", pending.challengeId())
                .append("assertionRequestJson", pending.assertionRequestJson())
                .append("transactionId", pending.transactionId())
                .append("tenantId", pending.tenantId())
                .append("subjectId", pending.subjectId())
                .append("sessionId", pending.sessionId())
                .append("audience", pending.audience())
                .append("transactionDigest", pending.transactionDigest())
                .append("noteAuthorizationDigest", pending.noteAuthorizationDigest())
                .append("expiresAt", Date.from(pending.expiresAt()))
                .append("state", "PENDING")
                .append("createdAt", new Date()));
    }

    @Override
    public Optional<PendingAssertion> claim(
            String challengeId, String tenantId, String subjectId, String sessionId, Instant now) {
        Document doc = challenges.findOneAndUpdate(
                and(eq("_id", challengeId), eq("tenantId", tenantId), eq("subjectId", subjectId),
                        eq("sessionId", sessionId), eq("state", "PENDING"),
                        gt("expiresAt", Date.from(now))),
                Updates.combine(Updates.set("state", "VERIFYING"),
                        Updates.set("claimedAt", Date.from(now))),
                new FindOneAndUpdateOptions().returnDocument(ReturnDocument.AFTER));
        if (doc == null) {
            challenges.updateOne(and(eq("_id", challengeId), eq("state", "PENDING"),
                    lte("expiresAt", Date.from(now))),
                    Updates.combine(Updates.set("state", "EXPIRED"),
                            Updates.set("expiredAt", Date.from(now))));
            return Optional.empty();
        }
        return Optional.of(toPending(doc));
    }

    @Override
    public boolean commit(String challengeId, String spendKey, OutboxCommand command, Instant now) {
        java.util.Objects.requireNonNull(command, "command");
        try (ClientSession session = client.startSession()) {
            Boolean committed = session.withTransaction(() -> {
                Date commitTime = Date.from(now);
                var claimed = challenges.updateOne(session,
                        and(eq("_id", challengeId), eq("state", "VERIFYING"),
                                gt("expiresAt", commitTime)),
                        Updates.combine(Updates.set("state", "CONSUMED"),
                                Updates.set("consumedAt", commitTime)));
                if (claimed.getMatchedCount() != 1) return Boolean.FALSE;

                spentNotes.insertOne(session, new Document("_id", spendKey)
                        .append("transactionId", command.transactionId())
                        .append("tenantId", command.tenantId())
                        .append("subjectId", command.subjectId())
                        .append("transactionDigest", command.transactionDigest())
                        .append("consumedAt", commitTime));

                authorizations.insertOne(session, new Document("_id", command.idempotencyKey())
                        .append("idempotencyKey", command.idempotencyKey())
                        .append("transactionId", command.transactionId())
                        .append("tenantId", command.tenantId())
                        .append("subjectId", command.subjectId())
                        .append("audience", command.audience())
                        .append("actionType", command.actionType())
                        .append("targetId", command.targetId())
                        .append("transactionDigest", command.transactionDigest())
                        .append("authorizedAt", commitTime)
                        .append("decision", "AUTHORIZED"));

                Document payloadFields = new Document();
                command.payloadFields().forEach(payloadFields::append);
                outbox.insertOne(session, new Document("_id", command.idempotencyKey())
                        .append("transactionId", command.transactionId())
                        .append("tenantId", command.tenantId())
                        .append("subjectId", command.subjectId())
                        .append("audience", command.audience())
                        .append("actionType", command.actionType())
                        .append("targetId", command.targetId())
                        .append("transactionDigest", command.transactionDigest())
                        .append("canonicalTransaction", command.canonicalTransaction())
                        .append("payloadFields", payloadFields)
                        .append("status", "PENDING")
                        .append("attemptCount", 0)
                        .append("createdAt", commitTime)
                        .append("nextAttemptAt", commitTime));
                return Boolean.TRUE;
            }, TX_OPTIONS);
            return Boolean.TRUE.equals(committed);
        } catch (MongoException error) {
            if (isDuplicateKey(error)) {
                invalidate(challengeId, "duplicate-note-or-transaction");
                return false;
            }
            throw error;
        }
    }

    @Override
    public void invalidate(String challengeId, String reason) {
        challenges.updateOne(and(eq("_id", challengeId), in("state", "PENDING", "VERIFYING")),
                Updates.combine(Updates.set("state", "INVALID"),
                        Updates.set("invalidReason", reason == null ? "invalidated" : reason),
                        Updates.set("invalidatedAt", new Date())));
    }

    private static PendingAssertion toPending(Document doc) {
        return new PendingAssertion(doc.getString("_id"), doc.getString("assertionRequestJson"),
                doc.getString("transactionId"), doc.getString("tenantId"), doc.getString("subjectId"),
                doc.getString("sessionId"), doc.getString("audience"),
                doc.get("transactionDigest", byte[].class),
                doc.get("noteAuthorizationDigest", byte[].class), doc.getDate("expiresAt").toInstant());
    }

    static boolean isDuplicateKey(Throwable error) {
        for (Throwable current = error; current != null; current = current.getCause()) {
            if (current instanceof MongoException mongo && mongo.getCode() == 11000) return true;
        }
        return false;
    }
}
