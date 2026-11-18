package io.tornnote.wallet;

import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.FindOneAndUpdateOptions;
import com.mongodb.client.model.Indexes;
import com.mongodb.client.model.ReturnDocument;
import com.mongodb.client.model.Sorts;
import com.mongodb.client.model.Updates;
import org.bson.Document;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

import static com.mongodb.client.model.Filters.*;

/** Durable outbox lease/ack/retry operations for at-least-once action delivery. */
public final class MongoOutboxRepository {
    private final MongoCollection<Document> outbox;

    public MongoOutboxRepository(MongoDatabase database) {
        this.outbox = java.util.Objects.requireNonNull(database, "database")
                .getCollection(MongoBoundAuthorizationStore.OUTBOX);
        outbox.createIndex(Indexes.compoundIndex(
                Indexes.ascending("status"), Indexes.ascending("nextAttemptAt"),
                Indexes.ascending("createdAt")));
        outbox.createIndex(Indexes.compoundIndex(
                Indexes.ascending("status"), Indexes.ascending("leaseUntil")));
    }

    /** Atomically leases the oldest due command; expired leases are reclaimable. */
    public Optional<LeasedCommand> claimNext(String workerId, Instant now, Duration leaseDuration) {
        java.util.Objects.requireNonNull(workerId, "workerId");
        java.util.Objects.requireNonNull(now, "now");
        java.util.Objects.requireNonNull(leaseDuration, "leaseDuration");
        if (workerId.isBlank() || leaseDuration.isNegative() || leaseDuration.isZero())
            throw new IllegalArgumentException("worker-and-positive-lease-required");
        Date nowDate = Date.from(now);
        Document doc = outbox.findOneAndUpdate(
                or(and(eq("status", "PENDING"), lte("nextAttemptAt", nowDate)),
                        and(eq("status", "IN_FLIGHT"), lte("leaseUntil", nowDate))),
                Updates.combine(Updates.set("status", "IN_FLIGHT"),
                        Updates.set("leaseOwner", workerId),
                        Updates.set("leaseUntil", Date.from(now.plus(leaseDuration))),
                        Updates.set("lastClaimedAt", nowDate),
                        Updates.inc("attemptCount", 1)),
                new FindOneAndUpdateOptions()
                        .sort(Sorts.ascending("createdAt"))
                        .returnDocument(ReturnDocument.AFTER));
        return doc == null ? Optional.empty() : Optional.of(toLeased(doc));
    }

    public boolean markDelivered(String idempotencyKey, String workerId, Instant now) {
        var result = outbox.updateOne(and(eq("_id", idempotencyKey), eq("status", "IN_FLIGHT"),
                        eq("leaseOwner", workerId)),
                Updates.combine(Updates.set("status", "DELIVERED"),
                        Updates.set("deliveredAt", Date.from(now)),
                        Updates.unset("leaseOwner"), Updates.unset("leaseUntil")));
        return result.getMatchedCount() == 1;
    }

    public boolean scheduleRetry(String idempotencyKey, String workerId, Instant now,
                                 Instant nextAttemptAt, String errorCode) {
        if (!nextAttemptAt.isAfter(now)) throw new IllegalArgumentException("retry-time-must-be-in-future");
        var result = outbox.updateOne(and(eq("_id", idempotencyKey), eq("status", "IN_FLIGHT"),
                        eq("leaseOwner", workerId)),
                Updates.combine(Updates.set("status", "PENDING"),
                        Updates.set("nextAttemptAt", Date.from(nextAttemptAt)),
                        Updates.set("lastErrorCode", errorCode == null ? "delivery-failed" : errorCode),
                        Updates.set("lastFailedAt", Date.from(now)),
                        Updates.unset("leaseOwner"), Updates.unset("leaseUntil")));
        return result.getMatchedCount() == 1;
    }

    public long countByStatus(String status) {
        return outbox.countDocuments(eq("status", status));
    }

    private static LeasedCommand toLeased(Document doc) {
        Document payload = doc.get("payloadFields", Document.class);
        Map<String, String> fields = new TreeMap<>();
        if (payload != null) payload.forEach((key, value) -> fields.put(key, (String) value));
        BoundAuthorizationStore.OutboxCommand command = new BoundAuthorizationStore.OutboxCommand(
                doc.getString("_id"), doc.getString("transactionId"), doc.getString("tenantId"),
                doc.getString("subjectId"), doc.getString("audience"), doc.getString("actionType"),
                doc.getString("targetId"), doc.get("transactionDigest", byte[].class),
                doc.get("canonicalTransaction", byte[].class), fields);
        return new LeasedCommand(command, doc.getInteger("attemptCount", 0),
                doc.getString("leaseOwner"), doc.getDate("leaseUntil").toInstant());
    }

    public record LeasedCommand(BoundAuthorizationStore.OutboxCommand command,
                                int attemptCount, String workerId, Instant leaseUntil) {}
}
