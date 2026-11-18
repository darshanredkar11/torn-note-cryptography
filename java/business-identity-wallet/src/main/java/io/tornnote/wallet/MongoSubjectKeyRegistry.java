package io.tornnote.wallet;

import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Indexes;
import com.mongodb.client.model.Updates;
import org.bson.Document;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.Objects;

import static com.mongodb.client.model.Filters.eq;

/**
 * Durable tenant/subject association for the Torn Note master identity public key.
 * Assignments must be written only by a trusted enrollment/issuer workflow.
 */
public final class MongoSubjectKeyRegistry implements WebAuthnBoundAuthorizationService.SubjectKeyRegistry {
    private static final byte[] DOMAIN =
            "TORN-NOTE/subject-key-record/v1\0".getBytes(StandardCharsets.US_ASCII);
    private final MongoCollection<Document> keys;

    public MongoSubjectKeyRegistry(MongoDatabase database) {
        this.keys = Objects.requireNonNull(database, "database").getCollection("subject_identity_keys");
        keys.createIndex(Indexes.ascending("tenantId", "subjectId"));
    }

    public void assign(String tenantId, String subjectId, PublicKey identityPublicKey) {
        Objects.requireNonNull(identityPublicKey, "identityPublicKey");
        String id = recordId(tenantId, subjectId, identityPublicKey);
        keys.updateOne(eq("_id", id),
                Updates.combine(
                        Updates.setOnInsert("tenantId", tenantId),
                        Updates.setOnInsert("subjectId", subjectId),
                        Updates.setOnInsert("publicKeySpki", identityPublicKey.getEncoded()),
                        Updates.setOnInsert("createdAt", new Date()),
                        Updates.set("active", true),
                        Updates.set("updatedAt", new Date())),
                new com.mongodb.client.model.UpdateOptions().upsert(true));
    }

    public boolean revoke(String tenantId, String subjectId, PublicKey identityPublicKey) {
        String id = recordId(tenantId, subjectId, identityPublicKey);
        var result = keys.updateOne(eq("_id", id),
                Updates.combine(Updates.set("active", false), Updates.set("revokedAt", new Date())));
        return result.getMatchedCount() == 1;
    }

    @Override
    public boolean isAssigned(String tenantId, String subjectId, PublicKey identityPublicKey) {
        if (tenantId == null || subjectId == null || identityPublicKey == null) return false;
        Document record = keys.find(eq("_id", recordId(tenantId, subjectId, identityPublicKey))).first();
        return record != null && record.getBoolean("active", false)
                && MessageDigest.isEqual(record.get("publicKeySpki", byte[].class), identityPublicKey.getEncoded());
    }

    private static String recordId(String tenantId, String subjectId, PublicKey key) {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(subjectId, "subjectId");
        Objects.requireNonNull(key, "key");
        if (tenantId.isBlank() || subjectId.isBlank())
            throw new IllegalArgumentException("tenant-and-subject-required");
        try {
            byte[] tenant = tenantId.getBytes(StandardCharsets.UTF_8);
            byte[] subject = subjectId.getBytes(StandardCharsets.UTF_8);
            byte[] encodedKey = key.getEncoded();
            ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES + tenant.length
                    + Integer.BYTES + subject.length + Integer.BYTES + encodedKey.length);
            buffer.putInt(tenant.length).put(tenant);
            buffer.putInt(subject.length).put(subject);
            buffer.putInt(encodedKey.length).put(encodedKey);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(DOMAIN);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest.digest(buffer.array()));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256-is-required", impossible);
        }
    }
}
