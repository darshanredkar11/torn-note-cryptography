package io.tornnote.wallet;

import com.mongodb.TransactionOptions;
import com.mongodb.client.ClientSession;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Indexes;
import com.mongodb.client.model.Updates;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.UserIdentity;
import org.bson.Document;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.Objects;

import static com.mongodb.client.model.Filters.*;

/**
 * Mongo-backed Yubico CredentialRepository.
 * Stores credential public COSE keys only; passkey private keys remain in authenticators.
 */
public final class MongoCredentialRepository implements CredentialRepository {
    private static final String CREDENTIALS = "webauthn_credentials";
    private static final String USER_HANDLES = "webauthn_user_handles";

    private final MongoClient client;
    private final MongoCollection<Document> credentials;
    private final MongoCollection<Document> userHandles;

    public MongoCredentialRepository(MongoClient client, MongoDatabase database) {
        this.client = Objects.requireNonNull(client, "client");
        Objects.requireNonNull(database, "database");
        this.credentials = database.getCollection(CREDENTIALS);
        this.userHandles = database.getCollection(USER_HANDLES);
        credentials.createIndex(Indexes.compoundIndex(
                Indexes.ascending("username"), Indexes.ascending("active")));
        credentials.createIndex(Indexes.compoundIndex(
                Indexes.ascending("userHandle"), Indexes.ascending("active")));
        credentials.createIndex(Indexes.ascending("tenantId", "subjectId"));
    }

    /**
     * Persist only after RelyingParty.finishRegistration has succeeded.
     * User handles must be random opaque values (recommended: 32 random bytes).
     */
    public void storeVerifiedRegistration(String tenantId, String subjectId, UserIdentity userIdentity,
                                          RegistrationResult registrationResult) {
        Objects.requireNonNull(userIdentity, "userIdentity");
        Objects.requireNonNull(registrationResult, "registrationResult");
        String username = WebAuthnIdentity.usernameFor(tenantId, subjectId);
        if (!registrationResult.isUserVerified())
            throw new SecurityException("registration-user-verification-required");

        Set<String> transports = new TreeSet<>();
        registrationResult.getKeyId().getTransports().ifPresent(values ->
                values.forEach(transport -> transports.add(transport.getId())));

        storeCredentialRecord(tenantId, subjectId, username, userIdentity.getId(),
                registrationResult.getKeyId().getId(), registrationResult.getPublicKeyCose(),
                transports, registrationResult.getSignatureCount(),
                registrationResult.isBackupEligible(), registrationResult.isBackedUp(),
                userIdentity.getName(), userIdentity.getDisplayName());
    }

    private void storeCredentialRecord(String tenantId, String subjectId, String username,
                                       ByteArray userHandle, ByteArray credentialId, ByteArray publicKeyCose,
                                       Set<String> transports, long signatureCount,
                                       boolean backupEligible, boolean backupState,
                                       String name, String displayName) {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(subjectId, "subjectId");
        if (!username.equals(WebAuthnIdentity.usernameFor(tenantId, subjectId)))
            throw new SecurityException("webauthn-username-does-not-match-tenant-subject");
        if (signatureCount < 0) throw new IllegalArgumentException("negative-signature-counter");

        String userHandleId = userHandle.getBase64Url();
        String credentialIdValue = credentialId.getBase64Url();
        Date now = new Date();
        Document credential = new Document("_id", credentialIdValue)
                .append("tenantId", tenantId)
                .append("subjectId", subjectId)
                .append("username", username)
                .append("userHandle", userHandleId)
                .append("publicKeyCose", publicKeyCose.getBytes())
                .append("signatureCount", signatureCount)
                .append("transports", new ArrayList<>(transports))
                .append("backupEligible", backupEligible)
                .append("backupState", backupState)
                .append("name", name)
                .append("displayName", displayName)
                .append("active", true)
                .append("createdAt", now)
                .append("updatedAt", now);

        try (ClientSession session = client.startSession()) {
            session.withTransaction(() -> {
                // A handle cannot be rebound to another tenant-scoped subject.
                userHandles.updateOne(session, eq("_id", userHandleId),
                        Updates.combine(
                                Updates.setOnInsert("tenantId", tenantId),
                                Updates.setOnInsert("subjectId", subjectId),
                                Updates.setOnInsert("username", username),
                                Updates.setOnInsert("createdAt", now)),
                        new com.mongodb.client.model.UpdateOptions().upsert(true));
                Document owner = userHandles.find(session, eq("_id", userHandleId)).first();
                if (owner == null || !tenantId.equals(owner.getString("tenantId"))
                        || !subjectId.equals(owner.getString("subjectId"))
                        || !username.equals(owner.getString("username")))
                    throw new SecurityException("webauthn-user-handle-already-assigned");
                credentials.insertOne(session, credential);
                return Boolean.TRUE;
            }, TransactionOptions.builder().writeConcern(com.mongodb.WriteConcern.MAJORITY).build());
        }
    }

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        Set<PublicKeyCredentialDescriptor> result = new TreeSet<>();
        for (Document doc : credentials.find(and(eq("username", username), eq("active", true)))) {
            result.add(PublicKeyCredentialDescriptor.builder()
                    .id(ByteArray.fromBase64Url(doc.getString("_id")))
                    .transports(toTransports(doc))
                    .build());
        }
        return result;
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        Document doc = credentials.find(and(eq("username", username), eq("active", true))).first();
        return doc == null ? Optional.empty()
                : Optional.of(ByteArray.fromBase64Url(doc.getString("userHandle")));
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        Document doc = credentials.find(and(eq("userHandle", userHandle.getBase64Url()),
                eq("active", true))).first();
        return doc == null ? Optional.empty() : Optional.of(doc.getString("username"));
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        Document doc = credentials.find(and(eq("_id", credentialId.getBase64Url()),
                eq("userHandle", userHandle.getBase64Url()), eq("active", true))).first();
        return doc == null ? Optional.empty() : Optional.of(toRegisteredCredential(doc));
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        Set<RegisteredCredential> result = new HashSet<>();
        // Keep revoked IDs visible here: Yubico uses lookupAll to reject duplicate
        // credential IDs at registration. Active credentials are filtered by lookup().
        for (Document doc : credentials.find(eq("_id", credentialId.getBase64Url())))
            result.add(toRegisteredCredential(doc));
        return result;
    }

    /** Monotonic update: concurrent assertions cannot move the stored counter backwards. */
    public boolean updateSignatureCount(String username, String credentialIdBase64Url, long signatureCount) {
        if (signatureCount < 0) throw new IllegalArgumentException("negative-signature-counter");
        var result = credentials.updateOne(and(eq("_id", credentialIdBase64Url),
                        eq("username", username), eq("active", true)),
                Updates.combine(Updates.max("signatureCount", signatureCount),
                        Updates.set("lastUsedAt", new Date()),
                        Updates.set("updatedAt", new Date())));
        return result.getMatchedCount() == 1;
    }

    public boolean revoke(String tenantId, String subjectId, String credentialIdBase64Url) {
        var result = credentials.updateOne(and(eq("_id", credentialIdBase64Url),
                        eq("tenantId", tenantId), eq("subjectId", subjectId), eq("active", true)),
                Updates.combine(Updates.set("active", false),
                        Updates.set("revokedAt", new Date()),
                        Updates.set("updatedAt", new Date())));
        return result.getMatchedCount() == 1;
    }

    public long countActiveCredentials(String tenantId, String subjectId) {
        return credentials.countDocuments(and(eq("tenantId", tenantId),
                eq("subjectId", subjectId), eq("active", true)));
    }

    private static RegisteredCredential toRegisteredCredential(Document doc) {
        return RegisteredCredential.builder()
                .credentialId(ByteArray.fromBase64Url(doc.getString("_id")))
                .userHandle(ByteArray.fromBase64Url(doc.getString("userHandle")))
                .publicKeyCose(new ByteArray(doc.get("publicKeyCose", byte[].class)))
                .signatureCount(doc.getLong("signatureCount") == null ? 0L : doc.getLong("signatureCount"))
                .transports(toTransports(doc))
                .backupEligible(doc.getBoolean("backupEligible"))
                .backupState(doc.getBoolean("backupState"))
                .build();
    }

    private static Set<AuthenticatorTransport> toTransports(Document doc) {
        Set<AuthenticatorTransport> transports = new TreeSet<>();
        List<String> stored = doc.getList("transports", String.class, List.of());
        stored.forEach(value -> transports.add(AuthenticatorTransport.of(value)));
        return transports;
    }
}
