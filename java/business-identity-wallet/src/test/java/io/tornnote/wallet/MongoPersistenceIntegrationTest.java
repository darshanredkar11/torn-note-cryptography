package io.tornnote.wallet;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoDatabase;
import com.yubico.webauthn.data.ByteArray;
import org.bson.Document;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class MongoPersistenceIntegrationTest {
    private MongoClient client;
    private MongoDatabase database;

    @BeforeEach
    void connect() {
        String uri = System.getenv("MONGODB_TEST_URI");
        Assumptions.assumeTrue(uri != null && !uri.isBlank(),
                "Set MONGODB_TEST_URI to run MongoDB replica-set integration tests");
        client = MongoClients.create(uri);
        database = client.getDatabase("torn_note_it_" + UUID.randomUUID().toString().replace("-", ""));
    }

    @AfterEach
    void close() {
        if (database != null) database.drop();
        if (client != null) client.close();
    }

    @Test
    void transactionAtomicallyConsumesChallengeAndNoteAndEnqueuesOutbox() {
        var store = new MongoBoundAuthorizationStore(client, database);
        Instant now = Instant.now();
        byte[] digest = new byte[32];
        digest[0] = 1;
        byte[] noteDigest = new byte[32];
        noteDigest[0] = 2;
        store.create(new BoundAuthorizationStore.PendingAssertion(
                "challenge-1", "{\"assertion\":\"request\"}", "txn-1",
                "tenant-1", "subject-1", "session-1", "finance",
                digest, noteDigest, now.plusSeconds(120)));

        assertTrue(store.claim("challenge-1", "tenant-1", "subject-1", "wrong-session", now).isEmpty());
        assertTrue(store.claim("challenge-1", "tenant-1", "subject-1", "session-1", now).isPresent());

        var command = new BoundAuthorizationStore.OutboxCommand(
                "txn-1", "txn-1", "tenant-1", "subject-1", "finance",
                "UPDATE_ACCOUNT", "account-42", digest, new byte[]{1, 2, 3}, Map.of("account", "masked"));
        assertTrue(store.commit("challenge-1", "inventory-1:note-1", command, now));
        assertTrue(store.claim("challenge-1", "tenant-1", "subject-1", "session-1", now).isEmpty());
        assertEquals(1, database.getCollection(MongoBoundAuthorizationStore.SPENT_NOTES).countDocuments());
        assertEquals(1, database.getCollection(MongoBoundAuthorizationStore.AUTHORIZATIONS).countDocuments());
        assertEquals(1, database.getCollection(MongoBoundAuthorizationStore.OUTBOX).countDocuments());

        var outbox = new MongoOutboxRepository(database);
        var lease = outbox.claimNext("worker-1", now, Duration.ofSeconds(30)).orElseThrow();
        assertEquals("txn-1", lease.command().idempotencyKey());
        assertEquals(1, lease.attemptCount());
        assertTrue(outbox.markDelivered("txn-1", "worker-1", now.plusSeconds(1)));
        assertFalse(outbox.markDelivered("txn-1", "worker-1", now.plusSeconds(2)));
        assertEquals(1, outbox.countByStatus("DELIVERED"));
    }

    @Test
    void duplicateNoteSpendRollsBackChallengeAuthorizationAndOutboxWrites() {
        var store = new MongoBoundAuthorizationStore(client, database);
        Instant now = Instant.now();
        byte[] digest = new byte[32];
        store.create(new BoundAuthorizationStore.PendingAssertion(
                "challenge-a", "request-a", "txn-a", "tenant", "subject", "sid-a", "audience",
                digest, digest, now.plusSeconds(60)));
        store.create(new BoundAuthorizationStore.PendingAssertion(
                "challenge-b", "request-b", "txn-b", "tenant", "subject", "sid-b", "audience",
                digest, digest, now.plusSeconds(60)));
        assertTrue(store.claim("challenge-a", "tenant", "subject", "sid-a", now).isPresent());
        assertTrue(store.claim("challenge-b", "tenant", "subject", "sid-b", now).isPresent());

        var commandA = new BoundAuthorizationStore.OutboxCommand(
                "txn-a", "txn-a", "tenant", "subject", "audience", "UPDATE", "target",
                digest, new byte[]{1}, Map.of());
        var commandB = new BoundAuthorizationStore.OutboxCommand(
                "txn-b", "txn-b", "tenant", "subject", "audience", "UPDATE", "target",
                digest, new byte[]{2}, Map.of());
        assertTrue(store.commit("challenge-a", "same-spend-key", commandA, now));
        assertFalse(store.commit("challenge-b", "same-spend-key", commandB, now));

        assertEquals(1, database.getCollection(MongoBoundAuthorizationStore.SPENT_NOTES).countDocuments());
        assertEquals(1, database.getCollection(MongoBoundAuthorizationStore.AUTHORIZATIONS).countDocuments());
        assertEquals(1, database.getCollection(MongoBoundAuthorizationStore.OUTBOX).countDocuments());
        assertEquals("INVALID", database.getCollection(MongoBoundAuthorizationStore.CHALLENGES)
                .find(new Document("_id", "challenge-b")).first().getString("state"));
    }

    @Test
    void concurrentClaimsAcrossDifferentStoreInstancesHaveExactlyOneWinner() throws Exception {
        var storeA = new MongoBoundAuthorizationStore(client, database);
        var storeB = new MongoBoundAuthorizationStore(client, database);
        Instant now = Instant.now();
        byte[] digest = new byte[32];
        storeA.create(new BoundAuthorizationStore.PendingAssertion(
                "challenge-race", "request", "txn", "tenant", "subject", "session", "audience",
                digest, digest, now.plusSeconds(120)));

        int contenders = 12;
        var ready = new CountDownLatch(contenders);
        var start = new CountDownLatch(1);
        var winners = new AtomicInteger();
        try (var pool = Executors.newFixedThreadPool(contenders)) {
            for (int i = 0; i < contenders; i++) {
                final int worker = i;
                pool.submit(() -> {
                    ready.countDown();
                    try {
                        start.await();
                        var store = worker % 2 == 0 ? storeA : storeB;
                        if (store.claim("challenge-race", "tenant", "subject", "session", now).isPresent())
                            winners.incrementAndGet();
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                    }
                });
            }
            ready.await();
            start.countDown();
            pool.shutdown();
            while (!pool.isTerminated()) Thread.sleep(5);
        }
        assertEquals(1, winners.get());
    }

    @Test
    void credentialRepositoryLoadsActiveCredentialsAndRetainsRevokedIdsForDuplicateChecks() {
        var credentials = new MongoCredentialRepository(client, database);
        String tenant = "tenant-credentials";
        String subject = "subject-credentials";
        String username = WebAuthnIdentity.usernameFor(tenant, subject);
        byte[] handleBytes = new byte[32];
        handleBytes[0] = 7;
        byte[] credentialBytes = new byte[32];
        credentialBytes[0] = 8;
        byte[] coseBytes = new byte[]{(byte) 0xa1, 0x01, 0x02};
        String handle = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(handleBytes);
        String credentialId = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(credentialBytes);

        database.getCollection("webauthn_user_handles").insertOne(new Document("_id", handle)
                .append("tenantId", tenant).append("subjectId", subject).append("username", username));
        database.getCollection("webauthn_credentials").insertOne(new Document("_id", credentialId)
                .append("tenantId", tenant).append("subjectId", subject).append("username", username)
                .append("userHandle", handle).append("publicKeyCose", coseBytes)
                .append("signatureCount", 4L).append("transports", List.of("internal"))
                .append("backupEligible", true).append("backupState", true).append("active", true));

        ByteArray credential = new ByteArray(java.util.Base64.getUrlDecoder().decode(credentialId));
        ByteArray userHandle = new ByteArray(java.util.Base64.getUrlDecoder().decode(handle));
        assertEquals(1, credentials.getCredentialIdsForUsername(username).size());
        assertEquals(userHandle, credentials.getUserHandleForUsername(username).orElseThrow());
        assertEquals(username, credentials.getUsernameForUserHandle(userHandle).orElseThrow());
        var registered = credentials.lookup(credential, userHandle).orElseThrow();
        assertEquals(4L, registered.getSignatureCount());
        assertEquals(new ByteArray(coseBytes), registered.getPublicKeyCose());
        assertEquals(1, credentials.lookupAll(credential).size());

        assertTrue(credentials.updateSignatureCount(username, credentialId, 9));
        assertTrue(credentials.updateSignatureCount(username, credentialId, 3));
        assertEquals(9L, credentials.lookup(credential, userHandle).orElseThrow().getSignatureCount());
        assertTrue(credentials.revoke(tenant, subject, credentialId));
        assertTrue(credentials.getCredentialIdsForUsername(username).isEmpty());
        assertTrue(credentials.lookup(credential, userHandle).isEmpty());
        assertEquals(1, credentials.lookupAll(credential).size());
    }

    @Test
    void aTenantScopedUsernameCanOwnOnlyOneStableUserHandle() {
        new MongoCredentialRepository(client, database); // creates the unique username index
        var owners = database.getCollection("webauthn_user_handles");
        owners.insertOne(new Document("_id", "handle-1")
                .append("username", "tenant-scoped-user").append("tenantId", "tenant")
                .append("subjectId", "subject"));
        assertThrows(com.mongodb.MongoWriteException.class, () -> owners.insertOne(
                new Document("_id", "handle-2").append("username", "tenant-scoped-user")
                        .append("tenantId", "tenant").append("subjectId", "subject")));
    }

    @Test
    void subjectKeyRegistryPersistsAssignmentAndRevocation() throws Exception {
        var registry = new MongoSubjectKeyRegistry(database);
        var key = KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic();
        registry.assign("tenant-key", "subject-key", key);
        assertTrue(registry.isAssigned("tenant-key", "subject-key", key));
        assertFalse(registry.isAssigned("other-tenant", "subject-key", key));
        assertTrue(registry.revoke("tenant-key", "subject-key", key));
        assertFalse(registry.isAssigned("tenant-key", "subject-key", key));
    }
}
