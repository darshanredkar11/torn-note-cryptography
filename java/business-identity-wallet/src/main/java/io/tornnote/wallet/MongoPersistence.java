package io.tornnote.wallet;

import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.ReadPreference;
import com.mongodb.WriteConcern;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoDatabase;
import org.bson.Document;

/**
 * Shared MongoDB production wiring. Fails fast on standalone mongod because
 * authorization requires multi-document transactions.
 */
public final class MongoPersistence implements AutoCloseable {
    private final MongoClient client;
    private final MongoDatabase database;

    private MongoPersistence(MongoClient client, MongoDatabase database) {
        this.client = client;
        this.database = database;
    }

    public static MongoPersistence fromEnvironment() {
        String uri = System.getenv("MONGODB_URI");
        if (uri == null || uri.isBlank())
            throw new IllegalStateException("MONGODB_URI-must-be-configured");
        String databaseName = System.getenv().getOrDefault("MONGODB_DATABASE", "torn_note_auth");

        MongoClientSettings settings = MongoClientSettings.builder()
                .applyConnectionString(new ConnectionString(uri))
                .readPreference(ReadPreference.primary())
                .writeConcern(WriteConcern.MAJORITY)
                .build();
        MongoClient client = MongoClients.create(settings);
        try {
            MongoDatabase database = client.getDatabase(databaseName)
                    .withReadPreference(ReadPreference.primary())
                    .withWriteConcern(WriteConcern.MAJORITY);
            Document hello = database.runCommand(new Document("hello", 1));
            if (!hello.containsKey("setName") && !"isdbgrid".equals(hello.getString("msg")))
                throw new IllegalStateException(
                        "MongoDB-transactions-require-a-replica-set-or-sharded-cluster");
            return new MongoPersistence(client, database);
        } catch (RuntimeException error) {
            client.close();
            throw error;
        }
    }

    public MongoClient client() { return client; }
    public MongoDatabase database() { return database; }
    public MongoCredentialRepository credentials() { return new MongoCredentialRepository(client, database); }
    public MongoBoundAuthorizationStore boundAuthorizationStore() {
        return new MongoBoundAuthorizationStore(client, database);
    }
    public MongoSubjectKeyRegistry subjectKeyRegistry() { return new MongoSubjectKeyRegistry(database); }
    public MongoSpendStore spendStore() { return new MongoSpendStore(database); }
    public MongoOutboxRepository outbox() { return new MongoOutboxRepository(database); }

    @Override public void close() { client.close(); }
}
