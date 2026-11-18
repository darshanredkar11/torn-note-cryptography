package io.tornnote.wallet;

import com.mongodb.MongoException;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import org.bson.Document;

import java.util.Date;

/** Atomic insert-if-absent spend adapter for the existing AuthorizationVerifier API. */
public final class MongoSpendStore implements AuthorizationVerifier.SpendStore {
    private final MongoCollection<Document> spentNotes;

    public MongoSpendStore(MongoDatabase database) {
        this.spentNotes = java.util.Objects.requireNonNull(database, "database")
                .getCollection(MongoBoundAuthorizationStore.SPENT_NOTES);
    }

    @Override
    public boolean consumeIfAbsent(String spendKey) {
        try {
            spentNotes.insertOne(new Document("_id", spendKey).append("consumedAt", new Date()));
            return true;
        } catch (MongoException error) {
            if (MongoBoundAuthorizationStore.isDuplicateKey(error)) return false;
            throw error;
        }
    }
}
