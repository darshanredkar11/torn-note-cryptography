package io.tornnote.wallet;

import org.bson.Document;
import org.bson.types.Binary;

import java.util.Objects;

/** Converts BSON binary values to defensive byte-array copies. */
final class MongoBytes {
    private MongoBytes() {}

    static byte[] get(Document document, String field) {
        Objects.requireNonNull(document, "document");
        Object value = document.get(field);
        if (value instanceof byte[] bytes) return bytes.clone();
        if (value instanceof Binary binary) return binary.getData().clone();
        throw new IllegalStateException("missing-or-invalid-bson-binary-field:" + field);
    }
}
