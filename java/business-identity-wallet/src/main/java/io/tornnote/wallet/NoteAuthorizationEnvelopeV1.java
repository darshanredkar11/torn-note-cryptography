package io.tornnote.wallet;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Objects;

/** V1 commitment binding a Torn Note authorization to one immutable transaction. */
public final class NoteAuthorizationEnvelopeV1 {
    private static final byte[] DIGEST_DOMAIN =
            "TORN-NOTE/note-authorization/v1\0".getBytes(StandardCharsets.US_ASCII);

    private final String transactionId, tenantId, subjectId, audience, actionType, targetId, inventoryId;
    private final byte[] transactionDigest, manifestRoot, noteId;
    private final byte[] identityPublicKey, factorAPublicKey, factorBPublicKey;

    public NoteAuthorizationEnvelopeV1(TransactionEnvelopeV1 transaction, InventoryManifest manifest,
                                       NoteInventoryIssuer.PublicNote note, PublicKey identityPublicKey) {
        Objects.requireNonNull(transaction, "transaction");
        Objects.requireNonNull(manifest, "manifest");
        Objects.requireNonNull(note, "note");
        Objects.requireNonNull(identityPublicKey, "identityPublicKey");
        if (!manifest.inventoryId().equals(note.inventoryId()))
            throw new IllegalArgumentException("note-inventory-mismatch");
        if (note.index() < 0 || note.index() >= manifest.noteCount())
            throw new IllegalArgumentException("note-index-out-of-range");
        transactionId = transaction.transactionId();
        tenantId = transaction.tenantId();
        subjectId = transaction.subjectId();
        audience = transaction.audience();
        actionType = transaction.actionType();
        targetId = transaction.targetId();
        inventoryId = manifest.inventoryId();
        transactionDigest = transaction.digest();
        manifestRoot = manifest.root();
        noteId = note.noteId();
        this.identityPublicKey = identityPublicKey.getEncoded().clone();
        factorAPublicKey = note.publicA();
        factorBPublicKey = note.publicB();
    }

    private static void writeBytes(DataOutputStream out, byte[] value) throws IOException {
        out.writeInt(value.length);
        out.write(value);
    }

    private static void writeText(DataOutputStream out, String value) throws IOException {
        writeBytes(out, value.getBytes(StandardCharsets.UTF_8));
    }

    /** Canonical fixed-schema bytes committed by the three note-signing factors. */
    public byte[] canonicalBytes() {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            out.writeInt(1);
            writeText(out, transactionId);
            writeText(out, tenantId);
            writeText(out, subjectId);
            writeText(out, audience);
            writeText(out, actionType);
            writeText(out, targetId);
            writeText(out, inventoryId);
            writeBytes(out, transactionDigest);
            writeBytes(out, manifestRoot);
            writeBytes(out, noteId);
            writeBytes(out, identityPublicKey);
            writeBytes(out, factorAPublicKey);
            writeBytes(out, factorBPublicKey);
            out.flush();
            return bytes.toByteArray();
        } catch (IOException impossible) {
            throw new IllegalStateException("in-memory-canonical-encoding-failed", impossible);
        }
    }

    public byte[] digest() { return Hashes.sha256(DIGEST_DOMAIN, canonicalBytes()); }

    public boolean matches(TransactionEnvelopeV1 transaction) {
        return transaction != null
                && transactionId.equals(transaction.transactionId())
                && tenantId.equals(transaction.tenantId())
                && subjectId.equals(transaction.subjectId())
                && audience.equals(transaction.audience())
                && actionType.equals(transaction.actionType())
                && targetId.equals(transaction.targetId())
                && MessageDigest.isEqual(transactionDigest, transaction.digest());
    }

    public boolean matches(InventoryManifest manifest, NoteInventoryIssuer.PublicNote note,
                           PublicKey identityKey) {
        return manifest != null && note != null && identityKey != null
                && inventoryId.equals(manifest.inventoryId())
                && inventoryId.equals(note.inventoryId())
                && MessageDigest.isEqual(manifestRoot, manifest.root())
                && MessageDigest.isEqual(noteId, note.noteId())
                && MessageDigest.isEqual(factorAPublicKey, note.publicA())
                && MessageDigest.isEqual(factorBPublicKey, note.publicB())
                && MessageDigest.isEqual(identityPublicKey, identityKey.getEncoded());
    }

    public byte[] transactionDigest() { return transactionDigest.clone(); }
}
