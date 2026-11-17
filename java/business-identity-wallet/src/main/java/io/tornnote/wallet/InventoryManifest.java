package io.tornnote.wallet;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Objects;

/**
 * Public, issuer-signed commitment to one finite note inventory.
 *
 * The verifier must pin the issuer public key independently. A public key
 * carried alongside an untrusted manifest is not a trust anchor.
 */
public final class InventoryManifest {
    private static final byte[] DOMAIN =
            "TORN-NOTE/inventory-manifest/v1\0".getBytes(StandardCharsets.UTF_8);

    private final String inventoryId;
    private final int noteCount;
    private final byte[] root;
    private final byte[] signature;

    public InventoryManifest(String inventoryId, int noteCount, byte[] root, byte[] signature) {
        this.inventoryId = Objects.requireNonNull(inventoryId, "inventoryId");
        if (inventoryId.isBlank()) throw new IllegalArgumentException("inventoryId is blank");
        if (noteCount < 1) throw new IllegalArgumentException("noteCount must be positive");
        if (root == null || root.length != 32) throw new IllegalArgumentException("root must be 32 bytes");
        if (signature == null || signature.length == 0) throw new IllegalArgumentException("signature is empty");
        this.noteCount = noteCount;
        this.root = root.clone();
        this.signature = signature.clone();
    }

    static InventoryManifest sign(String inventoryId, int noteCount, byte[] root, PrivateKey issuerKey)
            throws GeneralSecurityException {
        byte[] payload = payload(inventoryId, noteCount, root);
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(issuerKey);
        signer.update(payload);
        return new InventoryManifest(inventoryId, noteCount, root, signer.sign());
    }

    /** Verify against an issuer key already trusted/pinned by the verifier. */
    public boolean verify(PublicKey trustedIssuerKey) throws GeneralSecurityException {
        if (trustedIssuerKey == null) return false;
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(trustedIssuerKey);
        verifier.update(payload(inventoryId, noteCount, root));
        return verifier.verify(signature);
    }

    private static byte[] payload(String inventoryId, int noteCount, byte[] root) {
        byte[] id = inventoryId.getBytes(StandardCharsets.UTF_8);
        return ByteBuffer.allocate(DOMAIN.length + Integer.BYTES + id.length
                        + Integer.BYTES + Integer.BYTES + root.length)
                .put(DOMAIN)
                .putInt(id.length)
                .put(id)
                .putInt(noteCount)
                .putInt(root.length)
                .put(root)
                .array();
    }

    public String inventoryId() { return inventoryId; }
    public int noteCount() { return noteCount; }
    public byte[] root() { return root.clone(); }
    public byte[] signature() { return signature.clone(); }
}