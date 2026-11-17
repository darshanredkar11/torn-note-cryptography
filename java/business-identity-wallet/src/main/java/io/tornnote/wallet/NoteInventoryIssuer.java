package io.tornnote.wallet;

import io.tornnote.TornNote;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Issuance-side component. It commits a finite inventory and signs the
 * manifest. The verifier is not given this object or any fragment private key.
 *
 * WalletNoteCredential represents material delivered to the wallet holder;
 * production delivery must use a protected channel and separate factor stores.
 */
public final class NoteInventoryIssuer {
    private final KeyPair issuerSigningKey;

    private NoteInventoryIssuer(KeyPair issuerSigningKey) {
        this.issuerSigningKey = issuerSigningKey;
    }

    public static NoteInventoryIssuer create() throws GeneralSecurityException {
        return new NoteInventoryIssuer(KeyPairGenerator.getInstance("Ed25519").generateKeyPair());
    }

    /** Provision this public key to verifiers out of band as the issuer trust anchor. */
    public PublicKey issuerPublicKey() {
        return issuerSigningKey.getPublic();
    }

    public IssuedInventory issue(String inventoryId, int noteCount) throws GeneralSecurityException {
        Objects.requireNonNull(inventoryId, "inventoryId");
        if (inventoryId.isBlank()) throw new IllegalArgumentException("inventoryId is blank");
        if (noteCount < 1 || noteCount > 100_000)
            throw new IllegalArgumentException("noteCount must be between 1 and 100000");

        List<TornNote.Note> generated = new ArrayList<>(noteCount);
        List<byte[]> leaves = new ArrayList<>(noteCount);
        for (int i = 0; i < noteCount; i++) {
            byte[] noteId = (inventoryId + ":note:" + i).getBytes(StandardCharsets.UTF_8);
            TornNote.Note note = new TornNote.Note(noteId, TornNote.keys("ed25519"), TornNote.keys("ed25519"));
            generated.add(note);
            leaves.add(TornNote.leaf(noteId, TornNote.pub(note.a().pair()), TornNote.pub(note.b().pair())));
        }

        byte[] root = TornNote.root(leaves);
        InventoryManifest manifest = InventoryManifest.sign(
                inventoryId, noteCount, root, issuerSigningKey.getPrivate());

        List<WalletNoteCredential> credentials = new ArrayList<>(noteCount);
        for (int i = 0; i < noteCount; i++) {
            TornNote.Note note = generated.get(i);
            PublicNote publicNote = new PublicNote(inventoryId, note.id(),
                    note.a().pair().getPublic(), note.b().pair().getPublic(),
                    TornNote.proof(leaves, i), i);
            credentials.add(new WalletNoteCredential(publicNote, note.a(), note.b()));
        }
        return new IssuedInventory(manifest, credentials);
    }

    public record IssuedInventory(InventoryManifest manifest, List<WalletNoteCredential> walletCredentials) {
        public IssuedInventory {
            Objects.requireNonNull(manifest, "manifest");
            walletCredentials = List.copyOf(walletCredentials);
        }
    }

    /** Public verification input. Contains no signing private keys. */
    public static final class PublicNote {
        private final String inventoryId;
        private final byte[] noteId;
        private final PublicKey factorA;
        private final PublicKey factorB;
        private final List<byte[]> proof;
        private final int index;

        public PublicNote(String inventoryId, byte[] noteId, PublicKey factorA,
                          PublicKey factorB, List<byte[]> proof, int index) {
            this.inventoryId = Objects.requireNonNull(inventoryId, "inventoryId");
            this.noteId = Objects.requireNonNull(noteId, "noteId").clone();
            this.factorA = Objects.requireNonNull(factorA, "factorA");
            this.factorB = Objects.requireNonNull(factorB, "factorB");
            this.proof = proof.stream().map(byte[]::clone).toList();
            this.index = index;
        }

        public String inventoryId() { return inventoryId; }
        public byte[] noteId() { return noteId.clone(); }
        public PublicKey factorA() { return factorA; }
        public PublicKey factorB() { return factorB; }
        public byte[] publicA() { return factorA.getEncoded().clone(); }
        public byte[] publicB() { return factorB.getEncoded().clone(); }
        public List<byte[]> proof() { return proof.stream().map(byte[]::clone).toList(); }
        public int index() { return index; }
    }

    /** Holder-side material; only the publicNote() projection goes to a verifier. */
    public static final class WalletNoteCredential {
        private final PublicNote publicNote;
        private final TornNote.Keys factorA;
        private final TornNote.Keys factorB;

        private WalletNoteCredential(PublicNote publicNote, TornNote.Keys factorA, TornNote.Keys factorB) {
            this.publicNote = publicNote;
            this.factorA = factorA;
            this.factorB = factorB;
        }

        public PublicNote publicNote() { return publicNote; }

        public TornNote.SignatureSet authorize(TornNote.Keys identityKey,
                                               InventoryManifest manifest,
                                               String canonicalTransaction)
                throws GeneralSecurityException {
            if (!manifest.inventoryId().equals(publicNote.inventoryId()))
                throw new SecurityException("credential-inventory-mismatch");
            return TornNote.authorize(identityKey, factorA, factorB, manifest.root(),
                    publicNote.noteId(), publicNote.publicA(), publicNote.publicB(),
                    canonicalTransaction, publicNote.proof(), publicNote.index());
        }
    }
}