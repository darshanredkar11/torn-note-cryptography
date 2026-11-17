package io.tornnote.wallet;

import io.tornnote.TornNote;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Shared, deliberately simple conventional-signature baselines for the demo. */
final class AuthorizationComparison {
    private static final byte[] DOMAIN = "BUSINESS-AUTHORIZATION/v1\0".getBytes(StandardCharsets.UTF_8);

    private AuthorizationComparison() {}

    static byte[] message(String canonicalTransaction) {
        byte[] body = canonicalTransaction.getBytes(StandardCharsets.UTF_8);
        byte[] result = new byte[DOMAIN.length + body.length];
        System.arraycopy(DOMAIN, 0, result, 0, DOMAIN.length);
        System.arraycopy(body, 0, result, DOMAIN.length, body.length);
        return result;
    }

    static byte[] sign(KeyPair key, String tx) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(key.getPrivate());
        signature.update(message(tx));
        return signature.sign();
    }

    static boolean verify(PublicKey key, String tx, byte[] bytes) throws GeneralSecurityException {
        if (bytes == null) return false;
        Signature signature = Signature.getInstance("Ed25519");
        signature.initVerify(key);
        signature.update(message(tx));
        return signature.verify(bytes);
    }

    static List<byte[]> signAll(List<KeyPair> keys, String tx) throws GeneralSecurityException {
        List<byte[]> signatures = new ArrayList<>();
        for (KeyPair key : keys) signatures.add(sign(key, tx));
        return signatures;
    }

    /**
     * Best-practice replay guard for the conventional baseline. Verification
     * and nonce consumption are one synchronized operation in this in-memory
     * harness; production must use a transactional durable store.
     */
    static final class ConventionalVerifier {
        private final List<PublicKey> signers;
        private final Set<String> consumedRequestIds = new HashSet<>();

        ConventionalVerifier(List<PublicKey> signers) { this.signers = List.copyOf(signers); }

        synchronized boolean verifyAndConsume(String requestId, String tx, List<byte[]> signatures)
                throws GeneralSecurityException {
            if (requestId == null || consumedRequestIds.contains(requestId)
                    || signatures == null || signatures.size() != signers.size()) return false;
            for (int i = 0; i < signers.size(); i++) {
                if (!verify(signers.get(i), tx, signatures.get(i))) return false;
            }
            consumedRequestIds.add(requestId);
            return true;
        }
    }

    static final class TornFixture {
        final TornNote.Keys master;
        final List<TornNote.Note> notes = new ArrayList<>();
        final List<byte[]> leaves = new ArrayList<>();
        final byte[] root;
        final int selectedIndex = 3;
        final List<byte[]> proof;
        final TornNote.Note selected;

        TornFixture() throws GeneralSecurityException {
            master = TornNote.keys("ed25519");
            for (int i = 0; i < 8; i++) {
                TornNote.Note note = new TornNote.Note(
                        ("wallet-note-" + i).getBytes(StandardCharsets.UTF_8),
                        TornNote.keys("ed25519"), TornNote.keys("ed25519"));
                notes.add(note);
                leaves.add(TornNote.leaf(note.id(),
                        TornNote.pub(note.a().pair()), TornNote.pub(note.b().pair())));
            }
            root = TornNote.root(leaves);
            proof = TornNote.proof(leaves, selectedIndex);
            selected = notes.get(selectedIndex);
        }

        byte[] pubA() { return TornNote.pub(selected.a().pair()); }
        byte[] pubB() { return TornNote.pub(selected.b().pair()); }

        TornNote.SignatureSet authorize(String tx, boolean master, boolean a, boolean b)
                throws GeneralSecurityException {
            return TornNote.authorizeAvailable(this.master, selected.a(), selected.b(), root,
                    selected.id(), pubA(), pubB(), tx, proof, selectedIndex, master, a, b);
        }

        boolean verify(String tx, TornNote.SignatureSet signatures, boolean spent)
                throws GeneralSecurityException {
            return TornNote.verifyAuthorization(this.master.pair().getPublic(),
                    selected.a().pair().getPublic(), selected.b().pair().getPublic(),
                    root, selected.id(), pubA(), pubB(), tx, proof, selectedIndex, signatures, spent);
        }

        List<KeyPair> allSignerKeys() {
            return List.of(master.pair(), selected.a().pair(), selected.b().pair());
        }
    }
}
